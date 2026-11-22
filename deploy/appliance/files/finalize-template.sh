#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# The last step of the controller template build. Packer uploads this file to
# the build VM and runs it there as root, after the packages and the controller
# image are in place (deploy/appliance/packer/proxmox-clone.pkr.hcl). It
#
#   1. checks that the image the build pulled is the digest-pinned one, and
#      only then records its reference in /etc/certistack/controller-image;
#   2. writes /etc/certistack/build-manifest: the packages, OS release, image
#      and Packer version the template was built from;
#   3. resets the clone-specific identity: cloud-init state, seed and logs,
#      the machine ID, the SSH host keys and the journals (journald writes to
#      /run from then on), so every clone gets its own;
#   4. removes the build SSH key from every authorized_keys file, and refuses a
#      template with a symbolic link in the SSH paths it searches;
#   5. asserts each of those results and exits non-zero if any is not true.
#
# Nothing here is best effort. A failed command or a failed assertion fails the
# build, so Packer does not turn a half-cleaned guest into a template.
#
# Input, from Packer's environment_vars:
#   CERTISTACK_CONTROLLER_IMAGE  registry/repository@sha256:<digest>
#   CERTISTACK_BUILD_KEY_BLOB    the build public key's base64 field
#   CERTISTACK_PACKER_VERSION    recorded in the manifest
# CERTISTACK_FINALIZE_ROOT prefixes every path, so the tests can run this
# script against a scratch tree; a build leaves it unset.
set -eu
umask 022

root=${CERTISTACK_FINALIZE_ROOT:-}
image=${CERTISTACK_CONTROLLER_IMAGE:-}
key_blob=${CERTISTACK_BUILD_KEY_BLOB:-}
packer_version=${CERTISTACK_PACKER_VERSION:-unknown}

fail() {
    printf 'template finalization failed: %s\n' "$*" >&2
    exit 1
}

[ -n "$image" ] || fail 'CERTISTACK_CONTROLLER_IMAGE is not set'
case "$image" in
*@sha256:????????????????????????????????????????????????????????????????) ;;
*) fail "the controller image $image is not pinned by a sha256 digest" ;;
esac
digest=${image#*@}

# The key blob is matched as a whole authorized_keys field. An empty or short
# value would match nothing, and "nothing removed" must not read as success.
case "$key_blob" in
'' | *[!A-Za-z0-9+/=]*) fail 'CERTISTACK_BUILD_KEY_BLOB is empty or is not the base64 field of a public key' ;;
esac
[ "${#key_blob}" -ge 40 ] || fail 'CERTISTACK_BUILD_KEY_BLOB is too short to be a public key'

# 1. The image. podman pulled it by digest, which already binds the content;
# this confirms the store holds what the reference names before the template
# records it, by the store's digest or by the reference it lists.
stored_digest=$(podman image inspect --format '{{.Digest}}' "$image") ||
    fail "podman cannot inspect the pulled image $image"
stored_refs=$(podman image inspect --format '{{range .RepoDigests}}{{.}} {{end}}' "$image") ||
    fail "podman cannot list the repository digests of $image"
case " $stored_refs" in
*" $image "*) ;;
*) [ "$stored_digest" = "$digest" ] || fail "the image store holds $stored_digest (references: $stored_refs), not $image" ;;
esac
mkdir -p "$root/etc/certistack"
printf '%s\n' "$image" >"$root/etc/certistack/controller-image"
chmod 0644 "$root/etc/certistack/controller-image"

# 2. The build manifest. It names what the template was built from; it holds no
# secret, and a later build of the same recipe can differ in the package list.
# Each command runs on its own, so a failure of any of them stops the script.
manifest="$root/etc/certistack/build-manifest"
packages=$(mktemp)
dpkg-query -W -f='${binary:Package} ${Version}\n' >"$packages"
{
    printf 'certistack-appliance-build-manifest 1\n'
    printf 'controller_image=%s\n' "$image"
    printf 'packer_version=%s\n' "$packer_version"
    printf 'built_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '[os-release]\n'
} >"$manifest.new"
cat "$root/etc/os-release" >>"$manifest.new"
printf '[packages]\n' >>"$manifest.new"
sort "$packages" >>"$manifest.new"
rm -f "$packages"
mv "$manifest.new" "$manifest"
chmod 0644 "$manifest"

# 3. Clone identity. An empty or "uninitialized" /etc/machine-id tells systemd
# to make a new ID at the clone's first boot. A missing file does not: with /etc
# still read-only that early, systemd stops ("Missing /etc/machine-id and /etc
# is mounted read-only") and the clone comes up without a network. cloud-init's
# --machine-id writes "uninitialized" in some releases and deletes the file in
# others (Debian 12's), and older releases lack the option, so the script
# leaves an empty file wherever none remains. Step 5 checks the result.
if cloud-init clean --help 2>&1 | grep -q -- '--machine-id'; then
    cloud-init clean --logs --seed --machine-id || fail 'cloud-init clean failed'
else
    cloud-init clean --logs --seed || fail 'cloud-init clean failed'
    : >"$root/etc/machine-id"
fi
if [ ! -e "$root/etc/machine-id" ]; then : >"$root/etc/machine-id"; fi
# A copy of the ID that is not a link to the first would outlive the reset.
if [ -f "$root/var/lib/dbus/machine-id" ] && [ ! -L "$root/var/lib/dbus/machine-id" ]; then
    rm -f "$root/var/lib/dbus/machine-id"
fi
# The build VM's SSH host keys and its journals (and the source's, under their
# machine IDs). cloud-init writes new host keys at each clone's first boot.
# The build's own SSH connection is already established and is not affected.
# journald replaces a journal file deleted under it at once, and would write
# the build VM's shutdown into the template: --relinquish-var (systemd 243
# and later) moves it to /run, a tmpfs that ends with the VM.
rm -f "$root"/etc/ssh/ssh_host_*
journalctl --relinquish-var || fail 'journalctl --relinquish-var failed, so journald would keep writing to /var/log/journal'
rm -rf "$root"/var/log/journal/*

# Every non-directory under $1 that can hold authorized keys: a file named
# authorized_keys*, and a file inside a directory of that name (sshd's
# AuthorizedKeysFile can point into one, as in /etc/ssh/authorized_keys/%u).
# Further arguments go to find, which makes the expression in one place.
find_key_files() {
    find_dir=$1
    shift
    find "$find_dir" \( -name 'authorized_keys*' -o -path '*/authorized_keys*/*' \) ! -type d "$@"
}

# find does not follow symbolic links and sshd does: a linked SSH directory, or
# a link under one, can authorize a login through a file that neither the
# removal below nor the residual check lists, and the build would end with an
# empty search result and the key still in the template. A link as or under any
# of the directories searched fails the build, and the template must be built
# from a source whose SSH layout has none.
refuse_linked_ssh_paths() {
    for dir in "$root/root/.ssh" "$root/home" "$root/etc/ssh"; do
        if [ -L "$dir" ]; then
            fail "$dir is a symbolic link, so the authorized_keys files behind it are not searched; remove the link from the source template"
        fi
        [ -d "$dir" ] || continue
        links=$(find "$dir" -type l) ||
            fail "could not search $dir for symbolic links"
        [ -z "$links" ] ||
            fail "symbolic link(s) under $dir, whose targets the key search does not follow: $(printf '%s\n' "$links" | head -n 5 | tr '\n' ' ')"
    done
}

# 4. The build key, by key material rather than comment or options, from every
# authorized_keys file a login could read: root's, every home's, and sshd's own
# system-wide directory.
refuse_linked_ssh_paths
for dir in "$root/root/.ssh" "$root/home" "$root/etc/ssh"; do
    [ -d "$dir" ] || continue
    find_key_files "$dir" | while IFS= read -r file; do
        [ -f "$file" ] || continue
        scratch=$(mktemp)
        awk -v blob="$key_blob" '{ for (i = 1; i <= NF; i++) if ($i == blob) next } { print }' "$file" >"$scratch"
        # Written through the original file, so its owner, mode and links stay.
        cat "$scratch" >"$file"
        rm -f "$scratch"
    done
done

# 5. Postconditions. Each reads the guest's state afresh.
# 5a. The build key is in no authorized_keys file. The search lists file names
# with find -exec, so an unusual name cannot hide a file from it, and it runs
# only over a tree with no link it would not follow.
refuse_linked_ssh_paths
for dir in "$root/root/.ssh" "$root/home" "$root/etc/ssh"; do
    [ -d "$dir" ] || continue
    left=$(find_key_files "$dir" -exec awk -v blob="$key_blob" '{ for (i = 1; i <= NF; i++) if ($i == blob) print FILENAME }' {} +) ||
        fail "could not search $dir for the build key"
    [ -z "$left" ] || fail "the build key is still authorized in: $left"
done

# 5b. /etc/machine-id exists and is empty or "uninitialized", and D-Bus's copy,
# if there is one, says the same, so systemd makes a new ID on each clone's
# first boot.
[ -f "$root/etc/machine-id" ] || fail "$root/etc/machine-id is missing, and a clone would boot without a network"
for id_file in "$root/etc/machine-id" "$root/var/lib/dbus/machine-id"; do
    if [ -e "$id_file" ]; then
        content=$(cat "$id_file")
        case "$content" in
        '' | uninitialized) ;;
        *) fail "$id_file still holds a machine ID" ;;
        esac
    fi
done

# 5c. cloud-init has nothing left to say about the build instance: no state or
# seed file, no instance link, no log.
if [ -d "$root/var/lib/cloud" ]; then
    left=$(find "$root/var/lib/cloud" -mindepth 1 ! -type d) ||
        fail 'could not search /var/lib/cloud'
    [ -z "$left" ] || fail "cloud-init state remains: $(printf '%s\n' "$left" | head -n 5 | tr '\n' ' ')"
fi
for log in "$root/var/log/cloud-init.log" "$root/var/log/cloud-init-output.log"; do
    if [ -e "$log" ] || [ -L "$log" ]; then fail "$log remains"; fi
done

# 5d. No SSH host key and no journal file of the build remain.
for key in "$root"/etc/ssh/ssh_host_*; do
    if [ -e "$key" ] || [ -L "$key" ]; then fail "the SSH host key $key remains"; fi
done
if [ -d "$root/var/log/journal" ]; then
    left=$(find "$root/var/log/journal" -mindepth 1 ! -type d) ||
        fail 'could not search /var/log/journal'
    [ -z "$left" ] || fail "journal files remain: $(printf '%s\n' "$left" | head -n 5 | tr '\n' ' ')"
fi

# 5e. What the template will carry is what was checked above.
[ "$(cat "$root/etc/certistack/controller-image")" = "$image" ] ||
    fail 'the recorded controller image is not the one that was checked'
[ -s "$manifest" ] || fail 'the build manifest is empty'

rm -f "$0"
printf 'template finalized: %s\n' "$image"
