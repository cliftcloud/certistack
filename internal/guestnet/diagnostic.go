// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import "strconv"

// diagnosticBody records a failed sandbox VM's network and services. It
// starts by saying when it ran ($when): how long after boot, the system
// state, and whether multi-user.target was reached. An empty listener list
// means one thing after boot has settled and another while services are
// still starting (a capture from inside the recovery service, with
// multi-user.target still waiting). A tool the guest lacks is named rather
// than failing with "command not found". The dependency section is a
// timeline: when the kernel attached each disk and when udev was slow on
// it, beside the device and mount timeouts, so a data disk's timeout can be
// told apart: attached late (below the guest), or attached early and
// processed late by udev.
//
// A service that is enabled at boot but is not running is neither failed nor
// pending when systemd skipped it (a start condition that was not met, such as
// a file that is empty in a backup taken while the guest was writing it), so
// "failed services" and "pending jobs" are both empty and only the missing
// listener shows. The services section lists every enabled service that is not
// active with its state, its result and its condition result, the ones with
// something to explain (a condition not met, a result other than success, a
// state other than inactive) first.
//
// Every section that can be long is cut at a fixed number of bytes (cap), so
// a verbose or hostile guest cannot make a capture larger than the reader's
// limit, or one noisy section push out the sections after it. The
// limits add up to less than diagnosticReadLimit, and the capture as a whole
// is cut at diagnosticFileLimit besides.
const diagnosticBody = `have() { command -v "$1" >/dev/null 2>&1; }
# cap N passes on at most N bytes of its input, and ends the text with a newline
# when the cut (or the tool) did not, so the next section's heading starts a line.
cap() {
  c=$(head -c "$1"; echo x); c=${c%x}
  printf '%s' "$c"
  case "$c" in ''|*"
") ;; *) echo ;; esac
}
{
  echo "[captured $when: $(cut -d' ' -f1 /proc/uptime 2>/dev/null) s after boot; system $(systemctl is-system-running 2>/dev/null); multi-user.target $(systemctl is-active multi-user.target 2>/dev/null)]"
  echo '[interfaces]'
  ip -brief address 2>&1 | cap 1024 || true
  echo '[routes]'
  ip route 2>&1 | cap 1024 || true
  echo '[listeners]'
  if have ss; then ss -lntup 2>&1; elif have netstat; then netstat -lntup 2>&1; else echo 'neither ss nor netstat is installed'; fi | cap 2560
  echo '[failed services]'
  systemctl --failed --no-legend 2>&1 | cap 1024 || true
  echo '[enabled services not active]'
  units=$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '$1 ~ /^[-A-Za-z0-9:_.]+\.service$/ { print $1 }' | head -n 300)
  if [ -n "$units" ]; then
    systemctl show --no-pager -p Id -p ActiveState -p SubState -p Result -p ConditionResult $units 2>&1 | awk -F= '
      function flush() {
        if (id != "" && state != "active") {
          line = id " " state "/" (sub_state == "" ? "-" : sub_state) " result=" (result == "" ? "-" : result) " condition=" (condition == "" ? "-" : condition)
          if (condition == "no" || (result != "" && result != "success") || state != "inactive") first = first line "\n"; else rest = rest line "\n"
        }
        id = state = sub_state = result = condition = ""
      }
      /^$/ { flush(); next }
      $1 == "Id" { id = $2 }
      $1 == "ActiveState" { state = $2 }
      $1 == "SubState" { sub_state = $2 }
      $1 == "Result" { result = $2 }
      $1 == "ConditionResult" { condition = $2 }
      END { flush(); printf "%s%s", first, rest }' | cap 1536 || true
  fi
  echo '[mounts not active]'
  systemctl list-units --type=mount --all --no-legend 2>&1 | awk '{ o = ($1 == "●"); if ($(3+o) != "active" || $(4+o) != "mounted") print }' | head -n 20 | cap 1024 || true
  echo '[dependency and device failures]'
  journalctl -b --no-pager -o short-monotonic 2>/dev/null | grep -E 'Dependency failed|Timed out waiting for device|Failed to mount|Job .* timed out|Attached SCSI disk|\] [0-9]+ 512-byte logical blocks|is taking a long time|Worker .* (timed out|killed)' | tail -n 30 | tail -c 2048 | cap 2048 || true
  echo '[pending jobs]'
  systemctl list-jobs --no-legend 2>&1 | cap 1024 || true
  if have networkctl; then
    echo '[networkd links]'
    networkctl list --no-legend 2>&1 | cap 1024 || true
    echo '[networkd status]'
    networkctl status --no-pager 2>&1 | head -40 | cap 1024 || true
  else
    echo '[networkd] not installed'
  fi
  if have nmcli; then
    echo '[networkmanager devices]'
    nmcli -t -f GENERAL.DEVICE,GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY device show 2>&1 | cap 1024 || true
    echo '[networkmanager connections]'
    nmcli -t -f NAME,TYPE,DEVICE,STATE,AUTOCONNECT-PRIORITY connection show 2>&1 | cap 1024 || true
  else
    echo '[networkmanager] not installed'
  fi
}`

const (
	// diagnosticReadLimit is the most of a capture that is read back and
	// reported.
	diagnosticReadLimit = 16 << 10
	// diagnosticFileLimit is the most a capture writes, however much the guest's
	// tools print.
	diagnosticFileLimit = 32 << 10
	// diagnosticKeep is how many captures stay in the guest, newest first.
	diagnosticKeep = 8
)

// LiveDiagnosticCommand is the diagnostic the controller runs through the
// guest agent while a failed VM still runs.
func LiveDiagnosticCommand() string {
	return "when='live, through the guest agent'\n" + diagnosticBody + " 2>&1"
}

// bootDiagnosticScript is the diagnostic network recovery installs in the
// COW overlay, for when the guest agent cannot run it. It runs during boot
// (its service), on each NetworkManager device event (the dispatcher, with
// the interface and event as arguments), and once boot has settled (its
// "after-boot" service, which waits for that: see the script). These can overlap, so no capture ever replaces
// another: each is published whole under a name that carries when it began, in
// hundredths of a second since boot, and the reader takes the one that began
// last. A capture that began earlier but finished later therefore cannot
// replace a settled one; only the newest few are kept.
//
// The captures are written by root into a directory it checks and closes
// first: a real directory (not a link), owned by root and not open to anyone
// else, with a private temporary file whose name is made up on the spot and
// created exclusively. A predictable temporary name that another user could
// have planted as a link would send the root-owned write to an unrelated file.
// The temporary file is removed on every way out.
func bootDiagnosticScript(output string) string {
	return `#!/bin/sh
umask 077
case "$1" in
  after-boot) when='after boot settled' ;;
  '') when='during boot' ;;
  *) when="on NetworkManager event ${2:-unknown} for $1" ;;
esac
out='` + output + `'
dir=${out%/*}
[ -d "$dir" ] && [ ! -L "$dir" ] || { echo "certistack: $dir is not a directory of its own" >&2; exit 1; }
chown 0:0 "$dir" 2>/dev/null
chmod 700 "$dir" 2>/dev/null
[ -O "$dir" ] || { echo "certistack: cannot make $dir private" >&2; exit 1; }
# The after-boot capture is started when multi-user.target is reached, which is
# often many seconds before the services that are still starting have settled
# (a capture at 12 s still said "system starting"). It waits for the manager to
# leave "starting", looking every 2 s for at most 120 s, and says so when it
# gave up. It waits before it stamps itself, so its stamp is when it began.
if [ "$1" = after-boot ]; then
  waited=0
  while [ "$waited" -lt 60 ]; do
    case $(systemctl is-system-running 2>/dev/null) in starting|initializing) ;; *) break ;; esac
    sleep 2
    waited=$((waited + 1))
  done
  [ "$waited" -lt 60 ] || when='after waiting 120 s for boot to settle, which it had not'
fi
up=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)
case $up in *[!0-9.]*|'') up=0.00 ;; esac
case $up in *.*) ;; *) up=$up.00 ;; esac
gen=0000000000${up%.*}${up#*.}
gen=${gen#"${gen%??????????}"}
# Remove abandoned captures, keeping files owned by a capture still running.
# PID-qualified names let concurrent boot and dispatcher captures coexist.
for stale in "$dir"/.capture.*; do
  [ -e "$stale" ] || [ -L "$stale" ] || continue
  capture_pid=${stale##*/.capture.}
  capture_pid=${capture_pid%%.*}
  case "$capture_pid" in
    ''|*[!0-9]*) ;;
    *) kill -0 "$capture_pid" 2>/dev/null && continue ;;
  esac
  rm -f -- "$stale"
done
tmp=$(mktemp "$dir/.capture.$$.XXXXXX") || exit 1
trap 'rm -f -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
` + diagnosticBody + ` 2>&1 | head -c ` + strconv.Itoa(diagnosticFileLimit) + ` > "$tmp" || exit 1
mv -f -- "$tmp" "$out.$gen.$$" || exit 1
set -- "$out".[0-9]*
if [ -e "$1" ]; then
  while [ "$#" -gt ` + strconv.Itoa(diagnosticKeep) + ` ]; do rm -f -- "$1"; shift; done
fi
`
}
