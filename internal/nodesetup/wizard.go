// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// The pieces `certistack setup` puts together: the token secret read from a
// capture-mode script, the scripts it runs on the node for the packages and
// the overlay storage, and the environment file it writes.

// ParseTokenSecret returns the secret of the token a capture-mode part created
// (RBACParams.Capture): the "value" of the JSON object the creating command
// printed on standard output: pveum's --output-format json, or
// proxmox-backup-manager's own "Result: {...}" (it has no --output-format). Nothing
// on standard output means the part found the token already there and created
// none (ErrTokenExists). The secret is checked for a shape the environment file
// can hold; it is never part of an error.
func ParseTokenSecret(stdout []byte) (string, error) {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return "", ErrTokenExists
	}
	// proxmox-backup-manager user generate-token has no --output-format: it
	// prints "Result: " and then the JSON object (PBS 4.2, as on 2.x and 3.x).
	trimmed = bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("Result:")))
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	secret := ""
	for {
		var value map[string]any
		err := decoder.Decode(&value)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("the token command's output is not the JSON it prints with --output-format json")
		}
		if v, ok := value["value"].(string); ok {
			secret = v
		}
	}
	if secret == "" {
		return "", errors.New("the token command printed no secret (no \"value\" in its JSON)")
	}
	if !tokenSecretForm.MatchString(secret) {
		return "", errors.New("the token secret has characters an environment file cannot hold literally")
	}
	return secret, nil
}

// ErrTokenExists is what ParseTokenSecret returns when the part created no
// token because one of that name exists: its secret cannot be read back.
var ErrTokenExists = errors.New("the token exists already, so none was created and its secret cannot be read back")

// tokenSecretForm is what PVE and PBS token secrets look like (a UUID), with
// room to spare: printable ASCII without space or quote, 8 to 256 characters.
var tokenSecretForm = regexp.MustCompile("^[A-Za-z0-9._~+/=:@!-]{8,256}$")

// Debian package names, for the package scripts.
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

func checkPackages(packages []string) error {
	if len(packages) == 0 {
		return errors.New("no package to install")
	}
	for _, p := range packages {
		if !packageName.MatchString(p) {
			return fmt.Errorf("%q is not a Debian package name", p)
		}
	}
	return nil
}

// PackagesPreviewScript has apt-get say, from the node's current package lists
// and without changing anything, what installing these would do: one
// "inst=NAME" line for each package it would add, one "upg=NAME" line for each
// installed package it would upgrade for them and one "rem=NAME" line for each
// installed package it would remove (a dependency conflict can do that), then
// "preview_end=1". When apt-get cannot (a package not in the lists, which a
// node whose lists were never refreshed gives), it prints "preview_error=" and
// apt-get's first E: line instead. Setup refreshes the lists first
// (PackagesUpdateScript), so that the preview is of what the install does.
func PackagesPreviewScript(packages []string) (string, error) {
	if err := checkPackages(packages); err != nil {
		return "", err
	}
	return fmt.Sprintf(`export LC_ALL=C DEBIAN_FRONTEND=noninteractive
if out=$(apt-get -s -y --no-upgrade install %s 2>&1); then
  printf '%%s\n' "$out" | awk '$1 == "Inst" { if ($3 ~ /^\[/) print "upg=" $2; else print "inst=" $2 } $1 == "Remv" { print "rem=" $2 }'
else
  echo "preview_error=$(printf '%%s\n' "$out" | grep '^E:' | head -n 1)"
fi
echo preview_end=1
`, strings.Join(packages, " ")), nil
}

// PackagesPreview is what PackagesPreviewScript reports.
type PackagesPreview struct {
	Install []string // packages apt-get would add
	Upgrade []string // installed packages it would upgrade for them
	Remove  []string // installed packages it would remove
	Error   string   // apt-get's E: line when it could not say
}

// ParsePackagesPreview reads PackagesPreviewScript's output.
func ParsePackagesPreview(output []byte) (PackagesPreview, error) {
	var preview PackagesPreview
	ended, failed := false, false
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "inst":
			preview.Install = append(preview.Install, value)
		case "upg":
			preview.Upgrade = append(preview.Upgrade, value)
		case "rem":
			preview.Remove = append(preview.Remove, value)
		case "preview_error":
			failed = true
			preview.Error = strings.TrimSpace(value)
			if preview.Error == "" {
				preview.Error = "apt-get failed"
			}
		case "preview_end":
			ended = true
		}
	}
	if !ended {
		return PackagesPreview{}, errors.New("apt-get's preview ended early")
	}
	if !failed && len(preview.Install) == 0 {
		preview.Error = "apt-get would install nothing"
	}
	return preview, nil
}

// PackagesUpdateScript refreshes the node's package lists (apt-get update),
// which changes nothing but apt's lists. On a node without a subscription it
// ends with a 401 error for the enterprise repositories, which is expected and
// ignored, as the guides say.
const PackagesUpdateScript = `exec 1>&2
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get update || true
`

// PackagesInstallScript installs the packages, from the lists the preview was
// made from: it does not refresh them, so that it does what the operator was
// shown. --no-upgrade keeps a named package that is installed as it is; an
// installed dependency that needs a newer version is upgraded, and one that
// conflicts is removed, which the preview lists.
func PackagesInstallScript(packages []string) (string, error) {
	if err := checkPackages(packages); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -e
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get -y --no-upgrade install %s
`, strings.Join(packages, " ")), nil
}

// overlayPath is a directory the overlay storage can be: absolute, clean, of
// characters that need no quoting.
var overlayPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// StorageScript adds the overlay storage: a directory storage with images
// content, not shared, on this node only when it is in a cluster. It is the
// command the manual steps give (docs/manual-setup.md, "Set up by hand").
func StorageScript(id, path, node string, cluster bool) (string, error) {
	if !config.ValidPVEStorageID(id) {
		return "", fmt.Errorf("invalid storage ID %q", id)
	}
	if err := CheckOverlayPath(path); err != nil {
		return "", err
	}
	nodes := ""
	if cluster {
		if !validNodeName(node) {
			return "", fmt.Errorf("invalid node name %q", node)
		}
		nodes = " --nodes " + node
	}
	return fmt.Sprintf("set -e\nmkdir -p %s\npvesm add dir %s --path %s --content images --shared 0%s\n", path, id, path, nodes), nil
}

// CheckOverlayPath refuses a directory StorageScript would refuse.
func CheckOverlayPath(path string) error {
	if !overlayPath.MatchString(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("the overlay directory %q must be a clean absolute path of letters, digits and . _ - /", path)
	}
	return nil
}

// PathProbeScript reports, changing nothing, where a directory that may not
// exist yet would be: the findmnt SOURCE and the free bytes of its nearest
// existing ancestor ("source=", "avail=", then "probe_end=1").
func PathProbeScript(path string) (string, error) {
	if err := CheckOverlayPath(path); err != nil {
		return "", err
	}
	return fmt.Sprintf(`export LC_ALL=C
p=%s
while [ ! -e "$p" ]; do p=$(dirname "$p"); done
echo "source=$(findmnt -n -o SOURCE -T "$p" 2>/dev/null)"
echo "avail=$(df -B1 --output=avail "$p" 2>/dev/null | tail -n 1 | tr -d ' ')"
echo probe_end=1
`, path), nil
}

// ParsePathProbe reads PathProbeScript's output: the source, and the free
// bytes (-1 when unknown).
func ParsePathProbe(output []byte) (source string, avail int64, err error) {
	avail = -1
	ended := false
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "source":
			source = value
		case "avail":
			if n, perr := strconv.ParseInt(value, 10, 64); perr == nil && n >= 0 {
				avail = n
			}
		case "probe_end":
			ended = true
		}
	}
	if !ended {
		return "", -1, errors.New("the node did not say where the directory is")
	}
	return source, avail, nil
}

// CheckStorageID refuses what is not a PVE storage ID.
func CheckStorageID(id string) error {
	if !config.ValidPVEStorageID(id) {
		return fmt.Errorf("%q is not a PVE storage ID (letters, digits, - _ and ., starting with a letter)", id)
	}
	return nil
}

// CheckDatastore refuses what is not a PBS datastore name, as the PBS part of
// the script does.
func CheckDatastore(name string) error {
	if !validDatastore(name) {
		return fmt.Errorf("%q is not a PBS datastore name (3 to 32 letters, digits, - _ and ., not starting with - or .)", name)
	}
	return nil
}

// CheckNamespace refuses what is not a PBS namespace ("" is the root one).
func CheckNamespace(ns string) error {
	if ns == "" {
		return nil
	}
	return initplan.ValidateRequest(initplan.Request{Node: "pve", Namespace: ns})
}

var nodeNameForm = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)

func validNodeName(name string) bool { return nodeNameForm.MatchString(name) }

// EnvFile is what `certistack setup` writes as the controller environment
// file, the variables the manual steps have the operator type.
type EnvFile struct {
	PVEURL         string
	PVETokenID     string
	PVETokenSecret string
	PBSRepository  string
	PBSPassword    string
	PBSFingerprint string
	PBSNamespace   string
	PBSKeyFile     string
	Node           string
	SSHHost        string
	SSHPort        int
	SSHUser        string
	SSHIdentity    string
	SSHKnownHosts  string
	PVECASource    string
	OverlayStorage string
	OutputDir      string
	// Kept are the variables of an earlier file that setup does not set,
	// written after its own, in this order.
	Kept []EnvVar
}

// EnvVar is one NAME=value line.
type EnvVar struct{ Name, Value string }

// LiteralValue reports whether an environment file can hold value literally
// on a NAME=value line: no line break or NUL, and no leading quote, which the
// reader would take as quoting.
func LiteralValue(value string) bool {
	return !strings.ContainsAny(value, "\x00\r\n") && !strings.HasPrefix(value, "'") && !strings.HasPrefix(value, `"`)
}

// Render is the file's text: each variable with the comment that says what it
// is, values literal, comments on lines of their own.
func (e EnvFile) Render(now time.Time) ([]byte, error) {
	var b strings.Builder
	written := map[string]bool{}
	set := func(comment, name, value string) error {
		if value == "" {
			return nil
		}
		if !LiteralValue(value) {
			return fmt.Errorf("%s has a value an environment file cannot hold literally", name)
		}
		if written[name] {
			return fmt.Errorf("%s would be written twice", name)
		}
		written[name] = true
		if comment != "" {
			fmt.Fprintf(&b, "# %s\n", comment)
		}
		fmt.Fprintf(&b, "%s=%s\n", name, value)
		return nil
	}
	fmt.Fprintf(&b, "# Written by certistack setup on %s. Mode 0600: it holds the token secrets.\n", now.UTC().Format("2006-01-02 15:04 MST"))
	b.WriteString("# Values are literal (never shell-sourced); a comment must be on a line of its own.\n")
	fields := []struct{ comment, name, value string }{
		{"The PVE API, as the node reaches it.", "PVE_URL", e.PVEURL},
		{"", "PVE_TOKEN_ID", e.PVETokenID},
		{"", "PVE_TOKEN_SECRET", e.PVETokenSecret},
		{"The read-only PBS token and the datastore it reads.", "PBS_REPOSITORY", e.PBSRepository},
		{"", "PBS_PASSWORD", e.PBSPassword},
		{"The PBS certificate's SHA-256 fingerprint.", "PBS_FINGERPRINT", e.PBSFingerprint},
		{"The PBS namespace that holds the backups.", "PBS_NAMESPACE", e.PBSNamespace},
		{"The PBS storage's encryption key, copied from the node.", "CERTISTACK_PBS_KEYFILE", e.PBSKeyFile},
		{"The node's name in PVE, and how this controller reaches it over SSH.", "CERTISTACK_NODE", e.Node},
		{"", "CERTISTACK_SSH_HOST", e.SSHHost},
	}
	if e.SSHPort != 0 && e.SSHPort != 22 {
		fields = append(fields, struct{ comment, name, value string }{"", "CERTISTACK_SSH_PORT", strconv.Itoa(e.SSHPort)})
	}
	fields = append(fields, []struct{ comment, name, value string }{
		{"", "CERTISTACK_SSH_USER", e.SSHUser},
		{"", "CERTISTACK_SSH_IDENTITY", e.SSHIdentity},
		{"", "CERTISTACK_SSH_KNOWN_HOSTS", e.SSHKnownHosts},
		{"The node's cluster CA, which signs its API certificate.", "CERTISTACK_PVE_CA_SOURCE", e.PVECASource},
		{"The storage for the sandbox overlays; setup granted the token on it.", "CERTISTACK_OVERLAY_STORAGE", e.OverlayStorage},
		{"Where reports are written.", "CERTISTACK_OUTPUT_DIR", e.OutputDir},
	}...)
	for _, f := range fields {
		if err := set(f.comment, f.name, f.value); err != nil {
			return nil, err
		}
	}
	comment := "Carried over from the earlier file; setup does not set these."
	for _, v := range e.Kept {
		if v.Value == "" {
			continue
		}
		if err := set(comment, v.Name, v.Value); err != nil {
			return nil, err
		}
		comment = ""
	}
	return []byte(b.String()), nil
}

// WriteEnvFile writes data to path with mode 0600, through a temporary file in
// the same directory renamed over it, so a reader never sees half a file. A
// file that is there already is kept first as path.bak-<time> (0600); its name
// is returned ("" when there was none).
func WriteEnvFile(path string, data []byte, now time.Time) (backup string, err error) {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s exists and is not a regular file; it was left alone", path)
		}
		old, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read the existing %s to keep a copy: %w", path, err)
		}
		backup = path + ".bak-" + now.UTC().Format("20060102T150405Z")
		if err := writeExclusive(backup, old); err != nil {
			return "", fmt.Errorf("keep a copy of the existing %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("look at %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".controller.env.*")
	if err != nil {
		return backup, fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if err = tmp.Chmod(0o600); err == nil {
		if _, err = tmp.Write(data); err == nil {
			err = tmp.Sync()
		}
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return backup, fmt.Errorf("write %s: %w", path, err)
	}
	if err = os.Rename(name, path); err != nil {
		return backup, fmt.Errorf("write %s: %w", path, err)
	}
	return backup, nil
}

// writeExclusive creates path with mode 0600 and data; it does not replace a
// file that is there.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteSecretFile writes a secret file (the PBS encryption key) with mode 0600
// through a temporary file renamed over path.
func WriteSecretFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secret.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}
