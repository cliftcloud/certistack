// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// The shape of a value, which the controller environment file is checked for
// when it is read. A name, a mode and the syntax of a line were checked; a
// value was not, so a PVE_URL without a scheme, a token with a pasted prefix or
// a repository in URL form passed layer 1 of check and failed the layers that
// follow, after the newcomer had done the SSH steps, as "exit status 255 (client
// output withheld)" or a bare 401. Each refusal names the variable and its
// line, what is expected and the exact fix, in words a person who has never
// seen Proxmox VE can act on. It never prints a value, or a part of one: a
// secret pasted into the wrong variable would be printed with it.

// shapeProblem is a value of the controller file that has the wrong shape.
type shapeProblem struct {
	name    string
	line    int
	message string
}

func (p shapeProblem) String() string {
	return fmt.Sprintf("invalid controller environment variable %q on line %d: %s", p.name, p.line, p.message)
}

// environmentShapeError holds every value of a file that has the wrong shape,
// in the order of the file, so that one run of check reports them all.
type environmentShapeError struct {
	problems []shapeProblem
}

func (e *environmentShapeError) Error() string {
	lines := make([]string, len(e.problems))
	for i, problem := range e.problems {
		lines[i] = problem.String()
	}
	return strings.Join(lines, "\n")
}

// layerDetail is what layer 1 of check says: how many values are wrong, and
// each with its line and fix. fix is the one line under them.
func (e *environmentShapeError) layerDetail(envPath string) (detail, fix string) {
	count := len(e.problems)
	var b strings.Builder
	if count == 1 {
		fmt.Fprintf(&b, "1 value in %s is not shaped as it should be:", envPath)
	} else {
		fmt.Fprintf(&b, "%d values in %s are not shaped as they should be:", count, envPath)
	}
	for _, problem := range e.problems {
		fmt.Fprintf(&b, "\nline %d, %s: %s", problem.line, problem.name, problem.message)
	}
	lines := "lines"
	if count == 1 {
		lines = "line"
	}
	return b.String(), fmt.Sprintf("Correct the %s above in %s. What each variable looks like is at https://certistack.dev/docs/configuration/#variables.", lines, envPath)
}

// shapeResult is what a rule makes of a value: the problem with it, or the
// value to use (a value in its normal form).
type shapeResult struct {
	problem string
	value   string
}

func shapeOK(value string) shapeResult    { return shapeResult{value: value} }
func shapeBad(message string) shapeResult { return shapeResult{problem: message} }
func shapeBadf(format string, args ...any) shapeResult {
	return shapeResult{problem: fmt.Sprintf(format, args...)}
}

// controllerShapes are the variables whose values have a shape, and the rule of
// each. The typed ones (a port, a yes or no) are read by envtypes.
var controllerShapes = map[string]func(string) shapeResult{
	"PVE_URL":             checkPVEURL,
	"PVE_TOKEN_ID":        checkPVETokenID,
	"PVE_TOKEN_SECRET":    checkPVETokenSecret,
	"PBS_REPOSITORY":      checkPBSRepository,
	"PBS_FINGERPRINT":     checkPBSFingerprint,
	"PBS_NAMESPACE":       checkPBSNamespace,
	"CERTISTACK_NODE":     checkNodeNameShape,
	"CERTISTACK_SSH_HOST": checkSSHHost,
	"CERTISTACK_SSH_USER": checkSSHUser,
}

// checkShapes checks every value of the file against its rule. It puts the
// normal form of an accepted value back (a trailing slash taken off PVE_URL, a
// fingerprint in the colon form), and returns the notes a passing file still
// earns: what is accepted but is likely not what the writer meant.
func (f *environmentFile) checkShapes() (problems []shapeProblem, notes []string) {
	problems = append(problems, f.typed...)
	for name, rule := range controllerShapes {
		value, set := f.values[name]
		if !set || value == "" {
			continue
		}
		result := rule(value)
		if result.problem != "" {
			problems = append(problems, shapeProblem{name: name, line: f.lines[name], message: result.problem})
			continue
		}
		f.values[name] = result.value
	}
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].line < problems[j].line })

	failed := map[string]bool{}
	for _, problem := range problems {
		failed[problem.name] = true
	}
	names := make([]string, 0, len(f.values))
	for name := range f.values {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return f.lines[names[i]] < f.lines[names[j]] })
	for _, name := range names {
		value := f.values[name]
		if failed[name] || value == "" {
			continue
		}
		if hasTrailingComment(value) {
			notes = append(notes, fmt.Sprintf("Note: line %d (%s) contains \" #\": values are literal, so everything from there on is part of the value. If it is a comment, put it on its own line above.", f.lines[name], name))
		}
		if name == "PVE_URL" && pveURLHasNoPort(value) {
			notes = append(notes, fmt.Sprintf("Note: line %d (PVE_URL) has no port, so port 443 is used. A stock Proxmox VE listens on 8006; 443 is right only behind a reverse proxy.", f.lines[name]))
		}
	}
	return problems, notes
}

// hasTrailingComment is a value with " #" or a tab and "#" in it: a comment
// written after the value, which a literal reading makes part of it.
func hasTrailingComment(value string) bool {
	return strings.Contains(value, " #") || strings.Contains(value, "\t#")
}

const commentProblem = "has a comment on the same line (\" #...\"): values are literal, so the comment would be part of the value. Put the comment on a line of its own and keep only the value here"

// spacesOrQuotes is what no shaped value has inside it.
func spacesOrQuotes(value string) bool { return strings.ContainsAny(value, " \t\"'") }

// pveURLHasNoPort is an accepted PVE_URL that names no port.
func pveURLHasNoPort(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Hostname() != "" && u.Port() == ""
}

// checkPVEURL: https://host[:port], the address of the web interface.
func checkPVEURL(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: PVE_URL is only the address, for example https://pve1.example.com:8006")
	}
	if !strings.Contains(value, "://") {
		return shapeBad("has no scheme: start it with https://, for example PVE_URL=https://pve1.example.com:8006")
	}
	u, err := url.Parse(value)
	if err != nil {
		// The error carries the URL, which may carry a password: not shown.
		if strings.Contains(err.Error(), "invalid port") {
			return shapeBad("has a port that is not a number from 1 to 65535")
		}
		return shapeBad("is not a valid address: write it as https://HOST[:PORT], for example https://pve1.example.com:8006")
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return shapeBad("uses http://, but PVE's API is served over https: use https://HOST:8006 (http:// is accepted for a loopback address only)")
		}
	default:
		return shapeBad("uses a scheme other than https://: use https://HOST:8006")
	}
	if u.User != nil {
		return shapeBad("contains a user name or password (user:password@): remove it. PVE_URL is only the address; the API token goes in PVE_TOKEN_ID and PVE_TOKEN_SECRET")
	}
	if u.Hostname() == "" {
		return shapeBad("has no host name: write the node's name or address after https://")
	}
	if path := u.EscapedPath(); path != "" && path != "/" {
		if strings.HasPrefix(path, "/api2") {
			return shapeBad("includes the API path (/api2/...): remove the path. PVE_URL is the address of the web interface (https://HOST:8006), and CertiStack adds /api2/json itself")
		}
		return shapeBad("has a path after the host: remove it. PVE_URL is only https://HOST[:PORT]")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return shapeBad("has a query (?...): remove it. PVE_URL is only https://HOST[:PORT]")
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return shapeBad("has a fragment (#...), like the #v1:... the browser shows after you log in to the PVE web interface: remove it. PVE_URL is only https://HOST[:PORT]")
	}
	if port := u.Port(); port != "" {
		number, _ := strconv.Atoi(port)
		switch {
		case number == 22:
			return shapeBad("uses port 22, which is SSH. PVE's API is on 8006 (or the port your reverse proxy listens on): use https://HOST:8006")
		case number == 8007:
			return shapeBad("uses port 8007, which is the Proxmox Backup Server's port. PVE's API is on 8006 (or the port your reverse proxy listens on): use https://HOST:8006")
		case number < 1 || number > 65535:
			return shapeBad("has a port that is not a number from 1 to 65535")
		}
	}
	// A single trailing slash is the same address.
	return shapeOK(strings.TrimSuffix(value, "/"))
}

// isLoopbackHost is localhost or a loopback address, the only hosts PVE_URL may
// reach over http (the PVE client's own rule).
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkPVETokenID: user@realm!tokenname.
func checkPVETokenID(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if strings.HasPrefix(strings.ToLower(value), "pveapitoken=") {
		return shapeBad("starts with PVEAPIToken=: remove PVEAPIToken=. PVE_TOKEN_ID is only user@realm!tokenname (for example certistack@pve!automation), and the secret goes in PVE_TOKEN_SECRET")
	}
	if strings.Contains(value, "=") {
		return shapeBad("contains \"=\" (a secret after the token name?): remove everything from the \"=\" on. PVE_TOKEN_ID is only user@realm!tokenname, and the secret goes in PVE_TOKEN_SECRET")
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: PVE_TOKEN_ID is only user@realm!tokenname, for example certistack@pve!automation")
	}
	user, token, hasToken := strings.Cut(value, "!")
	if !hasToken {
		if name, realm, ok := strings.Cut(user, "@"); ok && name != "" && realm != "" && !strings.Contains(realm, "@") {
			return shapeBad("is a user, not an API token: create a token for it and use user@realm!tokenname (certistack setup rbac prints the commands that create one)")
		}
		return shapeBad("is not shaped like user@realm!tokenname, for example certistack@pve!automation")
	}
	name, realm, ok := strings.Cut(user, "@")
	if !ok || name == "" || realm == "" || strings.Contains(realm, "@") {
		return shapeBad("is not shaped like user@realm!tokenname, for example certistack@pve!automation")
	}
	if token == "" {
		return shapeBad("has no token name after \"!\": use user@realm!tokenname, for example certistack@pve!automation")
	}
	if strings.Contains(token, "!") {
		return shapeBad("is not shaped like user@realm!tokenname, for example certistack@pve!automation")
	}
	return shapeOK(value)
}

// checkPVETokenSecret: a secret has no whitespace or quotes in it. PVE's are
// UUIDs, but another shape is accepted.
func checkPVETokenSecret(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space, tab or quote: the secret is only the UUID PVE showed once, when the token was created, copied without anything around it")
	}
	return shapeOK(value)
}

var (
	pbsHostName  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pbsIPv6Host  = regexp.MustCompile(`^\[[0-9A-Fa-f:.]+\]$`)
	pbsDatastore = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	pbsAuthID    = regexp.MustCompile(`^[^@!\s:/]+@[^@!\s:/]+(![^@!\s:/]+)?$`)
)

// checkPBSRepository: user@realm[!tokenname]@host[:port]:datastore, the host a
// name, an IPv4 address or an IPv6 address in square brackets.
func checkPBSRepository(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if strings.Contains(value, "://") {
		return shapeBad("is a URL: write it with no scheme and no path, as user@realm!tokenname@HOST:DATASTORE (for example certistack-ro@pbs!ro@pbs.example.com:8007:datastore)")
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: PBS_REPOSITORY is user@realm!tokenname@HOST:DATASTORE, for example certistack-ro@pbs!ro@pbs.example.com:8007:datastore")
	}
	authID, rest := "", value
	if i := strings.LastIndex(value, "@"); i >= 0 {
		authID, rest = value[:i], value[i+1:]
	}
	var problems []string
	switch {
	case authID == "":
		problems = append(problems, "has no user: add user@realm!tokenname@ in front (user@realm!tokenname@HOST:DATASTORE)")
	case !pbsAuthID.MatchString(authID):
		problems = append(problems, "starts with a user that is not user@realm or user@realm!tokenname (for example certistack-ro@pbs!ro): the user needs its realm")
	}

	// host[:port]:datastore
	host, after, hasAfter := rest, "", false
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			host = rest[:end+1]
			if tail := rest[end+1:]; strings.HasPrefix(tail, ":") {
				after, hasAfter = tail[1:], true
			} else if tail != "" {
				problems = append(problems, "has text after the IPv6 address that is not :PORT or :DATASTORE")
			}
		}
	} else if i := strings.Index(rest, ":"); i >= 0 {
		host, after, hasAfter = rest[:i], rest[i+1:], true
	}
	switch {
	case host == "":
		problems = append(problems, "has no host: write user@realm!tokenname@HOST:DATASTORE")
	case !pbsHostName.MatchString(host) && !pbsIPv6Host.MatchString(host):
		problems = append(problems, "has a host that is not a name or an address (an IPv6 address is written in square brackets)")
	}
	datastore, tooMany := "", false
	if hasAfter && after != "" {
		parts := strings.Split(after, ":")
		switch len(parts) {
		case 1:
			if port, err := strconv.Atoi(parts[0]); err == nil && port >= 1 && port <= 65535 && strings.Trim(parts[0], "0123456789") == "" {
				// A port and no datastore: PBS names its datastores with letters
				// as well, and one named by digits alone takes its port too
				// (HOST:8007:8007), so a lone number is read as the port it
				// nearly always is.
				problems = append(problems, "has no datastore: the number after the host looks like a port, so add :DATASTORE after it (user@realm!tokenname@HOST:PORT:DATASTORE); a datastore named with digits alone is written after its port too")
				break
			}
			datastore = parts[0]
		case 2:
			if port, err := strconv.Atoi(parts[0]); err != nil || port < 1 || port > 65535 || strings.Trim(parts[0], "0123456789") != "" {
				problems = append(problems, "has a port that is not a number from 1 to 65535")
			}
			datastore = parts[1]
		default:
			tooMany = true
			problems = append(problems, "has too many \":\" parts: it is user@realm!tokenname@HOST[:PORT]:DATASTORE, and an IPv6 address is written in square brackets")
		}
	}
	switch {
	case tooMany, portWithoutDatastore(problems):
	case datastore == "":
		problems = append(problems, "has no datastore: add :DATASTORE at the end (user@realm!tokenname@HOST:DATASTORE)")
	case !pbsDatastore.MatchString(datastore):
		problems = append(problems, "has a datastore name PBS does not allow (letters, digits, \"_\", \"-\" and \".\", not starting with \"-\" or \".\")")
	}
	if len(problems) > 0 {
		return shapeBad(strings.Join(problems, "; "))
	}
	return shapeOK(value)
}

// portWithoutDatastore is whether the problems already say that the part after
// the host is a port and no datastore follows it.
func portWithoutDatastore(problems []string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, "looks like a port") {
			return true
		}
	}
	return false
}

var (
	fingerprintColons = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)
	fingerprintDigits = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
)

// checkPBSFingerprint: 32 hex bytes separated by colons, or 64 hex digits, with
// or without a sha256: prefix. The colon form is what the PBS client is given.
func checkPBSFingerprint(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	stripped := value
	if len(stripped) >= len("sha256:") && strings.EqualFold(stripped[:len("sha256:")], "sha256:") {
		stripped = strings.TrimSpace(stripped[len("sha256:"):])
	}
	switch {
	case fingerprintColons.MatchString(stripped):
		return shapeOK(stripped)
	case fingerprintDigits.MatchString(stripped):
		pairs := make([]string, 0, 32)
		for i := 0; i < len(stripped); i += 2 {
			pairs = append(pairs, stripped[i:i+2])
		}
		return shapeOK(strings.Join(pairs, ":"))
	}
	what := "is not a SHA-256 fingerprint"
	if digits := strings.ReplaceAll(stripped, ":", ""); digits != "" && strings.Trim(digits, "0123456789abcdefABCDEF") == "" {
		if len(digits) == 64 {
			what += " (it has the 64 hex digits, but the colons are in the wrong places)"
		} else {
			what += fmt.Sprintf(" (it has %d hex digits; a SHA-256 fingerprint has 64)", len(digits))
		}
	}
	return shapeBad(what + ". A PBS fingerprint is 32 hex bytes separated by colons (aa:bb:...) or 64 hex digits; read it in the PBS web interface under Dashboard, Show Fingerprint (or on the PBS server: proxmox-backup-manager cert info)")
}

// namespaceLevel is one level of a PBS namespace: the rule pkg/initplan applies to
// the namespace it reads.
var namespaceLevel = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)

// checkPBSNamespace: levels of letters, digits, "_", "-" and ".", separated by
// "/", at most 7, without a leading or trailing "/".
func checkPBSNamespace(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return shapeBad("starts or ends with \"/\": write the namespace without a leading or trailing / (for example prod/team-a)")
	}
	levels := strings.Split(value, "/")
	if len(levels) > 7 {
		return shapeBad("has too many levels: a namespace has at most 7 levels, separated by /")
	}
	for _, level := range levels {
		if level == "" {
			return shapeBad("has an empty level (\"//\"): levels are separated by a single /, for example prod/team-a")
		}
		if !namespaceLevel.MatchString(level) {
			return shapeBad("has a level with characters PBS does not allow: a level starts with a letter, digit or \"_\", holds letters, digits, \"_\", \"-\" and \".\", and is at most 32 characters")
		}
	}
	return shapeOK(value)
}

var nodeNameShape = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// checkNodeNameShape: the node's short name as PVE shows it.
func checkNodeNameShape(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: CERTISTACK_NODE is the node's name as PVE shows it, for example pve1")
	}
	if strings.Contains(value, ".") {
		return shapeBad("contains a dot: give the short node name PVE shows (the part before the first dot), without the domain (a PVE node name has none)")
	}
	if !nodeNameShape.MatchString(value) {
		return shapeBad("must be the node's name as PVE shows it: letters, digits and hyphens only, starting and ending with a letter or digit")
	}
	return shapeOK(value)
}

// checkSSHHost: a host name or address, nothing else. The account is
// CERTISTACK_SSH_USER and the port CERTISTACK_SSH_PORT.
func checkSSHHost(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: CERTISTACK_SSH_HOST is only the node's host name or address, for example pve1.example.com")
	}
	if strings.Contains(value, "://") {
		return shapeBad("is a URL: give only the host name or address of the node (for example pve1.example.com); the account is CERTISTACK_SSH_USER and the port CERTISTACK_SSH_PORT")
	}
	if strings.Contains(value, "@") {
		return shapeBad("contains a user name (user@host): give only the host name or address, and put the account in CERTISTACK_SSH_USER (root on a stock Proxmox VE node)")
	}
	if !strings.HasPrefix(value, "[") && strings.Count(value, ":") == 1 {
		_, port, _ := strings.Cut(value, ":")
		if port != "" && strings.Trim(port, "0123456789") == "" {
			return shapeBad("ends in a :port: give only the host name or address, and put the port in CERTISTACK_SSH_PORT")
		}
	}
	// The rule every connection applies (layer 2 and the run): found here, not
	// after the SSH steps.
	if !controller.ValidSSHHost(value) {
		return shapeBad("is not a host name or address: use letters, digits, '.', '-' and ':' (an IPv6 address is written without brackets), starting with a letter or a digit, for example pve1.example.com or 192.0.2.10")
	}
	return shapeOK(value)
}

// checkSSHUser: the account the controller connects as, a Unix user name.
func checkSSHUser(value string) shapeResult {
	if hasTrailingComment(value) {
		return shapeBad(commentProblem)
	}
	if spacesOrQuotes(value) {
		return shapeBad("contains a space or a quote: CERTISTACK_SSH_USER is only the account name, for example root (the default is certistack)")
	}
	if strings.Contains(value, "@") {
		return shapeBad("contains an @: give only the account name; the host is CERTISTACK_SSH_HOST")
	}
	if !controller.ValidSSHUser(value) {
		return shapeBad("is not a user name: use letters, digits, '_' and '-', starting with a letter or '_', at most 32 characters, for example root or certistack")
	}
	return shapeOK(value)
}
