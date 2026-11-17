// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/cliftcloud/certistack/internal/envtypes"
	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/pkg/pve"
)

const maxEnvironmentFileBytes = 256 << 10

const testModeOptInEnvironment = "CERTISTACK_ALLOW_TEST_MODE"

var workerEnvironmentNames = map[string]struct{}{
	"PVE_URL":                    {},
	"PVE_TOKEN_ID":               {},
	"PVE_TOKEN_SECRET":           {},
	"PVE_TLS_INSECURE":           {},
	pve.InsecureTLSLabOptInEnv:   {},
	"CERTISTACK_PVE_CA_SOURCE":   {},
	"PBS_REPOSITORY":             {},
	"PBS_PASSWORD":               {},
	"PBS_FINGERPRINT":            {},
	"PBS_NAMESPACE":              {},
	"CERTISTACK_PBS_KEYFILE":     {},
	"PBS_ENCRYPTION_PASSWORD":    {},
	"CERTISTACK_PROGRESS_EVENTS": {},
	testModeOptInEnvironment:     {},
}

var controllerEnvironmentNames = map[string]struct{}{
	"PVE_URL":                    {},
	"PVE_TOKEN_ID":               {},
	"PVE_TOKEN_SECRET":           {},
	"PVE_TLS_INSECURE":           {},
	pve.InsecureTLSLabOptInEnv:   {},
	"CERTISTACK_PVE_CA_SOURCE":   {},
	"PBS_REPOSITORY":             {},
	"PBS_PASSWORD":               {},
	"PBS_FINGERPRINT":            {},
	"PBS_NAMESPACE":              {},
	"CERTISTACK_PBS_KEYFILE":     {},
	"PBS_ENCRYPTION_PASSWORD":    {},
	"CERTISTACK_NODE":            {},
	"CERTISTACK_SSH_HOST":        {},
	"CERTISTACK_SSH_USER":        {},
	"CERTISTACK_SSH_PORT":        {},
	"CERTISTACK_SSH_IDENTITY":    {},
	"CERTISTACK_SSH_KNOWN_HOSTS": {},
	"CERTISTACK_SSH_SUDO":        {},
	"CERTISTACK_OUTPUT_DIR":      {},
	"CERTISTACK_STATE_DIR":       {},
	"CERTISTACK_SCRATCH_DIR":     {},
	"CERTISTACK_OVERLAY_STORAGE": {},
	testModeOptInEnvironment:     {},
	"CERTISTACK_API_TOKEN":       {},
	// `doctor --env-file` is documented for use against a node worker's own
	// runtime.env (docs/configuration.md, doctor), not only a controller-style
	// file; that file always carries this key when progress events are
	// enabled, so it must be allowlisted here too or doctor rejects the
	// exact file the troubleshooting docs tell an operator to pass.
	"CERTISTACK_PROGRESS_EVENTS": {},
}

func testModeOptedIn() bool {
	return os.Getenv(testModeOptInEnvironment) == "1"
}

// loadWorkerEnvironment reads the controller-generated allowlisted file.
// It returns values without changing the caller's process environment and
// never evaluates shell syntax, expansions, or command substitutions.
func loadWorkerEnvironment(path string) (map[string]string, error) {
	return parseEnvironmentFile(path, workerEnvironmentNames, "node worker")
}

// loadControllerEnvironment loads an allowlisted controller environment file.
// Relative controller-local paths are resolved from the environment file's
// directory, so a portable file can reference a known_hosts or CA file beside
// it without depending on the caller's current directory.
func loadControllerEnvironment(path string) (map[string]string, error) {
	file, err := loadControllerEnvironmentFile(path)
	if err != nil {
		return nil, err
	}
	return file.values, nil
}

// loadControllerEnvironmentFile is loadControllerEnvironment with what the file
// says about itself: the line of each variable and the notes a file that is
// accepted still earns. A value with the wrong shape (environment_shape.go) is
// refused here, so every command that reads the file refuses it alike, and all
// the wrong values are in the one error.
func loadControllerEnvironmentFile(path string) (*environmentFile, error) {
	file, err := readEnvironmentFile(path, controllerEnvironmentNames, "controller", true)
	if err != nil {
		return nil, err
	}
	problems, notes := file.checkShapes()
	if len(problems) > 0 {
		return nil, &environmentShapeError{problems: problems}
	}
	file.notes = notes
	values := file.values

	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("resolve controller environment directory: %w", err)
	}
	for _, name := range []string{
		"CERTISTACK_PVE_CA_SOURCE",
		"CERTISTACK_PBS_KEYFILE",
		"CERTISTACK_SSH_IDENTITY",
		"CERTISTACK_SSH_KNOWN_HOSTS",
		"CERTISTACK_OUTPUT_DIR",
	} {
		value := values[name]
		if value != "" && !filepath.IsAbs(value) {
			values[name] = filepath.Clean(filepath.Join(baseDir, value))
		}
	}

	return file, nil
}

// useCommandEnvironment applies a file for the duration of one CLI command.
// The CLI and its dependencies read process variables, so activation is explicit
// at that boundary. Every exit restores the exact inherited values, including
// the distinction between an unset variable and an empty value.
func useCommandEnvironment(path string, worker bool) (func(), error) {
	restore, _, err := useCommandEnvironmentFile(path, worker)
	return restore, err
}

// useCommandEnvironmentFile is useCommandEnvironment, and also returns what the
// file says about itself.
func useCommandEnvironmentFile(path string, worker bool) (func(), *environmentFile, error) {
	allowed, role := controllerEnvironmentNames, "controller"
	load := loadControllerEnvironmentFile
	if worker {
		allowed, role = workerEnvironmentNames, "node worker"
		load = func(path string) (*environmentFile, error) {
			return readEnvironmentFile(path, workerEnvironmentNames, "node worker", false)
		}
	}
	file, err := load(path)
	if err != nil {
		return nil, nil, err
	}
	type inherited struct {
		value   string
		present bool
	}
	before := make(map[string]inherited, len(allowed))
	for name := range allowed {
		value, present := os.LookupEnv(name)
		before[name] = inherited{value, present}
	}
	restore := func() {
		for name, previous := range before {
			if previous.present {
				_ = os.Setenv(name, previous.value)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}
	if err := replaceEnvironment(allowed, file.values, role); err != nil {
		restore()
		return nil, nil, err
	}
	return restore, file, nil
}

// envFilePointerName is the file, in the per-user CertiStack directory, where
// certistack setup records the environment file it wrote.
const envFilePointerName = "env-file"

// maxEnvFilePointerBytes bounds the pointer file: one path and a newline.
const maxEnvFilePointerBytes = 4096

// envFilePointerPath is the pointer file: env-file in the directory the usage
// statistics use ($XDG_CONFIG_HOME/certistack, else ~/.config/certistack).
func envFilePointerPath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, envFilePointerName), nil
}

// recordEnvFile writes the pointer file: envPath as an absolute path, on one
// line and nothing else, mode 0600, through a temporary file renamed over the
// pointer; its directory is created 0700.
func recordEnvFile(pointer, envPath string) error {
	abs, err := filepath.Abs(envPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", envPath, err)
	}
	if strings.ContainsAny(abs, "\x00\r\n") {
		return fmt.Errorf("%q cannot be recorded on one line", abs)
	}
	if err := os.MkdirAll(filepath.Dir(pointer), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(pointer), err)
	}
	if err := nodesetup.WriteSecretFile(pointer, []byte(abs+"\n")); err != nil {
		return fmt.Errorf("write %s: %w", pointer, err)
	}
	return nil
}

// recordedEnvFile is the environment file certistack setup recorded, and the
// pointer file it is recorded in. target is "" when there is no pointer (or no
// per-user directory to hold one). A pointer that is not one absolute path, or
// that names a file that no longer exists, is an error naming both.
func recordedEnvFile() (pointer, target string, err error) {
	pointer, err = envFilePointerPath()
	if err != nil {
		return "", "", nil
	}
	again := "run certistack setup again, or pass --env-file FILE"
	file, err := openWithoutBlocking(pointer)
	if errors.Is(err, fs.ErrNotExist) {
		return pointer, "", nil
	}
	if err != nil {
		return pointer, "", fmt.Errorf("read %s, where certistack setup records the environment file: %w", pointer, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return pointer, "", fmt.Errorf("read %s, where certistack setup records the environment file: %w", pointer, err)
	}
	switch {
	case !info.Mode().IsRegular() || info.Size() > maxEnvFilePointerBytes:
		return pointer, "", fmt.Errorf("%s, where certistack setup records the environment file, is not the one-line file setup writes: %s", pointer, again)
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0:
		return pointer, "", fmt.Errorf("%s, where certistack setup records the environment file, can be changed by other users (mode %04o): %s", pointer, info.Mode().Perm(), again)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEnvFilePointerBytes+1))
	if err != nil {
		return pointer, "", fmt.Errorf("read %s, where certistack setup records the environment file: %w", pointer, err)
	}
	target = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if target == "" || !filepath.IsAbs(target) || strings.ContainsFunc(target, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return pointer, "", fmt.Errorf("%s, where certistack setup records the environment file, does not hold one absolute path: %s", pointer, again)
	}
	target = filepath.Clean(target)
	if _, err := os.Stat(target); errors.Is(err, fs.ErrNotExist) {
		return pointer, "", fmt.Errorf("the environment file certistack setup recorded in %s, %s, does not exist: %s", pointer, target, again)
	}
	return pointer, target, nil
}

// controllerEnvFile is the environment file a controller-side command uses.
type controllerEnvFile struct {
	// path is the file; "" is none, and the command uses the process
	// environment as it is.
	path string
	// isDefault: the command run without --env-file uses this same file, the
	// one certistack setup recorded.
	isDefault bool
}

// flag is what a command printed for the reader to run adds to name the file,
// written as shown: nothing when there is no file or it is the default, else
// --env-file and shown.
func (f controllerEnvFile) flag(shown string) string {
	if f.path == "" || f.isDefault {
		return ""
	}
	return " --env-file " + shown
}

// resolveControllerEnvFile decides the environment file of a controller-side
// command (init, plan, run, validate, doctor, check, setup pve-ca) from its
// --env-file value, in this order:
//
//  1. --env-file, when it is given;
//  2. none when PVE_URL is set in the process environment: the command uses
//     the process environment as it is, as in the controller container;
//  3. the file certistack setup recorded (envFilePointerPath), used as if it
//     had been given with --env-file, so every check of the file applies; a
//     record that names a file that no longer exists is an error;
//  4. none, as before setup.
//
// It changes nothing in the process environment, and logs at debug level which
// file it chose and why. The node worker's commands (node-run, node-plan,
// node-check, node-discover, node-inspect, recover) never call it: their file
// is the runtime.env of a workspace, and they are given it.
func resolveControllerEnvFile(flag string) (controllerEnvFile, error) {
	pveURLSet := os.Getenv("PVE_URL") != ""
	if flag != "" {
		chosen := controllerEnvFile{path: flag}
		if !pveURLSet {
			if _, recorded, err := recordedEnvFile(); err == nil && recorded != "" {
				abs, err := filepath.Abs(flag)
				chosen.isDefault = err == nil && abs == recorded
			}
		}
		slog.Debug("environment file: given with --env-file", "path", flag, "default", chosen.isDefault)
		return chosen, nil
	}
	if pveURLSet {
		slog.Debug("environment file: none: PVE_URL is set in the process environment, which is used as it is")
		return controllerEnvFile{}, nil
	}
	pointer, recorded, err := recordedEnvFile()
	if err != nil {
		return controllerEnvFile{}, err
	}
	if recorded == "" {
		slog.Debug("environment file: none: no --env-file, and certistack setup has recorded none", "pointer", pointer)
		return controllerEnvFile{}, nil
	}
	slog.Debug("environment file: the default certistack setup recorded", "path", recorded, "pointer", pointer)
	return controllerEnvFile{path: recorded, isDefault: true}, nil
}

// errEnvFileRequired is what check and setup pve-ca, which work only from an
// environment file, say when no --env-file was given and setup has recorded
// none: the words of the required flag they had before setup recorded one.
var errEnvFileRequired = errors.New(`required flag(s) "env-file" not set`)

// utf8BOM starts a file a Windows editor saved as UTF-8 with a signature. The
// plan, key and keyring loaders accept it, and so does the environment file.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// environmentNamePattern is what a variable's name looks like: capitals,
// digits and at least one underscore, as every name the files allow does. A
// name the file may not have is quoted back only if it is of this form.
// Whatever is before the first "=" of a line is taken for a name, and a
// secret pasted without its NAME= (a base64 value ends in "=") would
// otherwise be printed in the error that told the operator the line was wrong.
var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`)

// afterEnvironmentChecks, when set by a test, runs after the file has been
// opened and checked and before it is read.
var afterEnvironmentChecks func(path string)

// environmentFile is what an environment file holds.
type environmentFile struct {
	values map[string]string
	// lines is the line (from 1) each variable is on.
	lines map[string]int
	// typed are the typed values (a port, a yes or no) that are wrong, which the
	// controller's file reports with the other wrong shapes instead of stopping at
	// the first.
	typed []shapeProblem
	// notes are what the controller's file, once accepted, still says to its
	// writer.
	notes []string
}

func parseEnvironmentFile(path string, allowed map[string]struct{}, role string) (map[string]string, error) {
	file, err := readEnvironmentFile(path, allowed, role, false)
	if err != nil {
		return nil, err
	}
	return file.values, nil
}

// readEnvironmentFile reads and parses the file. collect has the typed values
// that are wrong collected into the result, to be reported with the other wrong
// shapes, instead of being the error.
func readEnvironmentFile(path string, allowed map[string]struct{}, role string, collect bool) (*environmentFile, error) {
	if path == "" {
		return nil, fmt.Errorf("%s environment file is required", role)
	}
	// The file is opened once, without waiting, and every check is made on the
	// open descriptor, so the file that was checked is the file that is read,
	// and a file that grows in between is not read past the limit.
	file, err := openWithoutBlocking(path)
	if err != nil {
		if role == "controller" {
			// A file that is not there is the first run not done: say what check
			// says, not how to make the directory.
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("open %s environment file: %w%s. %s", role, err, missingDirectoryNote(path, err), environmentFileMissingFix())
			}
			return nil, fmt.Errorf("open %s environment file: %w", role, err)
		}
		return nil, fmt.Errorf("open %s environment file: %w", role, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s environment file: %w", role, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s environment file must be a regular file", role)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s environment file must not be accessible by group or other users (mode %04o)", role, info.Mode().Perm())
	}
	if info.Size() > maxEnvironmentFileBytes {
		return nil, fmt.Errorf("%s environment file exceeds %d bytes", role, maxEnvironmentFileBytes)
	}
	if afterEnvironmentChecks != nil {
		afterEnvironmentChecks(path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEnvironmentFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s environment: %w", role, err)
	}
	if len(data) > maxEnvironmentFileBytes {
		return nil, fmt.Errorf("%s environment file exceeds %d bytes", role, maxEnvironmentFileBytes)
	}
	// A file saved by a Windows editor can start with a byte order mark. UTF-8's
	// is part of no name, so it is dropped; UTF-16's means every character
	// after it is two bytes, which no line below would parse, and the
	// operator is told to save the file as UTF-8 instead of being shown
	// names made of null bytes.
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		return nil, fmt.Errorf("%s environment file is UTF-16 encoded (it starts with a byte order mark); save it as UTF-8", role)
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	// What was read is what was checked: a mode change while reading is refused.
	if after, err := file.Stat(); err != nil || after.Mode().Perm() != info.Mode().Perm() {
		return nil, fmt.Errorf("%s environment file changed while it was being read", role)
	}

	result := &environmentFile{values: make(map[string]string), lines: make(map[string]int)}
	for index, line := range strings.Split(string(data), "\n") {
		lineNumber := index + 1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid %s environment line %d: a line is NAME=VALUE (its text is not shown, because it may be a secret)", role, lineNumber)
		}
		key = strings.TrimSpace(key)
		if !isAllowedName(allowed, key) {
			return nil, unsupportedEnvironmentLine(role, key, lineNumber, allowed)
		}
		if first, duplicate := result.lines[key]; duplicate {
			return nil, fmt.Errorf("duplicate %s environment variable %q on line %d (it is already set on line %d): keep one of the two", role, key, lineNumber, first)
		}
		value, err := parseEnvironmentValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("invalid %s environment variable %q on line %d: %w", role, key, lineNumber, err)
		}
		result.lines[key] = lineNumber
		// A typed value that is malformed is refused here, not defaulted
		// later. An empty value is a value left out.
		if err := envtypes.Check(key, value); err != nil {
			if collect {
				result.typed = append(result.typed, shapeProblem{name: key, line: lineNumber, message: err.Error()})
				continue
			}
			return nil, fmt.Errorf("invalid %s environment variable %q on line %d: %w", role, key, lineNumber, err)
		}
		result.values[key] = value
	}
	return result, nil
}

// commonEnvironmentNames are the names a shell profile or an init system sets
// that hold no underscore, so that environmentNamePattern does not match them:
// someone copying a profile into the file writes them first. They are told
// apart from a secret pasted without its NAME= because they are these words
// and no others.
var commonEnvironmentNames = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "PWD": true, "OLDPWD": true,
	"LANG": true, "TERM": true, "TZ": true, "EDITOR": true, "PAGER": true, "DISPLAY": true, "HOSTNAME": true,
	"TMPDIR": true, "MAIL": true, "DEBUG": true, "VERBOSE": true,
}

// notASettingNote says what an environment file holds, for a name that is not
// one of CertiStack's.
const notASettingNote = "an environment file holds only the settings in docs/configuration.md (it is read literally, not as a shell script)"

// unsupportedEnvironmentLine is the error for a line whose name the file may
// not have. What is before the "=" is quoted back only when it is shaped like a
// variable name, or is one in a different spelling: a secret pasted without its
// NAME= would otherwise be printed in the message that says the line is wrong.
func unsupportedEnvironmentLine(role, key string, lineNumber int, allowed map[string]struct{}) error {
	exported := false
	if word, rest, ok := strings.Cut(key, " "); ok && word == "export" {
		name := strings.TrimSpace(rest)
		if isAllowedName(allowed, name) {
			return fmt.Errorf("invalid %s environment line %d: remove the word \"export\": this is not a shell script, a line is NAME=VALUE (%s=VALUE)", role, lineNumber, name)
		}
		key, exported = name, true
	}
	if upper := strings.ToUpper(key); upper != key && isAllowedName(allowed, upper) {
		return fmt.Errorf("invalid %s environment line %d: variable names are written in capitals: use %s (the text before the \"=\" is not shown)", role, lineNumber, upper)
	}
	if !environmentNamePattern.MatchString(key) && !commonEnvironmentNames[key] {
		return fmt.Errorf("invalid %s environment line %d: the text before its first \"=\" is not shown, because it is not shaped like a variable name (CAPITALS_WITH_UNDERSCORES) and may be a value pasted without its name; a line is NAME=VALUE", role, lineNumber)
	}
	if key == "CERTISTACK_SIGN_KEY" {
		return fmt.Errorf("unsupported %s environment variable %q on line %d: the Community Edition writes its reports unsigned and reads no signing key, so remove the line (the Enterprise Edition signs its reports, with its own settings)", role, key, lineNumber)
	}
	message := fmt.Sprintf("unsupported %s environment variable %q on line %d", role, key, lineNumber)
	if near := nearestEnvironmentName(allowed, key); near != "" {
		message += fmt.Sprintf(" (did you mean %s?)", near)
	} else {
		// Not a typo of a setting: a name from a shell profile or another program.
		message += fmt.Sprintf(": %s is not a CertiStack setting; %s", key, notASettingNote)
	}
	if exported {
		message += ". Remove the word \"export\" too: a line is NAME=VALUE"
	}
	return errors.New(message)
}

func isAllowedName(allowed map[string]struct{}, name string) bool {
	_, ok := allowed[name]
	return ok
}

// nearestEnvironmentName is the allowed name that key is one or two edits away
// from (a transposed or missing letter), else "".
func nearestEnvironmentName(allowed map[string]struct{}, key string) string {
	best, bestDistance := "", 3
	for name := range allowed {
		if distance := editDistance(name, key); distance < bestDistance || (distance == bestDistance && name < best) {
			best, bestDistance = name, distance
		}
	}
	return best
}

// editDistance is the number of single-letter edits (insert, delete, replace)
// between two words.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

func parseEnvironmentValue(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("contains a prohibited control character")
	}
	if value == "" {
		return "", nil
	}
	quote := value[0]
	if quote != '\'' && quote != '"' {
		return value, nil
	}
	if len(value) < 2 || value[len(value)-1] != quote {
		if end := strings.IndexByte(value[1:], quote); end >= 0 {
			// A closing quote, and text after it: a comment on the same line.
			return "", fmt.Errorf("has text after the closing quote (a comment?): values are literal, so put a comment on a line of its own and keep only the quoted value here")
		}
		return "", fmt.Errorf("has an unterminated quoted value")
	}
	// Quoting only groups a literal value. In particular, $(), ${...}, and
	// backticks are never interpreted as shell syntax.
	return value[1 : len(value)-1], nil
}

func replaceEnvironment(allowed map[string]struct{}, values map[string]string, role string) error {
	for name := range allowed {
		if err := os.Unsetenv(name); err != nil {
			return fmt.Errorf("clear inherited %s environment variable %q: %w", role, name, err)
		}
	}
	for name, value := range values {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("set %s environment variable %q: %w", role, name, err)
		}
	}
	return nil
}
