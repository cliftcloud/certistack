// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// repoFile is a path in the repository, from this package's directory.
func repoFile(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

type workflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
	// ContinueOnError is set when the step names continue-on-error at all.
	ContinueOnError any `yaml:"continue-on-error"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Outputs     map[string]string `yaml:"outputs"`
	Steps       []workflowStep    `yaml:"steps"`
	RunsOn      string            `yaml:"runs-on"`
	// ContinueOnError is set when the job names continue-on-error at all.
	ContinueOnError any `yaml:"continue-on-error"`
}

type workflowFile struct {
	Permissions map[string]string                    `yaml:"permissions"`
	Defaults    struct{ Run struct{ Shell string } } `yaml:"defaults"`
	Jobs        map[string]workflowJob               `yaml:"jobs"`
}

func readWorkflowFile(t *testing.T, path string) workflowFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowFile
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return workflow
}

// rawWorkflow is a workflow as untyped YAML, for what the typed view cannot
// tell apart (a key that is absent from one that is empty).
func rawWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(repoFile(".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// needs lists the jobs this job waits for.
func (j workflowJob) needs() []string {
	switch v := j.Needs.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, item.(string))
		}
		return out
	}
	return nil
}

// environmentName is the environment the job deploys to, or "".
func (j workflowJob) environmentName() string {
	switch v := j.Environment.(type) {
	case string:
		return v
	case map[string]any:
		name, _ := v["name"].(string)
		return name
	}
	return ""
}

func readWorkflow(t *testing.T, name string) workflowFile {
	t.Helper()
	return readWorkflowFile(t, repoFile(".github", "workflows", name))
}

// step returns the index and definition of the job's step with this name.
func (j workflowJob) step(t *testing.T, name string) (int, workflowStep) {
	t.Helper()
	for i, step := range j.Steps {
		if step.Name == name {
			return i, step
		}
	}
	t.Fatalf("no step named %q", name)
	return -1, workflowStep{}
}

// needTools skips a test that runs shell where that shell or a tool it
// needs is unavailable (Windows, or a minimal development machine). CI's
// Linux runners have them all.
func needTools(t *testing.T, tools ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("runs POSIX shell")
	}
	for _, tool := range append([]string{"bash"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s: %v", tool, err)
		}
	}
}

// writeExecutable writes a stub program.
func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

// shellEnv is a minimal environment for a shell step: the stub directory
// ahead of the system tools, a private HOME and TMPDIR, and extra.
func shellEnv(t *testing.T, stubs, home string, extra map[string]string) []string {
	t.Helper()
	env := map[string]string{
		"PATH":   stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME":   home,
		"TMPDIR": home,
		"LANG":   "C",
		"LC_ALL": "C",
	}
	for name, value := range extra {
		env[name] = value
	}
	var list []string
	for name, value := range env {
		list = append(list, name+"="+value)
	}
	sort.Strings(list)
	return list
}

// runStep runs a workflow step's shell body the way GitHub's hosted runners
// run `shell: bash`: bash --noprofile --norc -eo pipefail on a script file.
func runStep(t *testing.T, dir string, env []string, body string) (string, error) {
	t.Helper()
	scratch := t.TempDir()
	script := filepath.Join(scratch, "step.sh")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Output goes to a file, not a pipe: a daemon the step leaves behind (gpg
	// starts a gpg-agent) inherits the descriptor, and a pipe would then
	// never reach end-of-file.
	outPath := filepath.Join(scratch, "output")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-eo", "pipefail", script)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	runErr := cmd.Run()
	output, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), runErr
}

// readLog returns a stub log's lines.
func readLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if trimmed := strings.TrimRight(string(data), "\n"); trimmed != "" {
		return strings.Split(trimmed, "\n")
	}
	return nil
}

// codeBlock is a fenced block of a Markdown file with the "## " heading it
// sits under.
type codeBlock struct {
	heading string
	lang    string
	body    string
}

// codeBlocks lists a Markdown file's fenced blocks in order.
func codeBlocks(t *testing.T, path string) []codeBlock {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []codeBlock
	var heading string
	var current *codeBlock
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case current != nil && strings.HasPrefix(line, "```"):
			blocks = append(blocks, *current)
			current = nil
		case current != nil:
			current.body += line + "\n"
		case strings.HasPrefix(line, "```"):
			current = &codeBlock{heading: heading, lang: strings.TrimPrefix(line, "```")}
		case strings.HasPrefix(line, "## "):
			heading = strings.TrimPrefix(line, "## ")
		}
	}
	return blocks
}

// commands splits a shell block into its commands: a line ending in a
// backslash continues on the next, and blank lines and comments are dropped.
func (b codeBlock) commands() []string {
	var out []string
	var pending string
	for _, line := range strings.Split(b.body, "\n") {
		trimmed := strings.TrimSpace(line)
		if pending == "" && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending += strings.TrimSuffix(trimmed, "\\") + " "
			continue
		}
		out = append(out, strings.Join(strings.Fields(pending+trimmed), " "))
		pending = ""
	}
	return out
}

// changelogVersion is the newest release CHANGELOG.md records, as its tag
// ("v0.1.0").
func changelogVersion(t *testing.T) string {
	t.Helper()
	release := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - `).FindStringSubmatch(readRepoText(t, "CHANGELOG.md"))
	if release == nil {
		t.Fatal("CHANGELOG.md has no released version")
	}
	return "v" + release[1]
}
