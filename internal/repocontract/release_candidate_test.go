// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// githubTagFilter compiles a workflow's tag filter pattern the way GitHub
// reads it for the pattern shapes the release workflow uses: the whole tag
// name must match; `[0-9]` is a range, `+` repeats the character before it,
// `*` is any run of characters other than `/`, and everything else is literal.
func githubTagFilter(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '[':
			end := strings.IndexByte(pattern[i:], ']')
			if end < 0 {
				t.Fatalf("unterminated range in %q", pattern)
			}
			b.WriteString(pattern[i : i+end+1])
			i += end
		case '+':
			b.WriteByte('+')
		case '*':
			b.WriteString("[^/]*")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// A release candidate (vX.Y.Z-rcN) is a git tag and a registry line and never
// starts the release workflow: its tag filter matches the stable form and
// nothing else, so pushing a candidate tag signs nothing, writes no registry
// tag and creates no release.
func TestReleaseWorkflowStartsOnlyOnStableTags(t *testing.T) {
	raw := rawWorkflow(t, "release.yml")
	on, _ := raw["on"].(map[string]any)
	push, _ := on["push"].(map[string]any)
	tags, _ := push["tags"].([]any)
	if len(tags) == 0 {
		t.Fatal("release.yml has no tag filter")
	}
	if _, ignored := push["tags-ignore"]; ignored {
		t.Error("the tag filter mixes tags and tags-ignore")
	}
	var filters []*regexp.Regexp
	for _, tag := range tags {
		filters = append(filters, githubTagFilter(t, tag.(string)))
	}
	starts := func(name string) bool {
		for _, filter := range filters {
			if filter.MatchString(name) {
				return true
			}
		}
		return false
	}
	for _, stable := range []string{"v0.1.0", "v1.2.3", "v10.20.30"} {
		if !starts(stable) {
			t.Errorf("the stable tag %s does not start the release workflow", stable)
		}
	}
	for _, other := range []string{
		"v0.1.0-rc1", "v0.1.0-rc2", "v0.1.0-rc10", "v1.2.3-rc1", "v0.1.0-beta", "v0.1.0+build", "v0.1", "0.1.0", "release/v0.1.0",
	} {
		if starts(other) {
			t.Errorf("the tag %s starts the release workflow; only a stable tag may publish", other)
		}
	}
}

// Actions are pinned by commit. A pin that is an annotated tag's object
// rather than the commit it names looks identical but is not a commit, and a
// hosted runner may fail to resolve it after the approval gate; the release
// workflow's softprops/action-gh-release pin was such an object
// (5113cdc, the v3 tag; its commit is efb3536, which is also v3.0.3). The
// known tag objects are refused here, and a pin is checked against the remote
// with `git ls-remote <repository> <sha>`, which lists a commit, not a tag
// object, only under a branch or a peeled (^{}) tag.
func TestWorkflowActionPinsAreCommitsNotTagObjects(t *testing.T) {
	tagObjects := map[string]string{
		"5113cdc90fd4d541c801c55356214017bf5ae34b": "softprops/action-gh-release v3 (commit efb35369e0ad2afab669f228072c1b0d510eae64)",
	}
	workflows := []string{"ci.yml", "cla.yml", "release.yml"}
	sawRelease := false
	for _, name := range workflows {
		data, err := os.ReadFile(repoFile(".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, use := range regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)@([0-9a-f]{40})\s*(?:#\s*(.*))?$`).FindAllStringSubmatch(string(data), -1) {
			if why, bad := tagObjects[use[2]]; bad {
				t.Errorf("%s pins %s to %s, a tag object, not a commit: %s", name, use[1], use[2], why)
			}
			if use[1] == "softprops/action-gh-release" {
				sawRelease = true
				if use[2] != "efb35369e0ad2afab669f228072c1b0d510eae64" || !strings.HasPrefix(use[3], "v3.0.3") {
					t.Errorf("softprops/action-gh-release is pinned to %s (%s), want the commit efb35369e0ad2afab669f228072c1b0d510eae64 labelled v3.0.3", use[2], use[3])
				}
			}
		}
	}
	if !sawRelease {
		t.Error("release.yml no longer uses softprops/action-gh-release; drop this expectation with it")
	}
}

// The Dockerfile's release-binary stage copies bin/certistack-linux-amd64,
// which exists only after a release build. BuildKit builds just the stages
// the target needs; the legacy builder builds every stage and fails on the
// missing file, which CI (BuildKit) never shows. So the guide says BuildKit is
// required, and the Makefile's image targets ask for it.
func TestControllerImageBuildRequiresBuildKitAndSaysSo(t *testing.T) {
	dockerfile, err := os.ReadFile(repoFile("deploy", "controller", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "FROM scratch AS release-binary\nCOPY bin/certistack-linux-amd64") {
		t.Fatal("the Dockerfile no longer has the release-binary stage; drop this test with it")
	}
	readme, err := os.ReadFile(repoFile("deploy", "controller", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "The Dockerfile needs BuildKit") || !strings.Contains(string(readme), "DOCKER_BUILDKIT=1") {
		t.Error("the controller guide does not say the Dockerfile needs BuildKit")
	}
	makefile, err := os.ReadFile(repoFile("Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"container", "container-release"} {
		recipe := regexp.MustCompile(`(?m)^` + target + `:\n((?:\t.*\n)+)`).FindStringSubmatch(string(makefile))
		if recipe == nil || !strings.Contains(recipe[1], "DOCKER_BUILDKIT=1 docker build") {
			t.Errorf("make %s does not build with DOCKER_BUILDKIT=1", target)
		}
	}
}
