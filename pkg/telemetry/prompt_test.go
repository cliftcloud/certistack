// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestAskFlow(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		want         Answer
		wantBusiness bool // the second question was put
	}{
		{"yes then yes", "y\ny\n", Answer{Share: true, Business: true}, true},
		{"yes then no", "yes\nn\n", Answer{Share: true}, true},
		{"yes then empty", "Y\n\n", Answer{Share: true}, true},
		{"yes then end of input", "y\n", Answer{Share: true}, true},
		{"yes without a newline, then end of input", "y", Answer{Share: true}, true},
		{"spaces and capitals", "  YES  \n  Yes \n", Answer{Share: true, Business: true}, true},
		{"no", "n\n", Answer{}, false},
		{"empty line is no", "\n", Answer{}, false},
		{"end of input is no", "", Answer{}, false},
		{"garbage is no", "maybe\n", Answer{}, false},
		{"yesterday is not yes", "yesterday\n", Answer{}, false},
		{"y with trailing text is not yes", "y please\n", Answer{}, false},
		{"garbage to the second question is no", "y\nsure\n", Answer{Share: true}, true},
		{"a no does not read on", "n\ny\n", Answer{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got, ok := Ask(context.Background(), strings.NewReader(tc.input), &out)
			if !ok || got != tc.want {
				t.Fatalf("Ask = %+v ok=%v, want %+v", got, ok, tc.want)
			}
			if !strings.Contains(out.String(), QuestionShare) {
				t.Errorf("the first question was not put: %q", out.String())
			}
			if asked := strings.Contains(out.String(), QuestionBusiness); asked != tc.wantBusiness {
				t.Errorf("business question put = %v, want %v", asked, tc.wantBusiness)
			}
		})
	}
}

func TestTheQuestionsAreWordForWord(t *testing.T) {
	if QuestionShare != "Share usage statistics with Clift Cloud? Nothing but the five fields shown by `certistack telemetry show` is sent. [y/N] " {
		t.Errorf("share question = %q", QuestionShare)
	}
	if QuestionBusiness != "Do you use CertiStack for a business or commercial purpose? [y/N] " {
		t.Errorf("business question = %q", QuestionBusiness)
	}
}

func TestAskGivesUpWhenTheCommandIsInterrupted(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		_, ok := Ask(ctx, pr, io.Discard)
		done <- ok
	}()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("an interrupted question counted as answered")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ask kept waiting for input after the context ended")
	}
}

func TestShouldPromptMatrix(t *testing.T) {
	type tc struct {
		name          string
		command       string
		stdin, stderr bool
		env           []string
		setup         func(t *testing.T, h *harness)
		want          bool
	}
	for _, c := range []tc{
		{name: "run at a terminal", command: "run", stdin: true, stderr: true, want: true},
		{name: "plan at a terminal", command: "plan", stdin: true, stderr: true, want: true},
		{name: "doctor at a terminal", command: "doctor", stdin: true, stderr: true, want: true},
		{name: "init at a terminal", command: "init", stdin: true, stderr: true, want: true},
		{name: "stdin is not a terminal", command: "run", stdin: false, stderr: true},
		{name: "stderr is not a terminal", command: "run", stdin: true, stderr: false},
		{name: "neither is", command: "run"},
		{name: "CI set", command: "run", stdin: true, stderr: true, env: []string{"CI", "true"}},
		{name: "CI set to false still counts as CI", command: "run", stdin: true, stderr: true, env: []string{"CI", "false"}},
		{name: "version", command: "version", stdin: true, stderr: true},
		{name: "help", command: "help", stdin: true, stderr: true},
		{name: "completion", command: "completion", stdin: true, stderr: true},
		{name: "verify-report", command: "verify-report", stdin: true, stderr: true},
		{name: "telemetry", command: "telemetry", stdin: true, stderr: true},
		{name: "validate", command: "validate", stdin: true, stderr: true},
		{name: "keygen", command: "keygen", stdin: true, stderr: true},
		{name: "node-run on the PVE node", command: "node-run", stdin: true, stderr: true},
		{name: "recover", command: "recover", stdin: true, stderr: true},
		{name: "DO_NOT_TRACK", command: "run", stdin: true, stderr: true, env: []string{"DO_NOT_TRACK", "1"}},
		{name: "CERTISTACK_TELEMETRY=off", command: "run", stdin: true, stderr: true, env: []string{"CERTISTACK_TELEMETRY", "off"}},
		{name: "CERTISTACK_TELEMETRY=1", command: "run", stdin: true, stderr: true, env: []string{"CERTISTACK_TELEMETRY", "1"}},
		{name: "already said yes", command: "run", stdin: true, stderr: true, setup: func(t *testing.T, h *harness) { mustEnable(t, h, false) }},
		{name: "already said no", command: "run", stdin: true, stderr: true, setup: func(t *testing.T, h *harness) { _, _ = h.Disable() }},
		{name: "corrupt state is left alone", command: "run", stdin: true, stderr: true, setup: func(t *testing.T, h *harness) { writeRaw(t, h.StatePath, "junk") }},
		{name: "answered:false is still unasked", command: "run", stdin: true, stderr: true, want: true, setup: func(t *testing.T, h *harness) { writeRaw(t, h.StatePath, `{"answered": false}`) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "", c.env...)
			if c.setup != nil {
				c.setup(t, h)
			}
			if got := h.ShouldPrompt(c.command, c.stdin, c.stderr); got != c.want {
				t.Fatalf("ShouldPrompt = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRecordStoresYesAndNoSoTheQuestionIsAskedOnce(t *testing.T) {
	for _, a := range []Answer{{}, {Share: true}, {Share: true, Business: true}} {
		h := newHarness(t, "")
		if !h.ShouldPrompt("run", true, true) {
			t.Fatal("a fresh install should be asked")
		}
		if err := h.Record(a); err != nil {
			t.Fatal(err)
		}
		if h.ShouldPrompt("run", true, true) {
			t.Errorf("%+v: asked again after an answer", a)
		}
		st := h.state(t)
		if !st.Answered || st.Enabled != a.Share || st.BusinessUse != a.Business {
			t.Errorf("%+v stored as %+v", a, st)
		}
		if a.Share && !uuid4.MatchString(st.InstallID) {
			t.Errorf("no install id after a yes: %+v", st)
		}
		if !a.Share && (st.InstallID != "" || st.Salt != "") {
			t.Errorf("a no kept an identity: %+v", st)
		}
	}
}
