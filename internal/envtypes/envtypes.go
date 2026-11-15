// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package envtypes holds the rules for the typed environment variables of a
// controller or node worker: a port, a yes or no. One rule serves the
// controller's dotenv file, the controller's inherited environment (which it
// forwards to the worker) and the worker's own file, so a value the
// controller accepts is never one the worker then refuses.
package envtypes

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The typed variables. The two TLS names equal pve.PVE_TLS_INSECURE's and
// pve.InsecureTLSLabOptInEnv's; a test keeps them in step.
const (
	InsecureTLS       = "PVE_TLS_INSECURE"
	InsecureTLSLabOpt = "CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB"
	SSHPort           = "CERTISTACK_SSH_PORT"
	SSHSudo           = "CERTISTACK_SSH_SUDO"
	ProgressEvents    = "CERTISTACK_PROGRESS_EVENTS"
	AllowTestMode     = "CERTISTACK_ALLOW_TEST_MODE"
)

const (
	trueFalseGuidance = "use true or false (or 1 or 0)"
	zeroOneGuidance   = "only 1 turns it on"
	booleanGuidance   = "use true or false (1, 0, yes and no also work)"
	portGuidance      = "give a whole number from 1 to 65535"
	maxDigitsOfAPort  = 5
)

// typed maps each typed variable to the check the code that reads it applies.
var typed = map[string]func(string) error{
	SSHPort:           checkPort,
	SSHSudo:           checkBoolean,
	InsecureTLS:       checkTrueFalse,
	InsecureTLSLabOpt: checkTrueFalse,
	// Only the exact value 1 turns these on.
	ProgressEvents: checkZeroOne,
	AllowTestMode:  checkZeroOne,
}

// maxQuotedLength bounds a value that a message shows: a host name, a port or a
// yes or no is short.
const maxQuotedLength = 32

var (
	plainCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:/+@[]# "
	uuidShape       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	unbrokenRun     = regexp.MustCompile(`^[A-Za-z0-9_+-]{20,}$`)
)

// Quoted is value as a message may show it. None of the typed variables is a
// secret, and neither is an SSH host or user, but the value of any line can be
// a secret pasted into the wrong one, which is the mistake the messages exist
// for. So a value is shown, in quotes, only when it is short, made of what a
// host name, an address, a port or a yes or no is made of, and not shaped like
// a credential (a UUID, an unbroken run of letters and digits); otherwise the
// message says how long it is and that it is not shown. (review R2-07)
func Quoted(value string) string {
	if len(value) <= maxQuotedLength && strings.Trim(value, plainCharacters) == "" && !looksLikeACredential(value) {
		return strconv.Quote(value)
	}
	return fmt.Sprintf("a value of %d characters (not shown, in case it is a secret)", utf8.RuneCountInString(value))
}

// looksLikeACredential is whether any word of value is a UUID (what a PVE token
// secret is) or an unbroken run of 20 or more letters, digits, '_', '+' and '-'
// holding both a letter and a digit (what an API token or a generated password
// is).
func looksLikeACredential(value string) bool {
	for _, word := range strings.Fields(value) {
		if uuidShape.MatchString(word) {
			return true
		}
		if unbrokenRun.MatchString(word) && strings.ContainsAny(word, "0123456789") && strings.ContainsAny(word, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return true
		}
	}
	return false
}

// Check is nil when name is not a typed variable, when value is empty (a value
// left out), or when value is one the reader of name understands; else an
// error that says what is accepted. It names the value only as Quoted allows.
func Check(name, value string) error {
	check := typed[name]
	if check == nil || value == "" {
		return nil
	}
	return check(value)
}

// ParsePort reads a whole decimal SSH port from 1 to 65535. Its error says
// what is wrong with the value without showing it: the value of an
// environment line can be a secret pasted into the wrong one.
func ParsePort(value string) (int, error) {
	switch {
	case value == "":
		return 0, fmt.Errorf("is empty, not a port: %s", portGuidance)
	case strings.Trim(value, "0123456789") != "":
		return 0, fmt.Errorf("is not a port: it holds %s other than a digit; %s", describeRuns(value), portGuidance)
	case len(value) > maxDigitsOfAPort:
		return 0, fmt.Errorf("is not a port: it has %d digits; %s", len(value), portGuidance)
	}
	port, _ := strconv.Atoi(value)
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("is not a port: it is outside 1 to 65535; %s", portGuidance)
	}
	return port, nil
}

// describeRuns says, without showing value, how many of its characters are
// not digits.
func describeRuns(value string) string {
	count := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			count++
		}
	}
	if count == 1 {
		return "a character"
	}
	return fmt.Sprintf("%d characters", count)
}

func checkPort(value string) error {
	_, err := ParsePort(value)
	return err
}

// ParseBoolean reads the spellings of a yes or no setting, in either case.
func ParseBoolean(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("is not a yes or no value (%s long): %s", length(value), booleanGuidance)
}

func checkBoolean(value string) error {
	_, err := ParseBoolean(value)
	return err
}

// checkTrueFalse accepts what the readers of PVE_TLS_INSECURE and the lab
// opt-in understand: 1 or true, 0 or false. Anything else they would read as
// false, which is not what a yes or on says.
func checkTrueFalse(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "0", "false":
		return nil
	}
	return fmt.Errorf("is not true or false (%s long): %s", length(value), trueFalseGuidance)
}

func checkZeroOne(value string) error {
	if value == "0" || value == "1" {
		return nil
	}
	return fmt.Errorf("is not 0 or 1 (%s long): %s", length(value), zeroOneGuidance)
}

// length is how long value is, in characters, for a message that does not
// show it.
func length(value string) string {
	if n := utf8.RuneCountInString(value); n != 1 {
		return fmt.Sprintf("%d characters", n)
	}
	return "1 character"
}
