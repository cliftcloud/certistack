// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// DecodeReportUnverified reads a report's contents WITHOUT checking its
// signature. It exists for commands that only show or tally reports (report
// show, and the Enterprise Edition's per-VM history) and say so when no
// trusted key was given: what it returns is
// whatever the file says, and anyone can write a file that says anything. It
// must never be used to decide that a report is evidence; VerifyReport is the
// only function that does.
//
// The bytes still pass through the same structure and size checks a verifier
// applies before anything is decoded (the limits of MaxReportFileBytes and its
// companions, no repeated member name at any depth, no integer a signature
// could not cover exactly), so a hostile file is refused here as it is there.
// A file that is valid JSON but not a report object is an error that says what
// it holds instead.
func DecodeReportUnverified(data []byte) (*Report, error) {
	if err := checkReportDocument(data); err != nil {
		return nil, fmt.Errorf("invalid report JSON: %w", err)
	}
	// JSON null decodes into a struct as no error and an empty report, which a
	// caller would take for a report with nothing in it: it is not a report.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, errors.New("not a CertiStack report: the file holds a JSON null, not a report object")
	}
	var report Report
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&report); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			if typeErr.Field == "" {
				return nil, fmt.Errorf("not a CertiStack report: the file holds a JSON %s, not a report object", typeErr.Value)
			}
			return nil, fmt.Errorf("not a CertiStack report: its member %q is a JSON %s, which a report does not have there", typeErr.Field, typeErr.Value)
		}
		return nil, fmt.Errorf("not a CertiStack report: %w", err)
	}
	return &report, nil
}

// CarriedSignatureMembers names the top-level members of a report document that
// are one of the signature members (UnsignedReportMembers) under any spelling
// the decoder reads as that member: encoding/json matches a member to a field
// without regard to case, so "Signature" fills the same field as "signature". The
// names are as the document spells them, in the order of UnsignedReportMembers
// and then alphabetically. A member that merely holds a signature-like value, or
// a nested member of that name, is content and not named. An empty result is a
// document with no signature member at all, the only unsigned report; a member
// named here whose value is not a usable signature makes the report neither
// signed nor unsigned.
func CarriedSignatureMembers(data []byte) ([]string, error) {
	document, err := decodeReportDocument(data)
	if err != nil {
		return nil, fmt.Errorf("invalid report JSON: %w", err)
	}
	return carriedSignatureMembers(document), nil
}

func carriedSignatureMembers(document map[string]interface{}) []string {
	var names []string
	for _, member := range unsignedReportMembers {
		var spelled []string
		for name := range document {
			if strings.EqualFold(name, member) {
				spelled = append(spelled, name)
			}
		}
		sort.Strings(spelled)
		names = append(names, spelled...)
	}
	return names
}

// isExactSignatureMember is whether name is one of the signature members spelled
// as they are written.
func isExactSignatureMember(name string) bool {
	for _, member := range unsignedReportMembers {
		if name == member {
			return true
		}
	}
	return false
}

// ErrReportSigned is what DecodeUnsignedReport returns for a report that carries
// a signature member.
var ErrReportSigned = errors.New("report carries a signature")

// DecodeUnsignedReport reads a report that is expected to carry no signature at
// all, as the Community Edition writes it, WITHOUT authenticating it: what it
// returns is whatever the file says, as with DecodeReportUnverified, and the
// caller says so wherever it shows or judges the report. The file is still held
// to the structure and size limits of a verifier.
//
// A report with any of the members UnsignedReportMembers lists (signature,
// public_key, signer_fingerprint, signature_timestamp) is not unsigned, however
// little of a signature it holds: it is refused with ErrReportSigned and the name
// of the first such member, so that a caller who expects no signature cannot be
// handed a signed report, or the debris of one, to read as an unauthenticated
// claim. Verify such a report with VerifyReport.
func DecodeUnsignedReport(data []byte) (*Report, error) {
	document, err := decodeReportDocument(data)
	if err != nil {
		return nil, fmt.Errorf("invalid report JSON: %w", err)
	}
	// Every spelling the decoder reads as a signature member counts, so that a
	// signature under another case is not read as an unauthenticated claim (and
	// its timestamp is never evaluated on a report declared unsigned).
	if carried := carriedSignatureMembers(document); len(carried) > 0 {
		return nil, fmt.Errorf("%w (member %q)", ErrReportSigned, carried[0])
	}
	return DecodeReportUnverified(data)
}
