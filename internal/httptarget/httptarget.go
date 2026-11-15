// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package httptarget decides whether the path an http probe asks for reaches
// the server as the plan wrote it. The plan validator and the prober share
// one rule, so a path the validator accepts is one the prober sends, and a
// probe cannot pass on a request for some other resource.
package httptarget

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Problem says why target, an http probe's request target (a path and an
// optional query, starting with "/"), would reach the server as something
// other than what was written, or returns "". The words follow "the path".
//
// Go's client sends the query exactly as written, and it sends a path with no
// percent-escapes in it in the standard percent-encoding (a space as %20, an
// accented letter as its UTF-8 octets), which is what the author meant. What it
// cannot do is honor both: a path that has percent-escapes and also a
// character that needs encoding is re-encoded as a whole, and an escape such as
// %2F is decoded on the way (a%2Fb c is sent as a/b%20c). Other targets are
// altered or lost outright: a #fragment is never sent, a space in the query
// ends the request line early, and a % that starts no escape is no request.
func Problem(target string) string {
	if !strings.HasPrefix(target, "/") {
		return `must start with "/"`
	}
	if strings.Contains(target, "#") {
		return "must not contain '#': a fragment is never sent to the server"
	}
	for i := 0; i < len(target); i++ {
		if target[i] < ' ' || target[i] == 0x7f {
			return "must not contain a control character"
		}
	}
	path, query, hasQuery := strings.Cut(target, "?")
	if hasQuery && strings.Contains(query, " ") {
		return "has a space in its query, which would end the request target early: write it as %20 or +"
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Sprintf("is not a valid request target: %v", err)
	}
	if strings.Contains(path, "%") {
		if sent := parsed.EscapedPath(); sent != path {
			return fmt.Sprintf("has percent-escapes and other characters that must be encoded, so it would be sent as %q; write it fully percent-encoded, exactly as the server should receive it", sent)
		}
	}
	return ""
}

// Sent returns the request target Go's client puts on the request line for
// target, which Problem has accepted: the target as the server receives it.
func Sent(target string) string {
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return target
	}
	return parsed.RequestURI()
}
