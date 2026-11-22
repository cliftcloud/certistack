// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// MissingFix is what gives a node the SDN API it lacks. PVE 8.0 has SDN only
// when libpve-network-perl is installed (with ifupdown2, which applies the
// network); PVE 8.1 and later install both.
const MissingFix = "install libpve-network-perl and ifupdown2 on the node, or update the node to PVE 8.1 or later"

// MissingError is PVE's answer that its SDN API does not exist: HTTP 501
// ("Method 'GET /cluster/sdn/zones' not implemented") to the read of an SDN
// list, or pvesh's "No 'get' handler defined" (MissingFromPvesh). A run builds
// its sandbox network with SDN, so such a node cannot run. The error wraps
// PVE's HTTP answer.
type MissingError struct {
	// Call is the request PVE refused, "GET /cluster/sdn/zones", or the
	// command, PveshZonesCall.
	Call string
	// pvesh is pvesh's answer to Call; "" for the API's HTTP 501.
	pvesh string
	cause error
}

// Problem says what is missing, without the fix.
func (e *MissingError) Problem() string {
	answer := "PVE answers " + e.Call + " with HTTP 501 Not Implemented"
	if e.pvesh != "" {
		answer = e.Call + " on the node: " + e.pvesh
	}
	return "this node has no SDN API (" + answer + "): the package libpve-network-perl is not installed"
}

func (e *MissingError) Error() string {
	return e.Problem() + ". A run builds its sandbox network with PVE's SDN: " + MissingFix
}

func (e *MissingError) Unwrap() error { return e.cause }

// missingAPI is err as a MissingError when it is PVE's HTTP 501 to the read of
// path, and err unchanged otherwise.
func missingAPI(err error, path string) error {
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotImplemented {
		return err
	}
	path, _, _ = strings.Cut(path, "?")
	return &MissingError{Call: "GET /" + strings.TrimLeft(path, "/"), cause: err}
}

// PveshZonesCall reads the SDN zones as root on the node, through pvesh rather
// than the HTTP API: the read init and a run make first, made without a token.
// It changes nothing.
const PveshZonesCall = "pvesh get /cluster/sdn/zones"

// MissingFromPvesh is the MissingError of what PveshZonesCall printed when it
// failed, if that says PVE has no such call (pvesh's "No 'get' handler defined
// for '/cluster/sdn/zones'", which the API answers with HTTP 501), and nil
// otherwise: a read that failed for another reason, such as a cluster file
// system that does not answer, says nothing of SDN.
func MissingFromPvesh(output string) *MissingError {
	if !strings.Contains(strings.ToLower(output), "no 'get' handler") {
		return nil
	}
	return &MissingError{Call: PveshZonesCall, pvesh: "No 'get' handler defined"}
}
