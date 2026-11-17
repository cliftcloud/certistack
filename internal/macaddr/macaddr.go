// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package macaddr decides which MAC addresses CertiStack accepts for a
// sandbox VM's NICs, and keeps track of who holds each. Every place that
// reads one, the plan loaders, the PBS profile and layout parsers, backup
// resolution and the PVE create request, asks this package, so a value one
// layer accepts is a value the next one sends and the other way round.
//
// An address is acceptable when it is six octets that can name one network
// interface. net.ParseMAC alone also accepts the all-zero address, the
// Ethernet broadcast address and every group (multicast) address, which no
// interface can hold: Linux refuses to assign them ("Cannot assign requested
// address"), so a guest or a hypervisor that is given one fails late, after
// the restore. It also accepts other octet counts and three spellings (colon,
// hyphen and dotted), which the registry must treat as one address.
package macaddr

import (
	"errors"
	"net"
	"strings"
)

// Describe is the rule in words, for validation errors and documents.
const Describe = "six octets naming one interface: not all zeros, not the all-ones broadcast address, and not a multicast address (the lowest bit of the first octet must be 0)"

// Parse returns the six octets of s. It refuses what no interface can hold:
// a value that is not exactly six octets, the all-zero address, the
// broadcast address and any group address (the lowest bit of the first octet
// set, which covers IPv4 and IPv6 multicast and broadcast).
func Parse(s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		return nil, errors.New("not a six-octet MAC address")
	}
	allZero, allOnes := true, true
	for _, octet := range mac {
		allZero = allZero && octet == 0x00
		allOnes = allOnes && octet == 0xff
	}
	switch {
	case allZero:
		return nil, errors.New("the all-zero address cannot name an interface")
	case allOnes:
		return nil, errors.New("the broadcast address cannot name an interface")
	case mac[0]&1 != 0:
		return nil, errors.New("a multicast (group) address cannot name an interface: the lowest bit of the first octet must be 0")
	}
	return mac, nil
}

// Valid reports whether s is an acceptable interface address (see Parse).
func Valid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// Canonical is s as PVE writes an address: six upper-case hex pairs
// separated by colons, whichever spelling s used.
func Canonical(s string) (string, error) {
	mac, err := Parse(s)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(mac.String()), nil
}

// Equal reports whether a and b are the same acceptable address, whatever
// their spelling or case. A value that is not acceptable equals nothing.
func Equal(a, b string) bool {
	left, errLeft := Canonical(a)
	right, errRight := Canonical(b)
	return errLeft == nil && errRight == nil && left == right
}

// Registry records which NIC holds each address of a set that must not share
// one: the NICs of one plan sit on one isolated VNet, and two of them with the
// same address make the bridge send frames for both guests to whichever port
// spoke last. Its zero value is ready to use.
type Registry struct {
	holder map[string]string
}

// Claim records that owner holds mac. If another owner already holds the same
// address, in any spelling, it returns that owner and false and records
// nothing. An address that is not acceptable (see Parse) is the caller's to
// refuse; Claim treats it as free.
func (r *Registry) Claim(mac, owner string) (previous string, ok bool) {
	canonical, err := Canonical(mac)
	if err != nil {
		return "", true
	}
	if r.holder == nil {
		r.holder = make(map[string]string)
	}
	if prior, held := r.holder[canonical]; held {
		return prior, false
	}
	r.holder[canonical] = owner
	return "", true
}
