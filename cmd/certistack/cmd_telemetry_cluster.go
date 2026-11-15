// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// telemetryClusterIdentity is what the usage report counts a cluster by. Every
// node of one Proxmox VE cluster shares the cluster CA that signs its API
// certificate, and a standalone node has its own, so the SHA-256 of the CA
// certificate in the file CERTISTACK_PVE_CA_SOURCE names (the one the
// controller pins) says which cluster a run tested. Without that file, or when
// it holds no certificate, the node name stands in. The identity is hashed again
// with the install's salt before it is kept, and it is never sent.
func telemetryClusterIdentity(nodeName string) string {
	if source := strings.TrimSpace(os.Getenv("CERTISTACK_PVE_CA_SOURCE")); source != "" {
		if id := caCertificateIdentity(source); id != "" {
			return id
		}
	}
	return nodeName
}

// caCertificateIdentity is the fingerprint of the first CA certificate in a PEM
// file (else of its first certificate), or "" when the file cannot be read or
// holds none. Only certificate blocks are read.
func caCertificateIdentity(path string) string {
	data, err := attest.ReadRegularFile(path, "PVE TLS CA file", pve.MaxCAFileBytes)
	if err != nil {
		return ""
	}
	first := ""
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return first
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		id := "pve-ca-sha256:" + hex.EncodeToString(sum[:])
		if cert.IsCA {
			return id
		}
		if first == "" {
			first = id
		}
	}
}
