// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PVERootCAPath is where a Proxmox VE node keeps its cluster CA certificate.
const PVERootCAPath = "/etc/pve/pve-root-ca.pem"

// maxCABytes bounds the CA file read from the node and the file it replaces.
// It is the limit the controller and the worker apply to
// CERTISTACK_PVE_CA_SOURCE (pve.MaxCAFileBytes).
const maxCABytes = 1 << 20

// CACertificate describes one CA certificate in a bundle, for the operator to
// see what is being trusted.
type CACertificate struct {
	Subject string
	// SHA256 is the certificate's SHA-256 fingerprint in the colon-separated
	// upper-case hexadecimal form the PVE web interface shows.
	SHA256   string
	NotAfter time.Time
}

// CABundle is a validated PVE CA file: the certificates to trust, re-encoded as
// PEM and nothing else.
type CABundle struct {
	PEM          []byte
	Certificates []CACertificate
	// IgnoredLeaves counts certificates in the input that are not CA
	// certificates and were left out.
	IgnoredLeaves int
}

// ParseCABundle checks that data is PEM with at least one CA certificate that
// has not expired, and returns the CA certificates only. A private key in the
// input is refused rather than copied: the file is written world-readable.
func ParseCABundle(data []byte, now time.Time) (CABundle, error) {
	var bundle CABundle
	rest := data
	blocks := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			return CABundle{}, errors.New("the file contains a private key. Nothing was written: a CA file is public and is written world-readable")
		case block.Type != "CERTIFICATE":
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CABundle{}, fmt.Errorf("the file holds a certificate that cannot be parsed: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			bundle.IgnoredLeaves++
			continue
		}
		if now.After(cert.NotAfter) {
			return CABundle{}, fmt.Errorf("the CA certificate %q expired on %s, so no certificate it signed can be verified; renew the node's certificates first (on the node: pvecm updatecerts --force)", cert.Subject.String(), cert.NotAfter.UTC().Format("2006-01-02"))
		}
		sum := sha256.Sum256(cert.Raw)
		bundle.Certificates = append(bundle.Certificates, CACertificate{
			Subject:  cert.Subject.String(),
			SHA256:   colonHex(sum[:]),
			NotAfter: cert.NotAfter.UTC(),
		})
		bundle.PEM = append(bundle.PEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	if len(bundle.Certificates) == 0 {
		if blocks == 0 {
			return CABundle{}, errors.New("the file is not PEM: it holds no -----BEGIN CERTIFICATE----- block")
		}
		return CABundle{}, errors.New("the file holds no CA certificate (a certificate whose basic constraints say CA:TRUE)")
	}
	return bundle, nil
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// WriteCAFile writes data to path (mode 0644) through a temporary file in the
// same directory and a rename, so a reader never sees half a file. It replaces
// an existing file only when that is a regular file that is empty or already a
// PEM certificate file: a path that names something else (an environment file,
// a key, a link) is refused rather than overwritten. It reports whether the
// file's content changed.
func WriteCAFile(path string, data []byte) (changed bool, err error) {
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false, fmt.Errorf("the directory %s does not exist: create it, or pass --out with a path in a directory that does", dir)
	}
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() {
			return false, fmt.Errorf("%s exists and is not a regular file, so it was not replaced", path)
		}
		previous, err := readBounded(path)
		if err != nil {
			return false, fmt.Errorf("read the existing %s: %w", path, err)
		}
		if bytes.Equal(previous, data) {
			return false, nil
		}
		if len(bytes.TrimSpace(previous)) > 0 {
			if block, _ := pem.Decode(previous); block == nil || block.Type != "CERTIFICATE" {
				return false, fmt.Errorf("%s exists and is not a PEM certificate file, so it was not replaced: pass --out with another path", path)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("check %s: %w", path, err)
	}

	temp, err := os.CreateTemp(dir, ".pve-root-ca-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create a temporary file in %s: %w", dir, err)
	}
	tempName := temp.Name()
	done := false
	defer func() {
		if !done {
			_ = temp.Close()
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o644); err != nil {
		return false, fmt.Errorf("set the mode of %s: %w", tempName, err)
	}
	if _, err := temp.Write(data); err != nil {
		return false, fmt.Errorf("write %s: %w", tempName, err)
	}
	if err := temp.Sync(); err != nil {
		return false, fmt.Errorf("write %s: %w", tempName, err)
	}
	if err := temp.Close(); err != nil {
		return false, fmt.Errorf("write %s: %w", tempName, err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return false, fmt.Errorf("move the CA into place at %s: %w", path, err)
	}
	done = true
	return true, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCABytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCABytes {
		return nil, fmt.Errorf("larger than %d bytes", maxCABytes)
	}
	return data, nil
}
