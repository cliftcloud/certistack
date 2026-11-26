// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// certificateProblem reports an error that is the TLS stack refusing the
// certificate PVE presented (a CA the host does not trust, an expired
// certificate, a name the certificate was not issued for), and says so in a
// fixed sentence with the remedy. The sentence quotes nothing of the error: the
// x509 text names the endpoint and the certificate's host names, which the
// client keeps out of its messages.
//
// Such a failure is permanent. The same certificate is refused again on every
// attempt, so Do does not retry it: a stock node's API certificate is signed by
// the cluster's own CA, and without CERTISTACK_PVE_CA_SOURCE every attempt
// would end in the same refusal.
func certificateProblem(err error) (string, bool) {
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var verification *tls.CertificateVerificationError
	switch {
	case errors.As(err, &unknown):
		return "PVE's TLS certificate is signed by a CA this host does not trust (x509: certificate signed by unknown authority). " +
			"A stock Proxmox VE node uses its own cluster CA: copy /etc/pve/pve-root-ca.pem from the node and set CERTISTACK_PVE_CA_SOURCE to that file, or let CertiStack fetch it: certistack setup pve-ca --env-file <your env file>. It was not retried", true
	case errors.As(err, &hostname):
		return "PVE's TLS certificate was not issued for the host name in PVE_URL (x509: certificate is valid for other host names). " +
			"Use a host name or IP address the certificate lists (a stock node's certificate names the node and its addresses), or issue one that covers the name. It was not retried", true
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "PVE's TLS certificate has expired or is not yet valid (x509: certificate has expired or is not yet valid). " +
			"Renew it on the node (pvecm updatecerts --force), check that the CA file in CERTISTACK_PVE_CA_SOURCE is current, and check this host's clock. It was not retried", true
	case errors.As(err, &invalid), errors.As(err, &verification):
		return "PVE's TLS certificate failed verification. " +
			"Check the node's certificate and that CERTISTACK_PVE_CA_SOURCE names the CA that signed it. It was not retried", true
	}
	return "", false
}
