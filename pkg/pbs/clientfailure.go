// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import "strings"

// clientFailureCauses name why proxmox-backup-client failed, in CertiStack's
// own words, for the failures a first-time user meets: a wrong secret, a
// certificate nobody pinned, a typo in the repository. A failure is matched on
// fixed phrases of the client's output (compared in lower case; every phrase
// of an entry must occur) and reported with the entry's fixed sentence. The
// output itself is never quoted: it can carry the repository, the user, a
// token name or a host, and the sentences hold none of them. The first entry
// that matches wins, so the more specific causes come first: a certificate
// failure also reads "error trying to connect".
//
// Output that matches nothing here is not guessed at; commandFailure reports
// only its size.
var clientFailureCauses = []struct {
	all    []string
	reason string
}{
	// The TLS handshake comes before the login. A pinned fingerprint that is
	// not the server's is told apart from none being set: the client warns
	// "certificate fingerprint does not match expected fingerprint!" before
	// the failure that an unpinned certificate also ends in.
	{[]string{"does not match expected fingerprint"}, reasonFingerprint},
	{[]string{"certificate verify failed"}, reasonCertificate},
	{[]string{"certificate validation failed"}, reasonCertificate},
	{[]string{"self-signed certificate"}, reasonCertificate},
	{[]string{"self signed certificate"}, reasonCertificate},
	{[]string{"unable to get local issuer certificate"}, reasonCertificate},
	{[]string{"certificate fingerprint"}, reasonCertificate},
	{[]string{"expected fingerprint"}, reasonCertificate},
	{[]string{"continue connecting"}, reasonCertificate},

	{[]string{"authentication failed"}, reasonLogin},
	{[]string{"authentication failure"}, reasonLogin},
	{[]string{"401 unauthorized"}, reasonLogin},
	{[]string{"invalid credentials"}, reasonLogin},

	{[]string{"permission check failed"}, reasonPermission},
	{[]string{"403 forbidden"}, reasonPermission},

	{[]string{"no such datastore"}, reasonDatastore},
	{[]string{"unable to open datastore"}, reasonDatastore},
	{[]string{"datastore '", "does not exist"}, reasonDatastore},

	{[]string{"no such namespace"}, reasonNamespace},
	{[]string{"namespace '", "does not exist"}, reasonNamespace},

	{[]string{"connection refused"}, reasonConnect},
	{[]string{"no route to host"}, reasonConnect},
	{[]string{"network is unreachable"}, reasonConnect},
	{[]string{"timed out"}, reasonConnect},
	{[]string{"failed to lookup address"}, reasonConnect},
	{[]string{"name or service not known"}, reasonConnect},
	{[]string{"temporary failure in name resolution"}, reasonConnect},
	{[]string{"tcp connect error"}, reasonConnect},
	{[]string{"dns error"}, reasonConnect},
	{[]string{"error trying to connect"}, reasonConnect},
	{[]string{"error connecting to"}, reasonConnect},
	{[]string{"client error (connect)"}, reasonConnect},
}

const (
	reasonCertificate = "PBS's TLS certificate was not confirmed: PBS_FINGERPRINT is not set and no CA the node trusts signed the certificate. Set PBS_FINGERPRINT to the server's SHA-256 fingerprint (PBS dashboard, Show Fingerprint)"
	reasonFingerprint = "PBS_FINGERPRINT does not match the certificate the server presents: use the fingerprint of the server's current certificate (PBS dashboard, Show Fingerprint; a renewed certificate has a new one), and check that PBS_REPOSITORY names the right server"
	reasonLogin       = "PBS refused the login: check PBS_PASSWORD (the API token's secret or the user's password) and the user or token name at the start of PBS_REPOSITORY; the token or user may also have been deleted or have expired"
	reasonPermission  = "PBS denied access: the user or API token in PBS_REPOSITORY needs the DatastoreReader role (Datastore.Audit and Datastore.Read) on the datastore, and on the namespace path when a namespace is used; an API token needs the permission itself, not only its user. PBS gives the same answer for a datastore or namespace the token cannot see, so also check their names in PBS_REPOSITORY and PBS_NAMESPACE"
	reasonDatastore   = "PBS has no such datastore: check the name after the last colon of PBS_REPOSITORY (user@realm!token@host:DATASTORE)"
	reasonNamespace   = "PBS found no such namespace or datastore path: the namespace in PBS_NAMESPACE (or storage.pbs_namespace in the plan, or init --namespace) does not exist in the datastore, or the datastore name in PBS_REPOSITORY is wrong"
	reasonConnect     = "the connection to the PBS server failed: check the host name and port in PBS_REPOSITORY (PBS listens on 8007 unless told otherwise) and that the node can reach the server (DNS, firewall, routing)"
)

// maxClassifiedOutput is how much of a client's output is searched for the
// phrases above: an error is at the start, and a listing that grew large is
// not one.
const maxClassifiedOutput = 64 << 10

// classifyClientFailure returns the fixed sentence for the cause of a client
// failure, or false when the output matches no known cause.
func classifyClientFailure(output []byte) (string, bool) {
	if len(output) > maxClassifiedOutput {
		output = output[:maxClassifiedOutput]
	}
	text := strings.ToLower(string(output))
next:
	for _, cause := range clientFailureCauses {
		for _, phrase := range cause.all {
			if !strings.Contains(text, phrase) {
				continue next
			}
		}
		return cause.reason, true
	}
	return "", false
}

// namedFailure is a failure reported in CertiStack's words. It keeps the
// error that ended the command (an exit status, or the cancelled context)
// reachable to errors.Is and errors.As without printing it.
type namedFailure struct {
	message string
	cause   error
}

func (e *namedFailure) Error() string { return e.message }
func (e *namedFailure) Unwrap() error { return e.cause }

// bareENOENT is the whole of what a listing prints for a namespace that does
// not exist: an errno with no word about the namespace.
const bareENOENT = "Error: ENOENT: No such file or directory"

// listFailure is commandFailure for a snapshot or group listing. Only there is
// a bare ENOENT the answer for a namespace (or datastore path) that does not
// exist; from a restore or a map the same words mean something else and stay
// withheld.
func listFailure(operation string, err error, output []byte) error {
	if strings.TrimSpace(string(output)) == bareENOENT {
		return &namedFailure{message: operation + ": " + reasonNamespace, cause: err}
	}
	return commandFailure(operation, err, output)
}
