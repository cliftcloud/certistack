// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

// The PBS HTTP API serves what proxmox-backup-client cannot: the backup
// task's log (client.log.blob), which vzdump uploads after the snapshot is
// complete, outside its manifest (the client's restore checks every blob
// against the manifest and so refuses the log), and the list of backup groups
// of a namespace (`group list` takes no --ns). The API is used with the same
// repository, credentials, namespace and certificate trust as the client.

const (
	clientLogBlob     = "client.log.blob"
	maxClientLogBytes = 1 << 20
	apiTimeout        = 20 * time.Second
	// apiGroupsTimeout is longer: PBS reads the owner and newest snapshot of
	// every group it lists.
	apiGroupsTimeout = 60 * time.Second
)

var (
	datastoreName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	pbsAuthID     = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+(![A-Za-z0-9._-]+)?$`)
	pbsHostName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// apiEndpoint is a PBS repository, [[auth-id@]server[:port]:]datastore, with
// proxmox-backup-client's defaults (root@pam, localhost, 8007).
type apiEndpoint struct {
	authID    string
	host      string
	port      string
	datastore string
}

func parseRepository(repository string) (apiEndpoint, error) {
	endpoint := apiEndpoint{authID: "root@pam", host: "localhost", port: "8007"}
	rest := strings.TrimSpace(repository)
	if colon := strings.LastIndex(rest, ":"); colon < 0 {
		endpoint.datastore, rest = rest, ""
	} else {
		endpoint.datastore, rest = rest[colon+1:], rest[:colon]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			endpoint.authID, rest = rest[:at], rest[at+1:]
		}
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]")
			if end < 0 {
				return apiEndpoint{}, errors.New("unterminated IPv6 address")
			}
			endpoint.host = rest[1:end]
			if port := rest[end+1:]; port != "" {
				if !strings.HasPrefix(port, ":") {
					return apiEndpoint{}, errors.New("invalid server")
				}
				endpoint.port = port[1:]
			}
			if net.ParseIP(endpoint.host) == nil {
				return apiEndpoint{}, errors.New("invalid IPv6 address")
			}
		} else if host, port, ok := strings.Cut(rest, ":"); ok {
			endpoint.host, endpoint.port = host, port
		} else {
			endpoint.host = rest
		}
	}
	if !datastoreName.MatchString(endpoint.datastore) {
		return apiEndpoint{}, errors.New("invalid datastore name")
	}
	if !pbsAuthID.MatchString(endpoint.authID) {
		return apiEndpoint{}, errors.New("invalid user or API token")
	}
	if net.ParseIP(endpoint.host) == nil && !pbsHostName.MatchString(endpoint.host) {
		return apiEndpoint{}, errors.New("invalid server")
	}
	if port, err := strconv.Atoi(endpoint.port); err != nil || port < 1 || port > 65535 {
		return apiEndpoint{}, errors.New("invalid port")
	}
	return endpoint, nil
}

// apiHTTPClient trusts the PBS certificate as proxmox-backup-client does: a
// certificate the system trusts for the server name, or else one whose
// SHA-256 fingerprint is the configured one. It never follows redirects and
// never uses a proxy (the client runs with a minimal environment).
func apiHTTPClient(endpoint apiEndpoint, fingerprint string) *http.Client {
	// "SHA256:aa:bb:..." is accepted too; hex never starts with "sha256".
	fingerprint = strings.TrimPrefix(normalizeFingerprint(fingerprint), "sha256")
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is done in VerifyConnection, with the fingerprint
		// fallback the standard verifier cannot express.
		InsecureSkipVerify: true, // #nosec G402 -- verified in VerifyConnection
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPBSCertificate(state, endpoint.host, fingerprint)
		},
	}
	if net.ParseIP(endpoint.host) == nil {
		tlsConfig.ServerName = endpoint.host
	}
	return &http.Client{
		Timeout:   apiTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func verifyPBSCertificate(state tls.ConnectionState, host, fingerprint string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("PBS presented no certificate")
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates}); err == nil {
		return nil
	}
	if fingerprint == "" {
		return errors.New("the PBS certificate is not trusted and no fingerprint is configured")
	}
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return errors.New("the PBS certificate does not match the configured fingerprint")
	}
	return nil
}

// readClientLog downloads the snapshot's backup log, decoded, through the
// PBS API: at most maxClientLogBytes of it, which covers the part vzdump
// writes before the data transfer. A longer log comes back with
// errLogTruncated.
func (c *Client) readClientLog(ctx context.Context, snapshot string) ([]byte, error) {
	return c.fetchClientLog(ctx, snapshot, "download-decoded", readLogPrefix)
}

// errLogUndecryptable marks an encrypted backup log that was fetched but
// could not be decrypted with the configured key.
var errLogUndecryptable = errors.New("the backup log is encrypted and could not be decrypted")

// readEncryptedClientLog downloads the snapshot's backup log as the raw PBS
// blob, decrypts it with the key in CERTISTACK_PBS_KEYFILE (the API decodes
// only a log that is not encrypted) and cuts it like readClientLog does. A
// log that does not authenticate under the key is an error, never partial
// text, and one that is not in an encrypted form, or is not this snapshot's,
// is refused.
func (c *Client) readEncryptedClientLog(ctx context.Context, snapshot string) ([]byte, error) {
	key, err := c.blobKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errLogUndecryptable, err)
	}
	raw, err := c.fetchClientLog(ctx, snapshot, "download", readRawBlob)
	if err != nil {
		return nil, err
	}
	// An encrypted backup's log is accepted only in an encrypted form: a
	// plaintext blob there needs no key to write, and is what a forged log
	// would be.
	if !isEncryptedBlob(raw) {
		return nil, fmt.Errorf("%w: the log is not encrypted, although the backup is; it was written or replaced by something that does not hold the backup's key", errLogRefused)
	}
	content, err := decodeBlob(raw, key, maxClientLogBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errLogUndecryptable, err)
	}
	if err := bindLogToSnapshot(content, snapshot); err != nil {
		return nil, err
	}
	return readLogPrefix(bytes.NewReader(content))
}

// readRawBlob reads a raw blob, refusing one longer than maxRawLogBytes.
func readRawBlob(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRawLogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRawLogBytes {
		return nil, errors.New("the backup log is larger than CertiStack reads")
	}
	return data, nil
}

// fetchClientLog requests the snapshot's log file from the given API route
// (download-decoded, or download for the raw blob) and passes the body to read.
func (c *Client) fetchClientLog(ctx context.Context, snapshot, route string, read func(io.Reader) ([]byte, error)) ([]byte, error) {
	endpoint, err := parseRepository(c.cfg.Repository)
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	if c.cfg.Password == "" {
		return nil, errors.New("no PBS password or API token secret is configured")
	}
	parts := strings.Split(snapshot, "/")
	if !validSnapshotPath(snapshot) {
		return nil, errors.New("invalid snapshot")
	}
	backupTime, _ := time.Parse(time.RFC3339, parts[2])
	query := url.Values{
		"backup-type": {parts[0]},
		"backup-id":   {parts[1]},
		"backup-time": {strconv.FormatInt(backupTime.Unix(), 10)},
		"file-name":   {clientLogBlob},
	}
	if c.cfg.Namespace != "" {
		query.Set("ns", c.cfg.Namespace)
	}
	return c.apiGet(ctx, endpoint, route, query, apiTimeout, read)
}

// apiGet requests route of the endpoint's datastore with query, as the
// repository's user or API token, and passes the body of an HTTP 200 answer to
// read. The request ends after timeout.
func (c *Client) apiGet(ctx context.Context, endpoint apiEndpoint, route string, query url.Values, timeout time.Duration, read func(io.Reader) ([]byte, error)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := apiHTTPClient(endpoint, c.cfg.Fingerprint)
	client.Timeout = timeout
	defer client.CloseIdleConnections()
	base := url.URL{Scheme: "https", Host: net.JoinHostPort(endpoint.host, endpoint.port)}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api2/json/admin/datastore/"+url.PathEscape(endpoint.datastore)+"/"+route+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if strings.Contains(endpoint.authID, "!") {
		request.Header.Set("Authorization", "PBSAPIToken="+endpoint.authID+":"+c.cfg.Password)
	} else {
		ticket, err := apiTicket(ctx, client, base, endpoint.authID, c.cfg.Password)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Cookie", "PBSAuthCookie="+url.QueryEscape(ticket))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, apiTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, apiStatusError(response)
	}
	return read(response.Body)
}

// backupGroupsRoute is the PBS API route that lists the backup groups of one
// namespace of a datastore (`ns` selects the namespace; without it, the
// root).
const backupGroupsRoute = "groups"

// listBackupGroupsAPI lists the backup groups of the configured namespace
// through the PBS API, as the repository's user or token. It exists because
// `proxmox-backup-client group list` takes no --ns in any client version, and
// the 3.x client ignores PBS_NAMESPACE: the command can only read the root
// namespace. The answer is bounded by pbsListOutputLimit like a client
// listing.
func (c *Client) listBackupGroupsAPI(ctx context.Context) ([]backupGroup, error) {
	endpoint, err := parseRepository(c.cfg.Repository)
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	if c.cfg.Password == "" {
		return nil, errors.New("no PBS password or API token secret is configured")
	}
	query := url.Values{}
	if c.cfg.Namespace != "" {
		query.Set("ns", c.cfg.Namespace)
	}
	body, err := c.apiGet(ctx, endpoint, backupGroupsRoute, query, apiGroupsTimeout, func(r io.Reader) ([]byte, error) {
		data, err := io.ReadAll(io.LimitReader(r, pbsListOutputLimit+1))
		if err != nil {
			return nil, err
		}
		if len(data) > pbsListOutputLimit {
			return nil, fmt.Errorf("the PBS API wrote more than the %d bytes CertiStack accepts: %w", pbsListOutputLimit, process.ErrOutputLimit)
		}
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	var answer struct {
		Data []backupGroup `json:"data"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.Data == nil {
		return nil, errors.New("the PBS API answered with no list of backup groups")
	}
	return answer.Data, nil
}

// errLogTruncated marks a log of which only the first maxClientLogBytes
// were read. The part read ends at its last complete line.
var errLogTruncated = errors.New("the backup log is longer than 1 MiB; only its first 1 MiB was read")

// readLogPrefix reads at most maxClientLogBytes of a log. A longer log is
// cut at its last complete line within the limit and returned with
// errLogTruncated, never silently: ParseBackupLog then needs its complete
// sequence within that part.
func readLogPrefix(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxClientLogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) <= maxClientLogBytes {
		return data, nil
	}
	data = data[:maxClientLogBytes]
	if end := bytes.LastIndexByte(data, '\n'); end >= 0 {
		data = data[:end+1]
	} else {
		data = nil
	}
	return data, errLogTruncated
}

// apiTicket logs a PBS user (not an API token) in for one request.
func apiTicket(ctx context.Context, client *http.Client, base url.URL, authID, password string) (string, error) {
	form := url.Values{"username": {authID}, "password": {password}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/api2/json/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", apiTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", apiStatusError(response)
	}
	var body struct {
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil || body.Data.Ticket == "" {
		return "", errors.New("PBS login returned no ticket")
	}
	if strings.Contains(body.Data.Ticket, "!tfa!") {
		return "", errors.New("the PBS user needs a second factor; use an API token")
	}
	return body.Data.Ticket, nil
}

// apiTransportError keeps the cause but not the server's name or address,
// which the URL, a dial error and a DNS error all carry: the reason ends up
// in the report.
func apiTransportError(err error) error {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.As(err, &dnsErr):
		return errors.New("PBS API unreachable: the server name does not resolve")
	case errors.As(err, &opErr) && opErr.Err != nil:
		return fmt.Errorf("PBS API unreachable: %s", opErr.Err.Error())
	case errors.As(err, &netErr) && netErr.Timeout():
		return errors.New("PBS API unreachable: timed out")
	case errors.As(err, &urlErr):
		return fmt.Errorf("PBS API unreachable: %w", urlErr.Err)
	}
	return fmt.Errorf("PBS API unreachable: %w", err)
}

func apiStatusError(response *http.Response) error {
	var body struct {
		Message string `json:"message"`
	}
	// Only PBS's own JSON message is kept: another body, such as a proxy's
	// error page, can name hosts, and the reason ends up in the report.
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if json.Unmarshal(data, &body) != nil {
		body.Message = ""
	}
	return &apiError{status: response.StatusCode, message: boundedLogText(body.Message)}
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("PBS API answered HTTP %d", e.status)
	}
	return fmt.Sprintf("PBS API answered HTTP %d: %s", e.status, e.message)
}

// backupConsistency reads how consistent the snapshot's disks were from its
// backup log. It never fails: anything that prevents an answer is reported
// as unknown with the reason, and the run goes on.
func (c *Client) backupConsistency(ctx context.Context, snapshot, cryptMode string) BackupConsistency {
	if strings.TrimSpace(c.cfg.Repository) == "" {
		return unknownConsistency("no PBS repository is configured")
	}
	read := c.readClientLog
	if cryptMode == CryptModeEncrypt {
		// The log of an encrypted backup is encrypted with its key; it is
		// read raw and decrypted here.
		read = c.readEncryptedClientLog
	}
	if c.clientLogReader != nil {
		read = c.clientLogReader
	}
	log, err := read(ctx, snapshot)
	var status *apiError
	switch {
	case errors.Is(err, errLogTruncated):
		consistency := ParseBackupLog(string(log))
		if consistency.State == ConsistencyUnknown {
			consistency.Detail += " (" + err.Error() + ")"
		}
		return consistency
	case errors.As(err, &status) && (status.status == http.StatusNotFound || strings.Contains(strings.ToLower(status.message), "no such file")):
		return unknownConsistency("the snapshot has no backup log")
	case errors.Is(err, errLogUndecryptable), errors.Is(err, errLogRefused):
		return unknownConsistency(boundedLogText(err.Error()))
	case errors.As(err, &status) && strings.Contains(strings.ToLower(status.message), "encrypt"):
		return unknownConsistency("the backup log is encrypted with the backup's key")
	case err != nil:
		return unknownConsistency("the backup log could not be read: " + boundedLogText(err.Error()))
	}
	return ParseBackupLog(string(log))
}
