package zyxel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// DNSEntry contains the supported part of one local DNS host record.
type DNSEntry struct {
	Index       int64
	HostName    string
	IPv4Address string
}

var dnsHostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

// NormalizeHostname validates a local DNS host name and returns its canonical
// lowercase form. Host names need at least two dot-separated labels because the
// router rejects single-label names; ASCII letters, digits, hyphens, and
// underscores are accepted in each label.
func NormalizeHostname(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 256 {
		return "", errors.New("host name must be nonempty, at most 256 characters, and have no surrounding whitespace")
	}
	canonical := strings.ToLower(value)
	labels := strings.Split(canonical, ".")
	if len(labels) < 2 {
		return "", errors.New("host name must contain at least two dot-separated labels")
	}
	for _, label := range labels {
		if len(label) > 63 || !dnsHostnameLabel.MatchString(label) {
			return "", errors.New("host name labels must be 1-63 characters of letters, digits, hyphens, or underscores, starting and ending with a letter or digit")
		}
	}
	return canonical, nil
}

// ReadDNSEntry resolves a host name, ignoring letter case, and rejects duplicate
// identities. A nil entry with no error means the entry is absent.
func (c *Client) ReadDNSEntry(ctx context.Context, hostname string) (*DNSEntry, error) {
	canonical, err := NormalizeHostname(hostname)
	if err != nil {
		return nil, err
	}
	rows, err := c.DNSEntries(ctx)
	if err != nil {
		return nil, err
	}
	return findDNSEntry(rows, canonical)
}

func (c *Client) DNSEntries(ctx context.Context) ([]DNSEntry, error) {
	var entries []DNSEntry
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		entries, err = s.readDNSEntries(ctx)
		return err
	})
	return entries, err
}

// CreateDNSEntry creates a local DNS host record for an IPv4 address. The
// boolean is true if creation succeeded or may have succeeded, including when an
// error prevents confirmation. Reconcile by host name before retrying.
func (c *Client) CreateDNSEntry(ctx context.Context, hostname, ipv4 string) (bool, error) {
	canonical, err := NormalizeHostname(hostname)
	if err != nil {
		return false, err
	}
	if canonical != hostname {
		return false, errors.New("host name must use canonical lowercase form")
	}
	address, err := netip.ParseAddr(ipv4)
	if err != nil || !address.Is4() {
		return false, errors.New("DNS entry must use an IPv4 address")
	}
	created := false
	err = c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDNSEntries(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if sameHostname(row.HostName, hostname) {
				return errors.New("a DNS entry with this host name already exists; import it before managing it")
			}
		}
		result, err := s.writeDAL(ctx, http.MethodPost, "dns", "", map[string]any{
			"HostName": hostname, "IPv4Address": ipv4,
		})
		if err != nil {
			var ambiguous *AmbiguousWriteError
			if errors.As(err, &ambiguous) {
				created = true
			}
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DNS entry create request")
		}
		created = true
		rows, err = s.readDNSEntries(ctx)
		if err != nil {
			return err
		}
		found, err := findDNSEntry(rows, hostname)
		if err != nil {
			return err
		}
		if found == nil || found.IPv4Address != ipv4 || !sameHostname(found.HostName, hostname) {
			return errors.New("DNS entry create could not be confirmed by readback")
		}
		return nil
	})
	return created, err
}

func (c *Client) DeleteDNSEntry(ctx context.Context, hostname string) error {
	canonical, err := NormalizeHostname(hostname)
	if err != nil {
		return err
	}
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDNSEntries(ctx)
		if err != nil {
			return err
		}
		found, err := findDNSEntry(rows, canonical)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		// Indexes can move after another entry is removed, so resolve identity again
		// immediately before issuing DELETE while this client's session is locked.
		rows, err = s.readDNSEntries(ctx)
		if err != nil {
			return err
		}
		found, err = findDNSEntry(rows, canonical)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		if found.Index < 1 {
			return errors.New("router returned an invalid DNS entry index")
		}
		result, err := s.writeDAL(ctx, http.MethodDelete, "dns", fmt.Sprint(found.Index), map[string]any{})
		if err != nil {
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DNS entry delete request")
		}
		rows, err = s.readDNSEntries(ctx)
		if err != nil {
			return err
		}
		remaining, err := findDNSEntry(rows, canonical)
		if err != nil {
			return err
		}
		if remaining != nil {
			return errors.New("DNS entry delete could not be confirmed by readback")
		}
		return nil
	})
}

func (s *routerSession) readDNSEntries(ctx context.Context) ([]DNSEntry, error) {
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=dns&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected the DNS entry read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router DNS response did not contain an entry list")
	}
	rows := make([]DNSEntry, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned a malformed DNS entry")
		}
		entry, err := parseDNSEntry(row)
		if err != nil {
			return nil, err
		}
		rows = append(rows, entry)
	}
	return rows, nil
}

func parseDNSEntry(row map[string]any) (DNSEntry, error) {
	// Firmware can attach unrelated metadata to each row. Ignore it because the
	// supported create payload contains only the host name and address.
	index, indexOK := routerIndexValue(row["Index"])
	hostname, hostnameOK := row["HostName"].(string)
	ipv4, ipv4OK := row["IPv4Address"].(string)
	if !indexOK || !hostnameOK || !ipv4OK {
		return DNSEntry{}, errors.New("router returned a malformed or unsupported DNS entry")
	}
	canonical, err := NormalizeHostname(hostname)
	address, addressErr := netip.ParseAddr(ipv4)
	if err != nil || addressErr != nil || !address.Is4() {
		return DNSEntry{}, errors.New("router returned a malformed or unsupported DNS entry")
	}
	return DNSEntry{Index: index, HostName: canonical, IPv4Address: ipv4}, nil
}

func findDNSEntry(rows []DNSEntry, hostname string) (*DNSEntry, error) {
	var found *DNSEntry
	for i := range rows {
		if sameHostname(rows[i].HostName, hostname) {
			if found != nil {
				return nil, errors.New("router returned multiple DNS entries with this host name")
			}
			found = &rows[i]
		}
	}
	return found, nil
}

func sameHostname(left, right string) bool {
	return strings.EqualFold(left, right)
}
