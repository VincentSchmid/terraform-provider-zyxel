package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL                         = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv4RangesUserAgent      = "terraform-provider-zyxel"
	Timeout                            = 20 * time.Second
	cloudflareIPv4RangesMaxBodyBytes   = 4 << 20
	cloudflareIPv4RangesMinRangeCount  = 2
	cloudflareIPv4RangesMaxQuotedEntry = 80
)

// FetchIPv4Ranges performs one bounded GET without authentication or
// cookies and returns the parsed ranges plus the final URL after redirects.
func FetchIPv4Ranges(ctx context.Context, client *http.Client, rawURL string) ([]string, string, error) {
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("building request: %w", err)
	}
	request.Header.Set("User-Agent", cloudflareIPv4RangesUserAgent)
	request.Header.Set("Accept", "text/plain")

	response, err := client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()

	source := rawURL
	if response.Request != nil && response.Request.URL != nil {
		source = response.Request.URL.String()
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, source, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, cloudflareIPv4RangesMaxBodyBytes+1))
	if err != nil {
		return nil, source, fmt.Errorf("reading response body: %w", err)
	}
	if len(body) > cloudflareIPv4RangesMaxBodyBytes {
		return nil, source, fmt.Errorf("response body exceeds the %d byte limit", cloudflareIPv4RangesMaxBodyBytes)
	}

	ranges, err := ParseIPv4Ranges(body)
	if err != nil {
		return nil, source, err
	}
	return ranges, source, nil
}

// ParseIPv4Ranges parses a newline-separated list of canonical IPv4
// CIDRs. It preserves source order and rejects anything unexpected instead of
// silently dropping it.
func ParseIPv4Ranges(body []byte) ([]string, error) {
	lines := strings.Split(string(body), "\n")
	ranges := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for index, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		if err := validateCloudflareIPv4Range(entry); err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", index+1, quoteCloudflareIPv4Range(entry), err)
		}
		if _, duplicate := seen[entry]; duplicate {
			return nil, fmt.Errorf("line %d: duplicate range %s", index+1, strconv.Quote(entry))
		}
		seen[entry] = struct{}{}
		ranges = append(ranges, entry)
	}
	if len(ranges) < cloudflareIPv4RangesMinRangeCount {
		return nil, fmt.Errorf("expected at least %d IPv4 ranges, found %d", cloudflareIPv4RangesMinRangeCount, len(ranges))
	}
	return ranges, nil
}

func validateCloudflareIPv4Range(entry string) error {
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return errors.New("not a canonical IPv4 CIDR with a prefix length")
	}
	if !prefix.Addr().Is4() {
		return errors.New("not an IPv4 CIDR")
	}
	if prefix.Masked() != prefix {
		return errors.New("host bits are set; use the network address")
	}
	return nil
}

// quoteCloudflareIPv4Range bounds the entry shown in diagnostics so an HTML
// error page or other unexpected body cannot flood the output.
func quoteCloudflareIPv4Range(entry string) string {
	if len(entry) > cloudflareIPv4RangesMaxQuotedEntry {
		entry = entry[:cloudflareIPv4RangesMaxQuotedEntry] + "..."
	}
	return strconv.Quote(entry)
}

func ValidateURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("url must not be empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("url is not valid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("url must use the http or https scheme")
	}
	if parsed.Host == "" {
		return "", errors.New("url must be absolute and include a host")
	}
	if parsed.User != nil {
		return "", errors.New("url must not include credentials")
	}
	return rawURL, nil
}
