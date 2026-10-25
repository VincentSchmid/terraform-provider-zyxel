package cloudflare

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const testCloudflareIPv4RangesBody = "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n"

var testCloudflareIPv4Ranges = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"}

func TestParseCloudflareIPv4Ranges(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    []string
		wantErr string
	}{
		{name: "preserves source order", body: testCloudflareIPv4RangesBody, want: testCloudflareIPv4Ranges},
		{name: "trims whitespace and skips blank lines", body: "\n  173.245.48.0/20 \r\n\t\n103.21.244.0/22\r\n103.22.200.0/22\n\n", want: testCloudflareIPv4Ranges},
		{name: "empty body", body: "", wantErr: "expected at least 2 IPv4 ranges"},
		{name: "whitespace-only body", body: " \n\t\r\n", wantErr: "expected at least 2 IPv4 ranges"},
		{name: "HTML error page", body: "<!DOCTYPE html>\n<html><body>Service unavailable</body></html>\n", wantErr: "not a canonical IPv4 CIDR"},
		{name: "single-line HTML body", body: "<html><body>error</body></html>", wantErr: "not a canonical IPv4 CIDR"},
		{name: "IPv6 entry", body: "173.245.48.0/20\n2001:db8::/32\n", wantErr: "not an IPv4 CIDR"},
		{name: "host bits set", body: "173.245.48.1/20\n103.21.244.0/22\n", wantErr: "host bits are set"},
		{name: "missing prefix length", body: "173.245.48.0\n103.21.244.0/22\n", wantErr: "not a canonical IPv4 CIDR"},
		{name: "too few ranges", body: "173.245.48.0/20\n", wantErr: "expected at least 2 IPv4 ranges"},
		{name: "duplicate range", body: "173.245.48.0/20\n103.21.244.0/22\n173.245.48.0/20\n", wantErr: "duplicate range"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ranges, err := ParseIPv4Ranges([]byte(test.body))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(ranges, test.want) {
				t.Fatalf("ranges = %#v, want %#v", ranges, test.want)
			}
		})
	}
}

func TestParseCloudflareIPv4RangesBoundsDiagnosticEntry(t *testing.T) {
	body := "<html>" + strings.Repeat("x", cloudflareIPv4RangesMaxQuotedEntry*2) + "</html>\n173.245.48.0/20\n"
	_, err := ParseIPv4Ranges([]byte(body))
	if err == nil {
		t.Fatal("expected oversized HTML entry to be rejected")
	}
	if len(err.Error()) > cloudflareIPv4RangesMaxQuotedEntry+100 {
		t.Fatalf("diagnostic entry was not bounded: %d bytes", len(err.Error()))
	}
}

func TestFetchCloudflareIPv4Ranges(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "success", status: http.StatusOK, body: testCloudflareIPv4RangesBody},
		{name: "non-2xx status", status: http.StatusNotFound, body: "not found", wantErr: "unexpected HTTP status 404"},
		{name: "server error", status: http.StatusInternalServerError, body: "<html>error</html>", wantErr: "unexpected HTTP status 500"},
		{name: "empty body", status: http.StatusOK, body: "", wantErr: "expected at least 2 IPv4 ranges"},
		{name: "HTML body", status: http.StatusOK, body: "<html><body>maintenance</body></html>", wantErr: "not a canonical IPv4 CIDR"},
		{name: "IPv6 body", status: http.StatusOK, body: "2400:cb00::/32\n2606:4700::/32\n", wantErr: "not an IPv4 CIDR"},
		{name: "host bits set", status: http.StatusOK, body: "173.245.48.7/20\n103.21.244.0/22\n", wantErr: "host bits are set"},
		{name: "duplicate range", status: http.StatusOK, body: "173.245.48.0/20\n173.245.48.0/20\n", wantErr: "duplicate range"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var userAgent string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userAgent = r.Header.Get("User-Agent")
				if cookie := r.Header.Get("Cookie"); cookie != "" {
					t.Errorf("unexpected Cookie header %q", cookie)
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()

			ranges, source, err := FetchIPv4Ranges(context.Background(), server.Client(), server.URL+"/ips-v4")
			if userAgent != cloudflareIPv4RangesUserAgent {
				t.Fatalf("User-Agent = %q, want %q", userAgent, cloudflareIPv4RangesUserAgent)
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(ranges, testCloudflareIPv4Ranges) {
				t.Fatalf("ranges = %#v, want %#v", ranges, testCloudflareIPv4Ranges)
			}
			if source != server.URL+"/ips-v4" {
				t.Fatalf("source = %q, want %q", source, server.URL+"/ips-v4")
			}
		})
	}
}

func TestFetchCloudflareIPv4RangesRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("1", cloudflareIPv4RangesMaxBodyBytes+1))
	}))
	defer server.Close()

	if _, _, err := FetchIPv4Ranges(context.Background(), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want an oversized body error", err)
	}
}
