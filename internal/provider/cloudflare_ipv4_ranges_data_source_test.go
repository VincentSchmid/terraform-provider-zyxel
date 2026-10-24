package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
			ranges, err := parseCloudflareIPv4Ranges([]byte(test.body))
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
	_, err := parseCloudflareIPv4Ranges([]byte(body))
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

			ranges, source, err := fetchCloudflareIPv4Ranges(context.Background(), server.Client(), server.URL+"/ips-v4")
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

	if _, _, err := fetchCloudflareIPv4Ranges(context.Background(), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want an oversized body error", err)
	}
}

func TestResolveCloudflareIPv4RangesURL(t *testing.T) {
	cases := []struct {
		name    string
		value   types.String
		want    string
		wantErr string
	}{
		{name: "default", value: types.StringNull(), want: cloudflareIPv4RangesDefaultURL},
		{name: "configured", value: types.StringValue("https://example.com/ips-v4"), want: "https://example.com/ips-v4"},
		{name: "trims surrounding whitespace", value: types.StringValue("  https://example.com/ips-v4  "), want: "https://example.com/ips-v4"},
		{name: "unknown", value: types.StringUnknown(), wantErr: "known during planning"},
		{name: "empty", value: types.StringValue("   "), wantErr: "must not be empty"},
		{name: "relative", value: types.StringValue("/ips-v4"), wantErr: "must use the http or https scheme"},
		{name: "hostless", value: types.StringValue("https:///ips-v4"), wantErr: "must be absolute"},
		{name: "unsupported scheme", value: types.StringValue("ftp://example.com/ips-v4"), wantErr: "http or https"},
		{name: "embedded credentials", value: types.StringValue("https://user:pass@example.com/ips-v4"), wantErr: "must not include credentials"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveCloudflareIPv4RangesURL(test.value)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("url = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCloudflareIPv4RangesReadDefaultsToCloudflareURL(t *testing.T) {
	ctx := context.Background()
	schema := cloudflareIPv4RangesFrameworkSchema(t)
	var requested *url.URL
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = request.URL
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(testCloudflareIPv4RangesBody)),
			Request:    request,
		}, nil
	})
	dataSource := NewCloudflareIPv4RangesDataSource().(*CloudflareIPv4RangesDataSource)
	dataSource.client = &http.Client{Transport: transport}

	response := datasource.ReadResponse{State: tfsdk.State{Schema: schema}}
	dataSource.Read(ctx, datasource.ReadRequest{Config: cloudflareIPv4RangesConfig(t, schema, types.StringNull())}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read failed: %v", response.Diagnostics)
	}
	if requested == nil {
		t.Fatal("no HTTP request was made")
	}
	if requested.Scheme != "https" || requested.Host != "www.cloudflare.com" || requested.Path != "/ips-v4" {
		t.Fatalf("requested %q, want the default Cloudflare URL", requested.String())
	}

	var model cloudflareIPv4RangesModel
	if diags := response.State.Get(ctx, &model); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}
	if model.URL.ValueString() != cloudflareIPv4RangesDefaultURL {
		t.Fatalf("url = %q, want %q", model.URL.ValueString(), cloudflareIPv4RangesDefaultURL)
	}
	if model.Source.ValueString() != cloudflareIPv4RangesDefaultURL {
		t.Fatalf("source = %q, want %q", model.Source.ValueString(), cloudflareIPv4RangesDefaultURL)
	}
	var ranges []string
	if diags := model.Ranges.ElementsAs(ctx, &ranges, false); diags.HasError() {
		t.Fatalf("reading ranges: %v", diags)
	}
	if !slices.Equal(ranges, testCloudflareIPv4Ranges) {
		t.Fatalf("ranges = %#v, want %#v", ranges, testCloudflareIPv4Ranges)
	}
}

func TestCloudflareIPv4RangesReadRejectsInvalidURLWithoutRequest(t *testing.T) {
	ctx := context.Background()
	schema := cloudflareIPv4RangesFrameworkSchema(t)
	dataSource := NewCloudflareIPv4RangesDataSource().(*CloudflareIPv4RangesDataSource)
	dataSource.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request for an invalid URL")
		return nil, http.ErrUseLastResponse
	})}

	response := datasource.ReadResponse{State: tfsdk.State{Schema: schema}}
	dataSource.Read(ctx, datasource.ReadRequest{Config: cloudflareIPv4RangesConfig(t, schema, types.StringValue("example.com/ips-v4"))}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("expected invalid URL diagnostics")
	}
	diagnostic, ok := response.Diagnostics[0].(diag.DiagnosticWithPath)
	if !ok || !diagnostic.Path().Equal(path.Root("url")) {
		t.Fatalf("diagnostic = %v, want a url attribute error", response.Diagnostics[0])
	}
}

func TestCloudflareIPv4RangesReadReportsFetchFailure(t *testing.T) {
	ctx := context.Background()
	schema := cloudflareIPv4RangesFrameworkSchema(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	dataSource := NewCloudflareIPv4RangesDataSource().(*CloudflareIPv4RangesDataSource)
	response := datasource.ReadResponse{State: tfsdk.State{Schema: schema}}
	dataSource.Read(ctx, datasource.ReadRequest{Config: cloudflareIPv4RangesConfig(t, schema, types.StringValue(server.URL))}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("expected fetch failure diagnostics")
	}
	if !strings.Contains(response.Diagnostics[0].Detail(), "unexpected HTTP status 403") {
		t.Fatalf("detail = %q, want HTTP status failure", response.Diagnostics[0].Detail())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func cloudflareIPv4RangesFrameworkSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()
	var response datasource.SchemaResponse
	NewCloudflareIPv4RangesDataSource().Schema(context.Background(), datasource.SchemaRequest{}, &response)
	return response.Schema
}

func cloudflareIPv4RangesConfig(t *testing.T, schema datasourceschema.Schema, configuredURL types.String) tfsdk.Config {
	t.Helper()
	plan := tfsdk.Plan{Schema: schema}
	model := cloudflareIPv4RangesModel{URL: configuredURL, Ranges: types.ListNull(types.StringType), Source: types.StringNull()}
	if diags := plan.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("setting config: %v", diags)
	}
	return tfsdk.Config{Schema: schema, Raw: plan.Raw}
}
