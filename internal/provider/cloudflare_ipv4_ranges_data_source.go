package provider

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

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	cloudflareIPv4RangesDefaultURL     = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv4RangesUserAgent      = "terraform-provider-zyxel"
	cloudflareIPv4RangesTimeout        = 20 * time.Second
	cloudflareIPv4RangesMaxBodyBytes   = 4 << 20
	cloudflareIPv4RangesMinRangeCount  = 2
	cloudflareIPv4RangesMaxQuotedEntry = 80
)

var _ datasource.DataSource = &CloudflareIPv4RangesDataSource{}
var _ datasource.DataSourceWithConfigure = &CloudflareIPv4RangesDataSource{}

func NewCloudflareIPv4RangesDataSource() datasource.DataSource {
	return &CloudflareIPv4RangesDataSource{}
}

// CloudflareIPv4RangesDataSource reads Cloudflare's published IPv4 CIDR list
// so firewall rules can follow the live list instead of a hardcoded copy.
type CloudflareIPv4RangesDataSource struct{ client *http.Client }

type cloudflareIPv4RangesModel struct {
	URL    types.String `tfsdk:"url"`
	Ranges types.List   `tfsdk:"ranges"`
	Source types.String `tfsdk:"source"`
}

func (d *CloudflareIPv4RangesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudflare_ipv4_ranges"
}

func (d *CloudflareIPv4RangesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = datasourceschema.Schema{
		MarkdownDescription: "Reads Cloudflare's official IPv4 range list over HTTP(S) during planning, so firewall rules can follow the published list instead of a hardcoded copy.",
		Attributes: map[string]datasourceschema.Attribute{
			"url": datasourceschema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Absolute `http` or `https` URL of the IPv4 range list. Defaults to `https://www.cloudflare.com/ips-v4`. A change produces a new read during the next plan.",
			},
			"ranges": datasourceschema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Canonical IPv4 CIDRs in the exact order the source returned them. Values are validated but never sorted, deduplicated, or rewritten.",
			},
			"source": datasourceschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "URL the ranges were actually read from, including any redirects.",
			},
		},
	}
}

// Configure ignores ProviderData because this data source reads a public HTTP
// list and never uses the router client.
func (d *CloudflareIPv4RangesDataSource) Configure(_ context.Context, _ datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
}

func (d *CloudflareIPv4RangesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config cloudflareIPv4RangesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	requestURL, err := resolveCloudflareIPv4RangesURL(config.URL)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Invalid Cloudflare IPv4 ranges URL", err.Error())
		return
	}

	ranges, source, err := fetchCloudflareIPv4Ranges(ctx, d.httpClient(), requestURL)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Cloudflare IPv4 ranges", err.Error())
		return
	}

	rangeList, diags := types.ListValueFrom(ctx, types.StringType, ranges)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &cloudflareIPv4RangesModel{
		URL:    types.StringValue(requestURL),
		Ranges: rangeList,
		Source: types.StringValue(source),
	})...)
}

func (d *CloudflareIPv4RangesDataSource) httpClient() *http.Client {
	if d.client != nil {
		return d.client
	}
	return &http.Client{Timeout: cloudflareIPv4RangesTimeout}
}

// resolveCloudflareIPv4RangesURL applies the default and validates that a
// configured value is an absolute HTTP(S) URL without embedded credentials.
func resolveCloudflareIPv4RangesURL(configured types.String) (string, error) {
	if configured.IsUnknown() {
		return "", errors.New("url must be known during planning")
	}
	if configured.IsNull() {
		return cloudflareIPv4RangesDefaultURL, nil
	}

	rawURL := strings.TrimSpace(configured.ValueString())
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

// fetchCloudflareIPv4Ranges performs one bounded GET without authentication or
// cookies and returns the parsed ranges plus the final URL after redirects.
func fetchCloudflareIPv4Ranges(ctx context.Context, client *http.Client, rawURL string) ([]string, string, error) {
	if client == nil {
		client = &http.Client{Timeout: cloudflareIPv4RangesTimeout}
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

	ranges, err := parseCloudflareIPv4Ranges(body)
	if err != nil {
		return nil, source, err
	}
	return ranges, source, nil
}

// parseCloudflareIPv4Ranges parses a newline-separated list of canonical IPv4
// CIDRs. It preserves source order and rejects anything unexpected instead of
// silently dropping it.
func parseCloudflareIPv4Ranges(body []byte) ([]string, error) {
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
