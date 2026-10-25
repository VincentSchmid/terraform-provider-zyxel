package provider

import (
	"context"
	"errors"
	"net/http"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/cloudflare"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

	ranges, source, err := cloudflare.FetchIPv4Ranges(ctx, d.httpClient(), requestURL)
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
	return &http.Client{Timeout: cloudflare.Timeout}
}

// resolveCloudflareIPv4RangesURL applies the default and validates that a
// configured value is an absolute HTTP(S) URL without embedded credentials.
func resolveCloudflareIPv4RangesURL(configured types.String) (string, error) {
	if configured.IsUnknown() {
		return "", errors.New("url must be known during planning")
	}
	if configured.IsNull() {
		return cloudflare.DefaultURL, nil
	}

	return cloudflare.ValidateURL(configured.ValueString())
}
