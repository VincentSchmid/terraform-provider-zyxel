package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &StatusDataSource{}
var _ datasource.DataSourceWithConfigure = &StatusDataSource{}

func NewStatusDataSource() datasource.DataSource { return &StatusDataSource{} }

type StatusDataSource struct{ client *Client }
type statusModel struct {
	ModelName       types.String `tfsdk:"model_name"`
	FirmwareVersion types.String `tfsdk:"firmware_version"`
	Hostname        types.String `tfsdk:"hostname"`
}

func (d *StatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_status"
}
func (d *StatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = datasourceschema.Schema{Attributes: map[string]datasourceschema.Attribute{
		"model_name":       datasourceschema.StringAttribute{Computed: true, MarkdownDescription: "Router model name reported by the device."},
		"firmware_version": datasourceschema.StringAttribute{Computed: true, MarkdownDescription: "Router firmware version reported by the device."},
		"hostname":         datasourceschema.StringAttribute{Computed: true, MarkdownDescription: "Router hostname reported by the device."},
	}}
}
func (d *StatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected data source configuration", fmt.Sprintf("Expected *Client, got %T.", req.ProviderData))
		return
	}
	d.client = client
}
func (d *StatusDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	status, err := d.client.ReadStatus(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read router status", err.Error())
		return
	}
	model := statusModel{ModelName: nestedString(status, "DeviceInfo", "ModelName"), FirmwareVersion: nestedString(status, "DeviceInfo", "SoftwareVersion"), Hostname: nestedString(status, "SystemInfo", "HostName")}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func nestedString(object map[string]any, parent, key string) types.String {
	child, ok := object[parent].(map[string]any)
	if !ok {
		return types.StringNull()
	}
	value, ok := child[key].(string)
	if !ok {
		return types.StringNull()
	}
	return types.StringValue(value)
}
