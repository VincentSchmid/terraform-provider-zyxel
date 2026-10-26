package provider

import (
	"context"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &LANResource{}
	_ resource.ResourceWithConfigure      = &LANResource{}
	_ resource.ResourceWithImportState    = &LANResource{}
	_ resource.ResourceWithValidateConfig = &LANResource{}
)

func NewLANResource() resource.Resource { return &LANResource{} }

type LANResource struct{ client *zyxel.Client }
type lanModel struct {
	ID                 types.String `tfsdk:"id"`
	InterfaceGroupID   types.String `tfsdk:"interface_group_id"`
	IPAddress          types.String `tfsdk:"ip_address"`
	SubnetMask         types.String `tfsdk:"subnet_mask"`
	IGMPSnooping       types.String `tfsdk:"igmp_snooping"`
	DHCPMode           types.String `tfsdk:"dhcp_mode"`
	BeginningIPAddress types.String `tfsdk:"beginning_ip_address"`
	EndingIPAddress    types.String `tfsdk:"ending_ip_address"`
	AutoReserveIP      types.Bool   `tfsdk:"auto_reserve_ip"`
	RelayServerAddress types.String `tfsdk:"relay_server_address"`
}

func (*LANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_lan"
}
func (*LANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Manages IPv4 Home Networking > LAN Setup for an existing interface group. Create adopts and updates the built-in settings; updates are in place. Reference `zyxel_interface_group.example.id` or use `Default` for the built-in group. IPv6, DNS, lease times, and unrelated settings are not written. Manage only one LAN resource per group across all states. Destroy relinquishes management without changing settings. Changing the router IP/subnet or DHCP mode can interrupt access; if disconnected, update the provider host and refresh before retrying. Live writes remain unverified on hardware.", Attributes: map[string]schema.Attribute{
		"id":                   schema.StringAttribute{Computed: true, MarkdownDescription: "Exact interface-group name; also the import ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"interface_group_id":   schema.StringAttribute{Required: true, MarkdownDescription: "Interface-group ID (exact name), normally `zyxel_interface_group.example.id`; use `Default` for the built-in LAN. Changing groups relinquishes the old settings and adopts the new group.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"ip_address":           schema.StringAttribute{Required: true, MarkdownDescription: "Router's IPv4 address on this LAN. Changing it may disconnect the provider; update the provider host and refresh if necessary."},
		"subnet_mask":          schema.StringAttribute{Required: true, MarkdownDescription: "Contiguous dotted-decimal IPv4 subnet mask, with prefix length 1-30."},
		"igmp_snooping":        schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("disabled"), MarkdownDescription: "IGMP snooping: `disabled`, `standard`, or `blocking`. Defaults to `disabled`."},
		"dhcp_mode":            schema.StringAttribute{Required: true, MarkdownDescription: "DHCP state: `server` (Enable), `disabled` (Disable), or `relay` (DHCP Relay)."},
		"beginning_ip_address": schema.StringAttribute{Optional: true, MarkdownDescription: "Required in server mode: first usable host of the DHCP pool in the LAN subnet. The pool must not include the router address."},
		"ending_ip_address":    schema.StringAttribute{Optional: true, MarkdownDescription: "Required in server mode: last usable host of the DHCP pool; at least the beginning address."},
		"auto_reserve_ip":      schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Auto reserve IP for the same host. Defaults to false; may be true only in server mode."},
		"relay_server_address": schema.StringAttribute{Optional: true, MarkdownDescription: "Required in relay mode: IPv4 address of the upstream DHCP server. Omit in other modes."},
	}}
}
func (r *LANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*zyxel.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected resource configuration", fmt.Sprintf("Expected *zyxel.Client, got %T.", req.ProviderData))
		return
	}
	r.client = client
}
func lanFromModel(m lanModel) zyxel.LANSettings {
	return zyxel.LANSettings{InterfaceGroupID: m.InterfaceGroupID.ValueString(), IPAddress: m.IPAddress.ValueString(), SubnetMask: m.SubnetMask.ValueString(), IGMPSnooping: m.IGMPSnooping.ValueString(), DHCPMode: m.DHCPMode.ValueString(), BeginningIPAddress: m.BeginningIPAddress.ValueString(), EndingIPAddress: m.EndingIPAddress.ValueString(), AutoReserveIP: m.AutoReserveIP.ValueBool(), RelayServerAddress: m.RelayServerAddress.ValueString()}
}
func lanModelUnknown(m lanModel) bool {
	for _, v := range []types.String{m.InterfaceGroupID, m.IPAddress, m.SubnetMask, m.IGMPSnooping, m.DHCPMode, m.BeginningIPAddress, m.EndingIPAddress, m.RelayServerAddress} {
		if v.IsUnknown() {
			return true
		}
	}
	return m.AutoReserveIP.IsUnknown()
}
func (*LANResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m lanModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || lanModelUnknown(m) {
		return
	}
	// Defaults are inserted at planning time, not while validating configuration.
	if m.IGMPSnooping.IsNull() {
		m.IGMPSnooping = types.StringValue("disabled")
	}
	if err := lanFromModel(m).Validate(); err != nil {
		resp.Diagnostics.AddError("Invalid LAN settings", err.Error())
	}
}
func (r *LANResource) apply(ctx context.Context, m *lanModel, d *diag.Diagnostics) bool {
	if r.client == nil {
		d.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return false
	}
	if lanModelUnknown(*m) {
		d.AddError("Unknown LAN settings", "LAN values must be known before applying.")
		return false
	}
	m.ID = m.InterfaceGroupID
	applied, err := r.client.SetLAN(ctx, lanFromModel(*m))
	if err != nil {
		d.AddError("Error configuring LAN", err.Error()+" If the write may have applied, inspect the router and refresh before retrying. If access was lost, update the provider host to the new LAN address first.")
	}
	return applied
}
func (r *LANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m lanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if !resp.Diagnostics.HasError() && r.apply(ctx, &m, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}
func (r *LANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m lanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if !resp.Diagnostics.HasError() && r.apply(ctx, &m, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}
func (r *LANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m lanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	v, err := r.client.ReadLAN(ctx, m.InterfaceGroupID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading LAN", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	m = lanObservedModel(*v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func lanObservedModel(v zyxel.LANSettings) lanModel {
	m := lanModel{ID: types.StringValue(v.InterfaceGroupID), InterfaceGroupID: types.StringValue(v.InterfaceGroupID), IPAddress: types.StringValue(v.IPAddress), SubnetMask: types.StringValue(v.SubnetMask), IGMPSnooping: types.StringValue(v.IGMPSnooping), DHCPMode: types.StringValue(v.DHCPMode), BeginningIPAddress: types.StringNull(), EndingIPAddress: types.StringNull(), AutoReserveIP: types.BoolValue(v.AutoReserveIP), RelayServerAddress: types.StringNull()}
	if v.DHCPMode == "server" {
		m.BeginningIPAddress = types.StringValue(v.BeginningIPAddress)
		m.EndingIPAddress = types.StringValue(v.EndingIPAddress)
	}
	if v.DHCPMode == "relay" {
		m.RelayServerAddress = types.StringValue(v.RelayServerAddress)
	}
	return m
}
func (*LANResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}
func (*LANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError("Invalid LAN import ID", "Use the exact interface group name, for example Default.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("interface_group_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
