package provider

import (
	"context"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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
	ID               types.String `tfsdk:"id"`
	InterfaceGroupID types.String `tfsdk:"interface_group_id"`
	IPAddress        types.String `tfsdk:"ip_address"`
	SubnetMask       types.String `tfsdk:"subnet_mask"`
	IGMPSnooping     types.String `tfsdk:"igmp_snooping"`
	DNSMode          types.String `tfsdk:"dns_mode"`
	DHCP             types.Object `tfsdk:"dhcp"`
}
type lanDHCPModel struct {
	Mode               types.String `tfsdk:"mode"`
	BeginningIPAddress types.String `tfsdk:"beginning_ip_address"`
	EndingIPAddress    types.String `tfsdk:"ending_ip_address"`
	AutoReserveIP      types.Bool   `tfsdk:"auto_reserve_ip"`
	RelayServerAddress types.String `tfsdk:"relay_server_address"`
	LeaseTime          types.String `tfsdk:"dhcp_lease_time"`
}

var lanDHCPTypes = map[string]attr.Type{
	"mode": types.StringType, "beginning_ip_address": types.StringType,
	"ending_ip_address": types.StringType, "auto_reserve_ip": types.BoolType,
	"relay_server_address": types.StringType, "dhcp_lease_time": types.StringType,
}

func (*LANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_lan"
}
func (*LANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Manages IPv4 Home Networking > LAN Setup for an existing interface group, including DHCP and DNS advertisement. Create adopts and updates the built-in settings; updates are in place. Reference `zyxel_interface_group.example.id` or use `Default` for the built-in group. IPv6 and unrelated settings are not written. Manage only one LAN resource per group across all states. Destroy relinquishes management without changing settings. Changing the router IP/subnet or DHCP mode can interrupt access; if disconnected, update the provider host and refresh before retrying. Live writes remain unverified on hardware.", Attributes: map[string]schema.Attribute{
		"id":                 schema.StringAttribute{Computed: true, MarkdownDescription: "Exact interface-group name; also the import ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"interface_group_id": schema.StringAttribute{Required: true, MarkdownDescription: "Interface-group ID (exact name), normally `zyxel_interface_group.example.id`; use `Default` for the built-in LAN. Changing groups relinquishes the old settings and adopts the new group.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"ip_address":         schema.StringAttribute{Required: true, MarkdownDescription: "Router's IPv4 address on this LAN. Changing it may disconnect the provider; update the provider host and refresh if necessary."},
		"subnet_mask":        schema.StringAttribute{Required: true, MarkdownDescription: "Contiguous dotted-decimal IPv4 subnet mask, with prefix length 1-30."},
		"igmp_snooping":      schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("disabled"), MarkdownDescription: "IGMP snooping: `disabled`, `standard`, or `blocking`. Defaults to `disabled`."},
		"dns_mode":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("proxy"), MarkdownDescription: "DNS advertised by the DHCP server: `proxy` (default) or `isp`. Only active in server mode; omit or use `proxy` in relay/disabled mode, where DNS settings are left untouched."},
		"dhcp": schema.SingleNestedAttribute{Required: true, MarkdownDescription: "DHCP configuration. Pool, auto-reservation, and lease settings apply only to server mode; the relay address applies only to relay mode.", Attributes: map[string]schema.Attribute{
			"mode":                 schema.StringAttribute{Required: true, MarkdownDescription: "DHCP state: `server` (Enable), `disabled` (Disable), or `relay` (DHCP Relay)."},
			"beginning_ip_address": schema.StringAttribute{Optional: true, MarkdownDescription: "Required in server mode: first usable host of the DHCP pool in the LAN subnet. The pool must not include the router address."},
			"ending_ip_address":    schema.StringAttribute{Optional: true, MarkdownDescription: "Required in server mode: last usable host of the DHCP pool; at least the beginning address."},
			"auto_reserve_ip":      schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Auto reserve IP for the same host. Defaults to false; may be true only in server mode."},
			"relay_server_address": schema.StringAttribute{Optional: true, MarkdownDescription: "Required in relay mode: IPv4 address of the upstream DHCP server. Omit in other modes."},
			"dhcp_lease_time":      schema.StringAttribute{Optional: true, MarkdownDescription: "Required in server mode: whole days, hours, and/or minutes, for example `1d`, `24h`, `1440m`, or `1d5h12m`. Range: `1m` through `365d`. Omit in relay/disabled mode."},
		}},
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
func lanFromModel(ctx context.Context, m lanModel) (zyxel.LANSettings, diag.Diagnostics) {
	var dhcp lanDHCPModel
	d := m.DHCP.As(ctx, &dhcp, basetypes.ObjectAsOptions{})
	v := zyxel.LANSettings{InterfaceGroupID: m.InterfaceGroupID.ValueString(), IPAddress: m.IPAddress.ValueString(), SubnetMask: m.SubnetMask.ValueString(), IGMPSnooping: m.IGMPSnooping.ValueString(), DNSMode: m.DNSMode.ValueString(), DHCPMode: dhcp.Mode.ValueString(), BeginningIPAddress: dhcp.BeginningIPAddress.ValueString(), EndingIPAddress: dhcp.EndingIPAddress.ValueString(), AutoReserveIP: dhcp.AutoReserveIP.ValueBool(), RelayServerAddress: dhcp.RelayServerAddress.ValueString()}
	if !dhcp.LeaseTime.IsNull() && !dhcp.LeaseTime.IsUnknown() {
		seconds, err := zyxel.ParseLANLeaseTime(dhcp.LeaseTime.ValueString())
		if err != nil {
			d.AddAttributeError(path.Root("dhcp").AtName("dhcp_lease_time"), "Invalid DHCP lease time", err.Error())
		} else {
			v.DHCPLeaseTimeSeconds = seconds
		}
	}
	return v, d
}
func lanModelUnknown(m lanModel) bool {
	for _, v := range []types.String{m.InterfaceGroupID, m.IPAddress, m.SubnetMask, m.IGMPSnooping, m.DNSMode} {
		if v.IsUnknown() {
			return true
		}
	}
	if m.DHCP.IsUnknown() {
		return true
	}
	for _, v := range m.DHCP.Attributes() {
		if v.IsUnknown() {
			return true
		}
	}
	return false
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
	if m.DNSMode.IsNull() {
		m.DNSMode = types.StringValue("proxy")
	}
	if m.DHCP.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("dhcp"), "Missing DHCP settings", "Set dhcp to an object with a mode.")
		return
	}
	v, d := lanFromModel(ctx, m)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := v.Validate(); err != nil {
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
	v, diagnostics := lanFromModel(ctx, *m)
	d.Append(diagnostics...)
	if d.HasError() {
		return false
	}
	applied, err := r.client.SetLAN(ctx, v)
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
	previous := m
	m = lanObservedModel(*v)
	// Preserve the user's spelling when the router reports an equivalent lease.
	if !previous.DHCP.IsNull() && !previous.DHCP.IsUnknown() && v.DHCPMode == "server" {
		var old lanDHCPModel
		if d := previous.DHCP.As(ctx, &old, basetypes.ObjectAsOptions{}); !d.HasError() && !old.LeaseTime.IsUnknown() && !old.LeaseTime.IsNull() {
			if seconds, err := zyxel.ParseLANLeaseTime(old.LeaseTime.ValueString()); err == nil && seconds == v.DHCPLeaseTimeSeconds {
				attributes := m.DHCP.Attributes()
				attributes["dhcp_lease_time"] = old.LeaseTime
				m.DHCP = types.ObjectValueMust(lanDHCPTypes, attributes)
			}
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func lanObservedModel(v zyxel.LANSettings) lanModel {
	m := lanModel{ID: types.StringValue(v.InterfaceGroupID), InterfaceGroupID: types.StringValue(v.InterfaceGroupID), IPAddress: types.StringValue(v.IPAddress), SubnetMask: types.StringValue(v.SubnetMask), IGMPSnooping: types.StringValue(v.IGMPSnooping), DNSMode: types.StringValue(v.DNSMode)}
	attributes := map[string]attr.Value{"mode": types.StringValue(v.DHCPMode), "beginning_ip_address": types.StringNull(), "ending_ip_address": types.StringNull(), "auto_reserve_ip": types.BoolValue(v.AutoReserveIP), "relay_server_address": types.StringNull(), "dhcp_lease_time": types.StringNull()}
	if v.DHCPMode == "server" {
		attributes["beginning_ip_address"] = types.StringValue(v.BeginningIPAddress)
		attributes["ending_ip_address"] = types.StringValue(v.EndingIPAddress)
		attributes["dhcp_lease_time"] = types.StringValue(zyxel.FormatLANLeaseTime(v.DHCPLeaseTimeSeconds))
	}
	if v.DHCPMode == "relay" {
		attributes["relay_server_address"] = types.StringValue(v.RelayServerAddress)
	}
	m.DHCP = types.ObjectValueMust(lanDHCPTypes, attributes)
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
