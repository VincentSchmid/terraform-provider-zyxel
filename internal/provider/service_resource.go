package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &ServiceResource{}
	_ resource.ResourceWithConfigure      = &ServiceResource{}
	_ resource.ResourceWithImportState    = &ServiceResource{}
	_ resource.ResourceWithValidateConfig = &ServiceResource{}
)

func NewServiceResource() resource.Resource { return &ServiceResource{} }

type ServiceResource struct{ client *zyxel.Client }
type serviceModel struct {
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	Protocol         types.String `tfsdk:"protocol"`
	SourcePorts      types.String `tfsdk:"source_ports"`
	DestinationPorts types.String `tfsdk:"destination_ports"`
	ICMPType         types.Int64  `tfsdk:"icmp_type"`
	ICMPv6Type       types.Int64  `tfsdk:"icmpv6_type"`
	ProtocolNumber   types.Int64  `tfsdk:"protocol_number"`
	ID               types.String `tfsdk:"id"`
	RouterIndex      types.Int64  `tfsdk:"router_index"`
}

func (*ServiceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}
func (*ServiceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceString := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	replaceInt := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{MarkdownDescription: "Manages a reusable Firewall > Protocol service in `firewall_proto`. Reference its native `id` from `zyxel_acl_rule.service_id`. Import by exact name; changes replace the service. Deletion is refused while any ACL references the service because the router can cascade-delete associated ACL rules. Remove dependent ACL rules before replacing a service (a two-stage apply may be necessary). Live writes remain unverified on hardware.", Attributes: map[string]schema.Attribute{
		"name":              schema.StringAttribute{Required: true, MarkdownDescription: "Exact unique service name; natural identity and import key.", PlanModifiers: replaceString, Validators: []validator.String{aclServiceValidator{}}},
		"description":       schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), MarkdownDescription: "Service description. Defaults to empty. Changes replace the service.", PlanModifiers: replaceString},
		"protocol":          schema.StringAttribute{Required: true, MarkdownDescription: "Protocol: `tcp`, `udp`, `icmp`, `icmpv6`, or `other`.", PlanModifiers: replaceString},
		"source_ports":      schema.StringAttribute{Optional: true, MarkdownDescription: "TCP/UDP source ports: `*` (any), `443` (single), or `443-445` (inclusive range). Omit for any. Changes replace the service.", PlanModifiers: replaceString, Validators: []validator.String{portsValidator{}}},
		"destination_ports": schema.StringAttribute{Optional: true, MarkdownDescription: "TCP/UDP destination ports using `*`, a single port, or an inclusive range. Omit for any. Changes replace the service.", PlanModifiers: replaceString, Validators: []validator.String{portsValidator{}}},
		"icmp_type":         schema.Int64Attribute{Optional: true, MarkdownDescription: "ICMP type, -1 (any) through 143. Only valid for `icmp`; omitted means any. Codes are not filtered.", PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: -1, maximum: 143}}},
		"icmpv6_type":       schema.Int64Attribute{Optional: true, MarkdownDescription: "ICMPv6 type, -1 (any) through 143, for example 128 for echo request. Only valid for `icmpv6`; omitted means any. Codes are not filtered.", PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: -1, maximum: 143}}},
		"protocol_number":   schema.Int64Attribute{Optional: true, MarkdownDescription: "Required for `other`: IP protocol number 0-255. Use named protocols instead of 1, 6, 17, or 58.", PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 0, maximum: 255}}},
		"id":                schema.StringAttribute{Computed: true, MarkdownDescription: "Native router service Iid, suitable for `zyxel_acl_rule.service_id`. Not the display index. Changes when the service is recreated."},
		"router_index":      schema.Int64Attribute{Computed: true, MarkdownDescription: "Current display index for diagnostics only; refreshed before deletion."},
	}}
}
func (r *ServiceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func serviceFromModel(m serviceModel) zyxel.Service {
	return zyxel.Service{Name: m.Name.ValueString(), Description: m.Description.ValueString(), Protocol: m.Protocol.ValueString(), SourcePorts: aclModelString(m.SourcePorts), DestinationPorts: aclModelString(m.DestinationPorts), ICMPType: optionalServiceInt(m.ICMPType), ICMPv6Type: optionalServiceInt(m.ICMPv6Type), ProtocolNumber: optionalServiceInt(m.ProtocolNumber)}
}
func optionalServiceInt(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	n := v.ValueInt64()
	return &n
}

func serviceObservedModel(s zyxel.Service, old serviceModel) serviceModel {
	m := serviceModel{Name: types.StringValue(s.Name), Description: types.StringValue(s.Description), Protocol: types.StringValue(s.Protocol), ID: types.StringValue(s.ID), RouterIndex: types.Int64Value(s.RouterIndex), SourcePorts: types.StringNull(), DestinationPorts: types.StringNull(), ICMPType: types.Int64Null(), ICMPv6Type: types.Int64Null(), ProtocolNumber: types.Int64Null()}
	for _, p := range []struct {
		observed string
		old      types.String
		target   *types.String
	}{{s.SourcePorts, old.SourcePorts, &m.SourcePorts}, {s.DestinationPorts, old.DestinationPorts, &m.DestinationPorts}} {
		if p.observed == "" || (p.observed == "*" && p.old.IsNull()) {
			continue
		}
		value := p.observed
		if a, b, err := zyxel.ParsePorts(p.old.ValueString()); err == nil && !p.old.IsNull() && zyxel.FormatPorts(a, b) == value {
			value = p.old.ValueString()
		}
		*p.target = types.StringValue(value)
	}
	for _, p := range []struct {
		n      *int64
		old    types.Int64
		target *types.Int64
	}{{s.ICMPType, old.ICMPType, &m.ICMPType}, {s.ICMPv6Type, old.ICMPv6Type, &m.ICMPv6Type}, {s.ProtocolNumber, old.ProtocolNumber, &m.ProtocolNumber}} {
		if p.n != nil && !(*p.n == -1 && p.old.IsNull()) {
			*p.target = types.Int64Value(*p.n)
		}
	}
	return m
}

func (*ServiceResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m serviceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Protocol.IsUnknown() || m.Protocol.IsNull() {
		return
	}
	p := m.Protocol.ValueString()
	if p != "tcp" && p != "udp" && p != "icmp" && p != "icmpv6" && p != "other" {
		resp.Diagnostics.AddAttributeError(path.Root("protocol"), "Invalid service protocol", "Use tcp, udp, icmp, icmpv6, or other.")
	}
	for name, v := range map[string]types.String{"source_ports": m.SourcePorts, "destination_ports": m.DestinationPorts} {
		if !v.IsNull() && p != "tcp" && p != "udp" {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Protocol does not use ports", "Ports are only valid for tcp and udp.")
		}
	}
	for _, v := range []struct {
		name, protocol string
		value          types.Int64
	}{{"icmp_type", "icmp", m.ICMPType}, {"icmpv6_type", "icmpv6", m.ICMPv6Type}, {"protocol_number", "other", m.ProtocolNumber}} {
		if !v.value.IsNull() && p != v.protocol {
			resp.Diagnostics.AddAttributeError(path.Root(v.name), "Conflicting service type", v.name+" is only valid for "+v.protocol+".")
		}
	}
	if p == "other" && m.ProtocolNumber.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("protocol_number"), "Missing protocol number", "other requires protocol_number.")
	}
}

func (r *ServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var m serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, v := range []types.String{m.Name, m.Description, m.Protocol, m.SourcePorts, m.DestinationPorts} {
		if v.IsUnknown() {
			resp.Diagnostics.AddError("Unknown service plan values", "Service settings must be known before creation.")
			return
		}
	}
	for _, v := range []types.Int64{m.ICMPType, m.ICMPv6Type, m.ProtocolNumber} {
		if v.IsUnknown() {
			resp.Diagnostics.AddError("Unknown service plan values", "Service settings must be known before creation.")
			return
		}
	}
	outcome, err := r.client.CreateService(ctx, serviceFromModel(m))
	if outcome.Service != nil {
		m = serviceObservedModel(*outcome.Service, m)
	} else {
		m.ID = types.StringNull()
		m.RouterIndex = types.Int64Null()
	}
	if err != nil {
		if outcome.Applied || outcome.Ambiguous {
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		}
		resp.Diagnostics.AddError("Error creating service", err.Error())
		return
	}
	if !outcome.Applied || outcome.Service == nil {
		resp.Diagnostics.AddError("Unconfirmed service creation", "Router did not confirm service creation.")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (r *ServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var m serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.ReadService(ctx, m.Name.ValueString())
	if errors.Is(err, zyxel.ErrServiceNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading service", err.Error())
		return
	}
	m = serviceObservedModel(s, m)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (*ServiceResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unsupported service update", "Service changes require replacement.")
}
func (r *ServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var m serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteService(ctx, m.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting service", err.Error())
	}
}
func (*ServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError("Invalid service import ID", "Import using the exact non-empty service name.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
