package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &ACLRuleResource{}
	_ resource.ResourceWithConfigure      = &ACLRuleResource{}
	_ resource.ResourceWithImportState    = &ACLRuleResource{}
	_ resource.ResourceWithValidateConfig = &ACLRuleResource{}
)

func NewACLRuleResource() resource.Resource { return &ACLRuleResource{} }

type ACLRuleResource struct{ client *zyxel.Client }

type aclRuleModel struct {
	Name                 types.String `tfsdk:"name"`
	Action               types.String `tfsdk:"action"`
	Order                types.Int64  `tfsdk:"order"`
	Protocol             types.String `tfsdk:"protocol"`
	IPVersion            types.String `tfsdk:"ip_version"`
	Direction            types.String `tfsdk:"direction"`
	MACAddress           types.String `tfsdk:"mac_address"`
	Service              types.String `tfsdk:"service"`
	TCPFlag              types.String `tfsdk:"tcp_flag"`
	SourceCIDR           types.String `tfsdk:"source_cidr"`
	DestinationCIDR      types.String `tfsdk:"destination_cidr"`
	DestinationPortStart types.Int64  `tfsdk:"destination_port_start"`
	DestinationPortEnd   types.Int64  `tfsdk:"destination_port_end"`
	SourcePortStart      types.Int64  `tfsdk:"source_port_start"`
	SourcePortEnd        types.Int64  `tfsdk:"source_port_end"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	PacketsPerUnit       types.Int64  `tfsdk:"packets_per_unit"`
	RateLimitUnit        types.String `tfsdk:"rate_limit_unit"`
	RouterIndex          types.Int64  `tfsdk:"router_index"`
}

func (r *ACLRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_rule"
}

func (r *ACLRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceString := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	replaceInt := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	replaceBool := []planmodifier.Bool{boolplanmodifier.RequiresReplace()}
	portDescription := "Port from 1 through 65535; the range end must be at least the start. Set both bounds or omit both for any port. Ports are only used by the `tcp`, `udp`, and `tcp_udp` protocols. Changing it replaces the ACL rule."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one firewall ACL entry in the router's `firewall_acl` table. Interface selection is fixed to `ALL`, and schedule rules are not exposed yet. The protocol can be `all`, `tcp_udp`, `tcp`, `udp`, `icmp`, or `icmpv6`; the address family can be IPv4 or IPv6. MAC, custom service, TCP flag, and direction filters are supported. Optional packet rate limiting is supported for `accept` rules. Existing rows must be imported by exact name; imported rows outside this supported profile are rejected. All configurable fields require replacement because no safe in-place update or reorder operation has been verified. The router applies order globally; this resource does not guarantee a complete firewall policy across independent resources or Terraform states.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true, MarkdownDescription: "Exact, non-empty router rule name. This is the natural identity and import key; duplicate names are ambiguous.",
				PlanModifiers: replaceString, Validators: []validator.String{aclNameValidator{}},
			},
			"action": schema.StringAttribute{
				Required: true, MarkdownDescription: "ACL action: `accept`, `drop`, or `reject`. The router stores these as `Accept`, `Drop`, or `Reject`.",
				PlanModifiers: replaceString, Validators: []validator.String{aclActionValidator{}},
			},
			"order": schema.Int64Attribute{
				Required: true, MarkdownDescription: "Explicit desired order in the router's global ACL table. Existing use of this order is rejected. Router order behavior must be verified before production use.",
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1}},
			},
			"protocol": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("tcp"),
				MarkdownDescription: "Transport protocol: `all`, `tcp_udp`, `tcp`, `udp`, `icmp`, or `icmpv6`. `tcp_udp` is the router's TCP/UDP service. Defaults to `tcp`; changing it replaces the ACL rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclProtocolValidator{}},
			},
			"ip_version": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("ipv4"),
				MarkdownDescription: "Address family for `source_cidr` and `destination_cidr`: `ipv4` or `ipv6`. Defaults to `ipv4`. With `ipv6` you must set both CIDRs explicitly to IPv6 networks because the default source remains `0.0.0.0/0`. Changing it replaces the ACL rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclIPVersionValidator{}},
			},
			"direction": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("wan_to_lan"),
				MarkdownDescription: "Traffic direction: `wan_to_lan`, `lan_to_wan`, `wan_to_router`, or `lan_to_router`. Defaults to `wan_to_lan`. Changing it replaces the ACL rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclDirectionValidator{}},
			},
			"mac_address": schema.StringAttribute{
				Optional: true, MarkdownDescription: "Optional source MAC address filter in canonical uppercase six-octet colon-separated form (for example, `AA:BB:CC:DD:EE:FF`). Omit for any MAC address. Changing it replaces the ACL rule.",
				PlanModifiers: replaceString, Validators: []validator.String{aclMACValidator{}},
			},
			"service": schema.StringAttribute{
				Optional: true, MarkdownDescription: "Optional name of a custom protocol/service group on the router. Omit for none. The service must already exist; this resource does not create it. Changing it replaces the ACL rule.",
				PlanModifiers: replaceString, Validators: []validator.String{aclServiceValidator{}},
			},
			"tcp_flag": schema.StringAttribute{
				Optional: true, MarkdownDescription: "Optional TCP flag to match: `syn`, `ack`, `urg`, `psh`, `rst`, or `fin`. Omit for any flag. Only valid with the `tcp` and `tcp_udp` protocols. Changing it replaces the ACL rule.",
				PlanModifiers: replaceString, Validators: []validator.String{aclTCPFlagValidator{}},
			},
			"source_cidr": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("0.0.0.0/0"),
				MarkdownDescription: "Canonical source CIDR in the selected `ip_version`. Defaults to `0.0.0.0/0` (any IPv4 source). Use the canonical network address for the prefix; changing it replaces the rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclCIDRValidator{}},
			},
			"destination_cidr": schema.StringAttribute{
				Required: true, MarkdownDescription: "Canonical destination CIDR in the selected `ip_version`. Changing it replaces the ACL rule.",
				PlanModifiers: replaceString, Validators: []validator.String{aclCIDRValidator{}},
			},
			"destination_port_start": schema.Int64Attribute{
				Optional: true, MarkdownDescription: portDescription,
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"destination_port_end": schema.Int64Attribute{
				Optional: true, MarkdownDescription: portDescription,
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"source_port_start": schema.Int64Attribute{
				Optional: true, MarkdownDescription: "Optional source port range start for the `tcp`, `udp`, and `tcp_udp` protocols. Leave both source port bounds null for any source port; null maps to router values `-1/-1`.",
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"source_port_end": schema.Int64Attribute{
				Optional: true, MarkdownDescription: "Optional source port range end. Set this together with `source_port_start`; changing it replaces the ACL rule.",
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				MarkdownDescription: "Whether the ACL rule is enabled. Defaults to `true`; changing it replaces the rule.", PlanModifiers: replaceBool,
			},
			"packets_per_unit": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Optional packet rate limit: number of matching packets allowed per `rate_limit_unit`, from 1 through 512. Omit to disable rate limiting. Rate limiting requires `action = \"accept\"` and changing it replaces the ACL rule.",
				PlanModifiers:       replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 512}},
			},
			"rate_limit_unit": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("minute"),
				MarkdownDescription: "Time period for `packets_per_unit`: `minute` or `second`. Defaults to `minute`; only used when `packets_per_unit` is set. Changing it replaces the ACL rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclRateLimitUnitValidator{}},
			},
			"router_index": schema.Int64Attribute{
				Computed: true, MarkdownDescription: "Current router list index, exposed for diagnostics only. Indexes shift after deletes and are never used as resource identity.",
			},
		},
	}
}

func (r *ACLRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ACLRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config aclRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	usesPorts := true
	if !config.Protocol.IsUnknown() && !config.Protocol.IsNull() {
		usesPorts = aclProtocolSupportsPorts(config.Protocol.ValueString())
	}
	if !config.TCPFlag.IsNull() && !config.TCPFlag.IsUnknown() && !usesPorts {
		resp.Diagnostics.AddAttributeError(path.Root("tcp_flag"), "Protocol does not use TCP flags", "TCP flags are only supported by the `tcp` and `tcp_udp` protocols; remove `tcp_flag` for this protocol.")
	}
	ipVersion := "ipv4"
	ipVersionUnknown := config.IPVersion.IsUnknown()
	if !config.IPVersion.IsNull() && !ipVersionUnknown {
		ipVersion = config.IPVersion.ValueString()
	}
	family := int64(4)
	if ipVersion == "ipv6" {
		family = 6
	}
	if !ipVersionUnknown {
		if config.SourceCIDR.IsUnknown() {
			// Terraform may resolve this during apply; validate it then.
		} else if config.SourceCIDR.IsNull() {
			if family == 6 {
				resp.Diagnostics.AddAttributeError(path.Root("source_cidr"), "IPv6 source CIDR required", "`ip_version = \"ipv6\"` requires an explicit IPv6 `source_cidr`; the default `0.0.0.0/0` only applies to IPv4.")
			}
		} else if actual, ok := aclCIDRFamily(config.SourceCIDR.ValueString()); !ok || actual != family {
			resp.Diagnostics.AddAttributeError(path.Root("source_cidr"), "CIDR does not match ip_version", fmt.Sprintf("source_cidr must be a canonical IPv%d CIDR when ip_version is %q.", family, ipVersion))
		}
		if !config.DestinationCIDR.IsUnknown() && !config.DestinationCIDR.IsNull() {
			if actual, ok := aclCIDRFamily(config.DestinationCIDR.ValueString()); !ok || actual != family {
				resp.Diagnostics.AddAttributeError(path.Root("destination_cidr"), "CIDR does not match ip_version", fmt.Sprintf("destination_cidr must be a canonical IPv%d CIDR when ip_version is %q.", family, ipVersion))
			}
		}
	}
	if config.SourcePortStart.IsUnknown() || config.SourcePortEnd.IsUnknown() {
		// Terraform may resolve either bound during apply; validate the pair then.
	} else if config.SourcePortStart.IsNull() != config.SourcePortEnd.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("source_port_end"), "Incomplete source port range", "Set both `source_port_start` and `source_port_end`, or leave both null for any source port.")
	} else if !config.SourcePortStart.IsNull() && !usesPorts {
		resp.Diagnostics.AddAttributeError(path.Root("source_port_start"), "Protocol does not use source ports", "Source ports are only used by the `tcp`, `udp`, and `tcp_udp` protocols; remove the source port bounds for this protocol.")
	} else if !config.SourcePortStart.IsNull() && config.SourcePortEnd.ValueInt64() < config.SourcePortStart.ValueInt64() {
		resp.Diagnostics.AddAttributeError(path.Root("source_port_end"), "Invalid source port range", "source_port_end must be greater than or equal to source_port_start.")
	}
	if !config.PacketsPerUnit.IsUnknown() {
		if config.PacketsPerUnit.IsNull() {
			if !config.RateLimitUnit.IsUnknown() && !config.RateLimitUnit.IsNull() && config.RateLimitUnit.ValueString() != "minute" {
				resp.Diagnostics.AddAttributeError(path.Root("rate_limit_unit"), "Rate limit unit without a packet limit", "Set `packets_per_unit` when using `rate_limit_unit`; omit the unit or leave it as `minute` when rate limiting is disabled.")
			}
		} else if !config.Action.IsUnknown() && !config.Action.IsNull() && config.Action.ValueString() != "accept" {
			resp.Diagnostics.AddAttributeError(path.Root("packets_per_unit"), "Rate limit requires accept", "The router only supports rate limiting for `action = \"accept\"`; remove `packets_per_unit` or change the action.")
		}
	}
	if config.DestinationPortStart.IsUnknown() || config.DestinationPortEnd.IsUnknown() {
		return
	}
	if config.DestinationPortStart.IsNull() != config.DestinationPortEnd.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("destination_port_end"), "Incomplete destination port range", "Set both `destination_port_start` and `destination_port_end`, or leave both null for any destination port.")
		return
	}
	if !config.DestinationPortStart.IsNull() && !usesPorts {
		resp.Diagnostics.AddAttributeError(path.Root("destination_port_start"), "Protocol does not use destination ports", "Destination ports are only used by the `tcp`, `udp`, and `tcp_udp` protocols; remove the destination port bounds for this protocol.")
		return
	}
	if !config.DestinationPortStart.IsNull() && config.DestinationPortEnd.ValueInt64() < config.DestinationPortStart.ValueInt64() {
		resp.Diagnostics.AddAttributeError(path.Root("destination_port_end"), "Invalid destination port range", "destination_port_end must be greater than or equal to destination_port_start.")
	}
}

func (r *ACLRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var plan aclRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if unknown := unknownACLPlanAttributes(plan); len(unknown) > 0 {
		resp.Diagnostics.AddError("Unknown ACL rule plan values", "The router requires these ACL values to be known before creating a rule: "+strings.Join(unknown, ", "))
		return
	}
	planned := modelACLRule(plan)
	outcome, err := r.client.CreateACLRule(ctx, planned)
	if err != nil {
		if outcome.Applied || outcome.Ambiguous {
			state := plan
			if outcome.Rule != nil {
				state = modelFromACLRule(*outcome.Rule)
			} else {
				state.RouterIndex = types.Int64Null()
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		}
		resp.Diagnostics.AddError("Error creating ACL rule", fmt.Sprintf("creating ACL rule (%s): %s", planned.Name, err))
		return
	}
	if !outcome.Applied || outcome.Rule == nil {
		resp.Diagnostics.AddError("Unable to confirm ACL rule", "The router did not confirm the ACL rule create by name and readback.")
		return
	}
	state := modelFromACLRule(*outcome.Rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func unknownACLPlanAttributes(model aclRuleModel) []string {
	var unknown []string
	for name, value := range map[string]types.String{
		"name": model.Name, "action": model.Action, "protocol": model.Protocol,
		"ip_version": model.IPVersion, "direction": model.Direction,
		"mac_address": model.MACAddress, "service": model.Service, "tcp_flag": model.TCPFlag,
		"source_cidr": model.SourceCIDR, "destination_cidr": model.DestinationCIDR,
		"rate_limit_unit": model.RateLimitUnit,
	} {
		if value.IsUnknown() {
			unknown = append(unknown, name)
		}
	}
	for name, value := range map[string]types.Int64{
		"order": model.Order, "destination_port_start": model.DestinationPortStart,
		"destination_port_end": model.DestinationPortEnd, "source_port_start": model.SourcePortStart,
		"source_port_end": model.SourcePortEnd, "packets_per_unit": model.PacketsPerUnit,
	} {
		if value.IsUnknown() {
			unknown = append(unknown, name)
		}
	}
	if model.Enabled.IsUnknown() {
		unknown = append(unknown, "enabled")
	}
	sort.Strings(unknown)
	return unknown
}

func (r *ACLRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state aclRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	observed, err := r.client.ReadACLRule(ctx, state.Name.ValueString())
	if errors.Is(err, zyxel.ErrACLRuleNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading ACL rule", fmt.Sprintf("reading ACL rule (%s): %s", state.Name.ValueString(), err))
		return
	}
	state = modelFromACLRule(observed)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ACLRuleResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unsupported ACL rule update", "ACL rule changes require replacement; in-place updates and reordering are not supported.")
}

func (r *ACLRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state aclRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteACLRule(ctx, state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting ACL rule", fmt.Sprintf("deleting ACL rule (%s): %s", state.Name.ValueString(), err))
	}
}

func (r *ACLRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid ACL rule import ID", "Import ID must be the exact, non-empty router rule name.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func modelACLRule(model aclRuleModel) zyxel.ACLRule {
	var destinationStart, destinationEnd *int64
	if !model.DestinationPortStart.IsNull() && !model.DestinationPortStart.IsUnknown() {
		value := model.DestinationPortStart.ValueInt64()
		destinationStart = &value
	}
	if !model.DestinationPortEnd.IsNull() && !model.DestinationPortEnd.IsUnknown() {
		value := model.DestinationPortEnd.ValueInt64()
		destinationEnd = &value
	}
	var sourceStart, sourceEnd *int64
	if !model.SourcePortStart.IsNull() && !model.SourcePortStart.IsUnknown() {
		value := model.SourcePortStart.ValueInt64()
		sourceStart = &value
	}
	if !model.SourcePortEnd.IsNull() && !model.SourcePortEnd.IsUnknown() {
		value := model.SourcePortEnd.ValueInt64()
		sourceEnd = &value
	}
	var packetsPerUnit *int64
	if !model.PacketsPerUnit.IsNull() && !model.PacketsPerUnit.IsUnknown() {
		value := model.PacketsPerUnit.ValueInt64()
		packetsPerUnit = &value
	}
	rateLimitUnit := "minute"
	if !model.RateLimitUnit.IsNull() && !model.RateLimitUnit.IsUnknown() {
		rateLimitUnit = model.RateLimitUnit.ValueString()
	}
	ipVersion := model.IPVersion.ValueString()
	if ipVersion == "" {
		ipVersion = "ipv4"
	}
	direction := model.Direction.ValueString()
	if direction == "" {
		direction = "wan_to_lan"
	}
	return zyxel.ACLRule{
		Name: model.Name.ValueString(), Action: model.Action.ValueString(), Order: model.Order.ValueInt64(),
		Protocol: model.Protocol.ValueString(), IPVersion: ipVersion, Direction: direction,
		MACAddress: aclModelString(model.MACAddress), Service: aclModelString(model.Service),
		TCPFlag:    aclModelString(model.TCPFlag),
		SourceCIDR: model.SourceCIDR.ValueString(), DestinationCIDR: model.DestinationCIDR.ValueString(),
		DestinationPortStart: destinationStart, DestinationPortEnd: destinationEnd,
		SourcePortStart: sourceStart, SourcePortEnd: sourceEnd, Enabled: model.Enabled.ValueBool(),
		RateLimit: packetsPerUnit, RateLimitUnit: rateLimitUnit,
	}
}

func aclModelString(value types.String) string {
	if value.IsNull() || value.IsUnknown() {
		return ""
	}
	return value.ValueString()
}

func modelFromACLRule(rule zyxel.ACLRule) aclRuleModel {
	model := aclRuleModel{
		Name: types.StringValue(rule.Name), Action: types.StringValue(rule.Action), Order: types.Int64Value(rule.Order),
		Protocol: types.StringValue(rule.Protocol), IPVersion: types.StringValue(rule.IPVersion),
		Direction: types.StringValue(rule.Direction), SourceCIDR: types.StringValue(rule.SourceCIDR),
		DestinationCIDR:      types.StringValue(rule.DestinationCIDR),
		DestinationPortStart: types.Int64Null(), DestinationPortEnd: types.Int64Null(),
		Enabled: types.BoolValue(rule.Enabled), RouterIndex: types.Int64Value(rule.RouterIndex),
		SourcePortStart: types.Int64Null(), SourcePortEnd: types.Int64Null(),
		PacketsPerUnit: types.Int64Null(), RateLimitUnit: types.StringValue("minute"),
	}
	model.MACAddress = types.StringNull()
	if rule.MACAddress != "" {
		model.MACAddress = types.StringValue(rule.MACAddress)
	}
	model.Service = types.StringNull()
	if rule.Service != "" {
		model.Service = types.StringValue(rule.Service)
	}
	model.TCPFlag = types.StringNull()
	if rule.TCPFlag != "" {
		model.TCPFlag = types.StringValue(rule.TCPFlag)
	}
	if rule.DestinationPortStart != nil {
		model.DestinationPortStart = types.Int64Value(*rule.DestinationPortStart)
	}
	if rule.DestinationPortEnd != nil {
		model.DestinationPortEnd = types.Int64Value(*rule.DestinationPortEnd)
	}
	if rule.SourcePortStart != nil {
		model.SourcePortStart = types.Int64Value(*rule.SourcePortStart)
	}
	if rule.SourcePortEnd != nil {
		model.SourcePortEnd = types.Int64Value(*rule.SourcePortEnd)
	}
	if rule.RateLimit != nil {
		model.PacketsPerUnit = types.Int64Value(*rule.RateLimit)
	}
	if rule.RateLimitUnit != "" {
		model.RateLimitUnit = types.StringValue(rule.RateLimitUnit)
	}
	return model
}

type aclNameValidator struct{}

func (aclNameValidator) Description(context.Context) string {
	return "must not be empty or consist only of whitespace"
}
func (aclNameValidator) MarkdownDescription(ctx context.Context) string {
	return aclNameValidator{}.Description(ctx)
}
func (aclNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.TrimSpace(req.ConfigValue.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL rule name", "name must not be empty or consist only of whitespace.")
	}
}

type aclActionValidator struct{}

func (aclActionValidator) Description(context.Context) string {
	return "must be `accept`, `drop`, or `reject`"
}
func (aclActionValidator) MarkdownDescription(ctx context.Context) string {
	return aclActionValidator{}.Description(ctx)
}
func (aclActionValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch req.ConfigValue.ValueString() {
	case "accept", "drop", "reject":
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL action", "action must be `accept`, `drop`, or `reject`.")
}

type aclProtocolValidator struct{}

func (aclProtocolValidator) Description(context.Context) string {
	return "must be `all`, `tcp_udp`, `tcp`, `udp`, `icmp`, or `icmpv6`"
}
func (aclProtocolValidator) MarkdownDescription(ctx context.Context) string {
	return aclProtocolValidator{}.Description(ctx)
}
func (aclProtocolValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch req.ConfigValue.ValueString() {
	case "all", "tcp_udp", "tcp", "udp", "icmp", "icmpv6":
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL protocol", "protocol must be `all`, `tcp_udp`, `tcp`, `udp`, `icmp`, or `icmpv6`.")
}

func aclProtocolSupportsPorts(protocol string) bool {
	return protocol == "tcp" || protocol == "udp" || protocol == "tcp_udp"
}

type aclIPVersionValidator struct{}

func (aclIPVersionValidator) Description(context.Context) string { return "must be `ipv4` or `ipv6`" }
func (aclIPVersionValidator) MarkdownDescription(ctx context.Context) string {
	return aclIPVersionValidator{}.Description(ctx)
}
func (aclIPVersionValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueString() != "ipv4" && req.ConfigValue.ValueString() != "ipv6" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP version", "ip_version must be `ipv4` or `ipv6`.")
	}
}

type aclDirectionValidator struct{}

func (aclDirectionValidator) Description(context.Context) string {
	return "must be `wan_to_lan`, `lan_to_wan`, `wan_to_router`, or `lan_to_router`"
}
func (aclDirectionValidator) MarkdownDescription(ctx context.Context) string {
	return aclDirectionValidator{}.Description(ctx)
}
func (aclDirectionValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch req.ConfigValue.ValueString() {
	case "wan_to_lan", "lan_to_wan", "wan_to_router", "lan_to_router":
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL direction", "direction must be `wan_to_lan`, `lan_to_wan`, `wan_to_router`, or `lan_to_router`.")
}

type aclMACValidator struct{}

func (aclMACValidator) Description(context.Context) string {
	return "must be a canonical six-octet colon-separated uppercase MAC address"
}
func (aclMACValidator) MarkdownDescription(ctx context.Context) string {
	return aclMACValidator{}.Description(ctx)
}
func (aclMACValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 || strings.ToUpper(hardware.String()) != value {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid MAC address", "mac_address must be six colon-separated uppercase hexadecimal octets (for example, `AA:BB:CC:DD:EE:FF`).")
	}
}

type aclServiceValidator struct{}

func (aclServiceValidator) Description(context.Context) string {
	return "must be a non-empty custom service name without surrounding whitespace"
}
func (aclServiceValidator) MarkdownDescription(ctx context.Context) string {
	return aclServiceValidator{}.Description(ctx)
}
func (aclServiceValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL service name", "service must be a non-empty custom service name without leading or trailing whitespace.")
	}
}

type aclTCPFlagValidator struct{}

func (aclTCPFlagValidator) Description(context.Context) string {
	return "must be `syn`, `ack`, `urg`, `psh`, `rst`, or `fin`"
}
func (aclTCPFlagValidator) MarkdownDescription(ctx context.Context) string {
	return aclTCPFlagValidator{}.Description(ctx)
}
func (aclTCPFlagValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch req.ConfigValue.ValueString() {
	case "syn", "ack", "urg", "psh", "rst", "fin":
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid TCP flag", "tcp_flag must be `syn`, `ack`, `urg`, `psh`, `rst`, or `fin`.")
}

type aclRateLimitUnitValidator struct{}

func (aclRateLimitUnitValidator) Description(context.Context) string {
	return "must be `minute` or `second`"
}
func (aclRateLimitUnitValidator) MarkdownDescription(ctx context.Context) string {
	return aclRateLimitUnitValidator{}.Description(ctx)
}
func (aclRateLimitUnitValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueString() != "minute" && req.ConfigValue.ValueString() != "second" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid rate limit unit", "rate_limit_unit must be `minute` or `second`.")
	}
}

type aclCIDRValidator struct{}

func (aclCIDRValidator) Description(context.Context) string {
	return "must be a canonical IPv4 or IPv6 CIDR network address"
}
func (aclCIDRValidator) MarkdownDescription(ctx context.Context) string {
	return aclCIDRValidator{}.Description(ctx)
}
func (aclCIDRValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, ok := aclCIDRFamily(req.ConfigValue.ValueString()); !ok {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR", "CIDR must use IPv4 or IPv6 and the canonical network address for its prefix (for example, `192.0.2.0/24` or `2001:db8::/32`).")
	}
}

// aclCIDRFamily returns 4 or 6 for a canonical CIDR. IPv4-mapped IPv6
// addresses are rejected so the value maps cleanly to the router's IPVersion.
func aclCIDRFamily(value string) (int64, bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() {
		return 0, false
	}
	if prefix.Addr().Is4() {
		return 4, true
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return 6, true
	}
	return 0, false
}

type aclInt64Validator struct{ minimum, maximum int64 }

func (v aclInt64Validator) Description(context.Context) string {
	if v.maximum == 0 {
		return fmt.Sprintf("must be at least %d", v.minimum)
	}
	return fmt.Sprintf("must be between %d and %d", v.minimum, v.maximum)
}
func (v aclInt64Validator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v aclInt64Validator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueInt64()
	if value < v.minimum || (v.maximum != 0 && value > v.maximum) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL numeric value", v.Description(context.Background())+".")
	}
}
