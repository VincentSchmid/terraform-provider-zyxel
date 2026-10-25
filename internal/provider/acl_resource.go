package provider

import (
	"context"
	"errors"
	"fmt"
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
	portDescription := "TCP port from 1 through 65535; the range end must be at least the start. Changing it replaces the ACL rule."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one firewall ACL entry in the router's `firewall_acl` table, limited to the supported IPv4/TCP/`WAN_TO_LAN` profile with interface `ALL`, custom service index `0`, no schedule, and no MAC or IPv6 filters. Optional packet rate limiting is supported for `accept` rules. Existing rows must be imported by exact name; imported rows outside this fixed profile are rejected. All configurable fields require replacement because no safe in-place update or reorder operation has been verified. The router applies order globally; this resource does not guarantee a complete firewall policy across independent resources or Terraform states.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true, MarkdownDescription: "Exact, non-empty router rule name. This is the natural identity and import key; duplicate names are ambiguous.",
				PlanModifiers: replaceString, Validators: []validator.String{aclNameValidator{}},
			},
			"action": schema.StringAttribute{
				Required: true, MarkdownDescription: "ACL action: `accept` or `drop`. The router stores these as `Accept` or `Drop`.",
				PlanModifiers: replaceString, Validators: []validator.String{aclActionValidator{}},
			},
			"order": schema.Int64Attribute{
				Required: true, MarkdownDescription: "Explicit desired order in the router's global ACL table. Existing use of this order is rejected. Router order behavior must be verified before production use.",
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1}},
			},
			"source_cidr": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("0.0.0.0/0"),
				MarkdownDescription: "IPv4 source CIDR. Defaults to `0.0.0.0/0` (any source). Use the canonical network address for the prefix; changing it replaces the rule.",
				PlanModifiers:       replaceString, Validators: []validator.String{aclIPv4CIDRValidator{}},
			},
			"destination_cidr": schema.StringAttribute{
				Required: true, MarkdownDescription: "Canonical IPv4 destination CIDR. Changing it replaces the ACL rule.",
				PlanModifiers: replaceString, Validators: []validator.String{aclIPv4CIDRValidator{}},
			},
			"destination_port_start": schema.Int64Attribute{
				Required: true, MarkdownDescription: portDescription,
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"destination_port_end": schema.Int64Attribute{
				Required: true, MarkdownDescription: portDescription,
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"source_port_start": schema.Int64Attribute{
				Optional: true, MarkdownDescription: "Optional TCP source port range start. Leave both source port bounds null for any source port; null maps to router values `-1/-1`.",
				PlanModifiers: replaceInt, Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 65535}},
			},
			"source_port_end": schema.Int64Attribute{
				Optional: true, MarkdownDescription: "Optional TCP source port range end. Set this together with `source_port_start`; changing it replaces the ACL rule.",
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
	if config.SourcePortStart.IsUnknown() || config.SourcePortEnd.IsUnknown() {
		// Terraform may resolve either bound during apply; validate the pair then.
	} else if config.SourcePortStart.IsNull() != config.SourcePortEnd.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("source_port_end"), "Incomplete source port range", "Set both `source_port_start` and `source_port_end`, or leave both null for any source port.")
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
	if config.DestinationPortStart.IsUnknown() || config.DestinationPortEnd.IsUnknown() || config.DestinationPortStart.IsNull() || config.DestinationPortEnd.IsNull() {
		return
	}
	if config.DestinationPortEnd.ValueInt64() < config.DestinationPortStart.ValueInt64() {
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
	for name, value := range map[string]types.String{"name": model.Name, "action": model.Action, "source_cidr": model.SourceCIDR, "destination_cidr": model.DestinationCIDR, "rate_limit_unit": model.RateLimitUnit} {
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
	return zyxel.ACLRule{
		Name: model.Name.ValueString(), Action: model.Action.ValueString(), Order: model.Order.ValueInt64(),
		SourceCIDR: model.SourceCIDR.ValueString(), DestinationCIDR: model.DestinationCIDR.ValueString(),
		DestinationPortStart: model.DestinationPortStart.ValueInt64(), DestinationPortEnd: model.DestinationPortEnd.ValueInt64(),
		SourcePortStart: sourceStart, SourcePortEnd: sourceEnd, Enabled: model.Enabled.ValueBool(),
		RateLimit: packetsPerUnit, RateLimitUnit: rateLimitUnit,
	}
}

func modelFromACLRule(rule zyxel.ACLRule) aclRuleModel {
	model := aclRuleModel{
		Name: types.StringValue(rule.Name), Action: types.StringValue(rule.Action), Order: types.Int64Value(rule.Order),
		SourceCIDR: types.StringValue(rule.SourceCIDR), DestinationCIDR: types.StringValue(rule.DestinationCIDR),
		DestinationPortStart: types.Int64Value(rule.DestinationPortStart), DestinationPortEnd: types.Int64Value(rule.DestinationPortEnd),
		Enabled: types.BoolValue(rule.Enabled), RouterIndex: types.Int64Value(rule.RouterIndex),
		SourcePortStart: types.Int64Null(), SourcePortEnd: types.Int64Null(),
		PacketsPerUnit: types.Int64Null(), RateLimitUnit: types.StringValue("minute"),
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

func (aclActionValidator) Description(context.Context) string { return "must be `accept` or `drop`" }
func (aclActionValidator) MarkdownDescription(ctx context.Context) string {
	return aclActionValidator{}.Description(ctx)
}
func (aclActionValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueString() != "accept" && req.ConfigValue.ValueString() != "drop" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ACL action", "action must be `accept` or `drop`.")
	}
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

type aclIPv4CIDRValidator struct{}

func (aclIPv4CIDRValidator) Description(context.Context) string {
	return "must be a canonical IPv4 CIDR network address"
}
func (aclIPv4CIDRValidator) MarkdownDescription(ctx context.Context) string {
	return aclIPv4CIDRValidator{}.Description(ctx)
}
func (aclIPv4CIDRValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IPv4 CIDR", "CIDR must use IPv4 and the canonical network address for its prefix (for example, `192.0.2.0/24`).")
	}
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
