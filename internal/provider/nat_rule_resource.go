package provider

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &NATRuleResource{}
	_ resource.ResourceWithConfigure      = &NATRuleResource{}
	_ resource.ResourceWithImportState    = &NATRuleResource{}
	_ resource.ResourceWithValidateConfig = &NATRuleResource{}
)

func NewNATRuleResource() resource.Resource { return &NATRuleResource{} }

type NATRuleResource struct{ client *zyxel.Client }

type natRuleModel struct {
	Name              types.String `tfsdk:"name"`
	Protocol          types.String `tfsdk:"protocol"`
	ExternalPortStart types.Int64  `tfsdk:"external_port_start"`
	ExternalPortEnd   types.Int64  `tfsdk:"external_port_end"`
	InternalClient    types.String `tfsdk:"internal_client"`
	InternalPortStart types.Int64  `tfsdk:"internal_port_start"`
	InternalPortEnd   types.Int64  `tfsdk:"internal_port_end"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	RouterIndex       types.Int64  `tfsdk:"router_index"`
}

func (r *NATRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nat_rule"
}

func (r *NATRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceString := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	replaceInt := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	portValidators := []validator.Int64{natPortValidator{}}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one supported router NAT rule. The router has no verified in-place update operation, so changes replace the rule. Existing rules must be imported by exact name. Enabled rules cannot overlap external ports for an intersecting protocol; disabled rules do not reserve ports. The create payload omits interface-specific settings and lets the router choose its defaults.",
		Attributes: map[string]schema.Attribute{
			"name":                schema.StringAttribute{Required: true, MarkdownDescription: "Exact, nonempty router description. This is the natural identity and import key; leading and trailing whitespace are not allowed.", PlanModifiers: replaceString, Validators: []validator.String{natNameValidator{}}},
			"protocol":            schema.StringAttribute{Required: true, MarkdownDescription: "Transport protocol: `tcp`, `udp`, `both`, or `all`. The router stores these as `TCP`, `UDP`, `TCP+UDP`, or `ALL`; `all` forwards every protocol, which is not the same as `both`.", PlanModifiers: replaceString, Validators: []validator.String{natProtocolValidator{}}},
			"external_port_start": schema.Int64Attribute{Required: true, MarkdownDescription: "First external port, from 1 through 65535. External and internal ranges must have equal lengths.", PlanModifiers: replaceInt, Validators: portValidators},
			"external_port_end":   schema.Int64Attribute{Required: true, MarkdownDescription: "Last external port, from 1 through 65535, inclusive. Must be greater than or equal to the start port.", PlanModifiers: replaceInt, Validators: portValidators},
			"internal_client":     schema.StringAttribute{Required: true, MarkdownDescription: "IPv4 address of the destination host.", PlanModifiers: replaceString, Validators: []validator.String{natIPv4Validator{}}},
			"internal_port_start": schema.Int64Attribute{Required: true, MarkdownDescription: "First internal port, from 1 through 65535. External and internal ranges must have equal lengths.", PlanModifiers: replaceInt, Validators: portValidators},
			"internal_port_end":   schema.Int64Attribute{Required: true, MarkdownDescription: "Last internal port, from 1 through 65535, inclusive. Must be greater than or equal to the start port.", PlanModifiers: replaceInt, Validators: portValidators},
			"enabled":             schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the router reports this rule enabled. New rules are created enabled; this attribute is read-only because no safe update operation is verified."},
			"router_index":        schema.Int64Attribute{Computed: true, MarkdownDescription: "Current router list index used only as a locator. It may change when other rules are added or removed and is not used as resource identity."},
		},
	}
}

func (r *NATRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config natRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.ExternalPortStart.IsUnknown() || config.ExternalPortEnd.IsUnknown() || config.InternalPortStart.IsUnknown() || config.InternalPortEnd.IsUnknown() {
		return
	}
	if config.ExternalPortStart.IsNull() || config.ExternalPortEnd.IsNull() || config.InternalPortStart.IsNull() || config.InternalPortEnd.IsNull() {
		return
	}
	extStart, extEnd := config.ExternalPortStart.ValueInt64(), config.ExternalPortEnd.ValueInt64()
	intStart, intEnd := config.InternalPortStart.ValueInt64(), config.InternalPortEnd.ValueInt64()
	if extStart < 1 || extStart > 65535 || extEnd < 1 || extEnd > 65535 || intStart < 1 || intStart > 65535 || intEnd < 1 || intEnd > 65535 {
		return
	}
	if extEnd < extStart {
		resp.Diagnostics.AddAttributeError(path.Root("external_port_end"), "Invalid external port range", "external_port_end must be greater than or equal to external_port_start.")
	}
	if intEnd < intStart {
		resp.Diagnostics.AddAttributeError(path.Root("internal_port_end"), "Invalid internal port range", "internal_port_end must be greater than or equal to internal_port_start.")
	}
	if extEnd >= extStart && intEnd >= intStart && extEnd-extStart != intEnd-intStart {
		resp.Diagnostics.AddAttributeError(path.Root("internal_port_end"), "Unequal port range lengths", "The external and internal port ranges must contain the same number of ports.")
	}
}

func (r *NATRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *NATRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var plan natRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rule := modelNATRule(plan)
	created, err := r.client.CreateNATRule(ctx, rule)
	if created {
		// Preserve the known natural identity and arguments if POST succeeded but
		// readback failed. Terraform must not receive unknown computed state.
		plan.Enabled = types.BoolValue(true)
		plan.RouterIndex = types.Int64Null()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
	if err != nil {
		resp.Diagnostics.AddError("Error creating NAT rule", fmt.Sprintf("creating NAT rule (%s): %s", plan.Name.ValueString(), err))
		return
	}
	found, err := r.client.ReadNATRule(ctx, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading created NAT rule", fmt.Sprintf("reading NAT rule (%s): %s", plan.Name.ValueString(), err))
		return
	}
	if found == nil {
		resp.Diagnostics.AddError("Missing NAT rule after create", "The router accepted the create request, but the rule is not present in the subsequent read.")
		return
	}
	setNATComputed(&plan, *found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NATRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state natRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.client.ReadNATRule(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading NAT rule", fmt.Sprintf("reading NAT rule (%s): %s", state.Name.ValueString(), err))
		return
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.Protocol = types.StringValue(found.Protocol)
	state.ExternalPortStart = types.Int64Value(found.ExternalPortStart)
	state.ExternalPortEnd = types.Int64Value(found.ExternalPortEnd)
	state.InternalClient = types.StringValue(found.InternalClient)
	state.InternalPortStart = types.Int64Value(found.InternalPortStart)
	state.InternalPortEnd = types.Int64Value(found.InternalPortEnd)
	setNATComputed(&state, *found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NATRuleResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unsupported NAT rule update", "NAT rule changes require replacement; in-place updates are not supported.")
}

func (r *NATRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state natRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteNATRule(ctx, state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting NAT rule", fmt.Sprintf("deleting NAT rule (%s): %s", state.Name.ValueString(), err))
	}
}

func (r *NATRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID
	if name == "" || strings.TrimSpace(name) != name {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid NAT rule import ID", "Import ID must exactly match a nonempty router rule description without surrounding whitespace.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func modelNATRule(model natRuleModel) zyxel.NATRule {
	return zyxel.NATRule{Name: model.Name.ValueString(), Protocol: model.Protocol.ValueString(), ExternalPortStart: model.ExternalPortStart.ValueInt64(), ExternalPortEnd: model.ExternalPortEnd.ValueInt64(), InternalClient: model.InternalClient.ValueString(), InternalPortStart: model.InternalPortStart.ValueInt64(), InternalPortEnd: model.InternalPortEnd.ValueInt64()}
}

func setNATComputed(model *natRuleModel, rule zyxel.NATRule) {
	model.Enabled = types.BoolValue(rule.Enabled)
	model.RouterIndex = types.Int64Value(rule.Index)
}

type natNameValidator struct{}

func (natNameValidator) Description(context.Context) string {
	return "value must be nonempty and have no leading or trailing whitespace"
}
func (natNameValidator) MarkdownDescription(ctx context.Context) string {
	return natNameValidator{}.Description(ctx)
}
func (natNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	if value == "" || strings.TrimSpace(value) != value {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid NAT rule name", "Name must be nonempty and must not have leading or trailing whitespace.")
	}
}

type natIPv4Validator struct{}

func (natIPv4Validator) Description(context.Context) string {
	return "value must be a valid IPv4 address"
}
func (natIPv4Validator) MarkdownDescription(ctx context.Context) string {
	return natIPv4Validator{}.Description(ctx)
}
func (natIPv4Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	parsed := net.ParseIP(req.ConfigValue.ValueString())
	if parsed == nil || parsed.To4() == nil || strings.ContainsAny(req.ConfigValue.ValueString(), "/:") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IPv4 address", "Value must be a valid IPv4 address, such as `192.0.2.10`.")
	}
}

type natProtocolValidator struct{}

func (natProtocolValidator) Description(context.Context) string {
	return "value must be tcp, udp, both, or all"
}
func (natProtocolValidator) MarkdownDescription(ctx context.Context) string {
	return natProtocolValidator{}.Description(ctx)
}
func (natProtocolValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch req.ConfigValue.ValueString() {
	case "tcp", "udp", "both", "all":
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid NAT protocol", "Protocol must be `tcp`, `udp`, `both`, or `all`.")
}

type natPortValidator struct{}

func (natPortValidator) Description(context.Context) string {
	return "value must be between 1 and 65535"
}
func (natPortValidator) MarkdownDescription(ctx context.Context) string {
	return natPortValidator{}.Description(ctx)
}
func (natPortValidator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	port := req.ConfigValue.ValueInt64()
	if port < 1 || port > 65535 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid port", "Port must be between 1 and 65535.")
	}
}
