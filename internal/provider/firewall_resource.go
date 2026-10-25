package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &FirewallResource{}
	_ resource.ResourceWithConfigure   = &FirewallResource{}
	_ resource.ResourceWithImportState = &FirewallResource{}
)

func NewFirewallResource() resource.Resource { return &FirewallResource{} }

type FirewallResource struct{ client *Client }

type firewallModel struct {
	ID                   types.String `tfsdk:"id"`
	IPv4Enabled          types.Bool   `tfsdk:"ipv4_enabled"`
	IPv6Enabled          types.Bool   `tfsdk:"ipv6_enabled"`
	SecurityLevel        types.String `tfsdk:"security_level"`
	DoSProtectionEnabled types.Bool   `tfsdk:"dos_protection_enabled"`
}

func (r *FirewallResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall"
}

func (r *FirewallResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages router-wide Firewall General settings and DoS Protection Blocking. Create adopts and configures the built-in settings; changes update in place. Only the documented General and DoS fields are written, leaving ACL rules and other settings untouched. Manage only one instance per router, including across Terraform states. Destroy stops management without changing the router. Live writes have not been verified on hardware.",
		Attributes: map[string]schema.Attribute{
			"id":                     schema.StringAttribute{Computed: true, MarkdownDescription: "Singleton identity, always `router`. Use `router` as the import ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ipv4_enabled":           schema.BoolAttribute{Required: true, MarkdownDescription: "Whether the IPv4 firewall is enabled."},
			"ipv6_enabled":           schema.BoolAttribute{Required: true, MarkdownDescription: "Whether the IPv6 firewall is enabled."},
			"security_level":         schema.StringAttribute{Required: true, MarkdownDescription: "Firewall security level as shown in the UI: `low`, `medium` (recommended), or `high`. These map to router Level_GUI values Off, Low, and High respectively.", Validators: []validator.String{firewallLevelValidator{}}},
			"dos_protection_enabled": schema.BoolAttribute{Required: true, MarkdownDescription: "Whether DoS Protection Blocking is enabled."},
		},
	}
}

func (r *FirewallResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected resource configuration", fmt.Sprintf("Expected *Client, got %T.", req.ProviderData))
		return
	}
	r.client = client
}

func (r *FirewallResource) apply(ctx context.Context, plan *firewallModel, diagnostics *diag.Diagnostics) bool {
	if r.client == nil {
		diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return false
	}

	for name, unknown := range map[string]bool{
		"ipv4_enabled":           plan.IPv4Enabled.IsNull() || plan.IPv4Enabled.IsUnknown(),
		"ipv6_enabled":           plan.IPv6Enabled.IsNull() || plan.IPv6Enabled.IsUnknown(),
		"security_level":         plan.SecurityLevel.IsNull() || plan.SecurityLevel.IsUnknown(),
		"dos_protection_enabled": plan.DoSProtectionEnabled.IsNull() || plan.DoSProtectionEnabled.IsUnknown(),
	} {
		if unknown {
			diagnostics.AddAttributeError(path.Root(name), "Unknown firewall value", "The value must be known before applying firewall settings.")
		}
	}
	if diagnostics.HasError() {
		return false
	}
	plan.ID = types.StringValue("router")
	applied, err := r.client.SetFirewall(ctx, FirewallSettings{IPv4Enabled: plan.IPv4Enabled.ValueBool(), IPv6Enabled: plan.IPv6Enabled.ValueBool(), SecurityLevel: plan.SecurityLevel.ValueString(), DoSProtectionEnabled: plan.DoSProtectionEnabled.ValueBool()})
	if err != nil {
		detail := err.Error()
		if applied {
			detail += " The router may have applied the setting. Refresh state and inspect the router before retrying."
		}
		diagnostics.AddError("Error configuring firewall", detail)
	}
	return applied
}

func (r *FirewallResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan firewallModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.apply(ctx, &plan, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *FirewallResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	settings, err := r.client.ReadFirewall(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall", err.Error())
		return
	}
	state := firewallModel{ID: types.StringValue("router"), IPv4Enabled: types.BoolValue(settings.IPv4Enabled), IPv6Enabled: types.BoolValue(settings.IPv6Enabled), SecurityLevel: types.StringValue(settings.SecurityLevel), DoSProtectionEnabled: types.BoolValue(settings.DoSProtectionEnabled)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *FirewallResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan firewallModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.apply(ctx, &plan, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *FirewallResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// This built-in setting cannot be deleted; preserve protection on destroy.
}

func (r *FirewallResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != "router" {
		resp.Diagnostics.AddError("Invalid firewall import ID", "The import ID must be router.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), "router")...)
}

type firewallLevelValidator struct{}

func (firewallLevelValidator) Description(context.Context) string {
	return "value must be low, medium, or high"
}
func (v firewallLevelValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (firewallLevelValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, ok := firewallLevels[req.ConfigValue.ValueString()]; !ok {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid firewall security level", "security_level must be low, medium, or high.")
	}
}
