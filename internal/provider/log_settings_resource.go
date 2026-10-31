package provider

import (
	"context"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &LogSettingsResource{}
	_ resource.ResourceWithConfigure   = &LogSettingsResource{}
	_ resource.ResourceWithImportState = &LogSettingsResource{}
)

func NewLogSettingsResource() resource.Resource { return &LogSettingsResource{} }

type LogSettingsResource struct{ client *zyxel.Client }

type logSettingsModel struct {
	ID      types.String `tfsdk:"id"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func (r *LogSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_log_settings"
}

func (r *LogSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages local-only logging under Maintenance > Log Setting. Create adopts and configures the built-in settings; changes update in place. Apply always selects Local File mode, stopping remote forwarding if a remote mode was previously selected. Remote server, port, TLS/certificates, email, and active log categories are preserved, not managed. Manage only one instance per router, including across Terraform states. Destroy stops management without changing logging. Enabling logging records new events; it does not recover past events. Live writes have not been verified on hardware.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Singleton identity, always `router`. Use `router` as the import ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"enabled": schema.BoolAttribute{Required: true, MarkdownDescription: "Whether local-only logging is enabled. Apply sets the logging switch to this value and always selects Local File mode. Refresh reports false if logging is disabled or a remote mode is selected."},
		},
	}
}

func (r *LogSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *LogSettingsResource) apply(ctx context.Context, plan *logSettingsModel, diagnostics *diag.Diagnostics) bool {
	if r.client == nil {
		diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return false
	}
	if plan.Enabled.IsNull() || plan.Enabled.IsUnknown() {
		diagnostics.AddAttributeError(path.Root("enabled"), "Unknown logging value", "The value must be known before applying logging settings.")
	}
	if diagnostics.HasError() {
		return false
	}
	plan.ID = types.StringValue("router")
	applied, err := r.client.SetLogSettings(ctx, zyxel.LogSettings{Enabled: plan.Enabled.ValueBool()})
	if err != nil {
		detail := err.Error()
		if applied {
			detail += " The router may have applied the settings. Refresh state and inspect the router before retrying."
		}
		diagnostics.AddError("Error configuring logging", detail)
	}
	return applied
}

func (r *LogSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan logSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.apply(ctx, &plan, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *LogSettingsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	settings, err := r.client.ReadLogSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading logging settings", err.Error())
		return
	}
	state := logSettingsModel{ID: types.StringValue("router"), Enabled: types.BoolValue(settings.Enabled)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *LogSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan logSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.apply(ctx, &plan, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *LogSettingsResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// Relinquish the built-in settings without disabling logging on destroy.
}

func (r *LogSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != "router" {
		resp.Diagnostics.AddError("Invalid logging import ID", "The import ID must be router.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), "router")...)
}
