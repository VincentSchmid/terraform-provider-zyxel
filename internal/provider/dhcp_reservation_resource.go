package provider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &DHCPReservationResource{}
	_ resource.ResourceWithConfigure      = &DHCPReservationResource{}
	_ resource.ResourceWithImportState    = &DHCPReservationResource{}
	_ resource.ResourceWithValidateConfig = &DHCPReservationResource{}
)

func NewDHCPReservationResource() resource.Resource { return &DHCPReservationResource{} }

type DHCPReservationResource struct{ client *zyxel.Client }

type dhcpReservationModel struct {
	MACAddress types.String `tfsdk:"mac_address"`
	IPv4       types.String `tfsdk:"ipv4_address"`
	Enabled    types.Bool   `tfsdk:"enabled"`
}

func (r *DHCPReservationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_reservation"
}

func (r *DHCPReservationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Manages one static DHCP reservation on the router. The router binds reservations to its default LAN bridge; that bridge is fixed by the provider.", Attributes: map[string]schema.Attribute{
		"mac_address":  schema.StringAttribute{Required: true, MarkdownDescription: "Canonical uppercase colon-separated MAC address. This is the resource identity and import key.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Validators: []validator.String{macValidator{}}},
		"ipv4_address": schema.StringAttribute{Required: true, MarkdownDescription: "IPv4 address reserved for this MAC address. Changing it replaces the reservation.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Validators: []validator.String{ipv4Validator{}}},
		"enabled":      schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Whether the reservation is enabled. It is configurable as `true` and defaults to `true`; a router-reported disabled value requires replacement.", PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}},
	}}
}

type macValidator struct{}

func (macValidator) Description(context.Context) string {
	return "value must be a canonical uppercase colon-separated MAC address"
}
func (macValidator) MarkdownDescription(ctx context.Context) string {
	return macValidator{}.Description(ctx)
}
func (macValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`).MatchString(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid MAC address", "Value must be a canonical uppercase colon-separated MAC address, such as `02:00:5E:10:00:01`.")
	}
}

func (r *DHCPReservationResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config dhcpReservationModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Enabled.IsNull() || config.Enabled.IsUnknown() {
		return
	}
	if !config.Enabled.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("enabled"), "Invalid enabled value", "enabled can only be configured as true; the router-reported value remains readable for drift detection.")
	}
}

func (r *DHCPReservationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DHCPReservationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var plan dhcpReservationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, unknown := range map[string]bool{
		"mac_address":  plan.MACAddress.IsNull() || plan.MACAddress.IsUnknown(),
		"ipv4_address": plan.IPv4.IsNull() || plan.IPv4.IsUnknown(),
		"enabled":      plan.Enabled.IsNull() || plan.Enabled.IsUnknown(),
	} {
		if unknown {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown DHCP reservation value", "The planned value must be known before creating a DHCP reservation.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Enabled.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("enabled"), "Invalid enabled value", "enabled can only be configured as true.")
		return
	}
	created, err := r.client.CreateDHCPReservation(ctx, plan.MACAddress.ValueString(), plan.IPv4.ValueString(), plan.Enabled.ValueBool())
	if created {
		// Keep the natural key and requested values recoverable if the router accepted
		// the write but its subsequent readback failed.
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
	if err != nil {
		detail := fmt.Sprintf("creating DHCP reservation (%s): %s", plan.MACAddress.ValueString(), err)
		var ambiguous *zyxel.AmbiguousWriteError
		if errors.As(err, &ambiguous) && created {
			detail += " The router may have applied the write; refresh the reservation or import its MAC address to recover state."
		}
		resp.Diagnostics.AddError("Error creating DHCP reservation", detail)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPReservationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state dhcpReservationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.client.ReadDHCPReservation(ctx, state.MACAddress.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading DHCP reservation", fmt.Sprintf("reading DHCP reservation (%s): %s", state.MACAddress.ValueString(), err))
		return
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.MACAddress = types.StringValue(strings.ToUpper(found.MACAddr))
	state.IPv4 = types.StringValue(found.IPAddr)
	state.Enabled = types.BoolValue(found.Enabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DHCPReservationResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unsupported DHCP reservation update", "DHCP reservation changes require replacement; in-place updates are not supported.")
}

func (r *DHCPReservationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state dhcpReservationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteDHCPReservation(ctx, state.MACAddress.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting DHCP reservation", fmt.Sprintf("deleting DHCP reservation (%s): %s", state.MACAddress.ValueString(), err))
	}
}

func (r *DHCPReservationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mac, err := zyxel.NormalizeMAC(req.ID)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("mac_address"), "Invalid DHCP reservation import ID", "Import ID must be a MAC address in colon or hyphen notation.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mac_address"), mac)...)
}

type ipv4Validator struct{}

func (ipv4Validator) Description(_ context.Context) string {
	return "value must be a valid IPv4 address"
}
func (ipv4Validator) MarkdownDescription(ctx context.Context) string {
	return ipv4Validator{}.Description(ctx)
}
func (ipv4Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	parsed, err := netip.ParseAddr(req.ConfigValue.ValueString())
	if err != nil || !parsed.Is4() {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IPv4 address", "Value must be a valid IPv4 address, such as `192.0.2.10`.")
	}
}
