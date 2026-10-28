package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &DNSRecordResource{}
	_ resource.ResourceWithConfigure   = &DNSRecordResource{}
	_ resource.ResourceWithImportState = &DNSRecordResource{}
)

func NewDNSRecordResource() resource.Resource { return &DNSRecordResource{} }

type DNSRecordResource struct{ client *zyxel.Client }

type dnsRecordModel struct {
	Hostname    types.String `tfsdk:"hostname"`
	IPv4Address types.String `tfsdk:"ipv4_address"`
	RouterIndex types.Int64  `tfsdk:"router_index"`
}

func (r *DNSRecordResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_record"
}

func (r *DNSRecordResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceString := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one local DNS host record (`Network Setting > DNS > DNS Entry`) that maps a host name to an IPv4 address. The router has no verified in-place update operation, so every configurable change replaces the record. Existing records must be imported by host name. Host names are compared without regard to letter case; the router's own entry limit still applies.",
		Attributes: map[string]schema.Attribute{
			"hostname":     schema.StringAttribute{Required: true, MarkdownDescription: "Canonical lowercase host name with at least two dot-separated labels, such as `host.example.test`. Each label is 1-63 characters of letters, digits, hyphens, or underscores and starts and ends with a letter or digit. This is the natural identity and import key.", PlanModifiers: replaceString, Validators: []validator.String{dnsHostnameValidator{}}},
			"ipv4_address": schema.StringAttribute{Required: true, MarkdownDescription: "IPv4 address returned for this host name. Changing it replaces the record.", PlanModifiers: replaceString, Validators: []validator.String{ipv4Validator{}}},
			"router_index": schema.Int64Attribute{Computed: true, MarkdownDescription: "Current router list index used only as a locator. It may change when other records are added or removed and is not used as resource identity."},
		},
	}
}

func (r *DNSRecordResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DNSRecordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var plan dnsRecordModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, unknown := range map[string]bool{
		"hostname":     plan.Hostname.IsNull() || plan.Hostname.IsUnknown(),
		"ipv4_address": plan.IPv4Address.IsNull() || plan.IPv4Address.IsUnknown(),
	} {
		if unknown {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown DNS record value", "The planned value must be known before creating a DNS record.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	hostname := plan.Hostname.ValueString()
	created, err := r.client.CreateDNSEntry(ctx, hostname, plan.IPv4Address.ValueString())
	if created {
		// Preserve the known natural identity and arguments if POST succeeded but
		// readback failed. Terraform must not receive unknown computed state.
		plan.RouterIndex = types.Int64Null()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
	if err != nil {
		detail := fmt.Sprintf("creating DNS record (%s): %s", hostname, err)
		var ambiguous *zyxel.AmbiguousWriteError
		if errors.As(err, &ambiguous) && created {
			detail += " The router may have applied the write; refresh the record or import its host name to recover state."
		}
		resp.Diagnostics.AddError("Error creating DNS record", detail)
		return
	}
	found, err := r.client.ReadDNSEntry(ctx, hostname)
	if err != nil {
		resp.Diagnostics.AddError("Error reading created DNS record", fmt.Sprintf("reading DNS record (%s): %s", hostname, err))
		return
	}
	if found == nil {
		resp.Diagnostics.AddError("Missing DNS record after create", "The router accepted the create request, but the record is not present in the subsequent read.")
		return
	}
	setDNSRecordObserved(&plan, *found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DNSRecordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state dnsRecordModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.client.ReadDNSEntry(ctx, state.Hostname.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading DNS record", fmt.Sprintf("reading DNS record (%s): %s", state.Hostname.ValueString(), err))
		return
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	setDNSRecordObserved(&state, *found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DNSRecordResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unsupported DNS record update", "DNS record changes require replacement; in-place updates are not supported.")
}

func (r *DNSRecordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var state dnsRecordModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteDNSEntry(ctx, state.Hostname.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting DNS record", fmt.Sprintf("deleting DNS record (%s): %s", state.Hostname.ValueString(), err))
	}
}

func (r *DNSRecordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	hostname, err := zyxel.NormalizeHostname(req.ID)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("hostname"), "Invalid DNS record import ID", "Import ID must be a valid host name such as `host.example.test`.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("hostname"), hostname)...)
}

func setDNSRecordObserved(model *dnsRecordModel, entry zyxel.DNSEntry) {
	model.Hostname = types.StringValue(entry.HostName)
	model.IPv4Address = types.StringValue(entry.IPv4Address)
	model.RouterIndex = types.Int64Value(entry.Index)
}

type dnsHostnameValidator struct{}

func (dnsHostnameValidator) Description(context.Context) string {
	return "value must be a canonical lowercase host name with at least two dot-separated labels"
}
func (dnsHostnameValidator) MarkdownDescription(ctx context.Context) string {
	return dnsHostnameValidator{}.Description(ctx)
}
func (dnsHostnameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	if canonical, err := zyxel.NormalizeHostname(value); err != nil || canonical != value {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid host name", "Value must be a canonical lowercase host name such as `host.example.test`, with at least two dot-separated labels of 1-63 letters, digits, hyphens, or underscores that start and end with a letter or digit.")
	}
}
