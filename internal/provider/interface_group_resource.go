package provider

import (
	"context"
	"fmt"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &InterfaceGroupResource{}
	_ resource.ResourceWithConfigure      = &InterfaceGroupResource{}
	_ resource.ResourceWithImportState    = &InterfaceGroupResource{}
	_ resource.ResourceWithValidateConfig = &InterfaceGroupResource{}
)

func NewInterfaceGroupResource() resource.Resource { return &InterfaceGroupResource{} }

type InterfaceGroupResource struct{ client *zyxel.Client }
type interfaceGroupModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	WANInterfaces types.Set    `tfsdk:"wan_interfaces"`
	LANInterfaces types.Set    `tfsdk:"lan_interfaces"`
	RouterIndex   types.Int64  `tfsdk:"router_index"`
}

func (*InterfaceGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface_group"
}
func (*InterfaceGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Manages a port-based Network Setting > Interface Grouping entry. Its exact unique name is the ID for `zyxel_lan.interface_group_id`. Import existing groups explicitly; changes replace the group and interrupt its network. At least one WAN and one LAN interface are required. DHCP option, MAC, and VLAN classification criteria are not supported. The built-in Default group cannot be managed here; configure it with `zyxel_lan`. Deletion returns member interfaces to Default and removes the group's LAN configuration. Do not use create_before_destroy with the same name or interfaces. Replacing a group with a dependent LAN resource can require two applies: remove both resources, then recreate them. Live writes remain unverified on hardware.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true, MarkdownDescription: "Stable ID: exact group name, suitable for `zyxel_lan.interface_group_id`. Not a router row index."},
		"name":           schema.StringAttribute{Required: true, MarkdownDescription: "Exact unique group name and import key. Default is reserved. Changes replace the group.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"wan_interfaces": schema.SetAttribute{Required: true, ElementType: types.StringType, MarkdownDescription: "WAN interface paths, for example `IP.Interface.2`, obtained from the router WAN interface list. Must resolve uniquely and not belong to another non-default group. Changes replace the group.", PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()}},
		"lan_interfaces": schema.SetAttribute{Required: true, ElementType: types.StringType, MarkdownDescription: "LAN lower-layer paths, for example `Ethernet.Interface.2` or `WiFi.SSID.3`. The API resolves current bridge ports automatically. Must not belong to another non-default group. Changes replace the group.", PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()}},
		"router_index":   schema.Int64Attribute{Computed: true, MarkdownDescription: "Current display index for diagnostics only. Refreshed by name before deletion; never a durable identity."},
	}}
}
func (r *InterfaceGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func interfaceGroupFromModel(ctx context.Context, m interfaceGroupModel) (zyxel.InterfaceGroup, error) {
	if m.Name.IsUnknown() || m.Name.IsNull() || m.WANInterfaces.IsUnknown() || m.WANInterfaces.IsNull() || m.LANInterfaces.IsUnknown() || m.LANInterfaces.IsNull() {
		return zyxel.InterfaceGroup{}, fmt.Errorf("name and interface sets must be known before applying")
	}
	v := zyxel.InterfaceGroup{Name: m.Name.ValueString()}
	d := m.WANInterfaces.ElementsAs(ctx, &v.WANInterfaces, false)
	d.Append(m.LANInterfaces.ElementsAs(ctx, &v.LANInterfaces, false)...)
	if d.HasError() {
		return v, fmt.Errorf("interface paths must be known non-null strings")
	}
	return v, v.Validate()
}
func (*InterfaceGroupResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m interfaceGroupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Name.IsUnknown() || m.WANInterfaces.IsUnknown() || m.LANInterfaces.IsUnknown() {
		return
	}
	for _, set := range []types.Set{m.WANInterfaces, m.LANInterfaces} {
		for _, value := range set.Elements() {
			if value.IsUnknown() {
				return
			}
		}
	}
	if _, err := interfaceGroupFromModel(ctx, m); err != nil {
		resp.Diagnostics.AddError("Invalid interface group", err.Error())
	}
}
func (r *InterfaceGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m interfaceGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	v, err := interfaceGroupFromModel(ctx, m)
	if err != nil {
		resp.Diagnostics.AddError("Invalid interface group", err.Error())
		return
	}
	applied, err := r.client.CreateInterfaceGroup(ctx, v)
	if applied {
		m.ID = m.Name
		// Persist identity before any optional observation: the write may have
		// disconnected us, and losing the name would make recovery unsafe.
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		if err == nil {
			observed, readErr := r.client.ReadInterfaceGroup(ctx, v.Name)
			if readErr != nil {
				err = readErr
			} else if observed == nil {
				err = fmt.Errorf("created interface group disappeared")
			} else {
				m = interfaceGroupObservedModel(ctx, *observed)
				resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			}
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Error creating interface group", err.Error()+" If creation succeeded or may have succeeded, inspect the router and refresh state before retrying.")
	}
}
func interfaceGroupObservedModel(ctx context.Context, v zyxel.InterfaceGroup) interfaceGroupModel {
	wan, _ := types.SetValueFrom(ctx, types.StringType, v.WANInterfaces)
	lan, _ := types.SetValueFrom(ctx, types.StringType, v.LANInterfaces)
	return interfaceGroupModel{ID: types.StringValue(v.Name), Name: types.StringValue(v.Name), WANInterfaces: wan, LANInterfaces: lan, RouterIndex: types.Int64Value(v.RouterIndex)}
}
func (r *InterfaceGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m interfaceGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	v, err := r.client.ReadInterfaceGroup(ctx, m.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading interface group", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	m = interfaceGroupObservedModel(ctx, *v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (*InterfaceGroupResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Interface group replacement required", "All configurable changes require replacement.")
}
func (r *InterfaceGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m interfaceGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	if err := r.client.DeleteInterfaceGroup(ctx, m.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting interface group", err.Error())
	}
}
func (*InterfaceGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" || req.ID == "Default" {
		resp.Diagnostics.AddError("Invalid interface group import ID", "Use a non-default group's exact name. Configure Default using zyxel_lan instead.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
