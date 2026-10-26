package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
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
	_ resource.Resource                   = &ACLPolicyResource{}
	_ resource.ResourceWithConfigure      = &ACLPolicyResource{}
	_ resource.ResourceWithValidateConfig = &ACLPolicyResource{}
	_ resource.ResourceWithImportState    = &ACLPolicyResource{}
)

func NewACLPolicyResource() resource.Resource { return &ACLPolicyResource{} }

type ACLPolicyResource struct{ client *zyxel.Client }

type aclPolicyModel struct {
	Name           types.String         `tfsdk:"name"`
	Rules          []aclPolicyRuleModel `tfsdk:"rules"`
	Generation     types.String         `tfsdk:"generation"`
	RowNames       types.List           `tfsdk:"row_names"`
	ObservedOrders types.List           `tfsdk:"observed_orders"`
}

type aclPolicyRuleModel struct {
	Action           types.String `tfsdk:"action"`
	Protocol         types.String `tfsdk:"protocol"`
	ServiceID        types.String `tfsdk:"service_id"`
	IPVersion        types.String `tfsdk:"ip_version"`
	Direction        types.String `tfsdk:"direction"`
	SourceCIDR       types.String `tfsdk:"source_cidr"`
	DestinationCIDR  types.String `tfsdk:"destination_cidr"`
	SourcePorts      types.String `tfsdk:"source_ports"`
	DestinationPorts types.String `tfsdk:"destination_ports"`
}

func (*ACLPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_policy"
}

func (*ACLPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an ordered ACL tail: enabled equivalent-scope accepts followed by one catch-all source drop. The list is reconciled sequentially under a process-local endpoint lock. Updates stage and verify a new generation behind the old drop, then remove old accepts and finally the old drop. This is not atomic: traffic may be interrupted and old accepts may remain effective until retired. No PUT/reorder is used. Only source ranges and accept-list order/size can change in place; traffic-scope changes are rejected. Unrelated prefix rules must be accepts, reviewed by the operator for overlap. Do not manage its rows with other resources. See the ACL ordering and recovery guide before production use; hardware writes remain unverified.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{Required: true, MarkdownDescription: "Policy namespace (1-48 bytes). Router rows are named <name>-g<random-generation>-001, -002, etc. The entire namespace is reserved; existing rows are never automatically adopted. Changing it requires replacement.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"rules": schema.ListNestedAttribute{
				Required: true, MarkdownDescription: "Ordered list of 1-999 rules. All must share protocol (or service), address family, direction, destination and port filters. Only accepts may precede the final drop, whose source must be 0.0.0.0/0 (or ::/0). All rules are enabled. No numeric order is configured.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"action": schema.StringAttribute{Required: true, MarkdownDescription: "accept, except for the final rule which must be drop."},
					"protocol": schema.StringAttribute{
						Optional: true, Computed: true,
						MarkdownDescription: "Inline protocol: all, tcp_udp, tcp, udp, icmp or icmpv6. Required unless `service_id` is set; the neutral `all` value is then computed and the service selects the protocol.",
						PlanModifiers:       []planmodifier.String{aclPolicyProtocolDefault{}}, Validators: []validator.String{aclProtocolValidator{}},
					},
					"service_id": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Native custom service ID, for example `zyxel_service.https.id`, shared by all rules. Mutually exclusive with inline `protocol`, `source_ports` and `destination_ports`; the router rows are created through the same ACL rule write path.",
					},
					"ip_version":        schema.StringAttribute{Required: true, MarkdownDescription: "ipv4 or ipv6."},
					"direction":         schema.StringAttribute{Required: true, MarkdownDescription: "wan_to_lan, lan_to_wan, wan_to_router or lan_to_router."},
					"source_cidr":       schema.StringAttribute{Required: true, MarkdownDescription: "Canonical source network; the final drop must match any source."},
					"destination_cidr":  schema.StringAttribute{Required: true, MarkdownDescription: "Canonical destination network shared by all rules."},
					"source_ports":      schema.StringAttribute{Optional: true, MarkdownDescription: "Inline source ports: *, a port, or start-end. Omit for any. For portless protocols or with `service_id` omit this field."},
					"destination_ports": schema.StringAttribute{Optional: true, MarkdownDescription: "Inline destination ports: *, a port, or start-end. Omit for any. For portless protocols or with `service_id` omit this field."},
				}},
			},
			"generation":      schema.StringAttribute{Computed: true, MarkdownDescription: "Current generation token. Together with row_names this is a recovery ledger, not permission to adopt matching rows."},
			"row_names":       schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Exact router names owned by this resource, including accepted/ambiguous writes after partial failures. Never edit or discard this ledger without operator reconciliation."},
			"observed_orders": schema.ListAttribute{Computed: true, ElementType: types.Int64Type, MarkdownDescription: "Observed positions in rule-list order. Firmware compaction refreshes these values without changes to the configured list."},
		},
	}
}

func (r *ACLPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// modelACLPolicy maps policy rules onto the same ACL rule parameters that
// zyxel_acl_rule uses. Rule creation, service resolution and verification stay
// in the shared ACL rule write path.
func modelACLPolicy(model aclPolicyModel) (zyxel.ACLPolicy, bool) {
	p := zyxel.ACLPolicy{Name: model.Name.ValueString()}
	known := !model.Name.IsUnknown()
	for i, m := range model.Rules {
		for _, v := range []types.String{m.Action, m.IPVersion, m.Direction, m.SourceCIDR, m.DestinationCIDR, m.SourcePorts, m.DestinationPorts, m.ServiceID} {
			known = known && !v.IsUnknown()
		}
		protocol := m.Protocol
		if (protocol.IsNull() || protocol.IsUnknown()) && !m.ServiceID.IsNull() && !m.ServiceID.IsUnknown() {
			protocol = types.StringValue("all")
		}
		known = known && !protocol.IsUnknown()
		p.Rules = append(p.Rules, zyxel.ACLRule{
			Name: fmt.Sprintf("rule-%03d", i+1), Action: m.Action.ValueString(), Enabled: true,
			Protocol: protocol.ValueString(), ServiceID: m.ServiceID.ValueString(),
			IPVersion: m.IPVersion.ValueString(), Direction: m.Direction.ValueString(),
			SourceCIDR: m.SourceCIDR.ValueString(), DestinationCIDR: m.DestinationCIDR.ValueString(),
			SourcePorts: m.SourcePorts.ValueString(), DestinationPorts: m.DestinationPorts.ValueString(),
		})
	}
	return p, known
}

// The computed protocol is only stored when it was resolved from service_id.
func recordResolvedPolicyProtocol(model *aclPolicyModel, rules []zyxel.ACLRule) {
	for i := range model.Rules {
		if (model.Rules[i].Protocol.IsNull() || model.Rules[i].Protocol.IsUnknown()) && i < len(rules) && rules[i].Protocol != "" {
			model.Rules[i].Protocol = types.StringValue(rules[i].Protocol)
		}
	}
}

type aclPolicyProtocolDefault struct{}

func (aclPolicyProtocolDefault) Description(context.Context) string {
	return "defaults to all when service_id is set"
}
func (v aclPolicyProtocolDefault) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (aclPolicyProtocolDefault) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var id types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, req.Path.ParentPath().AtName("service_id"), &id)...)
	if resp.Diagnostics.HasError() || id.IsNull() || id.IsUnknown() {
		return
	}
	resp.PlanValue = types.StringValue("all")
}

func (*ACLPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Lists may contain expressions unknown during planning. Do not decode an
	// unknown collection into a Go slice; the authoritative API validates apply.
	var rules types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() || rules.IsUnknown() || rules.IsNull() {
		return
	}
	for _, element := range rules.Elements() {
		if element.IsUnknown() {
			return
		}
	}
	var model aclPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for i, m := range model.Rules {
		at := func(name string) path.Path { return path.Root("rules").AtListIndex(i).AtName(name) }
		if !m.ServiceID.IsNull() && !m.ServiceID.IsUnknown() {
			if !m.Protocol.IsNull() && !m.Protocol.IsUnknown() {
				resp.Diagnostics.AddAttributeError(at("protocol"), "Conflicting service filter", "service_id cannot be combined with an inline protocol; the referenced service selects the protocol.")
			}
			for _, port := range []struct {
				name  string
				value types.String
			}{{"source_ports", m.SourcePorts}, {"destination_ports", m.DestinationPorts}} {
				if !port.value.IsNull() && !port.value.IsUnknown() {
					resp.Diagnostics.AddAttributeError(at(port.name), "Conflicting service filter", "service_id cannot be combined with inline ports; the referenced service selects them.")
				}
			}
		} else if m.ServiceID.IsNull() && m.Protocol.IsNull() {
			resp.Diagnostics.AddAttributeError(at("protocol"), "Missing inline protocol", "Set an inline `protocol`, or set `service_id` so the referenced service selects the protocol.")
		}
	}
	p, known := modelACLPolicy(model)
	if !known {
		return
	}
	if err := p.Validate(); err != nil {
		resp.Diagnostics.AddError("Invalid ACL policy", err.Error())
	}
}

func policyLedger(ctx context.Context, model aclPolicyModel) (zyxel.ACLPolicyState, diag.Diagnostics) {
	p, _ := modelACLPolicy(model)
	s := zyxel.ACLPolicyState{Name: p.Name, Generation: model.Generation.ValueString()}
	diagnostics := model.RowNames.ElementsAs(ctx, &s.Names, false)
	for i, r := range p.Rules {
		r.SourcePortStart, r.SourcePortEnd, _ = zyxel.ParsePorts(r.SourcePorts)
		r.DestinationPortStart, r.DestinationPortEnd, _ = zyxel.ParsePorts(r.DestinationPorts)
		r.SourcePorts, r.DestinationPorts = "", ""
		if i < len(s.Names) {
			r.Name = s.Names[i]
		}
		s.Rules = append(s.Rules, r)
	}
	return s, diagnostics
}

func recordPolicyLedger(ctx context.Context, model *aclPolicyModel, state zyxel.ACLPolicyState) diag.Diagnostics {
	model.Generation = types.StringValue(state.Generation)
	var diagnostics diag.Diagnostics
	var d diag.Diagnostics
	model.RowNames, d = types.ListValueFrom(ctx, types.StringType, state.Names)
	diagnostics.Append(d...)
	orders := make([]int64, 0, len(state.Rules))
	for _, r := range state.Rules {
		orders = append(orders, r.Order)
	}
	model.ObservedOrders, d = types.ListValueFrom(ctx, types.Int64Type, orders)
	diagnostics.Append(d...)
	return diagnostics
}

func (r *ACLPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var model aclPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, known := modelACLPolicy(model)
	if !known {
		resp.Diagnostics.AddError("Unknown ACL policy", "All policy rules must be known before creating router rows.")
		return
	}
	recordResolvedPolicyProtocol(&model, p.Rules)
	out, err := r.client.ApplyACLPolicy(ctx, p, nil)
	if err == nil || out.Changed {
		resp.Diagnostics.Append(recordPolicyLedger(ctx, &model, out.State)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	}
	if err != nil {
		resp.Diagnostics.AddError("Error creating ACL policy", err.Error())
	}
}

func (r *ACLPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var model aclPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ledger, d := policyLedger(ctx, model)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	observed, err := r.client.ReadACLPolicy(ctx, ledger)
	if err != nil {
		resp.Diagnostics.AddError("ACL policy requires reconciliation", err.Error()+" Preserve state and inspect all tracked rows before retrying.")
		return
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &model, observed)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *ACLPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var plan, prior aclPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, known := modelACLPolicy(plan)
	if !known {
		resp.Diagnostics.AddError("Unknown ACL policy", "All policy rules must be known before updating router rows.")
		return
	}
	recordResolvedPolicyProtocol(&plan, p.Rules)
	ledger, d := policyLedger(ctx, prior)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.ApplyACLPolicy(ctx, p, &ledger)
	if err != nil {
		resp.Diagnostics.Append(recordPolicyLedger(ctx, &prior, out.State)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &prior)...)
		resp.Diagnostics.AddError("Error updating ACL policy", err.Error())
		return
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &plan, out.State)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ACLPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	var model aclPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ledger, d := policyLedger(ctx, model)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteACLPolicy(ctx, ledger); err != nil {
		resp.Diagnostics.AddError("Error deleting ACL policy", err.Error())
	}
}

func (r *ACLPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured Zyxel provider", "The Zyxel provider client is not configured.")
		return
	}
	name, generation, ok := strings.Cut(req.ID, "/")
	if !ok {
		resp.Diagnostics.AddError("Invalid ACL policy import", "Import ID must be policy-name/generation. Only complete provider-named generations are supported.")
		return
	}
	observed, err := r.client.ImportACLPolicy(ctx, name, generation)
	if err != nil {
		resp.Diagnostics.AddError("Error importing ACL policy", err.Error())
		return
	}
	model := aclPolicyModel{Name: types.StringValue(name)}
	for _, rule := range observed.Rules {
		m := aclPolicyRuleModel{
			Action: types.StringValue(rule.Action), Protocol: types.StringValue(rule.Protocol),
			IPVersion: types.StringValue(rule.IPVersion), Direction: types.StringValue(rule.Direction),
			SourceCIDR: types.StringValue(rule.SourceCIDR), DestinationCIDR: types.StringValue(rule.DestinationCIDR),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringNull(), ServiceID: types.StringNull(),
		}
		if rule.ServiceID != "" {
			m.ServiceID = types.StringValue(rule.ServiceID)
		}
		if rule.SourcePortStart != nil {
			m.SourcePorts = types.StringValue(zyxel.FormatPorts(rule.SourcePortStart, rule.SourcePortEnd))
		}
		if rule.DestinationPortStart != nil {
			m.DestinationPorts = types.StringValue(zyxel.FormatPorts(rule.DestinationPortStart, rule.DestinationPortEnd))
		}
		model.Rules = append(model.Rules, m)
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &model, observed)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
