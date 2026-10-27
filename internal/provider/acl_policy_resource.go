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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &ACLPolicyResource{}
	_ resource.ResourceWithConfigure      = &ACLPolicyResource{}
	_ resource.ResourceWithValidateConfig = &ACLPolicyResource{}
	_ resource.ResourceWithImportState    = &ACLPolicyResource{}
	_ resource.ResourceWithModifyPlan     = &ACLPolicyResource{}
	_ resource.ResourceWithUpgradeState   = &ACLPolicyResource{}
)

func NewACLPolicyResource() resource.Resource { return &ACLPolicyResource{} }

type ACLPolicyResource struct{ client *zyxel.Client }

// Refresh records pending reconciliation privately; making the generation
// unknown ensures apply runs even when configuration still matches prior state.
func (r *ACLPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() || req.Private == nil {
		return
	}
	pending, d := req.Private.GetKey(ctx, "acl_recovery_pending")
	resp.Diagnostics.Append(d...)
	if string(pending) == "true" {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("generation"), types.StringUnknown())...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("row_names"), types.ListUnknown(types.StringType))...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("observed_orders"), types.ListUnknown(types.Int64Type))...)
	}
}

type aclPolicyModel struct {
	ManagementRules []aclPolicyRuleModel `tfsdk:"management_rules"`
	Rules           []aclPolicyRuleModel `tfsdk:"rules"`
	DropRules       []aclPolicyRuleModel `tfsdk:"drop_rules"`
	Generation      types.String         `tfsdk:"generation"`
	RowNames        types.List           `tfsdk:"row_names"`
	ObservedOrders  types.List           `tfsdk:"observed_orders"`
}

type aclPolicyRuleModel struct {
	Name             types.String `tfsdk:"name"`
	Action           types.String `tfsdk:"action"`
	Protocol         types.String `tfsdk:"protocol"`
	Service          types.String `tfsdk:"service"`
	ServiceID        types.String `tfsdk:"service_id"`
	IPVersion        types.String `tfsdk:"ip_version"`
	Direction        types.String `tfsdk:"direction"`
	SourceCIDR       types.String `tfsdk:"source_cidr"`
	DestinationCIDR  types.String `tfsdk:"destination_cidr"`
	SourcePorts      types.String `tfsdk:"source_ports"`
	DestinationPorts types.String `tfsdk:"destination_ports"`
	MACAddress       types.String `tfsdk:"mac_address"`
	TCPFlag          types.String `tfsdk:"tcp_flag"`
	PacketsPerUnit   types.Int64  `tfsdk:"packets_per_unit"`
	RateLimitUnit    types.String `tfsdk:"rate_limit_unit"`
}

func (*ACLPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_policy"
}

func (*ACLPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:             2,
		MarkdownDescription: "Manages the ordered ACL tail: `management_rules`, then `rules`, then `drop_rules`. Management rules are required accepts; unchanged management identities are preserved. Updates delete old denies, delete normal rules, create and verify replacement management rules if needed, retire old management, then create normal rules and denies. The 32-rule router limit includes unmanaged rows and temporary management coexistence. Ownership is the exact `row_names` ledger, never a name prefix. No PUT/reorder is used. Unrelated prefix rules must be accepts; do not manage policy rows with other resources. See the ACL ordering and recovery guide.\n\n**Warning:** ACL updates are non-atomic. Deny rules are temporarily removed, potentially allowing normally blocked traffic. Management rule changes may also interrupt router access. Use a maintenance window and ensure a recovery path is available.",
		Attributes: map[string]schema.Attribute{
			"management_rules": schema.ListNestedAttribute{
				Required: true, MarkdownDescription: "Ordered management access rules. At least one accept is required. Unchanged rules retain their router identities; replacements are verified before old management rules are deleted.",
				NestedObject: aclPolicyRuleObject(),
				Validators:   []validator.List{aclPolicyManagementValidator{}},
			},
			"rules": schema.ListNestedAttribute{
				Optional: true, MarkdownDescription: "Ordered accept rules, evaluated before every entry in `drop_rules`. Each entry must have `action = \"accept\"`. Rules may have different protocols, services, address families, directions, destinations and ports. No numeric order is configured.",
				NestedObject: aclPolicyRuleObject(),
			},
			"drop_rules": schema.ListNestedAttribute{
				Required: true, MarkdownDescription: "Ordered drop/reject rules, evaluated after every accept. Each entry must have `action = \"drop\"` or `\"reject\"`; at least one entry is required so a policy cannot silently omit its deny coverage. Rules may have different scopes.",
				NestedObject: aclPolicyRuleObject(),
			},
			"generation":      schema.StringAttribute{Computed: true, MarkdownDescription: "Current generation token. Together with row_names this is a recovery ledger, not permission to adopt matching rows."},
			"row_names":       schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Exact router names owned by this resource, in effective rule order, including accepted/ambiguous writes after partial failures. Never edit or discard this ledger without operator reconciliation."},
			"observed_orders": schema.ListAttribute{Computed: true, ElementType: types.Int64Type, MarkdownDescription: "Observed positions in effective rule order (accepts, then drops/rejects). Firmware compaction refreshes these values without changes to the configured lists."},
		},
	}
}

type aclPolicyManagementValidator struct{}

func (aclPolicyManagementValidator) Description(context.Context) string {
	return "requires at least one management accept rule"
}
func (v aclPolicyManagementValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (aclPolicyManagementValidator) ValidateList(_ context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() && len(req.ConfigValue.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Missing management rules", "At least one management accept rule is required.")
	}
}

func aclPolicyRuleObject() schema.NestedAttributeObject {
	return schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
		"name": schema.StringAttribute{Optional: true, MarkdownDescription: "Optional logical rule name used as the router row name (for example `WebDAV` becomes `WebDAV-g7f`). Use ASCII letters, digits, underscores or hyphens, unique across all three lists; surrounding whitespace is rejected. Omit for an unnamed `g7f-01` row. Changing a name stages a new generation and retires the old rows."},
		"action": schema.StringAttribute{
			Required: true, MarkdownDescription: "`accept` in `management_rules` and `rules`; `drop` or `reject` in `drop_rules`.",
			Validators: []validator.String{aclActionValidator{}},
		},
		"protocol": schema.StringAttribute{
			Optional: true, Computed: true,
			MarkdownDescription: "Inline protocol: all, tcp_udp, tcp, udp, icmp or icmpv6. Required unless `service` or `service_id` is set; the neutral `all` value is computed for both service forms because the referenced service selects the protocol.",
			PlanModifiers:       []planmodifier.String{aclPolicyProtocolDefault{}}, Validators: []validator.String{aclProtocolValidator{}},
		},
		"service": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Name of an existing custom protocol/service group. Mutually exclusive with `service_id` and inline protocol/port/TCP-flag filters.",
			Validators: []validator.String{aclServiceValidator{}},
		},
		"service_id": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Native custom service ID, for example `zyxel_service.https.id`. Mutually exclusive with `service` and inline protocol/port/TCP-flag filters. The router rows are created through the same ACL rule write path.",
		},
		"ip_version": schema.StringAttribute{
			Required: true, MarkdownDescription: "ipv4 or ipv6.", Validators: []validator.String{aclIPVersionValidator{}},
		},
		"direction": schema.StringAttribute{
			Required: true, MarkdownDescription: "wan_to_lan, lan_to_wan, wan_to_router or lan_to_router.", Validators: []validator.String{aclDirectionValidator{}},
		},
		"source_cidr": schema.StringAttribute{
			Required: true, MarkdownDescription: "Canonical source network in the selected address family.", Validators: []validator.String{aclCIDRValidator{}},
		},
		"destination_cidr": schema.StringAttribute{
			Required: true, MarkdownDescription: "Canonical destination network in the selected address family.", Validators: []validator.String{aclCIDRValidator{}},
		},
		"source_ports": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Source ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.", Validators: []validator.String{portsValidator{}},
		},
		"destination_ports": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Destination ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.", Validators: []validator.String{portsValidator{}},
		},
		"mac_address": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Optional canonical uppercase source MAC filter. Omit for any MAC.", Validators: []validator.String{aclMACValidator{}},
		},
		"tcp_flag": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Optional TCP flag to match. Only valid with the `tcp` and `tcp_udp` protocols.", Validators: []validator.String{aclTCPFlagValidator{}},
		},
		"packets_per_unit": schema.Int64Attribute{
			Optional: true, MarkdownDescription: "Optional packet rate limit from 1 through 512 per `rate_limit_unit`. Requires `action = \"accept\"`.",
			Validators: []validator.Int64{aclInt64Validator{minimum: 1, maximum: 512}},
		},
		"rate_limit_unit": schema.StringAttribute{
			Optional: true, Computed: true, Default: stringdefault.StaticString("minute"),
			MarkdownDescription: "Time period for `packets_per_unit`: `minute` or `second`. Defaults to `minute`; only used when `packets_per_unit` is set.", Validators: []validator.String{aclRateLimitUnitValidator{}},
		},
	}}
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

// modelACLPolicy maps the three ordered lists onto the same ACL rule parameters
// that zyxel_acl_rule uses. The effective order is every accept, then every
// drop/reject. Rule creation, service resolution and verification stay in the
// shared ACL rule write path.
func modelACLPolicy(model aclPolicyModel) (zyxel.ACLPolicy, bool) {
	var p zyxel.ACLPolicy
	known := true
	appendRules := func(rules []aclPolicyRuleModel) {
		for _, m := range rules {
			for _, v := range []types.String{m.Name, m.Action, m.IPVersion, m.Direction, m.SourceCIDR, m.DestinationCIDR, m.SourcePorts, m.DestinationPorts, m.Service, m.ServiceID, m.MACAddress, m.TCPFlag, m.RateLimitUnit} {
				known = known && !v.IsUnknown()
			}
			known = known && !m.PacketsPerUnit.IsUnknown()
			protocol := m.Protocol
			// A custom service selects the protocol, so the neutral all value is
			// the only valid default for both the name and native ID forms.
			if protocol.IsNull() || protocol.IsUnknown() {
				if !m.Service.IsNull() || !m.ServiceID.IsNull() {
					protocol = types.StringValue("all")
				}
			}
			known = known && !protocol.IsUnknown()
			rule := zyxel.ACLRule{
				Name: m.Name.ValueString(), Action: m.Action.ValueString(), Enabled: true,
				Protocol: protocol.ValueString(), Service: m.Service.ValueString(), ServiceID: m.ServiceID.ValueString(),
				IPVersion: m.IPVersion.ValueString(), Direction: m.Direction.ValueString(),
				SourceCIDR: m.SourceCIDR.ValueString(), DestinationCIDR: m.DestinationCIDR.ValueString(),
				SourcePorts: m.SourcePorts.ValueString(), DestinationPorts: m.DestinationPorts.ValueString(),
				MACAddress: m.MACAddress.ValueString(), TCPFlag: m.TCPFlag.ValueString(),
			}
			if !m.PacketsPerUnit.IsNull() && !m.PacketsPerUnit.IsUnknown() {
				limit := m.PacketsPerUnit.ValueInt64()
				rule.RateLimit = &limit
				unit := m.RateLimitUnit.ValueString()
				if unit == "" {
					unit = "minute"
				}
				rule.RateLimitUnit = unit
			}
			p.Rules = append(p.Rules, rule)
		}
	}
	appendRules(model.ManagementRules)
	p.ManagementRules, p.Rules = p.Rules, nil
	appendRules(model.Rules)
	appendRules(model.DropRules)
	return p, known
}

// The computed protocol is only stored when it was resolved from a service.
func recordResolvedPolicyProtocol(model *aclPolicyModel, rules []zyxel.ACLRule) {
	record := func(entries []aclPolicyRuleModel, offset int) {
		for i := range entries {
			if (entries[i].Protocol.IsNull() || entries[i].Protocol.IsUnknown()) && offset+i < len(rules) && rules[offset+i].Protocol != "" {
				entries[i].Protocol = types.StringValue(rules[offset+i].Protocol)
			}
		}
	}
	record(model.ManagementRules, 0)
	record(model.Rules, len(model.ManagementRules))
	record(model.DropRules, len(model.ManagementRules)+len(model.Rules))
}

type aclPolicyProtocolDefault struct{}

func (aclPolicyProtocolDefault) Description(context.Context) string {
	return "defaults to all when a custom service is set"
}
func (v aclPolicyProtocolDefault) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (aclPolicyProtocolDefault) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	for _, name := range []string{"service", "service_id"} {
		var service types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, req.Path.ParentPath().AtName(name), &service)...)
		if resp.Diagnostics.HasError() {
			return
		}
		// An unknown service still selects the protocol, so compute the neutral
		// value now instead of leaving a computed attribute unknown at apply.
		if !service.IsNull() {
			resp.PlanValue = types.StringValue("all")
			return
		}
	}
}

func (*ACLPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Lists may contain expressions unknown during planning. Do not decode an
	// unknown collection into a Go slice; the authoritative API validates apply.
	for _, name := range []string{"management_rules", "rules", "drop_rules"} {
		var list types.List
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(name), &list)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if list.IsUnknown() {
			return
		}
		if list.IsNull() {
			continue
		}
		for _, element := range list.Elements() {
			if element.IsUnknown() {
				return
			}
		}
	}
	var model aclPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validate := func(listName string, entries []aclPolicyRuleModel, want func(string) bool, actionMessage string) {
		for i, m := range entries {
			at := func(name string) path.Path { return path.Root(listName).AtListIndex(i).AtName(name) }
			if !m.Name.IsNull() && !m.Name.IsUnknown() && m.Name.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(at("name"), "Empty rule name", "Omit name for an unnamed rule, or provide a non-empty logical name.")
			}
			if !m.Action.IsNull() && !m.Action.IsUnknown() && !want(m.Action.ValueString()) {
				resp.Diagnostics.AddAttributeError(at("action"), "Invalid action for this list", actionMessage)
			}
			if !m.ServiceID.IsNull() && !m.ServiceID.IsUnknown() {
				if !m.Service.IsNull() && !m.Service.IsUnknown() {
					resp.Diagnostics.AddAttributeError(at("service"), "Conflicting service filter", "service_id cannot be combined with a service name.")
				}
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
				if !m.TCPFlag.IsNull() && !m.TCPFlag.IsUnknown() {
					resp.Diagnostics.AddAttributeError(at("tcp_flag"), "Conflicting service filter", "service_id cannot be combined with a TCP flag.")
				}
			} else if m.ServiceID.IsNull() && m.Service.IsNull() && m.Protocol.IsNull() {
				resp.Diagnostics.AddAttributeError(at("protocol"), "Missing inline protocol", "Set an inline `protocol`, or set `service`/`service_id` so the service selects the protocol.")
			}
			if !m.PacketsPerUnit.IsNull() && !m.PacketsPerUnit.IsUnknown() && !m.Action.IsNull() && !m.Action.IsUnknown() && m.Action.ValueString() != "accept" {
				resp.Diagnostics.AddAttributeError(at("packets_per_unit"), "Rate limit requires accept", "The router only supports rate limiting for `action = \"accept\"`; remove `packets_per_unit` or change the action.")
			}
			if !m.RateLimitUnit.IsNull() && !m.RateLimitUnit.IsUnknown() && m.RateLimitUnit.ValueString() != "minute" && (m.PacketsPerUnit.IsNull() || m.PacketsPerUnit.IsUnknown()) {
				resp.Diagnostics.AddAttributeError(at("rate_limit_unit"), "Rate limit unit without a packet limit", "Set `packets_per_unit` when using `rate_limit_unit`; omit the unit or leave it as `minute` when rate limiting is disabled.")
			}
		}
	}
	validate("management_rules", model.ManagementRules, func(action string) bool { return action == "accept" }, "Every management rule must use action = accept.")
	if len(model.ManagementRules) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("management_rules"), "Missing management rules", "At least one management accept rule is required.")
	}
	validate("rules", model.Rules, func(action string) bool { return action == "accept" }, "Every `rules` entry must use `action = \"accept\"`; put drops and rejects in `drop_rules`.")
	validate("drop_rules", model.DropRules, func(action string) bool { return action == "drop" || action == "reject" }, "Every `drop_rules` entry must use `action = \"drop\"` or `\"reject\"`; put accepts in `rules`.")
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
	s := zyxel.ACLPolicyState{Generation: model.Generation.ValueString()}
	diagnostics := model.RowNames.ElementsAs(ctx, &s.Names, false)
	for i, r := range append(append([]zyxel.ACLRule(nil), p.ManagementRules...), p.Rules...) {
		if i >= len(s.Names) {
			break
		}
		r.SourcePortStart, r.SourcePortEnd, _ = zyxel.ParsePorts(r.SourcePorts)
		r.DestinationPortStart, r.DestinationPortEnd, _ = zyxel.ParsePorts(r.DestinationPorts)
		r.SourcePorts, r.DestinationPorts = "", ""
		if i < len(s.Names) {
			r.Name = s.Names[i]
		}
		s.Rules = append(s.Rules, r)
		if i < len(p.ManagementRules) {
			s.ManagementNames = append(s.ManagementNames, r.Name)
		}
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
	recordResolvedPolicyProtocol(&model, append(append([]zyxel.ACLRule(nil), p.ManagementRules...), p.Rules...))
	out, err := r.client.ApplyACLPolicy(ctx, p, nil)
	if err == nil || out.Changed {
		if resp.Private != nil {
			resp.Diagnostics.Append(storePolicyLedger(ctx, resp.Private, out.State)...)
		}
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
	ledger, d := loadPolicyLedger(ctx, model, req.Private)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	recovery, err := r.client.InspectACLPolicyRecovery(ctx, ledger)
	if err != nil {
		resp.Diagnostics.AddError("ACL policy requires reconciliation", err.Error()+" Preserve state and inspect all tracked rows before retrying.")
		return
	}
	if resp.Private != nil {
		pending := []byte(nil)
		if recovery.Pending {
			pending = []byte("true")
		}
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, "acl_recovery_pending", pending)...)
	}
	if recovery.Pending {
		resp.Diagnostics.AddWarning("ACL policy recovery scheduled", "A partial ownership ledger was verified without router writes. The next apply will reconcile the tracked rows and rebuild the desired policy. This can interrupt traffic and temporarily remove deny protection.")
		return
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &model, recovery.State)...)
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
	recordResolvedPolicyProtocol(&plan, append(append([]zyxel.ACLRule(nil), p.ManagementRules...), p.Rules...))
	ledger, d := loadPolicyLedger(ctx, prior, req.Private)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.ApplyACLPolicy(ctx, p, &ledger)
	if resp.Private != nil && (err == nil || out.Changed) {
		resp.Diagnostics.Append(storePolicyLedger(ctx, resp.Private, out.State)...)
	}
	if err != nil {
		resp.Diagnostics.Append(recordPolicyLedger(ctx, &prior, out.State)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &prior)...)
		resp.Diagnostics.AddError("Error updating ACL policy", err.Error())
		return
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &plan, out.State)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Private != nil {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, "acl_recovery_pending", nil)...)
	}
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
	ledger, d := loadPolicyLedger(ctx, model, req.Private)
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
	generation := req.ID
	if _, legacy, ok := strings.Cut(req.ID, "/"); ok {
		// Released providers accepted name/generation; the name no longer
		// identifies an owner, so keep reading that form but ignore the name.
		generation = legacy
	}
	observed, err := r.client.ImportACLPolicy(ctx, generation)
	if err != nil {
		resp.Diagnostics.AddError("Error importing ACL policy", err.Error())
		return
	}
	model := aclPolicyModel{}
	for i, rule := range observed.Rules {
		m := aclPolicyRuleModel{
			Name:   types.StringNull(),
			Action: types.StringValue(rule.Action), Protocol: types.StringValue(rule.Protocol),
			IPVersion: types.StringValue(rule.IPVersion), Direction: types.StringValue(rule.Direction),
			SourceCIDR: types.StringValue(rule.SourceCIDR), DestinationCIDR: types.StringValue(rule.DestinationCIDR),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringNull(),
			Service: types.StringNull(), ServiceID: types.StringNull(),
			MACAddress: types.StringNull(), TCPFlag: types.StringNull(),
			PacketsPerUnit: types.Int64Null(), RateLimitUnit: types.StringValue("minute"),
		}
		if observed.LogicalNames[i] != "" {
			m.Name = types.StringValue(observed.LogicalNames[i])
		}
		if rule.Service != "" && rule.ServiceID == "" {
			// Some legacy rows expose only a service name. Native-ID rules keep
			// the ID as identity; the readback name is not part of the config.
			m.Service = types.StringValue(rule.Service)
		}
		if rule.ServiceID != "" {
			m.ServiceID = types.StringValue(rule.ServiceID)
		}
		if rule.MACAddress != "" {
			m.MACAddress = types.StringValue(rule.MACAddress)
		}
		if rule.TCPFlag != "" {
			m.TCPFlag = types.StringValue(rule.TCPFlag)
		}
		if rule.SourcePortStart != nil {
			m.SourcePorts = types.StringValue(zyxel.FormatPorts(rule.SourcePortStart, rule.SourcePortEnd))
		}
		if rule.DestinationPortStart != nil {
			m.DestinationPorts = types.StringValue(zyxel.FormatPorts(rule.DestinationPortStart, rule.DestinationPortEnd))
		}
		if rule.RateLimit != nil {
			m.PacketsPerUnit = types.Int64Value(*rule.RateLimit)
			m.RateLimitUnit = types.StringValue(rule.RateLimitUnit)
		}
		if i < len(observed.ManagementNames) {
			model.ManagementRules = append(model.ManagementRules, m)
		} else if rule.Action == "accept" {
			model.Rules = append(model.Rules, m)
		} else {
			model.DropRules = append(model.DropRules, m)
		}
	}
	resp.Diagnostics.Append(recordPolicyLedger(ctx, &model, observed)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
