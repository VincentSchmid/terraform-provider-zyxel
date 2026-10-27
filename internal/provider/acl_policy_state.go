package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// aclPolicyModelV0 is the released shape with a root policy name. The name was
// redundant with per-rule names and never identified ownership; the exact
// row_names ledger did.
type aclPolicyModelV0 struct {
	Name           types.String         `tfsdk:"name"`
	Rules          []aclPolicyRuleModel `tfsdk:"rules"`
	DropRules      []aclPolicyRuleModel `tfsdk:"drop_rules"`
	Generation     types.String         `tfsdk:"generation"`
	RowNames       types.List           `tfsdk:"row_names"`
	ObservedOrders types.List           `tfsdk:"observed_orders"`
}

func aclPolicyPriorSchemaV0() *schema.Schema {
	return &schema.Schema{Attributes: map[string]schema.Attribute{
		"name":            schema.StringAttribute{Required: true},
		"rules":           schema.ListNestedAttribute{Optional: true, NestedObject: aclPolicyRuleObject()},
		"drop_rules":      schema.ListNestedAttribute{Required: true, NestedObject: aclPolicyRuleObject()},
		"generation":      schema.StringAttribute{Computed: true},
		"row_names":       schema.ListAttribute{Computed: true, ElementType: types.StringType},
		"observed_orders": schema.ListAttribute{Computed: true, ElementType: types.Int64Type},
	}}
}

// UpgradeState drops the redundant root name and copies every ledger attribute
// verbatim. No value is invented; refresh then validates the retained legacy
// row names against the router.
func (r *ACLPolicyResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{0: {
		PriorSchema: aclPolicyPriorSchemaV0(),
		StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
			var old aclPolicyModelV0
			resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
			if resp.Diagnostics.HasError() {
				return
			}
			upgraded := aclPolicyModel{
				Rules: old.Rules, DropRules: old.DropRules, Generation: old.Generation,
				RowNames: old.RowNames, ObservedOrders: old.ObservedOrders,
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
		},
	}}
}
