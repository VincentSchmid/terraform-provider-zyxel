package provider

import (
	"context"
	"encoding/json"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"

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
	upgraders := map[int64]resource.StateUpgrader{0: {
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
	priorV1 := aclPolicyPriorSchemaV0()
	delete(priorV1.Attributes, "name")
	upgraders[1] = resource.StateUpgrader{
		PriorSchema: priorV1,
		StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
			var upgraded aclPolicyModel
			for _, item := range []struct {
				name  string
				value any
			}{
				{"rules", &upgraded.Rules}, {"drop_rules", &upgraded.DropRules},
				{"generation", &upgraded.Generation}, {"row_names", &upgraded.RowNames},
				{"observed_orders", &upgraded.ObservedOrders},
			} {
				resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(item.name), item.value)...)
			}
			if !resp.Diagnostics.HasError() {
				resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
			}
		},
	}
	return upgraders
}

// The private ledger preserves actual rule configurations after partial updates;
// public lists may still contain the prior configuration when an apply fails.
type aclPolicyPrivate interface {
	GetKey(context.Context, string) ([]byte, diag.Diagnostics)
	SetKey(context.Context, string, []byte) diag.Diagnostics
}

func loadPolicyLedger(ctx context.Context, model aclPolicyModel, private aclPolicyPrivate) (zyxel.ACLPolicyState, diag.Diagnostics) {
	if private != nil {
		data, d := private.GetKey(ctx, "acl_policy_ledger")
		if d.HasError() {
			return zyxel.ACLPolicyState{}, d
		}
		if len(data) != 0 {
			var ledger zyxel.ACLPolicyState
			if err := json.Unmarshal(data, &ledger); err != nil {
				d.AddError("Invalid ACL recovery ledger", "Preserve state and reconcile tracked rows before retrying.")
			}
			return ledger, d
		}
	}
	return policyLedger(ctx, model)
}

func storePolicyLedger(ctx context.Context, private aclPolicyPrivate, ledger zyxel.ACLPolicyState) diag.Diagnostics {
	if private == nil {
		return nil
	}
	data, err := json.Marshal(ledger)
	if err != nil {
		var d diag.Diagnostics
		d.AddError("Cannot preserve ACL recovery ledger", err.Error())
		return d
	}
	return private.SetKey(ctx, "acl_policy_ledger", data)
}
