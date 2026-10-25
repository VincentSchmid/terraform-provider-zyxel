package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Version 0 stored four numeric bounds. Upgrading state preserves the natural
// identity without deleting, recreating, or re-importing a router entry.
func (r *NATRuleResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{0: {
		PriorSchema: &schema.Schema{Attributes: map[string]schema.Attribute{
			"name":                schema.StringAttribute{Required: true},
			"protocol":            schema.StringAttribute{Required: true},
			"external_port_start": schema.Int64Attribute{Required: true},
			"external_port_end":   schema.Int64Attribute{Required: true},
			"internal_client":     schema.StringAttribute{Required: true},
			"internal_port_start": schema.Int64Attribute{Required: true},
			"internal_port_end":   schema.Int64Attribute{Required: true},
			"enabled":             schema.BoolAttribute{Computed: true},
			"router_index":        schema.Int64Attribute{Computed: true},
		}},
		StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
			var old struct {
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
			resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
			if resp.Diagnostics.HasError() {
				return
			}
			ranges := [][2]types.Int64{{old.ExternalPortStart, old.ExternalPortEnd}, {old.InternalPortStart, old.InternalPortEnd}}
			ports := make([]types.String, len(ranges))
			for i, bounds := range ranges {
				if bounds[0].IsNull() && bounds[1].IsNull() {
					ports[i] = types.StringNull()
					continue
				}
				if bounds[0].IsNull() || bounds[1].IsNull() || bounds[0].IsUnknown() || bounds[1].IsUnknown() {
					resp.Diagnostics.AddError("Invalid prior NAT state", "Port bounds must both be known or both be null for an imported entry. The prior state is retained.")
					return
				}
				start, end := bounds[0].ValueInt64(), bounds[1].ValueInt64()
				if start < 1 || end > 65535 || end < start {
					resp.Diagnostics.AddError("Invalid prior NAT state", fmt.Sprintf("Cannot upgrade port bounds %d-%d. The prior state is retained.", start, end))
					return
				}
				ports[i] = observedNATPorts(types.StringNull(), start, end)
			}
			upgraded := natRuleModel{
				Name: old.Name, Protocol: old.Protocol, InternalClient: old.InternalClient,
				ExternalPorts: ports[0], TranslationPorts: ports[1],
				Enabled: old.Enabled, RouterIndex: old.RouterIndex,
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
		},
	}}
}
