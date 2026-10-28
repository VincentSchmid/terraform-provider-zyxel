---
page_title: "zyxel_lan Resource - zyxel"
subcategory: ""
description: |-
  Manages IPv4 Home Networking > LAN Setup for an existing interface group, including DHCP and DNS advertisement. Create adopts and updates the built-in settings; updates are in place. Reference zyxel_interface_group.example.id or use Default for the built-in group. IPv6 and unrelated settings are not written. Manage only one LAN resource per group across all states. Destroy relinquishes management without changing settings. Changing the router IP/subnet or DHCP mode can interrupt access; if disconnected, update the provider host and refresh before retrying. Live writes remain unverified on hardware.
---

# zyxel_lan (Resource)

Manages IPv4 Home Networking > LAN Setup for an existing interface group, including DHCP and DNS advertisement. Create adopts and updates the built-in settings; updates are in place. Reference `zyxel_interface_group.example.id` or use `Default` for the built-in group. IPv6 and unrelated settings are not written. Manage only one LAN resource per group across all states. Destroy relinquishes management without changing settings. Changing the router IP/subnet or DHCP mode can interrupt access; if disconnected, update the provider host and refresh before retrying. Live writes remain unverified on hardware.

## Example Usage

```terraform
# Addresses are documentation placeholders; substitute your actual LAN and pool.
# Built-in Default group; no zyxel_interface_group resource is needed.
resource "zyxel_lan" "default" {
  interface_group_id = "Default"
  ip_address         = "192.0.2.1"
  subnet_mask        = "255.255.255.0"
  igmp_snooping      = "blocking"
  dns_mode           = "proxy"

  dhcp = {
    mode                 = "server"
    beginning_ip_address = "192.0.2.100"
    ending_ip_address    = "192.0.2.200"
    auto_reserve_ip      = false
    dhcp_lease_time      = "1d"
  }
}

# Alternatives (do not manage the same group with multiple resources):
#
# DHCP disabled:
#   dhcp = { mode = "disabled" }
#
# DHCP relay:
#   dhcp = {
#     mode                 = "relay"
#     relay_server_address = "198.51.100.10"
#   }
# In both alternatives omit dns_mode or use "proxy" (inactive).
```

## Interface Group References

Create additional groups under **Network Setting > Interface Grouping**, modeled
by `zyxel_interface_group`. Reference the group's stable exact-name ID:

```terraform
interface_group_id = zyxel_interface_group.example.id
```

The built-in `Default` group already exists and needs no group resource. Manage
only one `zyxel_lan` instance per group, including across Terraform states.

## DHCP Modes And Ownership

- `dhcp.mode = "server"` corresponds to **Enable**. Set both pool addresses and
  `dhcp.dhcp_lease_time`. Pool addresses must be
  ordered usable addresses in the LAN subnet and must not include the router IP.
- `dhcp.mode = "disabled"` corresponds to **Disable**. Omit pool, lease, and relay fields.
- `dhcp.mode = "relay"` corresponds to **DHCP Relay**. Set `dhcp.relay_server_address`; omit the pool and lease.
- `dhcp.auto_reserve_ip` may be true only in `server` mode. When switching away from
  server mode, omit it or set it to false.

Inactive DHCP pool/relay fields are omitted from state. They are not cleared on
the router; switching modes writes only the fields needed for the new mode.
Lease strings accept whole days, hours, and minutes, separately or combined in
that order: `1d`, `24h`, `1440m`, and `1d5h12m`. The range is `1m` through `365d`.
The API receives the total in seconds; no rounding is performed. Refresh retains
an equivalent configured spelling; import uses a canonical days/hours/minutes form.

Top-level `dns_mode` defaults to `proxy`; `isp` advertises ISP DNS instead.
It is only active in server mode. For relay/disabled, omit it or use `proxy`;
stored DNS and lease settings are left untouched. Static DNS is not supported.
IPv6 and other unrelated settings remain outside this resource.
IGMP snooping combines the UI's Active switch and Standard/Blocking mode into
`disabled`, `standard`, or `blocking`.

## Connectivity And Recovery

Create adopts the group's existing LAN settings and updates the configured
fields. Updates are in place, not delete/recreate. Destroy leaves the router
unchanged. Changing `interface_group_id` relinquishes the old group and adopts
the new one, without resetting either group's settings.

Changing LAN IP/subnet, DHCP state, or group membership can disconnect clients
and the provider. Back up the router configuration and arrange a recovery path
before applying. The provider does not follow a changed management address or
automatically retry writes. If a write succeeds or may have succeeded but
readback fails, its group identity is retained. Inspect the router, update the
provider `host` if needed, and refresh state before retrying.

Deleting a `zyxel_interface_group` also removes its LAN settings. Replacing a
group whose exact-name ID stays the same does not force its dependent LAN
resource to be reapplied. Remove the dependent LAN and group first, then
recreate both in a second apply. Terraform dependencies order normal creation
and destruction but do not make changes atomic or coordinate web UI users.

The protocol is based on extracted Zyxel UI code and verified with encrypted
local mocks, not hardware writes or an exact-model/firmware compatibility check.

## Breaking Schema Migration

The former top-level `dhcp_mode`, pool addresses, `auto_reserve_ip`, and
`relay_server_address` are removed. Move them inside `dhcp = { ... }`, rename
`dhcp_mode` to `mode`, and add `dhcp_lease_time` for server mode. There are no
compatibility aliases or automatic old-state upgrades. Back up state, update HCL,
remove only this resource's old state binding (`terraform state rm ADDRESS`),
then reimport using its unchanged exact group name before planning. Neither state
removal nor import changes the router. Do not destroy/recreate the interface group.

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `dhcp` (Attributes) DHCP configuration. Pool, auto-reservation, and lease settings apply only to server mode; the relay address applies only to relay mode. (see [below for nested schema](#nestedatt--dhcp))
- `interface_group_id` (String) Interface-group ID (exact name), normally `zyxel_interface_group.example.id`; use `Default` for the built-in LAN. Changing groups relinquishes the old settings and adopts the new group.
- `ip_address` (String) Router's IPv4 address on this LAN. Changing it may disconnect the provider; update the provider host and refresh if necessary.
- `subnet_mask` (String) Contiguous dotted-decimal IPv4 subnet mask, with prefix length 1-30.

### Optional

- `dns_mode` (String) DNS advertised by the DHCP server: `proxy` (default) or `isp`. Only active in server mode; omit or use `proxy` in relay/disabled mode, where DNS settings are left untouched.
- `igmp_snooping` (String) IGMP snooping: `disabled`, `standard`, or `blocking`. Defaults to `disabled`.

### Read-Only

- `id` (String) Exact interface-group name; also the import ID.

<a id="nestedatt--dhcp"></a>
### Nested Schema for `dhcp`

Required:

- `mode` (String) DHCP state: `server` (Enable), `disabled` (Disable), or `relay` (DHCP Relay).

Optional:

- `auto_reserve_ip` (Boolean) Auto reserve IP for the same host. Defaults to false; may be true only in server mode.
- `beginning_ip_address` (String) Required in server mode: first usable host of the DHCP pool in the LAN subnet. The pool must not include the router address.
- `dhcp_lease_time` (String) Required in server mode: whole days, hours, and/or minutes, for example `1d`, `24h`, `1440m`, or `1d5h12m`. Range: `1m` through `365d`. Omit in relay/disabled mode.
- `ending_ip_address` (String) Required in server mode: last usable host of the DHCP pool; at least the beginning address.
- `relay_server_address` (String) Required in relay mode: IPv4 address of the upstream DHCP server. Omit in other modes.

## Import

Import uses the exact group name and does not change router settings:

```shell
terraform import zyxel_lan.default Default
```
