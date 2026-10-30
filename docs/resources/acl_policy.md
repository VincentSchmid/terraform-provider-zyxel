---
page_title: "zyxel_acl_policy Resource - zyxel"
subcategory: ""
description: |-
  Manages the ordered ACL tail: management_rules, then rules, then drop_rules. Management rules are required accepts; unchanged management identities are preserved. Updates delete old denies, delete normal rules, create and verify replacement management rules if needed, retire old management, then create normal rules and denies. The 32-rule router limit includes unmanaged rows and temporary management coexistence. Ownership is the exact row_names ledger, never a name prefix. No PUT/reorder is used. Unrelated prefix rules must be accepts; do not manage policy rows with other resources. See the ACL ordering and recovery guide.
  Warning: ACL updates are non-atomic. Deny rules are temporarily removed, potentially allowing normally blocked traffic. Management rule changes may also interrupt router access. Use a maintenance window and ensure a recovery path is available.
---

# zyxel_acl_policy (Resource)

Manages the ordered ACL tail: `management_rules`, then `rules`, then `drop_rules`. Management rules are required accepts; unchanged management identities are preserved. Updates delete old denies, delete normal rules, create and verify replacement management rules if needed, retire old management, then create normal rules and denies. The 32-rule router limit includes unmanaged rows and temporary management coexistence. Ownership is the exact `row_names` ledger, never a name prefix. No PUT/reorder is used. Unrelated prefix rules must be accepts; do not manage policy rows with other resources. See the ACL ordering and recovery guide.

**Warning:** ACL updates are non-atomic. Deny rules are temporarily removed, potentially allowing normally blocked traffic. Management rule changes may also interrupt router access. Use a maintenance window and ensure a recovery path is available.

Read the [ordering and recovery guide](../guides/acl-ordering-recovery.md) before
migration, production writes or retrying a partial apply.

## Example Usage

```terraform
# WARNING: ACL updates are non-atomic. Deny rules are temporarily removed,
# potentially allowing normally blocked traffic. Management rule changes may also
# interrupt router access. Use a maintenance window and ensure a recovery path is
# available.
# Choose ONE policy example per router; each resource owns the entire ACL tail.
# Destination addresses are documentation placeholders. Set the source ranges
# and management CIDRs for your network, and verify management port 443 applies.

# A custom service replaces the inline protocol and port filters. Each rule can
# reference its own service name or service_id; rules no longer have to share one
# scope.
resource "zyxel_service" "https" {
  name              = "policy-https"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

# Management rules precede normal accepts, then every drop rule. At least one drop
# rule is required. Review unrelated prefix accepts for overlap before creating
# this tail policy. Do not manage generated rows individually.
resource "zyxel_acl_policy" "https" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

  rules = [
    {
      action            = "accept"
      source_cidr       = "192.0.2.0/24"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      destination_cidr  = "203.0.113.10/32"
      destination_ports = "443"
    },
    {
      action            = "accept"
      source_cidr       = "198.51.100.0/24"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      destination_cidr  = "203.0.113.10/32"
      destination_ports = "443"
    },
  ]

  drop_rules = [{
    action            = "drop"
    source_cidr       = "0.0.0.0/0"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "wan_to_lan"
    destination_cidr  = "203.0.113.10/32"
    destination_ports = "443"
  }]
}

resource "zyxel_acl_policy" "https_service" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

  rules = [
    {
      action           = "accept"
      source_cidr      = "192.0.2.0/24"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      destination_cidr = "203.0.113.10/32"
      service_id       = zyxel_service.https.id
    },
    {
      action           = "accept"
      source_cidr      = "198.51.100.0/24"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      destination_cidr = "203.0.113.10/32"
      service_id       = zyxel_service.https.id
    },
  ]

  drop_rules = [{
    action           = "drop"
    source_cidr      = "0.0.0.0/0"
    ip_version       = "ipv4"
    direction        = "wan_to_lan"
    destination_cidr = "203.0.113.10/32"
    service_id       = zyxel_service.https.id
  }]
}

# Mixed-scope accepts are allowed; one or more drops follow them. The effective
# order is management, then normal accepts, then drops.
resource "zyxel_acl_policy" "mixed" {
  management_rules = [{
    name              = "Management"
    action            = "accept"
    protocol          = "tcp"
    ip_version        = "ipv4"
    direction         = "lan_to_router"
    source_cidr       = "192.0.2.0/24"
    destination_cidr  = "192.0.2.1/32"
    destination_ports = "443"
  }]

  rules = [
    {
      name              = "Web"
      action            = "accept"
      protocol          = "tcp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "198.51.100.0/24"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "8443"
    },
    {
      name              = "DNS"
      action            = "accept"
      protocol          = "udp"
      ip_version        = "ipv4"
      direction         = "wan_to_lan"
      source_cidr       = "198.51.100.0/24"
      destination_cidr  = "203.0.113.20/32"
      destination_ports = "53"
    },
  ]

  drop_rules = [
    {
      name             = "Deny"
      action           = "drop"
      protocol         = "all"
      ip_version       = "ipv4"
      direction        = "wan_to_lan"
      source_cidr      = "0.0.0.0/0"
      destination_cidr = "0.0.0.0/0"
    },
  ]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `drop_rules` (Attributes List) Ordered drop/reject rules, evaluated after every accept. Each entry must have `action = "drop"` or `"reject"`; at least one entry is required so a policy cannot silently omit its deny coverage. Rules may have different scopes. (see [below for nested schema](#nestedatt--drop_rules))
- `management_rules` (Attributes List) Ordered management access rules. At least one accept is required. Unchanged rules retain their router identities; replacements are verified before old management rules are deleted. (see [below for nested schema](#nestedatt--management_rules))

### Optional

- `rules` (Attributes List) Ordered accept rules, evaluated before every entry in `drop_rules`. Each entry must have `action = "accept"`. Rules may have different protocols, services, address families, directions, destinations and ports. No numeric order is configured. (see [below for nested schema](#nestedatt--rules))

### Read-Only

- `generation` (String) Current generation token. Together with row_names this is a recovery ledger, not permission to adopt matching rows.
- `observed_orders` (List of Number) Observed positions in effective rule order (accepts, then drops/rejects). Firmware compaction refreshes these values without changes to the configured lists.
- `row_names` (List of String) Exact router names owned by this resource, in effective rule order, including accepted/ambiguous writes after partial failures. Never edit or discard this ledger without operator reconciliation.

<a id="nestedatt--drop_rules"></a>
### Nested Schema for `drop_rules`

Required:

- `action` (String) `accept` in `management_rules` and `rules`; `drop` or `reject` in `drop_rules`.
- `destination_cidr` (String) Canonical destination network in the selected address family.
- `direction` (String) wan_to_lan, lan_to_wan, wan_to_router or lan_to_router.
- `ip_version` (String) ipv4 or ipv6.
- `source_cidr` (String) Canonical source network in the selected address family.

Optional:

- `destination_ports` (String) Destination ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `mac_address` (String) Optional canonical uppercase source MAC filter. Omit for any MAC.
- `name` (String) Optional logical rule name used as the router row name (for example `Web` becomes `Web-g7f`). Use ASCII letters, digits, underscores or hyphens, unique across all three lists; surrounding whitespace is rejected. Omit for an unnamed `g7f-01` row. Changing a name stages a new generation and retires the old rows.
- `packets_per_unit` (Number) Optional packet rate limit from 1 through 512 per `rate_limit_unit`. Requires `action = "accept"`.
- `protocol` (String) Inline protocol: all, tcp_udp, tcp, udp, icmp or icmpv6. Required unless `service` or `service_id` is set; the neutral `all` value is computed for both service forms because the referenced service selects the protocol.
- `rate_limit_unit` (String) Time period for `packets_per_unit`: `minute` or `second`. Defaults to `minute`; only used when `packets_per_unit` is set.
- `service` (String) Name of an existing custom protocol/service group. Mutually exclusive with `service_id` and inline protocol/port/TCP-flag filters.
- `service_id` (String) Native custom service ID, for example `zyxel_service.https.id`. Mutually exclusive with `service` and inline protocol/port/TCP-flag filters. The router rows are created through the same ACL rule write path.
- `source_ports` (String) Source ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `tcp_flag` (String) Optional TCP flag to match. Only valid with the `tcp` and `tcp_udp` protocols.


<a id="nestedatt--management_rules"></a>
### Nested Schema for `management_rules`

Required:

- `action` (String) `accept` in `management_rules` and `rules`; `drop` or `reject` in `drop_rules`.
- `destination_cidr` (String) Canonical destination network in the selected address family.
- `direction` (String) wan_to_lan, lan_to_wan, wan_to_router or lan_to_router.
- `ip_version` (String) ipv4 or ipv6.
- `source_cidr` (String) Canonical source network in the selected address family.

Optional:

- `destination_ports` (String) Destination ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `mac_address` (String) Optional canonical uppercase source MAC filter. Omit for any MAC.
- `name` (String) Optional logical rule name used as the router row name (for example `Web` becomes `Web-g7f`). Use ASCII letters, digits, underscores or hyphens, unique across all three lists; surrounding whitespace is rejected. Omit for an unnamed `g7f-01` row. Changing a name stages a new generation and retires the old rows.
- `packets_per_unit` (Number) Optional packet rate limit from 1 through 512 per `rate_limit_unit`. Requires `action = "accept"`.
- `protocol` (String) Inline protocol: all, tcp_udp, tcp, udp, icmp or icmpv6. Required unless `service` or `service_id` is set; the neutral `all` value is computed for both service forms because the referenced service selects the protocol.
- `rate_limit_unit` (String) Time period for `packets_per_unit`: `minute` or `second`. Defaults to `minute`; only used when `packets_per_unit` is set.
- `service` (String) Name of an existing custom protocol/service group. Mutually exclusive with `service_id` and inline protocol/port/TCP-flag filters.
- `service_id` (String) Native custom service ID, for example `zyxel_service.https.id`. Mutually exclusive with `service` and inline protocol/port/TCP-flag filters. The router rows are created through the same ACL rule write path.
- `source_ports` (String) Source ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `tcp_flag` (String) Optional TCP flag to match. Only valid with the `tcp` and `tcp_udp` protocols.


<a id="nestedatt--rules"></a>
### Nested Schema for `rules`

Required:

- `action` (String) `accept` in `management_rules` and `rules`; `drop` or `reject` in `drop_rules`.
- `destination_cidr` (String) Canonical destination network in the selected address family.
- `direction` (String) wan_to_lan, lan_to_wan, wan_to_router or lan_to_router.
- `ip_version` (String) ipv4 or ipv6.
- `source_cidr` (String) Canonical source network in the selected address family.

Optional:

- `destination_ports` (String) Destination ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `mac_address` (String) Optional canonical uppercase source MAC filter. Omit for any MAC.
- `name` (String) Optional logical rule name used as the router row name (for example `Web` becomes `Web-g7f`). Use ASCII letters, digits, underscores or hyphens, unique across all three lists; surrounding whitespace is rejected. Omit for an unnamed `g7f-01` row. Changing a name stages a new generation and retires the old rows.
- `packets_per_unit` (Number) Optional packet rate limit from 1 through 512 per `rate_limit_unit`. Requires `action = "accept"`.
- `protocol` (String) Inline protocol: all, tcp_udp, tcp, udp, icmp or icmpv6. Required unless `service` or `service_id` is set; the neutral `all` value is computed for both service forms because the referenced service selects the protocol.
- `rate_limit_unit` (String) Time period for `packets_per_unit`: `minute` or `second`. Defaults to `minute`; only used when `packets_per_unit` is set.
- `service` (String) Name of an existing custom protocol/service group. Mutually exclusive with `service_id` and inline protocol/port/TCP-flag filters.
- `service_id` (String) Native custom service ID, for example `zyxel_service.https.id`. Mutually exclusive with `service` and inline protocol/port/TCP-flag filters. The router rows are created through the same ACL rule write path.
- `source_ports` (String) Source ports: `*` (any), `443` (single), or `443-445` (inclusive range). Conflicts with `service`/`service_id`. TCP/UDP protocols only.
- `tcp_flag` (String) Optional TCP flag to match. Only valid with the `tcp` and `tcp_udp` protocols.

## Import

Import a complete tail with explicit management membership and exact names:
`terraform import zyxel_acl_policy.https '7f:1:Management-gab,g7f-02,g7f-03'`.
The format is `generation:management_count:row_name,row_name,...`, with names in
router evaluation order. The first `management_count` rows must be accepts.
This supports preserved management identities from earlier generations. Import
does not write router rows or guess management roles. Copy the exact inventory
from trusted state/router readback; never import rows owned elsewhere.

Bare-generation imports (for example `7f`) and legacy `name/generation` imports
remain supported for complete old single-generation policies. They preserve all
accepts in `rules` and leave `management_rules` empty, just like upgraded legacy
state. Add the required management configuration before the next apply. Current
two-hex, earlier four-hex and legacy 16-hex tokens are accepted. Partial,
unsupported or interleaved policies cannot be adopted. Logical labels are
restored and unnamed rows retain null names.

```shell
# Replace with the exact complete tail and management count from your router.
terraform import zyxel_acl_policy.https '7f:1:Management-gab,g7f-02,g7f-03'
```
