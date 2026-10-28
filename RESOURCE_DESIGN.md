# Proposed Zyxel resource structure

Status: **partially implemented**. Provider configuration, `zyxel_status`,
`zyxel_dhcp_reservation`, `zyxel_dns_record`, and `zyxel_nat_rule` are
implemented. Other resource proposals remain a discussion draft; their HCL
examples do not run against the current provider.

## Implemented IPv4 LAN And Interface Groups

`zyxel_lan` manages per-group Home Networking LAN Setup: IPv4 address/mask,
IGMP snooping (`disabled`, `standard`, `blocking`), DHCP (`server`, `disabled`,
`relay`), server pool/auto-reserve/lease, and relay IPv4 address. DHCP uses a
required `dhcp = { ... }` object with `mode`, replacing the former flat fields.
Server leases accept days/hours/minutes (`1d5h12m`, also `24h` or `1440m`) from
1 minute to 365 days and map to `DHCP_LeaseTime` seconds. Top-level `dns_mode`
defaults to `proxy` (`DNSProxy`); `isp` (`FromISP`) is server-only. IPv6 is deferred.
The existing exact-name group is selected by `interface_group_id`; Create adopts
its built-in settings, Update uses allowlisted PUT, and Delete stops management.
DNS and lease time are written only in server mode. Other modes require inactive
`dns_mode = "proxy"` and leave stored DNS/lease fields alone. IPv6 and unrelated
fields are neither copied nor written. Old flat state requires explicit reimport.
Inactive DHCP fields are null in state and not cleared on the router.

`zyxel_interface_group` implements explicit port-based groups in Network
Setting > Interface Grouping. Its exact unique name is `id` and the import key;
references use `interface_group_id = zyxel_interface_group.example.id`. WAN
`IP.Interface.N` paths are validated against `wan`; LAN lower-layer paths
(`Ethernet.Interface.N`, `WiFi.SSID.N`) resolve through `LAN_PORT_LIST_Get` to
current bridge-port paths for POST. Creation requires WAN and LAN members,
rejects conflicting memberships/names, and never adopts an existing group.
Criteria-based groups and managing/deleting Default are outside this resource.
All configurable group changes require replacement. Delete resolves its
current Index by name within the session and verifies absence.

Protocol evidence: the same pinned extracted
[Zyxel UI app.js](https://github.com/dennis-pellanda/Antigravity-REA/blob/5b3f570e3cbb5474892a72198c83a10ed6f8d08e/work/extracted_rootfs/web/static/js/app.js)
contains LANSetup's `LANSetupSetValue`/`apply_action`, the DHCP status screen's
partial `lan` PUTs, `AddNewInterface`'s `okAddNewInterface`/`submit`, and
`InterfaceGroupingContent`'s `qryifGroupObj`/`deleteHandler`. Reads use `lan`
and `intf_group`; group GET exposes `Group_Name`, `Index`, `wanIntf`, `lanIntf`,
and `Criteria`, while POST uses `Name`, `wanIntf`, resolved bridge `lanIntf`, and
empty `critInfo`. Delete uses the current Index. Official series help documents
[LAN Setup](https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/AX-DX-EX-PX_5-70/h_NetworkSetting_HomeNetworking_LoopGuard.html)
and [Interface Grouping](https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/AX-DX-EX-PX_5-70/h_NetworkSetting_InterfaceGrouping_AddNew.html).
These references do not prove exact-model or firmware compatibility.

Address/subnet changes set the UI's logout flag and can prevent readback. Both
APIs report success/uncertainty and adapters preserve names for refresh; writes
are never automatically retried or redirected to a guessed management address.
Group deletion also removes its LAN, so replacement with a dependent LAN may
need staged removal/recreation, especially when the exact-name ID stays the
same. Local encrypted API and Terraform acceptance tests cover these contracts;
no hardware access or mutation is authorized or performed.

## Implemented General Firewall Settings

`zyxel_firewall` manages router-wide Firewall General and DoS settings with
required `ipv4_enabled`, `ipv6_enabled`, `security_level` (`low`, `medium`,
`high`), and `dos_protection_enabled`, plus computed singleton `id = "router"`.
Create adopts and configures the built-in settings; Update changes them in
place; Read detects drift; import uses `router`. Delete stops management
without changing the router. Only one instance may manage a router, including
across Terraform states. ACL entries remain separate resources.

Protocol evidence: the `General` and `Dos` components in the extracted
[Zyxel web UI](https://github.com/dennis-pellanda/Antigravity-REA/blob/5b3f570e3cbb5474892a72198c83a10ed6f8d08e/work/extracted_rootfs/web/static/js/app.js)
use `GET /cgi-bin/DAL?oid=firewall` and separate PUT payloads for General
(`IPv4_Enable`, `IPv6_Enable`, `Level_GUI`, `Firewall_Enable`) and DoS
(`enableDos`). The master `Firewall_Enable` is derived as IPv4 OR IPv6.
The UI labels Low/Medium/High map to DAL `Off`/`Low`/`High`, respectively;
Terraform exposes the UI labels in lowercase. No raw DAL configuration is
exposed or stored in state.

The provider uses encrypted transport, serialized sessions, session-key
rotation, and readback verification. General and DoS updates are separate
requests, not an atomic transaction. Unconfirmed or partially applied writes
preserve singleton identity for refresh/recovery. Missing or malformed settings
are errors, never assumed disabled. Local encrypted mocks cover the contract;
target-firmware and hardware writes remain unverified. No live mutation is
performed.

## Implemented DNS increment

The user's request for the DNS Entry screen selects this first DNS increment:
required `hostname` and IPv4 `ipv4_address`, with the canonical lowercase host
name as identity and import key. The host name must contain at least two
dot-separated labels, each 1-63 characters of ASCII letters, digits, hyphens, or
underscores that starts and ends with a letter or digit, with at most 256
characters in total. Configuration requires the canonical lowercase form;
import accepts any letter case and stores the canonical form. Lookups compare
host names without regard to letter case, and duplicate matches are errors.
Several host names may resolve to the same address; only the name is unique.
Every configurable change requires replacement because no in-place update is
verified.

Router indexes are computed as `router_index` and refreshed before deletion.
Create rejects an existing host name rather than adopting it, and the boolean
outcome preserves identity when a write is ambiguous. Reads reject malformed
rows (missing or invalid index, host name, or non-IPv4 address). The router's own
entry limit is authoritative; the web UI offers at most 20 entries. Local
encrypted mock tests cover the lifecycle; hardware writes remain unverified and
are not authorized by this implementation request.

Protocol evidence: the same pinned extracted
[Zyxel UI app.js](https://github.com/dennis-pellanda/Antigravity-REA/blob/5b3f570e3cbb5474892a72198c83a10ed6f8d08e/work/extracted_rootfs/web/static/js/app.js)
contains the DNS Entry list (`/cgi-bin/DAL?oid=dns`) and `DNSRouteEdit`, which
POSTs `{HostName, IPv4Address}`, PUTs the merged row including its `Index`, and
DELETEs by `Index`, plus its `checkServerName` label validation. The provider
still replaces changed records because no in-place update has been verified.
`oid=dns_route` is a separate domain-based routing feature and is not managed by
this resource.

## Implemented DHCP increment

The user's request to implement DHCP reservations approves this narrow first
increment: required canonical uppercase colon-separated `mac_address` and
`ipv4_address`, optional `enabled` defaulting to `true` with only `true`
accepted in configuration, fixed LAN `BrWan = "Default"`, and replacement for
all configurable changes. The proposed configurable `bridge` and disabled
creation remain deferred because the CLI demonstrates neither behavior.

The MAC address is the import/state identity; there is no additional `id`.
Existing matching rows require explicit import. Duplicate MAC matches fail
rather than selecting a row. Read captures observed IP and enabled state,
removes a missing row from state, and Delete tolerates an already absent row.
Every deletion refreshes the current index inside a serialized client session.
Successful writes refresh the session key and verify the resulting table.
The implementation uses encrypted mock lifecycle tests; live DHCP mutations
remain unverified and require separate authorization.

Source evidence: `../zyxel-cli/zyxel_cli/cli.py` DAL operations (146–204), DHCP
methods (227–246), and DHCP commands (522–582). The sections below retain
future proposals; refer to README and resource docs for the implemented schema.

## Implemented NAT increment

The user's request to implement `zyxel_nat_rule` selects the unique-name
design: exact `name` maps to `Description`, with import by name, conflict on
an existing name during Create, and errors on ambiguous duplicate matches.
This is a provider convention, not a router uniqueness guarantee. The row
`Index` is computed as `router_index` and refreshed before deletion.

Configurable fields are `name`, `protocol` (`tcp`, `udp`, `both`, `all`),
`external_ports`, `internal_client` (IPv4), and `translation_ports`. The port
strings accept a single port or inclusive range with equal lengths. All require replacement;
there is no verified PUT. Port bounds must be ordered, within 1–65535,
and map equal-length ranges. Create rejects external-port overlaps for
intersecting protocols on enabled rules, regardless of interface. This is a
conservative provider restriction, not a claim about firmware conflict rules.

Creation always sends `Enable = true`; `enabled` is computed from the router.
Configurable toggling, interface selection, and the proposed plural NAT data
source remain deferred. Local encrypted mocks establish provider behavior;
hardware writes have not been verified. Replacement can interrupt forwarding
and failed recreation can leave a rule absent. No live mutation is authorized
by this implementation request.

Source evidence: `../zyxel-cli/zyxel_cli/cli.py` DAL transport (146–204), NAT
methods (250–280), list/create/delete commands (594–669), and protocol mapping
(1067–1083). See the generated resource docs for the current schema.

## Project boundaries

The implemented Go structure and mandatory package rules are defined in
[ARCHITECTURE.md](ARCHITECTURE.md) and [AGENTS.md](AGENTS.md). The router API
now lives in public `zyxel/`; `internal/provider/` contains Terraform adapters.
The sibling deployment layout below is historical context, not the current Go
package structure.

```text
router/
├── zyxel-cli/                  upstream reference; kept unchanged
├── provider-zyxel/             Go module and provider binary
│   ├── main.go
│   ├── internal/provider/
│   │   ├── provider.go         schema, configuration, client handoff
│   │   ├── client.go           authentication, crypto, HTTP/session lifecycle
│   │   ├── status_data_source.go
│   │   └── *_test.go           local protocol/configuration tests
│   └── RESOURCE_DESIGN.md      this discussion draft
├── terraform-zyxel/            independent Terraform root module
│   ├── main.tf                Terraform/provider requirements and provider config
│   ├── status.tf              status data source and its derived output
│   ├── dns.tf                 future DNS concern (create when implemented)
│   ├── dhcp.tf                future DHCP concern (create when implemented)
│   ├── acl.tf                 future ACL concern (create when implemented)
│   ├── nat.tf                 future NAT concern (create when implemented)
│   └── routes.tf              future routes concern (create when implemented)
├── .codex/                    coordinator and subagent configuration
└── .agents/skills/             local scouting and execution skills
```

Keep one `<name>_resource.go` adapter with meaningful tests per resource and
typed API methods in `zyxel/<domain>.go`. The earlier single-package client
layout is superseded by the enforced two-layer architecture. Avoid generic
Terraform resources accepting raw OIDs or untyped JSON payloads.

In the consumer, keep Terraform and provider version requirements, provider
aliases/settings, and provider inputs in `main.tf`. Group each implemented
concern's resources, data sources, inputs, locals, and derived outputs in its
own file (`status.tf`, then `dns.tf`, `dhcp.tf`, `acl.tf`, `nat.tf`, or
`routes.tf`). The consumer now includes `main.tf`, `status.tf`, and `acl.tf`;
create future concern files when those concerns are implemented, not as empty
placeholders. Do not activate HCL for a resource before the provider supports
it.

## Resource overview

| Priority | Terraform type | DAL OID | Proposed identity/import key | Main arguments |
| --- | --- | --- | --- | --- |
| Implemented | `zyxel_dns_record` | `dns` | Canonical lowercase host name; matched without regard to letter case | `hostname`, `ipv4_address` |
| Implemented | `zyxel_dhcp_reservation` | `static_dhcp` | Canonical uppercase MAC address | `mac_address`, `ipv4_address`, `enabled` (true only); fixed default LAN bridge |
| Implemented | `zyxel_acl_rule` | `firewall_acl` | Unique `name`; import existing rows before Terraform manages them | `name`, `action`, `order`, `protocol`, `ip_version`, `direction`, `source_cidr`, `destination_cidr`, destination/source port ranges, `mac_address`, `service`, `tcp_flag`, rate limit, `enabled` |
| 4 | `zyxel_nat_rule` | `nat` | Unique `name` mapped to DAL `Description`; verify uniqueness first | `name`, `protocol`, `external_ports`, `internal_client`, `translation_ports`, `enabled` |
| 5 | `zyxel_static_route` | `static_route` | Unique route `name` | `name`, `destination_cidr`, `gateway`, `interface`, `enabled` |

The CLI demonstrates create, list, and delete for DNS, DHCP, NAT, and routes;
`firewall_cf.py` is the separate ACL protocol reference described below.
Neither source establishes safe PUT updates for managed rows. First releases
should require replacement for changed fields until targeted updates are
verified. A reviewed update implementation can later reduce replacements
without changing identities.
The existence of an `enabled` field in read/create payloads does not establish
that arbitrary toggling is supported; test each transition before exposing it.

DHCP and DNS are implemented with the narrow scopes above. ACL is a high-priority design candidate based on `firewall_cf.py`, but
its explicit order semantics need verification before production use. Develop
against mocks, then verify router ordering, collision, deletion, and replacement
behavior in an authorized live check. NAT and routes need additional conflict, interface, and update
work.

## Implemented firewall ACL rule

`zyxel_acl_rule` now implements the `firewall_acl` GET/POST/DELETE contract
from `firewall_cf.py` directly in Go. The provider has no runtime dependency
on the script or Python. See [the generated resource documentation](docs/resources/acl_rule.md)
for the current schema, lifecycle, and import example.

The implemented scope covers the fields exposed by the router's Edit ACL Rule
screen for a rule with interface `ALL`: `action` (`accept`/`drop`/`reject`),
`protocol` (`all`, `tcp_udp`, `tcp`, `udp`, `icmp`, `icmpv6`), `ip_version`
(IPv4/IPv6), `direction`, source/destination CIDRs, destination and source port
ranges, `mac_address`, custom `service` groups, `tcp_flag`, and packet rate
limiting for `accept` rules through `packets_per_unit` (1–512 packets) and
`rate_limit_unit` (`minute` or `second`). Interface selection and schedule rules
remain outside this resource; schedule references are rejected on read.
Unrelated ACL entries remain untouched.

Required configuration: exact unique `name`, `action`, and canonical
`destination_cidr`. An explicit positive `order` selects strict semantics;
omitting it selects verified append semantics. `protocol` defaults to `tcp`,
`ip_version` to `ipv4`, `direction` to `wan_to_lan`, `source_cidr` to
`0.0.0.0/0`, and `enabled` to `true`. With `ip_version = "ipv6"` both CIDRs
must be IPv6. Destination and source port bounds must each be set together, or
both null for any port, and are only accepted for `tcp`, `udp`, and `tcp_udp`.
`tcp_flag` is only accepted for `tcp` and `tcp_udp`. A custom service is resolved
by name against the router's `firewall_proto` table on create and by the
router-returned `ServiceName` on read. Every configurable field requires
replacement; no undocumented PUT or reorder operation is called.

The name is the state/import identity. Import supports only the implemented
profile. Existing names require explicit import; duplicate names are errors.
The computed `router_index` is refreshed and used only as a current API
locator, including before deletion. Source/destination masks use prefix
lengths, and reads normalize string/numeric fields such as `IPVersion`.

Strict create rejects an occupied order, posts the requested value, and verifies
the stored fields and order. Only an omitted order opts into `max(Order)+1`,
with verified last placement and computed observed order. Append accepts behind
enabled drop/reject or unknown actions are refused. Neither model reorders other
entries. When a write has or may have succeeded but cannot be
confirmed, the resource records its identity in state and returns a diagnostic.
Inspect the router/state before retrying a failed creation. A disappeared
managed row is removed from state; deleting an absent row succeeds.

Replacement deletes the old entry first and may temporarily remove a firewall
rule. A later creation failure can leave the old rule absent. Independent
resource operations do not establish a global firewall policy: explicit rule
orders, earlier drop rules, unmanaged entries, and external configuration
changes still matter. Terraform `depends_on` controls operation sequencing,
not router evaluation order or cross-process coordination.

`zyxel_acl_policy` separately owns a contiguous ACL tail as two ordered lists:
`rules` holds accepts and `drop_rules` holds drops/rejects. The effective order
is every accept, then every drop/reject, and at least one drop/reject is
required. Rules are validated independently, so heterogeneous protocols,
services, address families, directions, destinations, ports, MAC filters and
rate limits are allowed; `service_id` is per rule. It stages complete
generations and verifies the replacement drops before removing old accepts and
old drops/rejects. See the architecture decision and
[ordering/recovery guide](docs/guides/acl-ordering-recovery.md) for the tail
restriction, partial ledgers, non-atomic transition semantics and explicit
import. It uses no ACL PUT or reorder operation.

### Observed firmware ordering limits

Live attempts on the AX7501-B0 established three constraints that rule out
independent, order-bearing ACL resources:

- **Order is a position, not a declarative slot.** POSTing order 3 onto a
  one-row table clamps to position 2; the readback differs from the request.
  A position cannot be reserved for a later insert.
- **Deletes compact the table.** Remaining rows renumber, so a stored `order`
  drifts after unrelated deletions. Treating the number as durable state
  requires `ignore_changes` and still cannot express insertion.
- **There is no verified insertion or reorder primitive.** The provider has only
  POST and DELETE. A requested order is not an insertion instruction, and the
  web UI's reorder behavior has not been captured as a DAL contract.

Therefore independent `zyxel_acl_rule` resources cannot enforce an order among
themselves: Terraform does not sequence independent resources, and the firmware
does not hold requested positions. The only ordering mechanism with a coherent
unit of ownership is the policy's staged tail. `zyxel_acl_rule` remains useful
for static, fully known sets where each row's position does not need to be
coordinated with a changing feed; dynamic lists (for example Cloudflare ranges)
belong in `zyxel_acl_policy`, which appends one complete generation behind the
old tail, verifies it, and retires the old generation.

Local encrypted mock tests and real Terraform tests cover the modeled API,
field replacement, import, disappearance, index changes, conflicting orders,
and partial-creation state. Live writes, insertion/renumbering, and firmware
ordering behavior still require a separately authorized verification plan.

The consumer groups its ACL resources, input map, and output in `acl.tf`.
`acl_rules` defaults to `{}`, so installing this increment activates no rules.
The provider does not fetch Cloudflare ranges; supply reviewed source CIDRs
and stable rule names in consumer configuration. Use stable identities rather
than names derived from a changing feed's position.

## Identity and ownership

Router `Index` is an API locator, not a demonstrated durable identity. A row
can move after another row is removed or configuration is changed externally.
Terraform should retain a natural key and find its **current** row before
every read, update, or delete. An observed index can be a computed `router_index`
for diagnostics, but it must never be used blindly for later mutations.

- Scope identities to the provider's router. Use provider aliases for multiple
  routers and keep identical names on different routers independent.
- Normalize DNS and MAC identities consistently only after confirming firmware
  matching behavior. Document import syntax and test it with a state round trip.
- Fail when zero/multiple matches make a mutation ambiguous. A missing row
  during managed-resource Read removes it from state; Delete treats an already
  missing row as success.
- Do not silently adopt an existing matching row during Create. Report the
  conflict and require explicit import. Import manages only that selected row.
- Manage individual entries and preserve unrelated configuration and rows.
  Do not claim ownership of an entire router list to manage one entry.
- Serialize mutations within one provider client, refresh the session key after
  writes, and resolve indexes inside the same critical section. Independent
  Terraform processes still require an operational coordination policy; local
  locking cannot prevent a web UI or another process from changing the router.

For NAT, a unique description is a proposed provider convention rather than a
proven router invariant. If duplicates are normal, use a documented composite
identity or a firmware-native identifier after research. Do not ship name-based
deletion while duplicate handling remains unresolved.

## Attribute decisions

DNS initially supports IPv4 because that is what the CLI writes. DHCP `bridge`
maps to `BrWan`; the CLI requires `Default` when creating a LAN reservation.
Treat DHCP IPv4 changes as replacement until an in-place update is demonstrated.

NAT protocol should use a documented Terraform enum and translate to the exact
router representation. Validate ports 1–65535, ordered ranges, matching mapped
range lengths where firmware requires them, and conflicts with existing rules.
Do not infer WAN-interface selection from fields absent in the CLI payload.

Route `destination_cidr` should map to `DestIPAddress` plus `DestSubnetMask`,
with IPv4-only validation first. `interface` needs the CLI's `Default`/DAL path
translation and read normalization to avoid perpetual drift when the router
returns `IP.Interface.1` instead of `Default`. Changing the identity name
requires replacement. The initial API calls also fix `IPType`, `ipver`, and
`UseGateIpAddr`; expose additional modes only after their semantics are known.

Replacement may require deleting the existing entry before creating its
successor, so a failed create can leave that entry absent. Do not recommend
`create_before_destroy` where unique keys or port conflicts prevent overlap.
Document this behavior and use mock failure tests before adding live coverage.

## Proposed data sources

| Type | Purpose | Timing |
| --- | --- | --- |
| `zyxel_status` | Model, firmware, hostname | Implemented now |
| `zyxel_dns_records` | List local host records | Alongside DNS resource |
| `zyxel_dhcp_reservations` | List static DHCP entries | Alongside DHCP resource |
| `zyxel_nat_rules` | Discover rules and conflict candidates | Alongside NAT resource |
| `zyxel_static_routes` | Discover routes and interface references | Alongside route resource |
| `zyxel_acl_rules` | List allowlisted IPv4/TCP ACL fields including current order | Alongside ACL resource; order proof required before release |
| `zyxel_wan_interfaces` | Allowlisted interface/address/link fields | Later; omit PPPoE credentials |
| `zyxel_wifi_networks` | Allowlisted SSID/radio settings | Later; omit WiFi keys |

Plural data sources return collections, including empty collections. Singular
lookups, if added, must reject ambiguous or missing matches. Keep passwords,
session tokens, PPPoE/SIP/GPON provisioning values, and whole raw DAL objects
out of state. Marking an attribute sensitive would only hide display, not
remove its bytes from state.

The proposed `zyxel_acl_rules` data source should expose one computed
`rules` collection with allowlisted rule identity, action, order, CIDRs, port
bounds, and enabled state. It should not expose arbitrary DAL objects or treat
router `Index` as a durable identifier.

## Deferred capabilities

- WAN DNS changes: the CLI reads and rewrites an entire interface; applying it
  can reconnect PPPoE. This needs separate ownership/recovery design.
- WiFi mutation: the current CLI only establishes reads. Avoid managing keys
  or toggles until their write contracts and state exposure are understood.
- ISP provisioning, reboot/reset/backup actions: outside this first resource
  plan. Nothing in the current scope warrants raw write access.
- Remote state: choose a backend after the local client and initial resource
  design are accepted. Provider distribution is now available through the
  [Terraform Registry](https://registry.terraform.io/providers/VincentSchmid/zyxel/latest).

## Example target shape

Illustrative future HCL, after these resources are implemented:

```hcl
resource "zyxel_dns_record" "host" {
  hostname     = "host.example.test"
  ipv4_address = "192.0.2.20"
}

resource "zyxel_dhcp_reservation" "host" {
  mac_address  = "02:00:00:00:00:20"
  ipv4_address = zyxel_dns_record.host.ipv4_address
  enabled      = true
}
```

The consumer can later use `for_each` over named input maps for multiple
entries. Keep the provider independent of household-specific device names,
addresses, and desired rules.

## Delivery and discussion

1. **Client foundation — implemented:** local provider, environment/config
   resolution, encrypted client, status data source, separate consumer, mock tests.
2. **DHCP — implemented:** enabled LAN reservations with MAC identity, duplicate
   guards, import, and replacement; local mock verification only. Broader DHCP
   settings remain proposals.
   **DNS — implemented:** local host records with canonical lowercase host-name
   identity, duplicate guards, import, and replacement; local mock verification
   only.
3. **ACL — implemented:** Go resource, import, replacement, encrypted mock
   lifecycle tests, and consumer `acl.tf`. Live ordering behavior remains
   unverified; verify it under a separately authorized plan before production use.
4. **NAT — implemented:** unique names, IPv4, enabled creation, import,
   conservative conflict checks, and replacement; local mock verification only.
   Routes and broader NAT settings remain proposals.
5. **Live verification:** mock lifecycle tests first; any live mutations require
   separate user authorization and a concrete, reviewed plan.

Suggested decisions for discussion: extend DHCP only with further protocol
evidence;
use the implemented ACL resource with explicit reviewed orders;
use unique NAT descriptions if acceptable; keep WAN/WiFi read-only initially;
accept replacement only for fields whose update behavior is unverified. These
are proposals, not implemented CRUD.

Source: `../zyxel-cli/zyxel_cli/cli.py`, especially authentication/status
(32–210), DNS/DHCP (214–246), NAT/routes (250–310), WAN (314–340), and WiFi
(357–360), at commit `4da28c4b69b77f162763d95c3b8bb86c506693ac`; ACL script
reference: `../firewall_cf.py` (working-tree script, not a provider CRUD
contract).
Framework design follows the installed
[HashiCorp skills](https://github.com/hashicorp/agent-skills).
