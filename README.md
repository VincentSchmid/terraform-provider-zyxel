# Terraform provider for Zyxel routers

A Terraform provider for Zyxel routers, talking directly to the router's
encrypted `DAL` HTTP API. No CLI, Python, or separate agent is needed at runtime.

> **Status: experimental.** Read paths and the mock-router lifecycle tests pass,
> and a read-only `terraform plan` has been verified against a physical router.
> **Live writes (NAT, DHCP, firewall ACL, services, general firewall settings, logging, LAN, and interface groups) have not been verified on hardware.**
> Review every plan before applying, and keep a router configuration backup.

## Requirements

- Terraform 1.14 or newer
- Go 1.27 or newer (only to build the provider yourself)

## Go API And Project Structure

The provider uses the public, Terraform-independent
`github.com/VincentSchmid/terraform-provider-zyxel/zyxel` Go package. It provides
typed status, DHCP, NAT, ACL, firewall-settings, logging, LAN, and interface-group operations, with session locking,
identity resolution, validation, and write verification. Other Go programs can
import it without importing the Terraform adapter.

`internal/provider/` contains Terraform schemas, plan/state handling, imports,
and diagnostics only. Cloudflare feed fetching lives separately in
`internal/cloudflare/`. See [ARCHITECTURE.md](ARCHITECTURE.md) for the enforced
package boundaries and [zyxel/example_test.go](zyxel/example_test.go) for direct
Go usage. [AGENTS.md](AGENTS.md) makes these rules mandatory for future changes;
dependency-boundary tests run in the normal test suite.

Create operations can return an error after a write succeeded or may have
succeeded. Direct Go callers must inspect the returned outcome and reconcile by
natural identity before retrying, just as the provider preserves recovery state.

## Installation

The provider is published on the
[Terraform Registry](https://registry.terraform.io/providers/VincentSchmid/zyxel/latest).
Declare it in your configuration:

```hcl
terraform {
  required_providers {
    zyxel = {
      source  = "VincentSchmid/zyxel"
      version = "~> 6.1"
    }
  }
}
```

Then install the provider:

```sh
terraform init
```

No local build or development override is needed. If you previously configured
a `dev_overrides` entry for this provider, remove it to use the published binary.

## Provider configuration

```hcl
variable "router_host" {
  description = "Hostname or address of the router to manage."
  type        = string
}

variable "router_username" {
  description = "Router administrator username."
  type        = string
  sensitive   = true
}

variable "router_password" {
  description = "Router administrator password."
  type        = string
  sensitive   = true
}

provider "zyxel" {
  host            = var.router_host
  username        = var.router_username
  password        = var.router_password
  timeout_seconds = 10
}
```

| Attribute | Resolution | Notes |
| --- | --- | --- |
| `host` | Explicit configuration, then `ZYXEL_HOST` | Hostname/IP with optional port, or an HTTP(S) origin. A bare host uses HTTP. |
| `username` | Complete configured pair, then the environment pair | `ZYXEL_USER`. Sensitive. |
| `password` | Complete configured pair, then the environment pair | `ZYXEL_PASS`. Sensitive. |
| `timeout_seconds` | Explicit configuration, otherwise `10` | Per-request timeout, 1-120 seconds. |

Set `username` and `password` from the same source: a complete configured pair
is used as a pair, and the provider never mixes a configured value with an
environment value. Configuration is validated without network access;
authentication happens on the first data source or resource operation. Each
operation owns a bounded login/request/logout session, and operations sharing a
normalized endpoint in this process are serialized, including separate clients.

The router firmware limits concurrent administrator logins. Terraform runs
resource operations one after another for that endpoint. Default parallelism is
supported, but use exclusive router access: endpoint aliases, separate Terraform
processes and UI users are not coordinated by the process-local lock.

## Resources and data sources

| Type | Kind | Purpose |
| --- | --- | --- |
| `zyxel_status` | data source | Model, firmware, hostname, uptime, resource use |
| `zyxel_cloudflare_ipv4_ranges` | data source | Fetches Cloudflare's IPv4 list for firewall rules |
| `zyxel_dhcp_reservation` | resource | Enabled static DHCP reservation by MAC address |
| `zyxel_dns_record` | resource | Local DNS host record mapping a host name to an IPv4 address |
| `zyxel_nat_rule` | resource | IPv4 port forwarding rule by service name |
| `zyxel_acl_rule` | resource | Firewall ACL entry with IPv4/IPv6, protocol, MAC, service, TCP flag, direction, and rate-limit filters |
| `zyxel_acl_policy` | resource | Required management accepts, normal accepts and denies, with verified management replacement |
| `zyxel_service` | resource | Reusable firewall protocol/service object referenced by ACL ID |
| `zyxel_firewall` | resource | Router-wide IPv4/IPv6 firewall, security level, and DoS protection |
| `zyxel_log_settings` | resource | Router-wide local-only logging, preserving unrelated log settings |
| `zyxel_interface_group` | resource | Port-based interface groups, referenced by exact-name ID |
| `zyxel_lan` | resource | Per-group IPv4 LAN address, IGMP snooping, DHCP server/disable/relay |

Full documentation is on the
[Terraform Registry](https://registry.terraform.io/providers/VincentSchmid/zyxel/latest/docs)
and in [`docs/`](docs), with examples in [`examples/`](examples).

## Example

All examples use illustrative names, locally administered MAC addresses, reserved
documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
and `2001:db8::/32`), and the reserved `example.test` domain. Replace them with
values for your network before use. Interface paths, management access rules,
and ACL positions must be selected for your router; examples are not a complete
security policy. A provider block with no arguments uses `ZYXEL_HOST`,
`ZYXEL_USER`, and `ZYXEL_PASS` from the environment.

```hcl
provider "zyxel" {}

data "zyxel_status" "router" {}

resource "zyxel_firewall" "router" {
  ipv4_enabled           = true
  ipv6_enabled           = true
  security_level         = "medium"
  dos_protection_enabled = true
}

# Record new events locally; view them under System Monitor > Log.
resource "zyxel_log_settings" "router" {
  enabled = true
}

resource "zyxel_nat_rule" "https" {
  name              = "HTTPS"
  protocol          = "tcp"
  external_ports    = "443"
  internal_client   = "192.0.2.20"
  translation_ports = "443"
}

resource "zyxel_dns_record" "host" {
  hostname     = "host.example.test"
  ipv4_address = "192.0.2.20"
}

resource "zyxel_dhcp_reservation" "host" {
  mac_address  = "02:00:00:00:00:20"
  ipv4_address = zyxel_dns_record.host.ipv4_address
}

# Allow the published Cloudflare ranges to reach the example HTTPS host.
# These accepts alone do not deny other sources. For an ordered allow/drop
# policy, use zyxel_acl_policy as described in the ACL ordering section.
data "zyxel_cloudflare_ipv4_ranges" "https" {}

resource "zyxel_acl_rule" "cloudflare" {
  for_each = toset(data.zyxel_cloudflare_ipv4_ranges.https.ranges)

  name                   = "Cloudflare-${replace(each.value, "/", "-")}"
  action                 = "accept"
  protocol               = "tcp"
  source_cidr            = each.value
  destination_cidr       = "192.0.2.20/32"
  destination_port_start = 443
  destination_port_end   = 443
}
```

## Reusable firewall services and compact ports

```hcl
resource "zyxel_service" "https" {
  name              = "HTTPS"
  protocol          = "tcp"
  source_ports      = "*"
  destination_ports = "443"
}

resource "zyxel_acl_rule" "https" {
  name             = "Allow-HTTPS"
  action           = "accept"
  order            = 10
  destination_cidr = "192.0.2.10/32"
  service_id       = zyxel_service.https.id
}
```

Both resources accept `source_ports` and `destination_ports` as `"*"` (any),
`"443"` (single), or `"443-445"` (inclusive range). Ports apply only to TCP/UDP
(`tcp_udp` is also supported inline in ACLs). ACL numeric bounds remain supported;
do not combine compact and numeric syntax for the same side. With `service_id`,
omit inline protocol, ports, TCP flags, and the legacy `service` name field.
Existing ACL configurations using `service` by name remain supported.

Services support `tcp`, `udp`, `icmp` with `icmp_type`, `icmpv6` with
`icmpv6_type`, and `other` with required `protocol_number`. Type fields are
numeric; omitted ICMP types mean any. See the resource docs for bounds.

Service `id` is the native router `Iid`, not the shifting display index. CRUD
and import use the exact service name. The API resolves the current display
index before ACL creation or service deletion. Import with
`terraform import zyxel_service.https HTTPS`.

**Deletion safety:** the router can remove associated ACL rules when deleting a
service. The provider refuses service deletion while any ACL still references
it, including unmanaged rules. Terraform references order initial creation and
final destruction, but replacing an in-use service may require two applies:
remove dependent ACL resources first, then replace the service and restore the
ACL resources. Do not use `create_before_destroy` with the same service name.
Service writes are covered by encrypted mocks, not verified hardware writes.

## Behavior of managed table entries

The following behavior applies to DHCP reservations, DNS records, NAT rules,
services, and ACL rules.

- **Names are identities.** `zyxel_nat_rule`, `zyxel_service`, and `zyxel_acl_rule` use the router
  entry name as identity and import key; `zyxel_dhcp_reservation` uses the MAC
  address and `zyxel_dns_record` uses the canonical lowercase host name.
  Existing entries must be imported explicitly. Create never adopts an
  existing entry, and duplicate matches are errors rather than guesses.
  `zyxel_acl_policy` owns generation-qualified rows through its `row_names`
  ledger, not a single name.
- **Changes replace entries.** No in-place update operation is verified on this
  firmware, so every configurable change deletes and recreates the entry.
  Forwarding or firewall coverage can be interrupted in between. ACL policies
  instead stage a verified replacement tail; see the ordering guide for limits.
- **Router indexes are observations.** `router_index` is refreshed from the
  router and is not identity; indexes shift when other entries are added or
  removed.
- **Router state wins on read.** An entry deleted outside Terraform is removed
  from state; an entry disabled in the router UI shows up as drift.

Import examples:

```sh
terraform import zyxel_nat_rule.https 'HTTPS'
# Import an existing row into the matching for_each instance; replace the CIDR
# and exact rule name with values from your router and configuration.
terraform import 'zyxel_acl_rule.cloudflare["198.51.100.0/24"]' 'Cloudflare-198.51.100.0-24'
terraform import zyxel_dhcp_reservation.host '02:00:00:00:00:20'
terraform import zyxel_dns_record.host 'host.example.test'
# Use the complete observed tail and management count, not these example names.
terraform import zyxel_acl_policy.https '7f:1:Management-gab,g7f-02,g7f-03'
```

## ACL Ordering And Policies

For `zyxel_acl_rule`, an explicit `order` preserves strict collision/readback
checks. Omit `order` to append from the current table and record the observed
position without numeric-order drift. Appending accepts behind enabled
drop/reject rules is conservatively refused. A separate drop plus `depends_on`
does not support adding accepts after that drop already exists.

For management accepts followed by dynamic normal accepts and drops/rejects, use `zyxel_acl_policy`
with required `management_rules`, optional `rules` and required `drop_rules`; see
[the example](examples/resources/zyxel_acl_policy/resource.tf). There is no
policy name; each rule may carry an optional `name`. Named rows are
`<rule-name>-g<2hex>` and unnamed rows are `g<2hex>-<NN>`. The effective order is
management accepts, normal accepts, then drops/rejects. Names must be unique
across all three lists. Each
rule may set its own `service` name or `service_id` instead of an inline
`protocol` and ports; those rows are created through the same ACL rule write
path.
Updates remove old denies and normal accepts first. Unchanged management
identities remain untouched; changed management is created and verified before
old management is deleted. Normal accepts and denies are then recreated and
final ordering is verified. Preflight enforces 32 total rows, including unmanaged
rules and temporary old/new management coexistence. Partial outcomes retain an
exact recovery ledger. No undocumented reorder operation is used. Initial
creation has no previous policy protection. Hardware writes remain unverified;
review the unrelated prefix for broad accepts.

**Warning:** ACL updates are non-atomic. Deny rules are temporarily removed,
potentially allowing normally blocked traffic. Management rule changes may also
interrupt router access. Use a maintenance window and ensure a recovery path is
available.

Read [ACL ordering, limitations and recovery](docs/guides/acl-ordering-recovery.md)
before migration or retrying partial/tainted creates. Existing rows are never
automatically adopted or moved into policy ownership.

## General firewall settings

`zyxel_firewall` groups **Firewall > General** and **Firewall > DoS** settings:
`ipv4_enabled`, `ipv6_enabled`, `security_level` (`low`, `medium`, or `high`),
and `dos_protection_enabled`. All four values are required and update in place.
`medium` corresponds to the UI's recommended security level. Disabling either
firewall is not recommended by Zyxel.

This is a built-in, router-wide configuration: Create adopts and configures it.
Manage only one instance per router, including across Terraform states. Reads
track UI changes. Writes send only the General screen's fields and the DoS
screen's toggle; ACL rules remain separate `zyxel_acl_rule` resources.
The UI maps Low/Medium/High to DAL `Level_GUI` values `Off`/`Low`/`High`;
Terraform uses the UI names, not those internal values.

General and DoS updates use separate requests and are not atomic. If a write
fails, inspect the router and refresh state before retrying. Destroy leaves all
settings unchanged and only removes Terraform management. Import without
changing the current settings:

```sh
terraform import zyxel_firewall.router router
```

## LAN Setup And Interface Groups

`zyxel_lan` manages **Home Networking > LAN Setup**, excluding IPv6. Select an
existing group with `interface_group_id = "Default"`, or create a group under
**Network Setting > Interface Grouping** using `zyxel_interface_group`:

```hcl
variable "wan_interface_paths" {
  description = "WAN IpIfacePath values selected from this router's UI."
  type        = set(string)
}

variable "lan_interface_paths" {
  description = "LAN IntfPath values selected from this router's UI."
  type        = set(string)
}

resource "zyxel_interface_group" "example" {
  name           = "Example"
  wan_interfaces = var.wan_interface_paths
  lan_interfaces = var.lan_interface_paths
}

resource "zyxel_lan" "example" {
  interface_group_id = zyxel_interface_group.example.id
  ip_address         = "198.51.100.1"
  subnet_mask        = "255.255.255.0"
  igmp_snooping      = "standard"
  dns_mode           = "proxy"
  dhcp = {
    mode                 = "server"
    beginning_ip_address = "198.51.100.100"
    ending_ip_address    = "198.51.100.200"
    auto_reserve_ip      = true
    dhcp_lease_time      = "1d"
  }
}
```

Interface paths are router-specific, not example values to copy blindly.
Inspect the UI's WAN list (`IpIfacePath`) and LAN port list (`IntfPath`); the API
resolves current bridge ports before creating a group. The exact group name is
its stable `id`, not a shifting display index. Group creation requires WAN and
LAN members; classification criteria are outside this increment. Group changes
replace the entry. Existing groups require import by exact name.

`dhcp = { mode = "disabled" }` omits pool, lease, and relay fields. Relay mode
requires `dhcp.relay_server_address` instead of pool/lease fields.
`dhcp.auto_reserve_ip` may be true only in server mode. Server mode requires
`dhcp.dhcp_lease_time`: `1d`, `24h`, `1440m`, or combinations such as `1d5h12m`,
between `1m` and `365d`. Top-level `dns_mode` is `proxy` (default) or `isp`;
`isp` is only valid in server mode. Other modes leave DNS/lease settings untouched.
`igmp_snooping` is `disabled`, `standard`, or `blocking`.
LAN updates are in place; IPv6 and unrelated settings are untouched.
LAN destroy only stops management. Manage one LAN resource per group.

This is a breaking DHCP schema change: old top-level DHCP fields are removed.
See [LAN migration instructions](docs/resources/lan.md#breaking-schema-migration)
to update configuration and reimport an existing state binding safely.

**Connectivity safety:** IP/subnet, DHCP, and membership changes may disconnect
the provider. No writes are retried automatically. If verification fails after
a possible write, inspect the router, update the provider `host` if the address
changed, and refresh state before retrying. Deleting/replacing an interface group
removes its LAN configuration. Replacing a group with a dependent LAN may need
two applies: remove both resources, then recreate both; same-name group IDs do
not trigger a LAN reapply on their own. No live hardware was contacted or changed.

```sh
terraform import zyxel_interface_group.example Example
terraform import zyxel_lan.example Example
terraform import zyxel_lan.default Default
```

## Cloudflare IPv4 ranges

`zyxel_cloudflare_ipv4_ranges` performs one unauthenticated `GET` during plan
against `https://www.cloudflare.com/ips-v4` (overridable with `url`). Every
entry must be a canonical IPv4 CIDR, at least two are required, and duplicates
or error pages fail the plan instead of yielding a partial list. Because the
list is read at plan time, plan output changes when Cloudflare updates it.

## Development

### Build and test

```sh
go build ./...       # build the provider
go vet ./...         # static checks
go test ./...        # unit and encrypted mock-router tests
gofmt -l -s .        # formatting
```

Acceptance tests run Terraform against an in-process mock router and are skipped
unless `TF_ACC` is set:

```sh
TF_ACC=1 go test ./internal/provider -run 'TestAcc' -timeout 10m
```

Regenerate documentation after schema changes with
[tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs):

```sh
go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name zyxel
```

No section of this provider opens a `.env` file or reads credentials from disk.

### Run a local build

To test provider changes instead of the published binary, build it locally:

```sh
go build -o bin/terraform-provider-zyxel .
```

Point Terraform at the directory containing the binary with a development override:

```hcl
# ~/.terraformrc, or the file in TF_CLI_CONFIG_FILE
provider_installation {
  dev_overrides {
    "registry.terraform.io/VincentSchmid/zyxel" = "/absolute/path/to/bin"
  }
  direct {}
}
```

Terraform prints a warning about the override on every command; it is expected.
Remove the override when you want to use the published provider again.

## Releasing

See [PUBLISHING.md](PUBLISHING.md) for the release workflow, signing key setup,
and how new versions reach the Terraform Registry.

## Acknowledgments

Thanks to [millaguie/zyxel-cli](https://github.com/millaguie/zyxel-cli) for the
reference implementation used to port the Zyxel router API integration to Go.

## License

[Mozilla Public License 2.0](LICENSE).
