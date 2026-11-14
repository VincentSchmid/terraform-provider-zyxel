---
page_title: "zyxel_nat_rule Resource - zyxel"
subcategory: ""
description: |-
  Manages one supported router NAT rule. The router has no verified in-place update operation, so changes replace the rule. Existing rules must be imported by exact name. Enabled rules cannot overlap external ports for an intersecting protocol; disabled rules do not reserve ports. Creation explicitly selects automatic default-WAN detection and unrestricted remote sources; interface and remote-source selection are not configurable.
---

# zyxel_nat_rule (Resource)

Manages one supported router NAT rule. The router has no verified in-place update operation, so changes replace the rule. Existing rules must be imported by exact name. Enabled rules cannot overlap external ports for an intersecting protocol; disabled rules do not reserve ports. Creation explicitly selects automatic default-WAN detection and unrestricted remote sources; interface and remote-source selection are not configurable.

## Example Usage

```terraform
# Replace the documentation address with your server's LAN address.
resource "zyxel_nat_rule" "https" {
  name              = "HTTPS-to-server"
  protocol          = "tcp"
  external_ports    = "443"
  internal_client   = "192.0.2.20"
  translation_ports = "443"
}
```

The provider creates enabled IPv4 forwarding rules. `enabled` reports the
observed router setting; enable/disable configuration and WAN interface
selection are not supported. Creation explicitly sends `Interface = ""`,
`X_ZYXEL_AutoDetectWanStatus = true`, `SetRemoteIP = false`, and
`RemoteHost = ""` for automatic default-WAN selection and unrestricted remote
sources. This four-field addition is source-backed, not independently hardware
verified; successful controlled requests used a larger UI-style object. See
the repository architecture decision for evidence and limitations.
Replacing an imported rule does not preserve interface selection or other
settings outside this resource's schema. `protocol` accepts `tcp`,
`udp`, `both`, or `all`, which map to `TCP`, `UDP`, `TCP+UDP`, and `ALL` on
the router. `all` forwards every protocol, so it is broader than `both`.
Use `external_ports` and `translation_ports` strings: `"8443"` is a single
port (equal start and end), and `"8443-8444"` is an inclusive range. Wildcards,
empty values, and port lists are not supported. Both ranges must have the same
length. An equal-bound range such as `"8443-8443"` is also accepted.

## Upgrading to v2.0.0

This is a breaking configuration change. Replace `external_port_start` and
`external_port_end` with `external_ports`, and replace `internal_port_start`
and `internal_port_end` with `translation_ports`. Remove all four old arguments;
they are no longer accepted. `internal_client`, rule names and resource
addresses are unchanged.

```terraform
external_ports    = "8443-8444"
translation_ports = "8443-8444"
```

Existing version-0 resource state is upgraded automatically, without router
writes or re-imports. Keep equivalent port values during migration to avoid
replacement. A real port change still replaces the rule; review the plan before
applying. Back up state through your backend before upgrading; do not downgrade
to a v1 provider after state has been upgraded.

## Identity and changes

The exact rule `name` maps to the router's `Description` and must be unique.
Existing rules with that name must be imported; Create never adopts them.
Duplicate matches fail without changing the router. The computed
`router_index` is an observed locator, not the Terraform identity. Delete
reads the table again and resolves the name to its current index.

Every configurable change replaces the rule because in-place updates have
not been verified. Replacement normally deletes the old rule before creating
the new one, so forwarding is interrupted and a failed creation may leave
the rule absent. Do not use `create_before_destroy` when the name or external
ports overlap.

Create rejects overlap with enabled rules using the same external ports and
an intersecting protocol, regardless of WAN interface. This conservative check
can reject combinations the router might otherwise allow. `both` and `all`
intersect every protocol. A client lock
serializes this provider's operations; it cannot coordinate other Terraform
processes or router UI edits.

The implementation is verified against local encrypted mock servers. This exact
create payload and provider deletion have not been verified on hardware.

### Uncertain or partial creation

A failed write or readback can leave a valid named row or an incomplete unnamed
row. The provider never retries POST or automatically cleans up/adopts such rows.
It retains the planned name and arguments when creation succeeded or may have
partially succeeded; computed values in that recovery state are not confirmation
of a valid router row. A verified rejection with an unchanged valid table does
not claim creation.

Malformed rows fail the entire NAT read, including reads of unrelated rules.
Inspect the table through an authorized recovery path before retrying. Do not
blindly untaint, replace state, or delete unnamed rows. If a valid named rule is
confirmed, reconcile/import its exact identity as appropriate. Removing an
incomplete row requires separately reviewed evidence and authorization.

Session-start diagnostics identify pre-auth discovery failures (credentials
were not submitted), separately from login rejection and uncertain writes.
The endpoint session gate coordinates only this process, not other processes,
endpoint aliases, or UI users; concurrent log lines alone do not establish
concurrent router requests.

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `external_ports` (String) External port or inclusive range, such as `8443` or `8443-8444`. Ports must be canonical decimal numbers from 1 through 65535; wildcards are not supported. Must contain the same number of ports as `translation_ports`.
- `internal_client` (String) IPv4 address of the destination host.
- `name` (String) Exact, nonempty router description. This is the natural identity and import key; leading and trailing whitespace are not allowed.
- `protocol` (String) Transport protocol: `tcp`, `udp`, `both`, or `all`. The router stores these as `TCP`, `UDP`, `TCP+UDP`, or `ALL`; `all` forwards every protocol, which is not the same as `both`.
- `translation_ports` (String) Destination port or inclusive range, such as `8443` or `8443-8444`. Ports must be canonical decimal numbers from 1 through 65535; wildcards are not supported. Must contain the same number of ports as `external_ports`.

### Read-Only

- `enabled` (Boolean) Whether the router reports this rule enabled. New rules are created enabled; this attribute is read-only because no safe update operation is verified.
- `router_index` (Number) Current router list index used only as a locator. It may change when other rules are added or removed and is not used as resource identity.

## Import

Import uses the exact, unique rule description, including its case:

```shell
# Import by the exact, unique router rule description.
terraform import zyxel_nat_rule.https 'HTTPS-to-server'
```
