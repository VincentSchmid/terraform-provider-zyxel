# Terraform provider for Zyxel routers

A Terraform provider for Zyxel routers, talking directly to the router's
encrypted `DAL` HTTP API. No CLI, Python, or separate agent is needed at runtime.

> **Status: experimental.** Read paths and the mock-router lifecycle tests pass,
> and a read-only `terraform plan` has been verified against a physical router.
> **Live writes (NAT, DHCP, firewall ACL) have not been verified on hardware.**
> Review every plan before applying, and keep a router configuration backup.

## Requirements

- Terraform 1.14 or newer
- Go 1.27 or newer (only to build the provider yourself)

## Installation

The provider is published on the
[Terraform Registry](https://registry.terraform.io/providers/VincentSchmid/zyxel/latest).
Declare it in your configuration:

```hcl
terraform {
  required_providers {
    zyxel = {
      source  = "VincentSchmid/zyxel"
      version = "~> 0.1"
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
provider "zyxel" {
  host            = "192.168.1.1"
  username        = "admin"
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
provider client are serialized.

The router firmware limits concurrent administrator logins. Terraform runs
resource operations one after another through one client, but avoid running
several Terraform processes against the router at the same time.

## Resources and data sources

| Type | Kind | Purpose |
| --- | --- | --- |
| `zyxel_status` | data source | Model, firmware, hostname, uptime, resource use |
| `zyxel_cloudflare_ipv4_ranges` | data source | Fetches Cloudflare's IPv4 list for firewall rules |
| `zyxel_dhcp_reservation` | resource | Enabled static DHCP reservation by MAC address |
| `zyxel_nat_rule` | resource | IPv4 port forwarding rule by service name |
| `zyxel_acl_rule` | resource | IPv4 TCP WAN-to-LAN firewall ACL entry |

Full documentation is on the
[Terraform Registry](https://registry.terraform.io/providers/VincentSchmid/zyxel/latest/docs)
and in [`docs/`](docs), with examples in [`examples/`](examples).

## Example

```hcl
provider "zyxel" {}

data "zyxel_status" "router" {}

resource "zyxel_nat_rule" "https" {
  name                = "HTTPS"
  protocol            = "tcp"
  external_port_start = 443
  external_port_end   = 443
  internal_client     = "192.168.1.240"
  internal_port_start = 443
  internal_port_end   = 443
}

resource "zyxel_dhcp_reservation" "nas" {
  mac_address  = "02:00:00:00:00:20"
  ipv4_address = "192.168.1.20"
}

# Allow only Cloudflare to reach the HTTPS host, then drop everyone else.
data "zyxel_cloudflare_ipv4_ranges" "https" {}

resource "zyxel_acl_rule" "cloudflare" {
  for_each = toset(data.zyxel_cloudflare_ipv4_ranges.https.ranges)

  name                   = "Cloudflare-${replace(each.value, "/", "-")}"
  action                 = "accept"
  order                  = index(data.zyxel_cloudflare_ipv4_ranges.https.ranges, each.value) + 1
  source_cidr            = each.value
  destination_cidr       = "192.168.1.240/32"
  destination_port_start = 443
  destination_port_end   = 443
}
```

## Behavior shared by the managed resources

- **Names are identities.** `zyxel_nat_rule` and `zyxel_acl_rule` use the router
  entry name as identity and import key; `zyxel_dhcp_reservation` uses the MAC
  address. Existing entries must be imported explicitly. Create never adopts an
  existing entry, and duplicate matches are errors rather than guesses.
- **Changes replace entries.** No in-place update operation is verified on this
  firmware, so every configurable change deletes and recreates the entry.
  Forwarding or firewall coverage can be interrupted in between.
- **Router indexes are observations.** `router_index` is refreshed from the
  router and is not identity; indexes shift when other entries are added or
  removed.
- **Router state wins on read.** An entry deleted outside Terraform is removed
  from state; an entry disabled in the router UI shows up as drift.

Import examples:

```sh
terraform import zyxel_nat_rule.https 'HTTPS'
terraform import zyxel_acl_rule.cloudflare 'Cloudflare-104.16.0.0-13'
terraform import zyxel_dhcp_reservation.nas '02:00:00:00:00:20'
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

## License

[Mozilla Public License 2.0](LICENSE).
