# Architecture

Two implementation layers: a reusable Go API and a thin Terraform adapter.
The API is a public package in the same Go module, not a server, separate
repository, or separately versioned module. These boundaries are mandatory.

```text
main.go                         executable wiring only
zyxel/
    doc.go                      package contract
    client.go                   HTTP, crypto, authentication, sessions
    status.go                   typed status projection
    dhcp.go                     DHCP types, validation, identity, operations
    dns.go                      local DNS host records and host-name identity
    nat.go                      NAT types, validation, conflicts, operations
    acl.go                      ACL types, validation, profile, operations
    acl_policy.go               ordered ACL tail ownership and management-safe reconciliation
    service.go                  reusable protocol services and compact port syntax
    firewall.go                 router-wide General and DoS settings
    log_settings.go             router-wide logging switch and destination mode
    lan.go                      per-group IPv4 LAN/DHCP settings
    interface_group.go          port-based groups and bridge-port resolution
    *_test.go                   API tests and public usage example
internal/
    provider/
        provider.go             Terraform config/environment resolution, handoff
        *_resource.go           resource adapters
        *_data_source.go        data source adapters
        *_test.go               adapter, encrypted mock, and acceptance tests
    cloudflare/                 independent plain-Go IPv4 feed integration
    routertest/                 encrypted mock protocol helpers; tests only
architecture_test.go            dependency-boundary checks
docs/                           generated registry documentation
templates/                      registry documentation templates
examples/                       Terraform examples
```

## Dependency Rules

```text
main -> internal/provider -> zyxel -> Go standard library
                         -> internal/cloudflare -> Go standard library
                         -> Terraform plugin framework
tests -> internal/routertest
```

1. `zyxel` owns router semantics. Export plain Go types, context-aware methods,
   outcomes, and errors. Never expose generic DAL JSON CRUD or import Terraform,
   read provider environment variables, or update Terraform state.
2. `internal/provider` owns Terraform semantics. Convert plans into API inputs,
   observations into state, and errors into diagnostics. Do not select rows,
   resolve indexes, send requests, decode responses, or implement encryption.
   It may configure an HTTP client for the feed; fetching belongs in `cloudflare`.
   `acl_policy_state.go` alone may use JSON to persist the typed recovery ledger
   in Terraform private state; it must not decode router wire responses. The
   architecture test enforces this narrow state-serialization exception.
3. Validate API inputs independently of Terraform. Early Terraform checks may
   repeat constraints for attribute diagnostics. Unknown/null handling and
   replacement decisions belong only to Terraform.
4. Keep independent integrations separate: Cloudflare's feed is neither a router
   operation nor Terraform business logic. New integrations need an explicit
   package and documented architecture decision.
5. Production code never imports test support. Do not add provider compatibility
   aliases or export API crypto/session internals for testing convenience.

`go test ./...` checks the transitive API dependency graph and rejects wire
protocol dependencies in provider production code. Changing these rules requires
an explicit architecture decision, documentation update, and matching tests.

## Router Safety Contract

- Natural identities are DHCP MACs, canonical lowercase DNS host names, and exact
  NAT/ACL names. Reads reject duplicate matches. Missing DHCP/DNS/NAT reads return
  `nil, nil`; ACL retains `ErrACLRuleNotFound`. The adapter decides how absence
  changes Terraform state.
- Delete resolves current indexes within a serialized authenticated session,
  tolerates absent rows, preserves unrelated rows, and verifies readback.
- Create rejects identity/conflict collisions rather than adopting existing rows.
  DHCP/DNS/NAT return a boolean indicating creation succeeded or may have succeeded.
  ACL returns `ACLCreateOutcome` with separate applied/ambiguous flags and an
  observed rule when available. An error does not necessarily mean no mutation.
- Services use exact names for CRUD/import and expose native `Iid` as `id` for
  ACL references. ACL writes resolve native IDs to current display indexes.
  Service deletion rejects remaining ACL references to prevent cascading loss.
- Router-wide firewall settings are a singleton, not a row resource. `SetFirewall`
  adopts/updates the built-in settings using the existing allowlisted PUTs. Its
  boolean reports success or possible/partial application; Terraform destroy
  relinquishes management without changing protection.
- The API reports uncertainty; Terraform preserves recoverable identity in state.
  Direct Go callers must also reconcile before retrying uncertain writes.
- Logging settings are a built-in singleton. `SetLogSettings` uses the supplied
  `logset` read/copy/PUT workflow, changing only `Enable` and `LogMode` and
  verifying both the requested values and preservation of all other fields.
  Remote destinations, TLS/certificates, email, and categories remain unmanaged.
  Create adopts settings; destroy relinquishes management without disabling logs.
- Locks cover all clients with the same normalized endpoint in this process,
  not endpoint aliases, other processes or web-UI users.
  Never automatically retry ambiguous writes.
- LAN settings are built-in per exact group name: Create adopts and updates,
  Delete relinquishes management. Only IPv4 address/mask, IGMP snooping, and
  active DHCP mode fields are written, including DNS mode and whole-minute lease
  seconds in server mode; IPv6 and unrelated settings are not copied.
  IP/subnet changes may disconnect the client; retain identity for recovery.
- Port-based interface groups use exact names as stable IDs, never display
  indexes. Create resolves WAN and LAN interface paths inside the session and
  translates LAN members to current bridge ports. Delete resolves the current
  display index, protects Default, and rejects duplicate names/criteria groups.
  Group deletion also removes its LAN; adapters document replacement recovery.
- Do not add undocumented PUT, toggling, reorder, or bulk replacement behavior.
  Extraction does not authorize hardware writes or expand firmware support.

### Ordered ACL Policy Decision

`zyxel_acl_policy` owns a contiguous tail ordered as `management_rules`
(required accepts), `rules` (normal accepts), then `drop_rules` (required
drops/rejects). Logical names are optional and unique across all lists. Named
rows are `<rule-name>-g<2hex>`; unnamed rows are `g<2hex>-<NN>`. Earlier 4-hex
and legacy 16-hex formats remain readable. Ownership is exactly `row_names`;
matching names, prefixes or generation tokens never confer ownership.

Configuration, service references, the exact tracked tail and capacity are
validated before mutations. The 32-row limit includes the unmanaged prefix.
Updates delete old denies, then normal accepts. Unchanged management rules are
compared by configuration, not generated identity or observed order, and are
left untouched. Changed management rules are appended and verified as a complete
replacement set before old management is deleted. Normal accepts and denies are
then appended, and final ordering and all supported fields are verified. The
capacity preflight includes temporary coexistence of old and new management;
there is no rejection-triggered capacity fallback or ambiguous-write retry.

All steps run under the endpoint session lock and reuse verified single-row
POST/DELETE, never undocumented PUT/reorder. Partial outcomes preserve exact
identities, expected configurations, management membership and a pending marker
in the API ledger and Terraform private state. Refresh inspects without writes;
pending reconciliation schedules apply even if configuration is unchanged.
Retries remove tracked denies and normal accepts, reuse verified replacement
management prefixes when possible, and never retire old management before
verifying the full replacement. Conflicting identities, unsupported/security-
drifted rows, untracked rows sharing a tracked generation and unrelated
interleaving require operator reconciliation. Destroy removes tracked accepts
before denies and deliberately removes protection.

Schema versions 0 and 1 upgrade without router writes, preserving existing
lists and identities with no inferred management membership. Configuration must
supply management rules for the next apply. Bare-generation and legacy
`name/generation` imports remain supported for old single-generation policies;
explicit `generation:management_count:row_name,row_name,...` import records a
complete mixed-generation tail and management membership without guessing.

**Warning:** ACL updates are non-atomic. Deny rules are temporarily removed,
potentially allowing normally blocked traffic. Management rule changes may also
interrupt router access. Use a maintenance window and ensure a recovery path is
available.

Unrelated prefix rules must be accepts; operators must ensure they do not bypass
the policy denies. Out-of-process writers remain unsupported during operations.

## Development Pattern

Implement and test router behavior in `zyxel/<domain>.go` first; add the smallest
Terraform adapter second. Test missing rows, duplicates, index shifts, conflicts,
sanitized errors, and partial writes at the appropriate layer. Encrypted mock
tests exercise the public API and adapter together. Terraform acceptance tests
use local mock routers, not hardware.

```sh
go test ./zyxel
go build ./...
go vet ./...
go test -race ./...
TF_ACC=1 go test ./internal/provider -run TestAcc -count=1
```

The last command requires Terraform on `PATH` and exercises only mock fixtures.
