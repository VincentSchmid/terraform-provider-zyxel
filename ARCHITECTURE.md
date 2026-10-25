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
    nat.go                      NAT types, validation, conflicts, operations
    acl.go                      ACL types, validation, profile, operations
    firewall.go                 router-wide General and DoS settings
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

- Natural identities are DHCP MACs and exact NAT/ACL names. Reads reject duplicate
  matches. Missing DHCP/NAT reads return `nil, nil`; ACL retains
  `ErrACLRuleNotFound`. The adapter decides how absence changes Terraform state.
- Delete resolves current indexes within a serialized authenticated session,
  tolerates absent rows, preserves unrelated rows, and verifies readback.
- Create rejects identity/conflict collisions rather than adopting existing rows.
  DHCP/NAT return a boolean indicating creation succeeded or may have succeeded.
  ACL returns `ACLCreateOutcome` with separate applied/ambiguous flags and an
  observed rule when available. An error does not necessarily mean no mutation.
- Router-wide firewall settings are a singleton, not a row resource. `SetFirewall`
  adopts/updates the built-in settings using the existing allowlisted PUTs. Its
  boolean reports success or possible/partial application; Terraform destroy
  relinquishes management without changing protection.
- The API reports uncertainty; Terraform preserves recoverable identity in state.
  Direct Go callers must also reconcile before retrying uncertain writes.
- Locks cover one client only, not other clients/processes or web-UI users.
  Never automatically retry ambiguous writes.
- Do not add undocumented PUT, toggling, reorder, or bulk replacement behavior.
  Extraction does not authorize hardware writes or expand firmware support.

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
