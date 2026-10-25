# Mandatory Project Rules

Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing implementation code.

- `zyxel/` is the public, standard-library-only router API. Router business
  rules, input validation, wire decoding, authentication, locking, identity
  resolution, and write verification belong here. Never import Terraform or
  this module's `internal/` packages.
- `internal/provider/` is a thin Terraform adapter: schemas, plan/state handling,
  import, Terraform-specific validation, conversions, and diagnostics. Call the
  API; never implement DAL requests, crypto, or row selection here.
- `internal/cloudflare/` owns the independent plain-Go public-range feed.
  Keep fetching/parsing out of the data source and out of the router API.
- `internal/routertest/` is test support only. Production code must not import
  it. Never export client internals just to support provider tests.
- Use one domain file per concern (`zyxel/nat.go`, etc.) and
  `<name>_resource.go` / `<name>_data_source.go` for Terraform adapters.
- No generic JSON resources, compatibility aliases, speculative abstraction
  layers, separate service/module, or generic `utils` package. Independent
  integrations need a named package and an explicit architecture decision.
- API validation is authoritative for Go callers. Terraform validators may
  duplicate checks for early attribute diagnostics; unknown/null handling,
  replacement decisions, and state updates belong only in the adapter.
- Preserve Terraform schemas/identities unless explicitly asked to change them.
  Never use saved router indexes as durable identities. Preserve recoverable
  state when writes succeeded or may have succeeded.
- Add API tests for router behavior and adapter tests for Terraform behavior.
  Keep encrypted mock integration and Terraform acceptance coverage. Never
  contact or mutate hardware without explicit authorization.

Before submission: `gofmt -w .`, `go build ./...`, `go vet ./...`, and
`go test -race ./...`. Architecture checks run with the tests. Run local mock
Terraform acceptance tests when available; `TF_ACC=1` is not hardware permission.
