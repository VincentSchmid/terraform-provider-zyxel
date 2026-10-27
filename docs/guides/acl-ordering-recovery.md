# ACL Ordering, Policies And Recovery

## Individual Rules

`zyxel_acl_rule` keeps exact-name identity. Setting `order` preserves strict
behavior: occupied positions fail before POST; a different readback position
fails after POST. A configured number is not an insertion/reorder instruction.
Terraform does not sort `for_each` creation numerically, even at parallelism 1.

Omit `order` (or set `null`) to opt into append behavior: select `max(Order)+1`
from the current table, write, verify last placement and all supported security
fields, and record the observed position. Firmware compaction refreshes computed
positions without replacement or apply inconsistency. Explicit orders are never
ignored. Removing a configured order relinquishes numeric position management;
it does not move an existing row. Adding a strict order can require replacement.

Append accepts are conservatively refused behind enabled drop/reject or unknown
actions, even unrelated terminal rules. Disabled terminal rows are ignored.
An appended drop plus `depends_on` is **not ongoing policy management**: later
accepts would follow the existing drop. Dependencies order pending operations;
they do not move existing rules. The provider does not move/delete that drop to
make an independent accept succeed.

## Ordered Policies

**Warning:** ACL updates are non-atomic. Deny rules are temporarily removed,
potentially allowing normally blocked traffic. Management rule changes may also
interrupt router access. Use a maintenance window and ensure a recovery path is
available.

Use `zyxel_acl_policy` for a contiguous managed tail with three ordered lists:

- `management_rules`: required, at least one `accept`, evaluated first.
- `rules`: optional normal accepts, evaluated next.
- `drop_rules`: required, at least one `drop` or `reject`, evaluated last.

Final ordering is `management_rules -> rules -> drop_rules`. Each rule may have
its own scope, protocol/service, address family, direction, ports and filters.
Rate limits are accept-only. Service references replace inline protocol/ports
and compute protocol `all`, as in `zyxel_acl_rule`. There is no numeric order.
Choose only one example from `examples/resources/zyxel_acl_policy/resource.tf`
per router. Management accepts must actually permit your access path; router
readback verification cannot prove network reachability.

Logical names are optional, unique across all lists, and limited to ASCII
letters, digits, underscores and hyphens. Named rows are `<name>-g<2hex>`;
unnamed rows are `g<2hex>-<NN>`. Earlier four-hex and legacy 16-hex formats
remain readable. Keep labels short: some firmware has a 16-character UI limit.
Ownership is exclusively the exact `row_names` ledger, not a prefix/token.
Unchanged management identities are preserved, so healthy policies may span
multiple generations. `generation` identifies the latest reconciliation.

The policy must own a contiguous tail. Unmanaged prefix rules must be accepts
or disabled; operators must review them for overlap because broad earlier
accepts can bypass policy denies. Do not manage generated rows individually,
append another policy after the tail, or use another state/writer concurrently.

### Update Sequence

Before mutations, validate configuration, all service references, ownership and
readback, the unmanaged prefix, and both capacity limits. Preflight failure
performs no POST/DELETE. Compare management rules by configuration and logical
labels, ignoring generated names and computed numeric ordering.

When management is unchanged:

1. Delete old deny rules.
2. Delete old normal rules.
3. Keep existing management rules untouched.
4. Create new normal rules.
5. Create new deny rules.
6. Verify the final tail ordering, supported security fields and prefix.

When management changes:

1. Delete old deny rules.
2. Delete old normal rules.
3. Create and verify the complete new management set.
4. Delete old management only after replacement verification.
5. Create new normal rules.
6. Create new deny rules.
7. Verify the final tail ordering, supported security fields and prefix.

Only verified single-row POST/DELETE are used, resolving current indexes by
exact name. No PUT/reorder, automatic rollback or ambiguous-write retry occurs.
Deny protection is absent between deletion and recreation; a failure can extend
that window until recovery. Verifying management readback does not prove that
a fresh session can reach the router. Initial creation may also leave accepts
without intended denies after failure. Connection tracking is firmware-dependent.

### Capacity And Recovery

The router limit is 32 total ACL rules, including unmanaged prefix rows:

- Final: `unmanaged + desired management + desired normal + desired deny <= 32`.
- Management transition: `unmanaged + old management + new management <= 32`.

Normal/deny removal precedes management replacement. The peak is the larger of
these totals and the initial table size. No capacity fallback retires management
early. Transitional overflow aborts before any mutation even if final size fits.

Accepted/ambiguous creates retain exact names and expected configurations.
Successful deletions remove names only after verified readback. The typed
recovery ledger includes management membership and an explicit pending marker;
Terraform private state preserves it even when public configuration is still
from the prior apply. Back up full Terraform state, not just public attributes.
Refresh inspects without writes and schedules apply for pending recovery, even
when configuration returns to its previous values. Retry removes only tracked
denies/normal accepts, reuses verified replacement management prefixes where
possible, and never retires old management before verifying the complete desired
set. Unchanged management remains untouched during recovery.

Missing tracked rows can be reconciled; namespace matches are never adopted.
Duplicate identities, unsupported/security-drifted rows, untracked rows sharing
tracked tokens, or unrelated interleaving require operator reconciliation.
Destroy deletes only tracked rows, accepts before denies, deliberately removing
protection. Do not discard a ledger or clear taint to bypass diagnostics.

### Existing State And Import

Schema versions 0 and 1 upgrade without router writes. Existing lists,
generation, row names and observed orders are retained; the obsolete root name
is discarded. No management role is inferred: upgraded state has an empty
management list. Add required `management_rules` configuration before the next
apply. Existing normal accepts/denies are rebuilt by the sequence documented
here; migration is not hitless and does not preserve a normal accept as management.

Import a complete modern tail with exact membership:

```sh
terraform import zyxel_acl_policy.https '7f:1:Management-gab,g7f-02,g7f-03'
```

Format: `generation:management_count:row_name,row_name,...`. All names must be
present and in the stated tail order; the first count entries are management
accepts. This explicitly supports mixed generations without writing rows or
guessing management roles. Bare `GENERATION` and legacy `NAME/GENERATION` forms
remain compatible with complete old single-generation policies, putting all
accepts in `rules` and leaving management empty. Add management configuration
before applying legacy imported state. Never import rows owned elsewhere.

One process-local endpoint lock covers login, selection, reconciliation,
verification and logout. Default Terraform parallelism is supported but does not
establish evaluation order. Endpoint aliases, other processes/states and web-UI
users are not coordinated; use one endpoint spelling and exclusive access.
Hardware writes remain unverified. GUI insertion documentation is not a DAL
reorder contract and does not authorize additional operations.

## Manual Recovery For Conflicts

For a verified partial policy ledger, review and apply Terraform's recovery
plan; manual state editing is not required. Refresh itself never cleans up
router rows. The following procedures are for conflicts that prevent verified
reconciliation, or for individually managed ACL rules.

These are **operator procedures**, not actions run automatically or during
development. Stop all writers. Obtain an approved maintenance window, router
backup, out-of-band/local management and rollback plan before any writes. Keep
router exports/state private: they may contain credentials and network details.

1. Back up state (`terraform state pull` to a private file), HCL and the entire
   router ACL table. Record exact names, current indexes/orders, enabled status
   and all filters. Do not retry apply yet.
2. Compare router inventory with `terraform state list` and `terraform state
   show`. Classify healthy tracked, tainted tracked, untracked and duplicate-name
   rows. Include every policy `row_names` entry and all router rows carrying a
   generation used by the ledger. Missing ledger rows may be ambiguous writes
   that never committed.
3. Operator-review the complete effective policy: management accepts must precede normal accepts, which precede
   every drop/reject, and prefix accepts must not bypass the drop rules. Resolve
   duplicate names through an explicitly approved manual change; the provider
   cannot choose.
4. To retain a tainted single-rule row, first verify every security field and
   matching HCL. Only after review, `terraform untaint ADDRESS` removes the
   forced replacement marker. It does **not** write or repair the router and can
   leave an ineffective accept behind a drop. Do not clear taint on name alone.
5. To retain an untracked single-rule row, add matching HCL and explicitly run
   `terraform import ADDRESS 'Exact-Name'`. This changes state, not the router.
   Never import a row already owned by another address/state. Do not use `state
   rm` as a generic fix: it abandons ownership and can cause the next create to
   collide with a live row.
6. Import complete supported tails with the exact-name form documented above.
   Bare-generation and legacy forms are for old single-generation policies and
   do not infer management roles. Partial/damaged policies require operator
   reconciliation while preserving the complete inventory and backup.
7. Migration from individually managed legacy rows is a separate approved router
   and state migration. There is no automatic transfer, rename or `moved`
   conversion. An existing legacy drop blocks fresh policy creation; do not
   remove it merely to make apply pass. Manual rebuild/rename/staging must
   preserve deny coverage, avoid double ownership and account for outage.
   Deleting rows removes live protection; removing state abandons management.
   Both require explicit review. If no safe migration is established, leave the
   legacy table individually managed and defer migration.
8. Review a fresh plan, including every replacement/destroy, before authorizing
   apply. Review refresh/state commands too: they read the router/update state.
   Independently verify the resulting table and traffic after approved writes.

Development uses loopback fixtures only. It never deletes live router rules,
removes deployment state, clears taint or runs live plan/apply.
