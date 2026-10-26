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

Use `zyxel_acl_policy` to own the accept collection **and its drop**, with an
ordered `rules` list. See `examples/resources/zyxel_acl_policy/resource.tf`.
Zero accepts plus one drop is supported, up to 998 accepts plus one drop. Names
are `<policy>-g<generation>-001`, `-002`, etc. Exact generated names are stored
in `row_names`; prefix matching never grants ownership during create.

This initial implementation intentionally supports only enabled inline accepts
followed by one enabled drop matching any source. All rules share protocol,
address family, direction, destination CIDR and source/destination port filters.
No services, MAC/TCP flags, rate limits, schedules or interface selection are
exposed. The drop is a catch-all **within those filters**, not for the entire
firewall. Policy rules have no numeric order. Traffic-scope changes are rejected
before writes; changing source ranges, accept order and collection size is
supported.

The policy must own a contiguous table tail after an unrelated prefix. Prefix
rules must be accepts or disabled. Operators must review them for overlap: a
broad earlier accept can bypass the policy drop. The provider does not prove
that arbitrary unmanaged prefix rules are unrelated. Interleaved/following rows,
untracked namespace rows, duplicates, missing rules and security drift cause
refusal instead of blind reconstruction/adoption. Only one such tail policy can
be managed per router. Do not place another policy or independent rule after it,
including through another Terraform state.

Updates use only the existing POST/DELETE operations:

1. Read and verify the old generation, ownership ledger and unrelated prefix.
2. Append a new generation of accepts and its drop behind the old drop.
3. Verify the complete staged block, every supported security field and trailing
   placement before retiring any old row.
4. Remove old accepts sequentially, re-resolving current indexes by exact name.
   Reverify the staged block before each retirement.
5. Remove the old drop last; the new accepts now precede the new drop.
6. Verify the final table and record compacted observed positions.

This is **not atomic or hitless**. Old accepts may remain effective until
retirement, and traffic may be blocked as old accepts retire before the old
drop. Connection tracking is firmware-dependent. Initial creation has no old
policy drop: existing router/default protection matters, and a partial initial
create can leave accepts without their intended drop. Staging needs temporary
capacity for both generations; failure stops without retiring the old policy.
Never promise uninterrupted access, instant revocation or automatic rollback.

Accepted/ambiguous POSTs are recorded by exact name even if readback fails.
Partial updates preserve names from both generations. Incomplete ownership
ledgers stop refresh/reconciliation with an error for operator recovery, rather
than disguising a damaged policy as absent. There are no blind retries or
automatic cleanup writes. Destroy deletes only tracked names, accepts before
drops, and **removes policy protection**; review resulting defaults first.

One process-local lock covers login, table selection, writes, verification,
complete policy reconciliation and logout for the same normalized endpoint,
including separate clients. Default Terraform parallelism is supported for that
endpoint. `-parallelism=1` is not required for position selection and does not
establish policy order. Endpoint aliases, other processes/states and web-UI users
are not coordinated. Use one endpoint spelling, one writer and exclusive router
access during apply. Serialize other administrator sessions if firmware requires
it. No lock survives a process crash. Hardware writes remain unverified.

The [Zyxel series firewall help](https://service-provider.zyxel.com/compact-help/AX-DX-EX-PX-Series/AX-DX-EX-PX_5-70/h_Security_Firewall_DoS.html)
documents ordered evaluation and GUI insertion, not a verified DAL insertion or
reorder contract for a particular firmware. No ACL PUT/reorder is introduced.
Documentation describes a 16-character UI name limit on some series; this
provider uses longer generation names based on the existing DAL profile.
Firmware that rejects or truncates them is unsupported: verification fails and
retains recovery state. Check model/build compatibility before production use.

## Recovering A Partial Apply

These are **operator procedures**, not actions run automatically or during
development. Stop all writers. Obtain an approved maintenance window, router
backup, out-of-band/local management and rollback plan before any writes. Keep
router exports/state private: they may contain credentials and network details.

1. Back up state (`terraform state pull` to a private file), HCL and the entire
   router ACL table. Record exact names, current indexes/orders, enabled status
   and all filters. Do not retry apply yet.
2. Compare router inventory with `terraform state list` and `terraform state
   show`. Classify healthy tracked, tainted tracked, untracked and duplicate-name
   rows. Include every policy `row_names` entry and all router rows in its
   namespace. Missing ledger rows may be ambiguous writes that never committed.
3. Operator-review the complete effective policy: all accepts must precede their
   intended drop, and prefix accepts must not bypass it. Resolve duplicate names
   through an explicitly approved manual change; the provider cannot choose.
4. To retain a tainted single-rule row, first verify every security field and
   matching HCL. Only after review, `terraform untaint ADDRESS` removes the
   forced replacement marker. It does **not** write or repair the router and can
   leave an ineffective accept behind a drop. Do not clear taint on name alone.
5. To retain an untracked single-rule row, add matching HCL and explicitly run
   `terraform import ADDRESS 'Exact-Name'`. This changes state, not the router.
   Never import a row already owned by another address/state. Do not use `state
   rm` as a generic fix: it abandons ownership and can cause the next create to
   collide with a live row.
6. A complete provider-named generation can be explicitly imported with
   `terraform import zyxel_acl_policy.https 'NAME/GENERATION'`. Import accepts
   only one complete, supported, contiguous generation. It does not adopt legacy
   arbitrary names, partial/mixed generations or damaged policies. Reconcile a
   partial ledger manually while preserving its complete row-name inventory and
   backup. Do not discard the ledger or clear taint to bypass diagnostics.
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
