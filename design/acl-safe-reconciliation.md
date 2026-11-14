# ACL Safety Checkpoint (Proposed, Not Approved)

No reconciliation code changes are authorized by this document. Current ACL
updates still remove denies first and can expose traffic. Consumer comments
claiming that replacements are safely staged behind old denies are stale;
their owner must review them separately. No consumer repository is changed here.

## Invariant And Assumptions

Select full normal-tail staging with unchanged management. For every packet p
and every intermediate table T, including a mutation committed before an error:

    Allow(T, p) implies Allow(old, p) or Allow(new, p)

Old/new include the same unrelated prefix, fixed management accepts, and fixed
router fallback action. This is the approved-policy union boundary, NOT their
intersection: old-authorized traffic may remain authorized until cutover, and
new-authorized traffic may become authorized before completion. Temporary denial
of otherwise authorized traffic is permitted. It does not promise atomicity,
connectivity, or immediate revocation at apply start. Approval must explicitly
accept this availability/security tradeoff. A stricter intersection boundary
would require a different algorithm and approval.

Assume deterministic first-match processing and append/delete behavior of the
supported profile, stable fallback action, and no out-of-process changes to
rules, service definitions, or global firewall settings during the operation.
The proof is parametric in fallback (allow or deny); it must not infer that
removing accepts is safe on its own. A fixed prefix cannot be repaired here;
prefix accepts that already bypass denies remain outside the managed boundary.
Firmware behavior outside this ordered profile must be rejected, not guessed.

Management configuration must be identical to the complete verified old set,
including referenced service semantics. Preserve those exact rows in place;
do not stage a broad deny. Changed management is a zero-write rejection in the
first implementation, requiring a separately approved transition/recovery path.
The invariant does not claim protection for sessions absent from management.

## Selected Algorithm And Capacity

Let U be unrelated prefix count, M unchanged management, Ao/Do old normal
accepts/denies, and An/Dn new normal accepts/denies. Validate the whole table,
exact ownership, all configurations/service references, unique generated names,
order, and operation ledger before any mutation. Simulate the complete schedule.
Require peak U + M + Ao + Do + An + Dn <= 32 (also enforce observed row/order
limits). Recovery computes peak from actual verified rows plus each missing
scheduled row; final size alone is insufficient. No capacity-error fallback.

1. Keep U, M, Ao, Do unchanged. Append An then Dn, recording exact identities
   and expected configurations before issuing requests. Verify each row and
   then the entire replacement suffix, including native service identities.
2. Only after complete replacement verification, delete Ao by current identity
   (all accepts before any old deny). Verify every deletion and remaining tail.
3. Delete Do by current identity, retaining M, An, Dn and unrelated U.
4. Verify complete final table/order/fields/prefix and service references before
   marking the operation complete. Never retry an uncertain POST automatically.

For multiple services, destinations, address families, and directions, use the
same ordered suffix: all new normal accepts precede all new denies. The proof
does not depend on filters being a single service or on deny coverage being a
catch-all. It requires correct matching/first-match semantics, not sampling as
a substitute for proof. Tests should partition each supported match dimension
at old/new boundaries and evaluate both fallback actions at every snapshot.

## Proof By Tables

Read sequences left to right. U and M are fixed and omitted here.

| Phase | Table | Why no traffic outside the union is newly allowed |
| --- | --- | --- |
| Baseline | Ao Do | Old policy |
| Stage partial accepts | Ao Do An(part) | Any old accept is old-authorized; old denies still win; a reached new accept is new-authorized |
| Stage partial denies | Ao Do An Dn(part) | Old denies still protect; partial new denies can only restrict the old fallback |
| Verified stage | Ao Do An Dn | Complete new protection exists before retiring old protection |
| Retire old accepts | Ao(part) Do An Dn | Remaining old accepts are old-authorized; reached new accepts are new-authorized |
| Retire old denies | Do(part) An Dn | Old denies only restrict a complete new policy |
| Final | An Dn | New policy |

If a staged table reaches fallback while Dn is incomplete, the full old table
also reached that same fallback (otherwise its unchanged accepts/denies already
decided). If fallback allows, old already authorized that packet. After Ao is
gone, Dn is complete. Thus unknown-but-fixed fallback does not create a hole.

Example tightening: old accepts source S1, new accepts subset S2, both drop
the protected destination. Old Do blocks An until old accepts are removed;
removing Ao may temporarily deny S2, but never opens another source. Example
loosening: new S2 superset S1 becomes reachable only after Do is retired, when
Dn is already complete. Example service change: Ao/Do reference ID 101 and
An/Dn ID 102; each filter is evaluated independently, including different port
sets. ID 101 cannot be deleted while any old or unmanaged reference remains.
Removal of a deny is permitted only with the complete target in place; traffic
then permitted by the new policy/fallback is intentionally authorized by new.

With U=1, M=1, Ao=18, Do=1, An=17, Dn=1, final count 20 fits, but peak 39
does not: reject with zero writes. With U=1, M=1 and two accepts/one deny per
generation, peak is 8, so full staging fits. This intentionally rejects some
updates that the existing unsafe algorithm can perform.

## Alternatives

Full-generation staging including management would need more capacity and a
separate access-continuity proof when old/new management differ; defer it.
Narrow deny-preserving transitions could save space by reusing identical rows
or proving filter containment, but arbitrary mixed filters and ordered prefixes
make simplistic subset tests unsound. Defer these optimizations; no silent
fallback to deny removal. Reject infeasible transitions rather than asking the
operator to temporarily weaken protection.

## Recovery Protocol And Zero-Write Rejections

Extend the typed API ledger with a versioned operation phase, immutable old/new
expected normal rows, exact staged identities, unchanged management membership,
and pre-write intent for the next mutation. Return it on every partial or
ambiguous result; the Terraform adapter persists it in private state and keeps
public row_names as exact ownership. Track service IDs without releasing
predecessor references early. No prefix/generation-based ownership inference.

The current API call cannot durably checkpoint Terraform private state before
each router request: pre-write intent is in memory until the call returns. A
process crash may therefore leave protective/staged rows absent from persisted
ownership. Such rows require reviewed explicit import/recovery, not automatic
adoption. The table-level safety invariant survives any committed schedule
prefix, but automatic ownership recovery across process death is not promised.
Durable per-step checkpoints would require a separately approved API protocol.

On refresh, only observe. On apply, resolve each intended identity: exact row
means committed; confirmed absence means not committed; failed, malformed,
duplicate, conflicting or interleaved readback means stop with pending state.
Do not blindly repeat POST or clean up an unowned row. Resume the stored target,
not a newly changed target: reject changed configuration while pending until
the stored transition is reconciled. Repeated reconciliation must be idempotent.
Revalidate the complete replacement before every retirement phase; if a write
fails, retain verified remaining protection rather than attempting rollback
with further unproven writes.

Reject before writes for insufficient peak capacity; changed management;
missing/ambiguous ownership or service references; unsupported/security-drifted
rows; untracked/interleaved rows; conflicting identities; changed pending target;
or an old pending/imported state lacking the complete phase/baseline/target
needed to prove this invariant. Do not infer that an existing unsafe partial
update is protected. Provide read-only diagnostics and require reviewed recovery.
An explicit legacy import with exact complete tail and management membership
can establish a fresh baseline if all configurations are fully observed and
verified; a bare import must first establish exact ownership using existing
import rules, not generation guesses at recovery time.

Existing schema v0/v1/public identities remain readable. A private ledger
version upgrade preserves old pending evidence without synthesizing missing
proof. No new Terraform attributes are proposed; schema migration and import
tests must demonstrate this before implementation approval is considered done.
Destroy remains explicitly destructive and outside the update invariant; keep
accept-before-deny removal and never destroy unrelated rows.

## Required Verification And Deployment Impact

Fault-inject rejection, dropped responses, post-commit failures, failed reads,
and cancellation at every POST/DELETE and final verification. Evaluate packet
decisions for every committed intermediate snapshot, including partial writes,
for tightening, loosening, removal, changed services/destinations/directions,
mixed IPv4/IPv6 and all supported match filters, management preservation,
prefix preservation, 31/32/33-row boundaries, pending imports, and index shifts.
Verify exact service guards, immutable pending targets, read-only refresh,
ledger round trips/upgrades, and final empty Terraform plans. Keep encrypted
API/adapter/mock acceptance and architecture/race checks.

Initial creation remains supported under this same union invariant with the
observed fixed router table as old baseline. It cannot promise new-policy
protection before all new rows exist. Approval must explicitly accept baseline
exposure during bootstrap; otherwise creation must be rejected until a separate
bootstrap design is approved. Never imply fail-closed bootstrap from this update
proof. Already damaged legacy pending policies are rejected as described above.

Deployment impact: unchanged schema and IDs, higher temporary capacity, some
formerly accepted updates now rejected, possible transient overblocking, no
automatic repair of legacy pending transitions, and changed-management updates
blocked. No hardware experiment, consumer edit, release publication, or claim of
atomic/hardware-verified ACL safety is authorized. Approval is required before
implementing this design and its state changes.
