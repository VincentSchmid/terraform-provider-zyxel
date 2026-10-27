package zyxel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ACLPolicy owns a contiguous tail of the ACL table. Rules is the effective
// evaluation order: zero or more accepts followed by one or more drops/rejects.
// Rules may use different scopes. Names in Rules are optional logical labels;
// the API creates generation-qualified names.
type ACLPolicy struct {
	Rules []ACLRule
}

// ACLPolicyState is the recoverable ownership ledger, not a prefix-adoption hint.
// Names is the complete ownership record; names never confer ownership by
// themselves. Keep Names even on errors: a write may have succeeded without
// readback.
type ACLPolicyState struct {
	Generation string
	Names      []string
	Rules      []ACLRule
	// LogicalNames contains optional configured labels, derived from exact router names.
	LogicalNames []string
}

type ACLPolicyOutcome struct {
	State   ACLPolicyState
	Changed bool
}

// ACLPolicyRecovery is a read-only inspection of an exact ownership ledger.
// State retains every tracked name, including absent or ambiguous writes.
// Pending means apply must clean up the tracked tail before creating a new one.
type ACLPolicyRecovery struct {
	State   ACLPolicyState
	Pending bool
	Present []ACLRule
	Missing []string
}

// InspectACLPolicyRecovery permits missing tracked rows and mixed generations,
// but never adopts namespace matches or changes the router.
func (c *Client) InspectACLPolicyRecovery(ctx context.Context, state ACLPolicyState) (ACLPolicyRecovery, error) {
	var result ACLPolicyRecovery
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		result, _, err = inspectACLPolicyRecovery(rows, state)
		return err
	})
	return result, err
}

var (
	aclPolicyLogicalName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	aclPolicyLegacyRow   = regexp.MustCompile(`^(.+)-g([0-9a-f]{16})-(\d{2,3})$`)
	aclPolicyUnnamedRow  = regexp.MustCompile(`^g([0-9a-f]{2}|[0-9a-f]{4})-(\d{2,3})$`)
)

// aclPolicyRowFormat records which naming scheme matched a router row. Ownership
// never comes from the scheme or from a name prefix; it comes only from the
// exact row_names ledger.
type aclPolicyRowFormat int

const (
	aclPolicyRowInvalid aclPolicyRowFormat = iota
	aclPolicyRowNamed
	aclPolicyRowUnnamed
	aclPolicyRowLegacy
)

func validPolicyGeneration(generation string) bool {
	decoded, err := hex.DecodeString(generation)
	return err == nil && (len(decoded) == 1 || len(decoded) == 2 || len(decoded) == 8) && hex.EncodeToString(decoded) == generation
}

func aclPolicyPosition(number string) (int, bool) {
	position, err := strconv.Atoi(number)
	if err != nil || position < 1 || position > 999 {
		return 0, false
	}
	return position, number == fmt.Sprintf("%02d", position) || number == fmt.Sprintf("%03d", position)
}

// parseACLPolicyRowName recognizes the current named and unnamed formats plus
// legacy provider names. Named rows split on the last -g that leaves two (or,
// for earlier releases, four) lowercase hex characters, so labels may contain
// "-" and "g". Legacy
// names carried an arbitrary policy prefix; it is ignored because it no longer
// identifies an owner.
func parseACLPolicyRowName(name string) (generation, label string, position int, format aclPolicyRowFormat, valid bool) {
	if match := aclPolicyLegacyRow.FindStringSubmatch(name); match != nil {
		position, valid = aclPolicyPosition(match[3])
		return match[2], "", position, aclPolicyRowLegacy, valid
	}
	if match := aclPolicyUnnamedRow.FindStringSubmatch(name); match != nil {
		position, valid = aclPolicyPosition(match[2])
		return match[1], "", position, aclPolicyRowUnnamed, valid
	}
	index := strings.LastIndex(name, "-g")
	if index <= 0 {
		return "", "", 0, aclPolicyRowInvalid, false
	}
	generation = name[index+2:]
	if !validPolicyGeneration(generation) || len(generation) == 16 {
		return "", "", 0, aclPolicyRowInvalid, false
	}
	label = name[:index]
	if !aclPolicyLogicalName.MatchString(label) {
		return "", "", 0, aclPolicyRowInvalid, false
	}
	return generation, label, 0, aclPolicyRowNamed, true
}

func validACLPolicyTrackedName(name string) bool {
	_, _, _, _, valid := parseACLPolicyRowName(name)
	return valid
}

func inspectACLPolicyRecovery(rows []map[string]any, state ACLPolicyState) (ACLPolicyRecovery, []map[string]any, error) {
	result := ACLPolicyRecovery{State: state, Pending: true}
	result.State.Names = append([]string(nil), state.Names...)
	result.State.Rules = append([]ACLRule(nil), state.Rules...)
	owned := map[string]int{}
	generations := map[string]bool{}
	for i, name := range state.Names {
		generation, _, _, _, valid := parseACLPolicyRowName(name)
		if _, exists := owned[name]; exists || !valid {
			return result, nil, errors.New("invalid ACL policy ownership ledger")
		}
		owned[name] = i
		generations[generation] = true
	}
	known := map[string]ACLRule{}
	for _, rule := range state.Rules {
		if _, ok := owned[rule.Name]; !ok {
			return result, nil, errors.New("ACL policy rule is outside ownership ledger")
		}
		if _, ok := known[rule.Name]; ok {
			return result, nil, errors.New("duplicate ACL policy ledger rule")
		}
		known[rule.Name] = rule
	}
	ordered := append([]map[string]any(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := aclInt64(ordered[i]["Order"])
		b, _ := aclInt64(ordered[j]["Order"])
		return a < b
	})
	prefix := []map[string]any{}
	seenNames, seenOrders := map[string]bool{}, map[int64]bool{}
	lastOwned := -1
	for _, row := range ordered {
		name, _ := row["Name"].(string)
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || seenOrders[order] || seenNames[name] {
			return result, nil, errors.New("ACL table has invalid or duplicate identities/orders")
		}
		seenNames[name], seenOrders[order] = true, true
		index, tracked := owned[name]
		if !tracked {
			if generation, _, _, _, valid := parseACLPolicyRowName(name); valid && generations[generation] {
				return result, nil, errors.New("ACL policy generation exists outside ownership ledger")
			}
			if lastOwned >= 0 {
				return result, nil, errors.New("ACL policy must own a contiguous tail; unrelated rules follow or interleave it")
			}
			prefix = append(prefix, aclPolicyComparableRow(row))
			continue
		}
		if index <= lastOwned {
			return result, nil, errors.New("ACL policy tracked rows are out of order")
		}
		lastOwned = index
		rule, err := parseACLRule(row)
		if err != nil {
			return result, nil, err
		}
		if want, ok := known[name]; ok {
			want.Order = rule.Order
			if diff := aclRuleDifferences(want, rule); len(diff) != 0 {
				return result, nil, fmt.Errorf("ACL policy recovery readback differs in: %s", strings.Join(diff, ", "))
			}
		}
		result.Present = append(result.Present, rule)
	}
	if err := validateACLAppend(prefix, "accept"); err != nil {
		return result, nil, err
	}
	for _, name := range state.Names {
		if !seenNames[name] {
			result.Missing = append(result.Missing, name)
		}
	}
	if _, err := inspectACLPolicyTable(rows, &state); err == nil {
		observed, err := observeACLPolicy(rows, state)
		if err != nil {
			return result, nil, err
		}
		result.State, result.Pending = observed, false
	}
	return result, prefix, nil
}

// Validate checks the policy shape without networking. Accepts must precede
// every drop/reject, and at least one drop/reject is required, so the managed
// tail always ends in explicit protection. Each rule is validated on its own;
// rules may have different scopes.
func (p ACLPolicy) Validate() error {
	if len(p.Rules) < 1 || len(p.Rules) > 999 {
		return errors.New("ACL policy requires 1-999 rules, including at least one drop or reject")
	}
	seen := map[string]bool{}
	dropped := false
	drops := 0
	for i, r := range p.Rules {
		if r.Name != "" {
			if seen[r.Name] || !aclPolicyLogicalName.MatchString(r.Name) {
				return errors.New("ACL policy logical rule names must be unique and contain only ASCII letters, digits, underscores or hyphens")
			}
			seen[r.Name] = true
		}
		if r.Order != 0 || r.OrderMode != "" || !r.Enabled {
			return errors.New("ACL policy rules must be enabled and must omit order and order mode")
		}
		switch r.Action {
		case "accept":
			if dropped {
				return errors.New("ACL policy accepts must precede every drop or reject rule")
			}
		case "drop", "reject":
			dropped = true
			drops++
		default:
			return fmt.Errorf("ACL policy rule %d has unsupported action %q", i+1, r.Action)
		}
		r.Order, r.OrderMode = 1, ""
		r.Name = aclPolicyRowName("0000", i, r.Name)
		// Readback carries the resolved service name next to the native ID it
		// was read with. The write path resolves the ID and must not also send a
		// name; the adapter rejects both on input.
		if r.ServiceID != "" {
			r.Service = ""
		}
		if err := r.validateForWrite(); err != nil {
			return fmt.Errorf("ACL policy rule %d: %w", i+1, err)
		}
	}
	if drops == 0 {
		return errors.New("ACL policy requires at least one drop or reject rule")
	}
	return nil
}

// aclPolicyRowName creates the router row name for one rule. Named rules carry
// only their label and generation; unnamed rules retain a generation-qualified
// position so that a complete generation remains ordered and recognizable.
// Positions of 100 and above naturally use three digits.
func aclPolicyRowName(generation string, i int, label string) string {
	if label != "" {
		return label + "-g" + generation
	}
	return "g" + generation + "-" + fmt.Sprintf("%02d", i+1)
}

func policyGeneration() (string, error) {
	var bytes [1]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("could not generate ACL policy generation")
	}
	return hex.EncodeToString(bytes[:]), nil
}

// Reserve a generation token against live rows and every retained identity,
// including absent ambiguous writes. Compare parsed tokens, never name prefixes,
// because a generation has no namespace of its own. Bound retries even if the
// random source repeats.
func unusedPolicyGeneration(rows []map[string]any, previous *ACLPolicyState, generate func() (string, error)) (string, error) {
	used := map[string]bool{}
	add := func(name string) {
		if generation, _, _, _, valid := parseACLPolicyRowName(name); valid {
			used[generation] = true
		}
	}
	for _, row := range rows {
		if name, ok := row["Name"].(string); ok {
			add(name)
		}
	}
	if previous != nil {
		for _, name := range previous.Names {
			add(name)
		}
	}
	for attempt := 0; attempt < 32; attempt++ {
		generation, err := generate()
		if err != nil {
			return "", err
		}
		if !used[generation] {
			return generation, nil
		}
	}
	return "", errors.New("could not allocate an unused ACL policy generation after 32 attempts")
}

// ApplyACLPolicy stages a complete new tail behind the old drop, verifies it,
// then removes the old accepts and finally its drops/rejects. At the observed
// 32-row capacity, explicit rejections trigger incremental early retirement,
// potentially removing old drops before the new protection is complete. It never uses
// PUT/reorder. Any rule may change, including its traffic scope. Partial
// failures retain an exact ownership ledger. Retrying a partial ledger cleans
// up its tracked rows (accepts before drops), then builds the desired tail;
// protection can be absent during this explicitly non-atomic recovery.
func (c *Client) ApplyACLPolicy(ctx context.Context, desired ACLPolicy, previous *ACLPolicyState) (ACLPolicyOutcome, error) {
	var out ACLPolicyOutcome
	if previous != nil {
		out.State = *previous
		out.State.Names = append([]string(nil), previous.Names...)
	}
	if err := desired.Validate(); err != nil {
		return out, err
	}
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		generation, err := unusedPolicyGeneration(rows, previous, policyGeneration)
		if err != nil {
			return err
		}
		// A failed staging/capacity retirement retains old rules and all attempted
		// names. Recover only those exact rows, never a name-discovered row.
		if previous != nil {
			recovery, prefix, inspectErr := inspectACLPolicyRecovery(rows, *previous)
			if inspectErr != nil {
				return inspectErr
			}
			if recovery.Pending {
				var accepts, drops []string
				for _, rule := range recovery.Present {
					if rule.Action == "accept" {
						accepts = append(accepts, rule.Name)
					} else {
						drops = append(drops, rule.Name)
					}
				}
				for _, name := range append(accepts, drops...) {
					current, readErr := s.readACLRows(ctx)
					if readErr != nil {
						return readErr
					}
					_, currentPrefix, inspectErr := inspectACLPolicyRecovery(current, *previous)
					if inspectErr != nil {
						return inspectErr
					}
					if !reflect.DeepEqual(prefix, currentPrefix) {
						return errors.New("unrelated ACL prefix changed during recovery")
					}
					out.Changed = true
					if err := s.deleteACLRule(ctx, name); err != nil {
						return fmt.Errorf("ACL policy recovery cleanup failed; retain ledger: %w", err)
					}
				}
				rows, err = s.readACLRows(ctx)
				if err != nil {
					return err
				}
				_, currentPrefix, inspectErr := inspectACLPolicyRecovery(rows, *previous)
				if inspectErr != nil {
					return inspectErr
				}
				if !reflect.DeepEqual(prefix, currentPrefix) {
					return errors.New("unrelated ACL prefix changed during recovery")
				}
				previous = nil
			}
		}
		prefix, err := inspectACLPolicyTable(rows, previous)
		if err != nil {
			return err
		}
		staged := ACLPolicyState{Generation: generation}
		if previous == nil && len(out.State.Names) == 0 {
			out.State = staged
		}
		retired := 0
		for i, logical := range desired.Rules {
			rule := logical
			rule.Name = aclPolicyRowName(generation, i, logical.Name)
			rule.OrderMode = ACLOrderAppend
			if err := rule.expandPorts(); err != nil {
				return err
			}
			created, err := s.createACLRule(ctx, rule, true)
			for err != nil && previous != nil && retired < len(previous.Names) && !created.Applied && !created.Ambiguous {
				var rejected *ACLWriteRejectedError
				if !errors.As(err, &rejected) || (rejected.Result != "ZCFG_INVALID_PARAM_VALUE" && rejected.Result != "ZCFG_EXCEED_MAX_INS_NUM") {
					break
				}
				// AX7501-B0 V5.17 rejects the 33rd row with either code; the
				// first is otherwise generic. Never infer capacity from the
				// code alone.
				current, readErr := s.readACLRows(ctx)
				if readErr != nil {
					return readErr
				}
				if len(current) != 32 || len(prefix)+len(desired.Rules) > 32 {
					break
				}
				if verifyErr := s.verifyACLPolicyTransition(ctx, prefix, previous, retired, staged); verifyErr != nil {
					return verifyErr
				}
				// Retire only as much as needed, accepts before drops. If
				// drops must go, protection is incomplete until staging ends.
				if deleteErr := s.deleteACLRule(ctx, previous.Names[retired]); deleteErr != nil {
					return fmt.Errorf("ACL policy capacity retirement failed; reconcile retained state: %w", deleteErr)
				}
				out.Changed = true
				retired++
				created, err = s.createACLRule(ctx, rule, true)
			}
			if created.Applied || created.Ambiguous {
				out.Changed = true
				out.State.Names = append(out.State.Names, rule.Name)
			}
			if err != nil {
				return fmt.Errorf("ACL policy staging failed; retain state and reconcile before retrying: %w", err)
			}
			staged.Names = append(staged.Names, rule.Name)
			staged.Rules = append(staged.Rules, *created.Rule)
		}
		// Do not retire any old protection until the entire staged block,
		// including its final drop, has been read back and verified.
		if err := s.verifyACLPolicyTransition(ctx, prefix, previous, retired, staged); err != nil {
			return err
		}
		if previous != nil {
			for _, name := range previous.Names[retired:] {
				if err := s.verifyStagedACLPolicy(ctx, prefix, previous, staged); err != nil {
					return err
				}
				if err := s.deleteACLRule(ctx, name); err != nil {
					return fmt.Errorf("ACL policy retirement failed; retain both generations for recovery: %w", err)
				}
				out.Changed = true
			}
		}
		rows, err = s.readACLRows(ctx)
		if err != nil {
			return err
		}
		// Deletions can compact positions; compare every field except numeric
		// order and then record the final observations for the whole block.
		observed, err := observeACLPolicy(rows, staged)
		if err != nil {
			return err
		}
		if _, err := inspectACLPolicyTable(rows, &observed); err != nil {
			return err
		}
		out.State = observed
		return nil
	})
	return out, err
}

// Verify the exact remaining old block as well as the staged tail before
// capacity retirement. A partial old generation cannot use observeACLPolicy's
// complete-generation identity check.
func (s *routerSession) verifyACLPolicyTransition(ctx context.Context, prefix []map[string]any, previous *ACLPolicyState, retired int, staged ACLPolicyState) error {
	if err := s.verifyStagedACLPolicy(ctx, prefix, previous, staged); err != nil {
		return err
	}
	rows, err := s.readACLRows(ctx)
	if err != nil {
		return err
	}
	remaining := 0
	if previous != nil {
		remaining = len(previous.Names) - retired
	}
	if len(rows) != len(prefix)+remaining+len(staged.Names) {
		return errors.New("ACL table changed during capacity retirement; reconcile retained state")
	}
	sort.Slice(rows, func(i, j int) bool {
		a, _ := aclInt64(rows[i]["Order"])
		b, _ := aclInt64(rows[j]["Order"])
		return a < b
	})
	for i := 0; i < remaining; i++ {
		got, err := parseACLRule(rows[len(prefix)+i])
		if err != nil {
			return err
		}
		want := previous.Rules[retired+i]
		want.Order = got.Order
		if got.Name != previous.Names[retired+i] || len(aclRuleDifferences(want, got)) != 0 {
			return errors.New("old ACL policy changed during capacity retirement; reconcile retained state")
		}
	}
	return nil
}

func (s *routerSession) verifyStagedACLPolicy(ctx context.Context, prefix []map[string]any, previous *ACLPolicyState, staged ACLPolicyState) error {
	rows, err := s.readACLRows(ctx)
	if err != nil {
		return err
	}
	if _, err := observeACLPolicy(rows, staged); err != nil {
		return err
	}
	ordered := append([]map[string]any(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := aclInt64(ordered[i]["Order"])
		b, _ := aclInt64(ordered[j]["Order"])
		return a < b
	})
	seenOrders := map[int64]bool{}
	for i, row := range ordered {
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || seenOrders[order] {
			return errors.New("invalid or duplicate ACL orders while staging")
		}
		seenOrders[order] = true
		if i >= len(ordered)-len(staged.Names) && row["Name"] != staged.Names[i-(len(ordered)-len(staged.Names))] {
			return errors.New("staged ACL policy is not the contiguous tail; refusing further writes")
		}
	}
	// previous supplies only the managed-name set here. Its content is verified
	// separately because capacity retirement may already have removed some of it.
	owned := map[string]bool{}
	for _, name := range staged.Names {
		owned[name] = true
	}
	if previous != nil {
		for _, name := range previous.Names {
			owned[name] = true
		}
	}
	currentPrefix := []map[string]any{}
	for _, row := range ordered {
		name, _ := row["Name"].(string)
		if !owned[name] {
			currentPrefix = append(currentPrefix, aclPolicyComparableRow(row))
		}
	}
	if !reflect.DeepEqual(prefix, currentPrefix) {
		return errors.New("unrelated ACL prefix changed while staging policy; refusing further writes")
	}
	return nil
}

func aclPolicyComparableRow(row map[string]any) map[string]any {
	copy := make(map[string]any, len(row))
	for k, v := range row {
		if k != "Order" && k != "Index" {
			copy[k] = v
		}
	}
	return copy
}

// inspectACLPolicyTable rejects adoption, untracked generations, interleaving,
// terminal prefix rules and stale/incomplete ledgers before any mutation.
// Ownership is the exact ledger; a live row is untracked even when its name
// looks like a generation this policy uses.
func inspectACLPolicyTable(rows []map[string]any, previous *ACLPolicyState) ([]map[string]any, error) {
	generations := map[string]bool{}
	owned := map[string]bool{}
	if previous != nil {
		if len(previous.Names) == 0 || len(previous.Names) != len(previous.Rules) {
			return nil, errors.New("incomplete ACL policy ledger; operator recovery required")
		}
		policy := ACLPolicy{Rules: append([]ACLRule(nil), previous.Rules...)}
		for i := range policy.Rules {
			policy.Rules[i].Order = 0
			generation, label, _, _, valid := parseACLPolicyRowName(policy.Rules[i].Name)
			if !valid {
				return nil, errors.New("invalid ACL policy ownership ledger")
			}
			generations[generation] = true
			policy.Rules[i].Name = label
		}
		if err := policy.Validate(); err != nil {
			return nil, fmt.Errorf("invalid ACL policy ledger: %w", err)
		}
		if _, err := observeACLPolicy(rows, *previous); err != nil {
			return nil, err
		}
		for _, n := range previous.Names {
			owned[n] = true
		}
	}
	sorted := append([]map[string]any(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		a, _ := aclInt64(sorted[i]["Order"])
		b, _ := aclInt64(sorted[j]["Order"])
		return a < b
	})
	prefix := []map[string]any{}
	seenOrder := map[int64]bool{}
	policyStarted := false
	for _, row := range sorted {
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || seenOrder[order] {
			return nil, errors.New("ACL table has invalid or duplicate orders")
		}
		seenOrder[order] = true
		n, _ := row["Name"].(string)
		if generation, _, _, _, valid := parseACLPolicyRowName(n); valid && generations[generation] && !owned[n] {
			return nil, errors.New("ACL policy generation already exists outside its ownership ledger; explicit import/recovery required")
		}
		if owned[n] {
			policyStarted = true
			continue
		}
		if policyStarted {
			return nil, errors.New("ACL policy must own a contiguous tail; unrelated rules follow or interleave it")
		}
		prefix = append(prefix, aclPolicyComparableRow(row))
	}
	if err := validateACLAppend(prefix, "accept"); err != nil {
		return nil, err
	}
	return prefix, nil
}

func observeACLPolicy(rows []map[string]any, state ACLPolicyState) (ACLPolicyState, error) {
	observed := state
	observed.Rules = nil
	observed.LogicalNames = nil
	var lastOrder int64
	for i, name := range state.Names {
		generation, label, position, format, valid := parseACLPolicyRowName(name)
		if i >= len(state.Rules) || !valid || generation != state.Generation {
			return state, errors.New("ACL policy has an incomplete ownership ledger; operator recovery required")
		}
		// Named rows carry no position. Legacy and unnamed rows must preserve
		// their positional suffix, which also catches missing rows.
		if format != aclPolicyRowNamed && position != i+1 {
			return state, errors.New("ACL policy has an incomplete ownership ledger; operator recovery required")
		}
		row, err := findACLRow(rows, name)
		if err != nil {
			return state, err
		}
		if row == nil {
			return state, errors.New("ACL policy row is missing; operator recovery required")
		}
		rule, err := parseACLRule(*row)
		if err != nil {
			return state, err
		}
		want := state.Rules[i]
		want.Order = rule.Order
		if diff := aclRuleDifferences(want, rule); len(diff) != 0 {
			return state, fmt.Errorf("ACL policy readback differs in: %s", strings.Join(diff, ", "))
		}
		if rule.Order <= lastOrder {
			return state, errors.New("ACL policy rules are not in the intended evaluation order")
		}
		lastOrder = rule.Order
		observed.Rules = append(observed.Rules, rule)
		observed.LogicalNames = append(observed.LogicalNames, label)
	}
	return observed, nil
}

func (c *Client) ReadACLPolicy(ctx context.Context, state ACLPolicyState) (ACLPolicyState, error) {
	var observed ACLPolicyState
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		if _, err := inspectACLPolicyTable(rows, &state); err != nil {
			return err
		}
		observed, err = observeACLPolicy(rows, state)
		return err
	})
	return observed, err
}

// ImportACLPolicy explicitly adopts a single complete generation by token, in
// table order. It rejects mixed/partial generations. Named rows have no
// positional suffix, so a generation missing only its final drop is rejected by
// policy validation, while an incomplete generation that still contains a drop
// cannot be distinguished from a complete one. The generation must form the
// contiguous managed tail.
func (c *Client) ImportACLPolicy(ctx context.Context, generation string) (ACLPolicyState, error) {
	state := ACLPolicyState{Generation: generation}
	if !validPolicyGeneration(generation) {
		return state, errors.New("ACL policy generation must be 2, 4 or 16 lowercase hexadecimal characters")
	}
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		sort.Slice(rows, func(i, j int) bool {
			a, _ := aclInt64(rows[i]["Order"])
			b, _ := aclInt64(rows[j]["Order"])
			return a < b
		})
		for _, row := range rows {
			n, _ := row["Name"].(string)
			g, label, _, _, valid := parseACLPolicyRowName(n)
			if !valid || g != generation {
				continue
			}
			rule, err := parseACLRule(row)
			if err != nil {
				return err
			}
			state.Names = append(state.Names, n)
			state.Rules = append(state.Rules, rule)
			state.LogicalNames = append(state.LogicalNames, label)
		}

		policy := ACLPolicy{Rules: append([]ACLRule(nil), state.Rules...)}
		for i := range policy.Rules {
			policy.Rules[i].Order = 0
			policy.Rules[i].Name = state.LogicalNames[i]
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		_, err = inspectACLPolicyTable(rows, &state)
		return err
	})
	return state, err
}

// DeleteACLPolicy deletes only exact tracked names, with every drop/reject last.
// It can clean up a partial staging ledger, but never discovers/adopts
// untracked rows.
func (c *Client) DeleteACLPolicy(ctx context.Context, state ACLPolicyState) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		var accepts, drops []string
		seen := map[string]bool{}
		for _, name := range state.Names {
			if !validACLPolicyTrackedName(name) || seen[name] {
				return errors.New("invalid ACL policy ownership ledger")
			}
			seen[name] = true
			row, err := findACLRow(rows, name)
			if err != nil {
				return err
			}
			if row == nil {
				continue
			}
			rule, err := parseACLRule(*row)
			if err != nil {
				return err
			}
			if rule.Action == "accept" {
				accepts = append(accepts, name)
			} else {
				drops = append(drops, name)
			}
		}
		for _, name := range append(accepts, drops...) {
			if err := s.deleteACLRule(ctx, name); err != nil {
				return err
			}
		}
		return nil
	})
}
