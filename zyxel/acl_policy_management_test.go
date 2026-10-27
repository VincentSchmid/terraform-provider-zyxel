package zyxel

import "testing"

func TestACLPolicyManagementValidation(t *testing.T) {
	for _, edit := range []func(*ACLPolicy){
		func(p *ACLPolicy) { p.ManagementRules = nil },
		func(p *ACLPolicy) { p.ManagementRules[0].Action = "drop" },
		func(p *ACLPolicy) { p.ManagementRules[0].Action = "reject" },
		func(p *ACLPolicy) { p.ManagementRules[0].Name = p.Rules[0].Name },
		func(p *ACLPolicy) { p.ManagementRules[0].Name = p.Rules[1].Name },
		func(p *ACLPolicy) {
			for len(p.allRules()) < 33 {
				r := p.ManagementRules[0]
				r.Name = ""
				p.ManagementRules = append(p.ManagementRules, r)
			}
		},
	} {
		p := validTestPolicy()
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted invalid policy: %#v", p)
		}
	}
}

func TestACLPolicyManagementConfigurationComparison(t *testing.T) {
	a := testACLRule("Management", "accept", 27)
	b := a
	b.Order = 0
	b.DestinationPortStart, b.DestinationPortEnd = nil, nil
	b.DestinationPorts = "443"
	if !sameACLPolicyConfiguration(a, b) {
		t.Fatal("computed order or port representation changed configuration")
	}
	b.SourceCIDR = "192.0.2.0/24"
	if sameACLPolicyConfiguration(a, b) {
		t.Fatal("scope change was ignored")
	}
}

func TestACLPolicyMixedGenerationManagementLedger(t *testing.T) {
	state, rows := recoveryFixture(t)
	state.ManagementNames = []string{state.Names[0]}
	state.Generation = "7f"
	state.Names[1] = "g7f-02"
	state.Rules[1].Name = state.Names[1]
	rows[2]["Name"] = state.Names[1]
	if _, err := inspectACLPolicyTable(rows, &state); err != nil {
		t.Fatal(err)
	}
	state.Pending = true
	r, _, err := inspectACLPolicyRecovery(rows, state)
	if err != nil || !r.Pending {
		t.Fatalf("partial apply incorrectly appears complete: %#v %v", r, err)
	}
}
