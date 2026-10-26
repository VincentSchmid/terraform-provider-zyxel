package zyxel

import "testing"

func validTestPolicy() ACLPolicy {
	a, d := testACLRule("accept", "accept", 0), testACLRule("drop", "drop", 0)
	d.SourceCIDR = "0.0.0.0/0"
	return ACLPolicy{Name: "policy", Rules: []ACLRule{a, d}}
}

func TestACLPolicyValidation(t *testing.T) {
	if err := validTestPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*ACLPolicy){
		func(p *ACLPolicy) { p.Name = "" },
		func(p *ACLPolicy) { p.Rules = nil },
		func(p *ACLPolicy) { p.Rules[1].Action = "accept" },
		func(p *ACLPolicy) { p.Rules[0].Action = "drop" },
		func(p *ACLPolicy) { p.Rules[1].SourceCIDR = "192.0.2.0/24" },
		func(p *ACLPolicy) { p.Rules[0].DestinationCIDR = "192.0.2.1/32" },
		func(p *ACLPolicy) { p.Rules[0].Order = 1 },
		func(p *ACLPolicy) { p.Rules[0].Enabled = false },
		func(p *ACLPolicy) { p.Rules[0].Service = "https" },
		func(p *ACLPolicy) { p.Rules[0].Name = p.Rules[1].Name },
	} {
		p := validTestPolicy()
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted unsafe policy: %#v", p)
		}
	}
}
