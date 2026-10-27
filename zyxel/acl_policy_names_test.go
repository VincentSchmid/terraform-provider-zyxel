package zyxel

import "testing"

func TestACLPolicyRowNameFormats(t *testing.T) {
	if got := aclPolicyRowName("7f3d", 0, "WebDAV"); got != "WebDAV-g7f3d" {
		t.Errorf("named row = %q", got)
	}
	if got := aclPolicyRowName("7f3d", 0, ""); got != "g7f3d-01" {
		t.Errorf("unnamed row = %q", got)
	}
	if got := aclPolicyRowName("7f3d", 41, ""); got != "g7f3d-42" {
		t.Errorf("unnamed second-digit row = %q", got)
	}
	if got := aclPolicyRowName("7f3d", 99, ""); got != "g7f3d-100" {
		t.Errorf("unnamed three-digit row = %q", got)
	}
}

func TestACLPolicyRowNameParsing(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation string
		label      string
		position   int
		format     aclPolicyRowFormat
	}{
		{"WebDAV-g7f", "7f", "WebDAV", 0, aclPolicyRowNamed},
		{"Web-DAV_2-g7f", "7f", "Web-DAV_2", 0, aclPolicyRowNamed},
		// A label may itself contain "-g"; split on the last suffix that
		// leaves a valid hex token.
		{"foo-gab-g7f", "7f", "foo-gab", 0, aclPolicyRowNamed},
		{"g-g7f", "7f", "g", 0, aclPolicyRowNamed},
		{"g7f-01", "7f", "", 1, aclPolicyRowUnnamed},
		{"g7f-100", "7f", "", 100, aclPolicyRowUnnamed},
		// Four-hex tokens from earlier releases remain readable.
		{"WebDAV-g7f3d", "7f3d", "WebDAV", 0, aclPolicyRowNamed},
		{"foo-gab-g7f3d", "7f3d", "foo-gab", 0, aclPolicyRowNamed},
		{"g7f3d-01", "7f3d", "", 1, aclPolicyRowUnnamed},
		{"g7f3d-001", "7f3d", "", 1, aclPolicyRowUnnamed},
		{"g7f3d-100", "7f3d", "", 100, aclPolicyRowUnnamed},
		{"ACL-g0123456789abcdef-01", "0123456789abcdef", "", 1, aclPolicyRowLegacy},
		{"whatever-g0123456789abcdef-001", "0123456789abcdef", "", 1, aclPolicyRowLegacy},
		{"ACL-g0123456789abcdef-999", "0123456789abcdef", "", 999, aclPolicyRowLegacy},
	} {
		generation, label, position, format, valid := parseACLPolicyRowName(tc.name)
		if !valid || generation != tc.generation || label != tc.label || position != tc.position || format != tc.format {
			t.Errorf("%q parsed as (%q, %q, %d, %v, %v), want (%q, %q, %d, %v, true)",
				tc.name, generation, label, position, format, valid, tc.generation, tc.label, tc.position, tc.format)
		}
	}
	for _, name := range []string{
		"ACL-g7F3d", "WebDAV-g7f3", "WebDAV-g7f3d-01", "WebDAV-g7f3d-1",
		"g7f3d-00", "g7f3d-1", "g7f3d-1000", "g7f3-01", "-g7f3d",
		"Web DAV-g7f3d", "Web/DAV-g7f3d", "ACL-g0123456789abcde-01",
		"ACL-g0123456789abcdef-00", "ACL-g0123456789abcdef-1",
		"ACL-g0123456789abcdef-1000", "ACL-g0123456789abcdeF-01",
		"WebDAV-g7", "WebDAV-g7F", "g7-01", "g7f-1", "g7f-00",
		"unrelated", "",
	} {
		if generation, label, position, _, valid := parseACLPolicyRowName(name); valid {
			t.Errorf("accepted %q as (%q, %q, %d)", name, generation, label, position)
		}
	}
}

func TestACLPolicyGenerationCollision(t *testing.T) {
	rows := []map[string]any{{"Name": "WebDAV-gaaaa"}, {"Name": "gbbbb-01"}}
	prior := &ACLPolicyState{Names: []string{"gcccc-02"}}
	tokens := []string{"aaaa", "bbbb", "cccc", "dddd"}
	calls := 0
	got, err := unusedPolicyGeneration(rows, prior, func() (string, error) { token := tokens[calls]; calls++; return token, nil })
	if err != nil || got != "dddd" || calls != 4 {
		t.Fatalf("generation=%q calls=%d err=%v", got, calls, err)
	}
	calls = 0
	_, err = unusedPolicyGeneration(rows, prior, func() (string, error) { calls++; return "aaaa", nil })
	if err == nil || calls != 32 {
		t.Fatalf("unbounded collision retries: %d %v", calls, err)
	}
	token, err := policyGeneration()
	if err != nil || len(token) != 2 || !validPolicyGeneration(token) {
		t.Fatalf("%q %v", token, err)
	}
}

func TestACLPolicyLogicalNamesValidation(t *testing.T) {
	for _, tc := range []struct {
		first, second string
		valid         bool
	}{
		{"", "", true}, {"WebDAV", "Deny", true}, {"WebDAV", "WebDAV", false},
		{"Web DAV", "Deny", false}, {"Web/DAV", "Deny", false}, {"Web-DAV_2", "", true},
		{"foo-gab", "Deny", true}, {" WebDAV", "Deny", false}, {"WebDAV ", "Deny", false},
	} {
		p := validTestPolicy()
		p.Rules[0].Name, p.Rules[1].Name = tc.first, tc.second
		if err := p.Validate(); (err == nil) != tc.valid {
			t.Errorf("names %q/%q: %v", tc.first, tc.second, err)
		}
	}
}

func TestACLPolicyNamedLabelsDriveRowNames(t *testing.T) {
	p := validTestPolicy()
	p.Rules[0].Name, p.Rules[1].Name = "foo-gab", "Deny"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := aclPolicyRowName("7f3d", 0, p.Rules[0].Name); got != "foo-gab-g7f3d" {
		t.Fatalf("named row = %q", got)
	}
	if _, label, _, format, valid := parseACLPolicyRowName("foo-gab-g7f3d"); !valid || label != "foo-gab" || format != aclPolicyRowNamed {
		t.Fatalf("label with -g did not parse: %q %v %v", label, format, valid)
	}
}
