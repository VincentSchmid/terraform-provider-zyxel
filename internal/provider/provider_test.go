package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestResolveCredentialsRequiresCompletePair(t *testing.T) {
	t.Setenv("ZYXEL_USER", "env-user")
	t.Setenv("ZYXEL_PASS", "env-pass")
	user, pass := resolveCredentials(types.StringValue("config-user"), types.StringNull())
	if user != "env-user" || pass != "env-pass" {
		t.Fatalf("partial config should fall back to a complete environment pair")
	}
	user, pass = resolveCredentials(types.StringValue("config-user"), types.StringValue("config-pass"))
	if user != "config-user" || pass != "config-pass" {
		t.Fatalf("complete config pair should take precedence")
	}
	_, pass = resolveCredentials(types.StringValue("config-user"), types.StringValue(" pass "))
	if pass != " pass " {
		t.Fatal("configured password whitespace must be preserved")
	}
	t.Setenv("ZYXEL_USER", "")
	t.Setenv("ZYXEL_PASS", "")
	user, pass = resolveCredentials(types.StringValue("only-user"), types.StringNull())
	if user != "only-user" || pass != "" {
		t.Fatalf("incomplete credentials should not be combined")
	}
}

func TestUnknownProviderSettings(t *testing.T) {
	got := unknownSettings(providerModel{Host: types.StringUnknown(), Username: types.StringNull(), Password: types.StringUnknown(), TimeoutSeconds: types.Int64Unknown()})
	if len(got) != 3 {
		t.Fatalf("expected unknown host, password, and timeout, got %v", got)
	}
	seen := map[string]bool{}
	for _, name := range got {
		seen[name] = true
	}
	for _, name := range []string{"host", "password", "timeout_seconds"} {
		if !seen[name] {
			t.Errorf("unknown setting %q was not detected", name)
		}
	}
}

func TestMissingAndIncompleteConfigurationDiagnostics(t *testing.T) {
	issues := validateConnectionSettings("", "", "")
	if len(issues) != 2 || issues[0].summary != "Missing router host" || issues[1].summary != "Missing router credentials" {
		t.Fatalf("unexpected missing configuration diagnostics: %#v", issues)
	}
	issues = validateConnectionSettings("router", "admin", "")
	if len(issues) != 1 || issues[0].summary != "Incomplete router credentials" {
		t.Fatalf("unexpected partial credentials diagnostic: %#v", issues)
	}
	for _, issue := range append(issues, validateConnectionSettings("", "", "")...) {
		if strings.Contains(issue.detail, "admin") || strings.Contains(issue.detail, "secret") {
			t.Fatalf("configuration diagnostic leaked a credential: %#v", issue)
		}
	}
}
