package main_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/VincentSchmid/terraform-provider-zyxel"

// Check the transitive graph, not just direct imports: a helper package must not
// smuggle Terraform dependencies into the reusable API.
func TestAPIDependencyBoundary(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-json", "./zyxel", "./internal/cloudflare")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var dependency struct {
			ImportPath string
			Standard   bool
		}
		if err := decoder.Decode(&dependency); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if !dependency.Standard && dependency.ImportPath != modulePath+"/zyxel" && dependency.ImportPath != modulePath+"/internal/cloudflare" {
			t.Errorf("API packages must use only the standard library; found %s", dependency.ImportPath)
		}
	}
}

func TestProviderDependencyBoundary(t *testing.T) {
	files, err := filepath.Glob("internal/provider/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		httpAlias := ""
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			// This file serializes a typed private-state ledger, not router JSON.
			stateJSON := importPath == "encoding/json" && name == "internal/provider/acl_policy_state.go"
			if strings.HasPrefix(importPath, "crypto/") || (importPath == "encoding/json" && !stateJSON) || importPath == "net/http/cookiejar" || importPath == modulePath+"/internal/routertest" {
				t.Errorf("%s imports %s: wire protocol and fixtures do not belong in the Terraform adapter", name, importPath)
			}
			if importPath == "net/http" {
				httpAlias = "http"
				if spec.Name != nil {
					httpAlias = spec.Name.Name
				}
			}
		}
		// Cloudflare's adapter may configure an HTTP client, but requests belong
		// in its plain-Go package, never inside a resource or data source.
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if ok && httpAlias != "" && qualifier.Name == httpAlias && selector.Sel.Name != "Client" {
				t.Errorf("%s uses http.%s: HTTP requests belong below the Terraform adapter", name, selector.Sel.Name)
			}
			return true
		})
	}
}
