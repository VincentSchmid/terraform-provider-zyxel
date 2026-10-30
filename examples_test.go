package main_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func TestResourceExamples(t *testing.T) {
	files, err := filepath.Glob("examples/resources/*/resource.tf")
	if err != nil || len(files) == 0 {
		t.Fatalf("find resource examples: %v", err)
	}
	for _, name := range files {
		t.Run(filepath.Base(filepath.Dir(name)), func(t *testing.T) {
			source, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			file, diagnostics := hclsyntax.ParseConfig(source, name, hcl.InitialPos)
			if diagnostics.HasErrors() {
				t.Fatal(diagnostics.Error())
			}
			target := filepath.Base(filepath.Dir(name))
			foundTarget := false
			body := file.Body.(*hclsyntax.Body)
			for _, block := range body.Blocks {
				if block.Type == "variable" || block.Type == "locals" {
					t.Errorf("use hardcoded values instead of %s blocks", block.Type)
				}
				if block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == target {
					foundTarget = true
				} else if foundTarget {
					t.Errorf("put prerequisites before the documented %s resources", target)
				}
			}
			if !foundTarget {
				t.Errorf("missing documented %s resource", target)
			}
			hclsyntax.VisitAll(body, func(node hclsyntax.Node) hcl.Diagnostics {
				if traversal, ok := node.(*hclsyntax.ScopeTraversalExpr); ok {
					root := traversal.Traversal.RootName()
					if root == "var" || root == "local" {
						t.Errorf("use hardcoded values instead of %s references", root)
					}
				}
				return nil
			})

			docName := "docs/resources/" + strings.TrimPrefix(target, "zyxel_") + ".md"
			doc, err := os.ReadFile(docName)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(doc), strings.TrimSpace(string(source))) {
				t.Errorf("%s is out of date; regenerate documentation", docName)
			}
		})
	}
}

func TestDocumentationExamplesUseNoVariablesOrLocals(t *testing.T) {
	codeFence := regexp.MustCompile("(?s)```(?:hcl|terraform)\\n(.*?)```")
	indirection := regexp.MustCompile(`(?m)^\s*(?:variable\s+"|locals\s*\{)|\b(?:var|local)\.`)
	for _, root := range []string{"README.md", "templates", "docs", "examples"} {
		err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			source, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			if filepath.Ext(name) == ".tf" && indirection.Match(source) {
				t.Errorf("%s: use hardcoded example values, not variables or locals", name)
			}
			snippets := codeFence.FindAllSubmatch(source, -1)
			for _, snippet := range snippets {
				if indirection.Match(snippet[1]) {
					t.Errorf("%s: use hardcoded example values, not variables or locals", name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
