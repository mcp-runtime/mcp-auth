package server

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The authorization server is secret-provider neutral: external credential
// connectors run in separate resource servers, so no secret-manager SDK may
// enter this module.
func TestAuthorizationServerHasNoSecretManagerDependency(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			if p := strings.ToLower(spec.Path.Value); strings.Contains(p, "1password") || strings.Contains(p, "vault") {
				t.Errorf("%s imports a secret-manager package: %s", path, spec.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(data)), "1password") {
			t.Errorf("%s mentions a secret-manager SDK", name)
		}
	}
}
