package goAuth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// auditCallerTextKeys are the audit metadata fields that carry text a caller
// chose: an identifier typed into a form, a challenge ID taken from a link.
// Every value written under one of them must go through one of the bounding
// helpers in auditCallerTextHelpers, so no queued event holds more of the
// request than the cap allows and none keeps the request's memory alive.
var auditCallerTextKeys = map[string]bool{
	"identifier": true,
}

// auditChallengeIDKeys are the fields that carry a challenge ID. The ID is the
// whole secret with a UUID strategy, so these are never written as a literal
// key: challengeIDMeta (internal/flows) decides between the bounded ID and a
// fingerprint of it, and is the only writer.
var auditChallengeIDKeys = map[string]bool{
	"verification_id":    true,
	"verification_id_fp": true,
	"reset_id":           true,
	"reset_id_fp":        true,
}

var auditCallerTextHelpers = map[string]bool{
	"auditIdentifier": true,
	"AuditIdentifier": true,
}

func TestAuditMetadataCallerTextIsBounded(t *testing.T) {
	var files []string
	for _, pattern := range []string{"engine*.go", filepath.Join("internal", "flows", "*.go")} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}

	checked := 0
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			lit, ok := kv.Key.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			if err == nil && auditChallengeIDKeys[key] {
				t.Errorf("%s: audit metadata %q is written by hand; use challengeIDMeta", fset.Position(kv.Pos()), key)
				return true
			}
			if err != nil || !auditCallerTextKeys[key] {
				return true
			}
			checked++
			if call, ok := kv.Value.(*ast.CallExpr); ok && auditCallerTextHelpers[calleeName(call)] {
				return true
			}
			t.Errorf("%s: audit metadata %q is not bounded by an audit helper", fset.Position(kv.Pos()), key)
			return true
		})
	}
	if checked < 50 {
		t.Fatalf("only %d caller-text metadata fields found; the scan is not seeing the audit sites", checked)
	}
}

func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}
