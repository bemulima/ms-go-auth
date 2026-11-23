package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"testing"
)

// Static call-site admission supplements the injected lifecycle tests without
// invoking New (which intentionally opens real Auth dependencies) or sockets.
func TestMentorRuntimeExecutableWiringSource(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", nil, 0)
	if err != nil {
		t.Fatal("application source unavailable")
	}
	functions := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			functions[fn.Name.Name] = fn
		}
	}
	calls := func(fn *ast.FuncDecl) map[string]token.Pos {
		out := map[string]token.Pos{}
		if fn != nil {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.Ident:
					if out[f.Name] == 0 {
						out[f.Name] = call.Pos()
					}
				case *ast.SelectorExpr:
					if out[f.Sel.Name] == 0 {
						out[f.Sel.Name] = call.Pos()
					}
				}
				return true
			})
		}
		return out
	}
	initCalls := calls(functions["New"])
	if initCalls["prepareMentorRuntime"] == 0 || initCalls["prepareMentorRuntime"] > initCalls["Open"] || initCalls["prepareMentorRuntime"] > initCalls["applyDatabaseMigrations"] || initCalls["connectMentorRuntimeBroker"] == 0 || initCalls["newMentorHTTPSServer"] == 0 {
		t.Fatal("enabled-only Mentor preflight/real composition not wired before runtime side effects")
	}
	if calls(functions["Run"])["runMentorHTTPS"] == 0 || calls(functions["runMentorHTTPS"])["runMentorServers"] == 0 || calls(functions["runMentorHTTPS"])["ListenAndServeTLS"] == 0 {
		t.Fatal("real executable dedicated HTTPS lifecycle not wired")
	}
}

func TestMentorRuntimeAppCloseOwnsOnlyDedicatedResources(t *testing.T) {
	f := &mentorRuntimeNATSFixture{}
	b := &mentorRuntimeBroker{connection: f, done: make(chan struct{})}
	a := &App{mentorBroker: b, mentorHTTPS: &http.Server{}}
	a.Close()
	a.Close()
	if f.closed.Load() != 1 {
		t.Fatal("App.Close did not release dedicated broker exactly once")
	}
	select {
	case <-b.done:
	default:
		t.Fatal("App.Close did not mark broker closed")
	}
}
