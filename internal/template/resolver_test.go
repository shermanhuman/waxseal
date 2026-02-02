package template

import (
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestResolver_ResolveInputs(t *testing.T) {
	r := NewResolver()
	r.SetKeyValue("username", "admin")
	r.SetKeyValue("password", "secret")
	r.SetParams(map[string]string{
		"host": "localhost",
		"port": "5432",
	})

	inputs := []InputRef{
		{Var: "user", KeyName: "username"},
		{Var: "pass", KeyName: "password"},
	}

	values, err := r.ResolveInputs(inputs)
	if err != nil {
		t.Fatalf("ResolveInputs failed: %v", err)
	}

	if values["user"] != "admin" {
		t.Errorf("user = %q, want %q", values["user"], "admin")
	}
	if values["pass"] != "secret" {
		t.Errorf("pass = %q, want %q", values["pass"], "secret")
	}
	if values["host"] != "localhost" {
		t.Errorf("host = %q, want %q", values["host"], "localhost")
	}
}

func TestResolver_MissingKey(t *testing.T) {
	r := NewResolver()
	r.SetKeyValue("username", "admin")

	inputs := []InputRef{
		{Var: "user", KeyName: "username"},
		{Var: "pass", KeyName: "password"}, // missing
	}

	_, err := r.ResolveInputs(inputs)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDependencyGraph_NoCycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependency("DATABASE_URL", "username")
	g.AddDependency("DATABASE_URL", "password")
	g.AddDependency("CONNECTION_STRING", "DATABASE_URL")

	cycle := g.DetectCycle()
	if cycle != nil {
		t.Errorf("unexpected cycle detected: %v", cycle)
	}

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort failed: %v", err)
	}

	// DATABASE_URL should come before CONNECTION_STRING
	dbIndex := -1
	connIndex := -1
	for i, key := range order {
		if key == "DATABASE_URL" {
			dbIndex = i
		}
		if key == "CONNECTION_STRING" {
			connIndex = i
		}
	}
	if connIndex != -1 && dbIndex != -1 && dbIndex > connIndex {
		t.Error("DATABASE_URL should come before CONNECTION_STRING in order")
	}
}

func TestDependencyGraph_SimpleCycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependency("A", "B")
	g.AddDependency("B", "A")

	cycle := g.DetectCycle()
	if cycle == nil {
		t.Fatal("expected cycle to be detected")
	}
}

func TestDependencyGraph_LongCycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependency("A", "B")
	g.AddDependency("B", "C")
	g.AddDependency("C", "D")
	g.AddDependency("D", "A")

	cycle := g.DetectCycle()
	if cycle == nil {
		t.Fatal("expected cycle to be detected")
	}
}

func TestDependencyGraph_SelfCycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependency("A", "A")

	cycle := g.DetectCycle()
	if cycle == nil {
		t.Fatal("expected self-cycle to be detected")
	}
}

func TestDependencyGraph_TopologicalSort_WithCycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependency("A", "B")
	g.AddDependency("B", "A")

	_, err := g.TopologicalSort()
	if err == nil {
		t.Fatal("expected error for cycle")
	}
	if !errors.Is(err, core.ErrCycle) {
		t.Errorf("expected ErrCycle, got %v", err)
	}
}

func TestDependencyGraph_AddDependencies(t *testing.T) {
	g := NewDependencyGraph()
	g.AddDependencies("DATABASE_URL", []string{"username", "password", "host"})

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort failed: %v", err)
	}

	if len(order) == 0 {
		t.Error("expected at least one key in order")
	}
}
