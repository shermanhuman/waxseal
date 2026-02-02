package template

import (
	"fmt"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Resolver resolves template inputs from various sources.
type Resolver struct {
	// keyValues maps keyName -> value for GSM-backed keys
	keyValues map[string]string
	// params are static constant values
	params map[string]string
}

// NewResolver creates a new input resolver.
func NewResolver() *Resolver {
	return &Resolver{
		keyValues: make(map[string]string),
		params:    make(map[string]string),
	}
}

// SetKeyValue sets a resolved key value (from GSM).
func (r *Resolver) SetKeyValue(keyName, value string) {
	r.keyValues[keyName] = value
}

// SetParam sets a static parameter value.
func (r *Resolver) SetParam(name, value string) {
	r.params[name] = value
}

// SetParams sets multiple static parameter values.
func (r *Resolver) SetParams(params map[string]string) {
	for k, v := range params {
		r.params[k] = v
	}
}

// InputRef describes how to resolve a template variable.
type InputRef struct {
	Var       string // Template variable name
	ShortName string // Source secret (empty = current secret)
	KeyName   string // Source key name
}

// ResolveInputs resolves all inputs needed for a computed key.
// Returns a map of variable name -> resolved value.
func (r *Resolver) ResolveInputs(inputs []InputRef) (map[string]string, error) {
	result := make(map[string]string)

	for _, input := range inputs {
		value, ok := r.keyValues[input.KeyName]
		if !ok {
			return nil, core.NewValidationError(
				fmt.Sprintf("input.%s", input.Var),
				fmt.Sprintf("key %q not found", input.KeyName),
			)
		}
		result[input.Var] = value
	}

	// Add params
	for k, v := range r.params {
		if _, exists := result[k]; !exists {
			result[k] = v
		}
	}

	return result, nil
}

// DependencyGraph tracks key dependencies for cycle detection.
type DependencyGraph struct {
	// deps maps keyName -> list of keyNames it depends on
	deps map[string][]string
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		deps: make(map[string][]string),
	}
}

// AddDependency records that 'key' depends on 'dependsOn'.
func (g *DependencyGraph) AddDependency(key, dependsOn string) {
	g.deps[key] = append(g.deps[key], dependsOn)
}

// AddDependencies records that 'key' depends on multiple keys.
func (g *DependencyGraph) AddDependencies(key string, dependsOn []string) {
	g.deps[key] = append(g.deps[key], dependsOn...)
}

// DetectCycle checks if there is a cycle in the dependency graph.
// Returns the cycle path if found, or nil if no cycle.
func (g *DependencyGraph) DetectCycle() []string {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	for key := range g.deps {
		if cycle := g.dfs(key, visited, recStack, nil); cycle != nil {
			return cycle
		}
	}

	return nil
}

func (g *DependencyGraph) dfs(key string, visited, recStack map[string]bool, path []string) []string {
	visited[key] = true
	recStack[key] = true
	path = append(path, key)

	for _, dep := range g.deps[key] {
		if !visited[dep] {
			if cycle := g.dfs(dep, visited, recStack, path); cycle != nil {
				return cycle
			}
		} else if recStack[dep] {
			// Found cycle - return the cycle path
			for i, p := range path {
				if p == dep {
					return append(path[i:], dep)
				}
			}
			return append(path, dep)
		}
	}

	recStack[key] = false
	return nil
}

// TopologicalSort returns keys in dependency order (dependencies first).
// Returns an error if there is a cycle.
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	if cycle := g.DetectCycle(); cycle != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrCycle, cycle)
	}

	visited := make(map[string]bool)
	var result []string

	var visit func(key string)
	visit = func(key string) {
		if visited[key] {
			return
		}
		visited[key] = true
		for _, dep := range g.deps[key] {
			visit(dep)
		}
		result = append(result, key)
	}

	for key := range g.deps {
		visit(key)
	}

	return result, nil
}
