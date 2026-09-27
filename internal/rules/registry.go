package rules

import (
	"context"
	"errors"
	"fmt"
)

// Registry indexes known rule sets by version. Registered sets are kept
// forever (new versions coexist with old ones) and a version may never be
// redefined with different content, which keeps old results reproducible.
type Registry struct {
	m       map[string]*Set
	ordered []string
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]*Set)}
}

// Register adds a rule set; registering an identical version again is an
// error (version tags are immutable content identifiers).
func (r *Registry) Register(s *Set) error {
	if s == nil {
		return errors.New("cannot register nil rule set")
	}
	v := s.Version()
	if _, exists := r.m[v]; exists {
		return fmt.Errorf("%w: %q", ErrVersionExists, v)
	}
	r.m[v] = s
	r.ordered = append(r.ordered, v)
	return nil
}

// MustRegister panics on registration failure; intended for built-in sets.
func (r *Registry) MustRegister(s *Set) {
	if err := r.Register(s); err != nil {
		panic(err)
	}
}

// Get returns the rule set for a version.
func (r *Registry) Get(version string) (*Set, error) {
	s, ok := r.m[version]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownVersion, version)
	}
	return s, nil
}

// Versions returns all registered version tags in registration order.
func (r *Registry) Versions() []string {
	out := make([]string, len(r.ordered))
	copy(out, r.ordered)
	return out
}

// ErrUnknownVersion is returned when a version is not registered.
var ErrUnknownVersion = errors.New("unknown rules version")

// ErrVersionExists is returned when a version is registered twice.
var ErrVersionExists = errors.New("rules version already registered")

// BasicRule is a convenience Rule backed by a plain function. When Check
// returns true a Match with the rule's severity/message is emitted.
type BasicRule struct {
	ID_   string
	Sev   Severity
	Msg   string
	Check func(ctx context.Context, f Facts) (bool, error)
}

func (r *BasicRule) ID() string { return r.ID_ }

func (r *BasicRule) Evaluate(ctx context.Context, f Facts) (*Match, error) {
	if r.Check == nil {
		return nil, nil
	}
	hit, err := r.Check(ctx, f)
	if err != nil || !hit {
		return nil, err
	}
	return &Match{RuleID: r.ID_, Severity: r.Sev, Message: r.Msg}, nil
}
