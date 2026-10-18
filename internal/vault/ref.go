package vault

import (
	"errors"
	"strings"
)

// Ref identifies one CyberArk account (Safe + Object). The zero Ref means
// "the shared default account".
type Ref struct {
	Safe   string
	Object string
}

// IsZero reports whether r designates the default account.
func (r Ref) IsZero() bool { return r.Safe == "" && r.Object == "" }

// String is safe to log: it names an account, it is not a secret.
func (r Ref) String() string {
	if r.IsZero() {
		return "default"
	}
	return r.Safe + "/" + r.Object
}

// ParseRef parses "safe/object" or "object" (the Safe then comes from the
// default account). Empty input yields the zero Ref.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, nil
	}
	safe, obj, found := strings.Cut(s, "/")
	if !found {
		return Ref{Object: s}, nil
	}
	if safe == "" || obj == "" {
		return Ref{}, errors.New("secret_ref must be \"safe/object\" or \"object\"")
	}
	return Ref{Safe: safe, Object: obj}, nil
}
