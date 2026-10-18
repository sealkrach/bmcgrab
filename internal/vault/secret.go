package vault

// Secret is a password held outside ordinary Go strings so it can be wiped
// and, with a protected Store, kept out of swap and core dumps.
type Secret interface {
	// Reveal returns a copy of the password. The copy lives in regular memory
	// and should be short-lived.
	Reveal() string
	// Destroy wipes the secret. The Secret must not be used afterwards.
	Destroy()
}

// Store seals passwords into Secrets.
type Store interface {
	Seal(password string) (Secret, error)
	Name() string
}

// PlainStore keeps the password in a byte slice that is zeroed on Destroy.
// It gives no protection against swap or core dumps; it is the fallback when
// no protected store is available.
func PlainStore() Store { return plainStore{} }

type plainStore struct{}

func (plainStore) Name() string { return "plain" }
func (plainStore) Seal(p string) (Secret, error) {
	return &plainSecret{b: []byte(p)}, nil
}

type plainSecret struct{ b []byte }

func (s *plainSecret) Reveal() string { return string(s.b) }
func (s *plainSecret) Destroy() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}
