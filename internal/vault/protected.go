package vault

import (
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
)

// ProtectedStore keeps passwords in memguard enclaves: encrypted in RAM with a
// key held in locked (mlock'd, guard-paged, dump-excluded) memory, so a secret
// never rests in clear in swap, a core dump or a heap scan. It is not a
// hardware enclave (SGX/SEV): a root attacker who can read the process memory
// while a password is being used can still get it.
//
// It returns an error if the platform cannot lock memory (for instance a
// RLIMIT_MEMLOCK that is too small), so the caller can decide to fall back.
func ProtectedStore() (s Store, err error) {
	defer func() {
		// memguard panics when the OS refuses to lock memory.
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("protected memory unavailable: %v", r)
		}
	}()
	st := guardStore{}
	probe, err := st.Seal("probe")
	if err != nil {
		return nil, err
	}
	if probe.Reveal() != "probe" {
		return nil, errors.New("protected memory self-test failed")
	}
	probe.Destroy()
	return st, nil
}

type guardStore struct{}

func (guardStore) Name() string { return "protected" }

func (guardStore) Seal(p string) (Secret, error) {
	b := []byte(p)
	enc := memguard.NewEnclave(b) // wipes b
	if enc == nil {
		return nil, errors.New("memguard: empty secret")
	}
	return &guardSecret{enc: enc}, nil
}

type guardSecret struct{ enc *memguard.Enclave }

func (g *guardSecret) Reveal() string {
	if g.enc == nil {
		return ""
	}
	buf, err := g.enc.Open()
	if err != nil {
		return ""
	}
	defer buf.Destroy()
	return string(buf.Bytes())
}

// Destroy drops the enclave; its ciphertext is unreadable once the process-wide
// key is gone and is reclaimed by the GC.
func (g *guardSecret) Destroy() { g.enc = nil }
