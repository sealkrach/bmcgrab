package buffer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sealkrach/bmcgrab/internal/model"
)

func results(n int) []*model.Result {
	out := make([]*model.Result, n)
	for i := range out {
		out[i] = &model.Result{Server: model.Server{ID: "s", Hostname: "h"}, CycleID: "c", Collected: time.Now(),
			Samples: []model.Sample{{Family: model.FamilyPower, Name: "power_w", Value: float64(i), Unit: "watt", Time: time.Now()}}}
	}
	return out
}

func TestWriteReplay(t *testing.T) {
	dir := t.TempDir()
	b, err := New(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Write("cycle-1", results(3)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // distinct timestamp in filename
	if err := b.Write("cycle-2", results(2)); err != nil {
		t.Fatal(err)
	}
	if b.Segments() != 2 || b.Size() == 0 {
		t.Fatalf("segments=%d size=%d", b.Segments(), b.Size())
	}

	// First replay: DB "down" on the second segment → one replayed, one left.
	calls := 0
	n, err := b.Replay(context.Background(), func(_ context.Context, rs []*model.Result) error {
		calls++
		if calls == 2 {
			return errors.New("db down")
		}
		if len(rs) != 3 {
			t.Errorf("first segment has %d results, want 3", len(rs))
		}
		return nil
	})
	if n != 1 || err == nil || b.Segments() != 1 {
		t.Fatalf("n=%d err=%v segments=%d", n, err, b.Segments())
	}

	// Corrupt segment is moved aside, not retried forever.
	seg, _ := filepath.Glob(filepath.Join(dir, "*.ndjson"))
	_ = os.WriteFile(seg[0], []byte("{\"garbage\n"), 0o600)
	n, err = b.Replay(context.Background(), func(context.Context, []*model.Result) error { return nil })
	if err != nil || n != 0 || b.Segments() != 0 {
		t.Fatalf("corrupt handling: n=%d err=%v segments=%d", n, err, b.Segments())
	}
	if c, _ := filepath.Glob(filepath.Join(dir, "*.corrupt")); len(c) != 1 {
		t.Fatalf("corrupt file not moved aside")
	}
}

func TestFull(t *testing.T) {
	b, _ := New(t.TempDir(), 10)
	_ = b.Write("c", results(5))
	if err := b.Write("c2", results(1)); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
}
