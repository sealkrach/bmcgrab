// Package buffer is the local write-ahead buffer used when the central
// database is unreachable. Each failed cycle is written as one NDJSON segment
// (one model.Result per line) with a trailing checksum line; segments are
// replayed in order and deleted once the database acknowledges them.
//
// NDJSON was chosen over SQLite/Bolt on purpose: sequential writes, one
// corrupt segment cannot damage the others, and an operator can inspect a
// segment with `cat`.
package buffer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sealkrach/bmcgrab/internal/model"
)

// Buffer manages a directory of segments.
type Buffer struct {
	dir      string
	maxBytes int64
}

// ErrFull is returned when the buffer would exceed its byte limit.
var ErrFull = errors.New("buffer: size limit reached")

// New creates the directory if needed.
func New(dir string, maxBytes int64) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("buffer: %w", err)
	}
	return &Buffer{dir: dir, maxBytes: maxBytes}, nil
}

// Size returns bytes currently buffered.
func (b *Buffer) Size() int64 {
	var total int64
	for _, s := range b.segments() {
		if fi, err := os.Stat(s); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// Segments returns the number of pending segments.
func (b *Buffer) Segments() int { return len(b.segments()) }

func (b *Buffer) segments() []string {
	matches, _ := filepath.Glob(filepath.Join(b.dir, "*.ndjson"))
	sort.Strings(matches)
	return matches
}

// Write appends one segment for a cycle. Atomic: written to .tmp then renamed.
func (b *Buffer) Write(cycleID string, results []*model.Result) error {
	if len(results) == 0 {
		return nil
	}
	if b.maxBytes > 0 && b.Size() >= b.maxBytes {
		return ErrFull
	}
	name := fmt.Sprintf("%s-%s.ndjson", time.Now().UTC().Format("20060102T150405Z"), sanitize(cycleID))
	tmp := filepath.Join(b.dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	h := crc32.NewIEEE()
	for _, r := range results {
		line, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return err
		}
		h.Write(line)
		if _, err := w.Write(append(line, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	fmt.Fprintf(w, "#crc32=%08x count=%d\n", h.Sum32(), len(results))
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.dir, name))
}

// Replay feeds each segment to write and deletes it on success. It stops at
// the first write error (the database is still down) and returns the number
// of segments replayed. Corrupt segments are moved aside as .corrupt and
// skipped so one bad file never blocks the queue.
func (b *Buffer) Replay(ctx context.Context, write func(context.Context, []*model.Result) error) (int, error) {
	replayed := 0
	for _, seg := range b.segments() {
		if ctx.Err() != nil {
			return replayed, ctx.Err()
		}
		results, err := readSegment(seg)
		if err != nil {
			_ = os.Rename(seg, seg+".corrupt")
			continue
		}
		if err := write(ctx, results); err != nil {
			return replayed, err
		}
		if err := os.Remove(seg); err != nil {
			return replayed, err
		}
		replayed++
	}
	return replayed, nil
}

func readSegment(path string) ([]*model.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	h := crc32.NewIEEE()
	var out []*model.Result
	var trailer string
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) > 0 && line[0] == '#' {
			trailer = string(line)
			break
		}
		h.Write(line)
		var r model.Result
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("bad line: %w", err)
		}
		out = append(out, &r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var sum uint32
	var count int
	if _, err := fmt.Sscanf(trailer, "#crc32=%x count=%d", &sum, &count); err != nil {
		return nil, errors.New("missing trailer (truncated segment)")
	}
	if sum != h.Sum32() || count != len(out) {
		return nil, errors.New("checksum mismatch")
	}
	return out, nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
