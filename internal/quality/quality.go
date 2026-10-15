// Package quality validates samples before they reach the database. A sample
// outside its plausible range, with a bad unit or an implausible timestamp is
// dropped and counted; the family is flagged "rejected" when every one of its
// samples was dropped.
package quality

import (
	"fmt"
	"math"
	"time"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/model"
)

// Validator holds the ranges from central config.
type Validator struct {
	TempMin, TempMax   float64
	PowerMin, PowerMax float64
	MaxClockSkew       time.Duration
}

// FromConfig builds a Validator from the central config.
func FromConfig(c *config.Central) *Validator {
	return &Validator{
		TempMin: c.Quality.TempMinC, TempMax: c.Quality.TempMaxC,
		PowerMin: c.Quality.PowerMinW, PowerMax: c.Quality.PowerMaxW,
		MaxClockSkew: c.Quality.MaxClockSkew,
	}
}

// Rejection explains one dropped sample (for logs and counters).
type Rejection struct {
	Sample model.Sample
	Reason string
}

// Check validates one sample; now is the collector's clock.
func (v *Validator) Check(s model.Sample, now time.Time) error {
	if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
		return fmt.Errorf("value is not a number")
	}
	switch s.Name {
	case "cpu_usage_percent", "memory_usage_percent":
		if s.Unit != "percent" {
			return fmt.Errorf("unit %q, want percent", s.Unit)
		}
		if s.Value < 0 || s.Value > 100 {
			return fmt.Errorf("%.1f%% outside 0..100", s.Value)
		}
	case "temperature_c":
		if s.Unit != "celsius" {
			return fmt.Errorf("unit %q, want celsius", s.Unit)
		}
		if s.Value < v.TempMin || s.Value > v.TempMax {
			return fmt.Errorf("%.1f°C outside %.0f..%.0f", s.Value, v.TempMin, v.TempMax)
		}
	case "power_w":
		if s.Unit != "watt" {
			return fmt.Errorf("unit %q, want watt", s.Unit)
		}
		if s.Value < v.PowerMin || s.Value > v.PowerMax {
			return fmt.Errorf("%.0fW outside %.0f..%.0f", s.Value, v.PowerMin, v.PowerMax)
		}
	default:
		return fmt.Errorf("unknown metric %q", s.Name)
	}
	if s.Time.IsZero() {
		return fmt.Errorf("missing timestamp")
	}
	if d := s.Time.Sub(now); d > v.MaxClockSkew {
		return fmt.Errorf("timestamp %s in the future", d.Round(time.Second))
	}
	if d := now.Sub(s.Time); d > 24*time.Hour {
		return fmt.Errorf("timestamp %s old", d.Round(time.Minute))
	}
	return nil
}

// Apply filters r.Samples in place, updates family states and returns the
// rejections for logging.
func (v *Validator) Apply(r *model.Result, now time.Time) []Rejection {
	var rejected []Rejection
	kept := r.Samples[:0]
	perFamily := map[model.Family][2]int{} // kept, dropped
	for _, s := range r.Samples {
		c := perFamily[s.Family]
		if err := v.Check(s, now); err != nil {
			rejected = append(rejected, Rejection{Sample: s, Reason: err.Error()})
			c[1]++
		} else {
			kept = append(kept, s)
			c[0]++
		}
		perFamily[s.Family] = c
	}
	r.Samples = kept
	for i, f := range r.Families {
		if f.State != model.StateCollected {
			continue
		}
		c := perFamily[f.Family]
		r.Families[i].Samples = c[0]
		if c[0] == 0 && c[1] > 0 {
			r.Families[i].State = model.StateRejected
			r.Families[i].Reason = fmt.Sprintf("all %d readings failed validation", c[1])
		} else if c[1] > 0 {
			r.Families[i].Reason = fmt.Sprintf("%d of %d readings rejected", c[1], c[0]+c[1])
		}
	}
	return rejected
}
