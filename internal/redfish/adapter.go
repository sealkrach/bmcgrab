package redfish

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sealkrach/bmcgrab/internal/model"
)

// Session is what an adapter works with for one server: the client, the
// target, and the already-fetched system resource (so adapters do not refetch
// it) plus the chassis links.
type Session struct {
	Client  *Client
	Target  Target
	SystemP string         // path of the first ComputerSystem
	System  map[string]any // its JSON
	Chassis []string       // chassis paths linked from the system
	Now     time.Time
}

// Adapter collects one metric family for one vendor. Returning
// (nil, ErrUnsupported) means the firmware does not expose the family; any
// other error is a transport/parse failure.
type Adapter interface {
	Vendor() string
	// Matches reports whether this adapter handles the Manufacturer string.
	Matches(manufacturer string) bool
	CPU(ctx context.Context, s *Session) ([]model.Sample, error)
	Memory(ctx context.Context, s *Session) ([]model.Sample, error)
	Thermal(ctx context.Context, s *Session) ([]model.Sample, error)
	Power(ctx context.Context, s *Session) ([]model.Sample, error)
}

// ErrUnsupported marks a family the BMC does not expose (3-state model).
var ErrUnsupported = errors.New("not exposed by this BMC/firmware")

// Registry holds adapters in priority order; the generic one is last.
type Registry struct{ adapters []Adapter }

// NewRegistry builds the default registry (vendors package registers itself).
func NewRegistry(adapters ...Adapter) *Registry { return &Registry{adapters: adapters} }

// Resolve picks the adapter for a manufacturer string (hint from inventory or
// Manufacturer field of the ComputerSystem).
func (r *Registry) Resolve(manufacturer string) Adapter {
	m := strings.ToLower(manufacturer)
	for _, a := range r.adapters {
		if a.Matches(m) {
			return a
		}
	}
	return r.adapters[len(r.adapters)-1]
}

// Vendors lists the registered vendor names.
func (r *Registry) Vendors() []string {
	out := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a.Vendor())
	}
	return out
}

// Open fetches the service root → first system → chassis links.
func (c *Client) Open(ctx context.Context, t Target) (*Session, error) {
	systems, err := c.Get(ctx, t, "/redfish/v1/Systems")
	if err != nil {
		return nil, err
	}
	members := MembersOf(systems)
	if len(members) == 0 {
		return nil, errors.New("redfish: no ComputerSystem member")
	}
	sys, err := c.Get(ctx, t, members[0])
	if err != nil {
		return nil, err
	}
	s := &Session{Client: c, Target: t, SystemP: members[0], System: sys, Now: time.Now().UTC()}
	for _, ch := range Arr(sys, "Links.Chassis") {
		if id := ODataID(ch); id != "" {
			s.Chassis = append(s.Chassis, id)
		}
	}
	if len(s.Chassis) == 0 {
		// Fall back to the chassis collection.
		if col, err := c.Get(ctx, t, "/redfish/v1/Chassis"); err == nil {
			s.Chassis = MembersOf(col)
		}
	}
	return s, nil
}

// Manufacturer returns the system's Manufacturer field.
func (s *Session) Manufacturer() string { return Str(s.System, "Manufacturer") }

// Model returns the system model.
func (s *Session) Model() string { return Str(s.System, "Model") }

// CPUModel returns the processor summary model.
func (s *Session) CPUModel() string { return Str(s.System, "ProcessorSummary.Model") }

// Collect runs the enabled families through the adapter and builds the Result.
func Collect(ctx context.Context, s *Session, a Adapter, families []model.Family) *model.Result {
	res := &model.Result{Vendor: a.Vendor(), Model: s.Model(), CPUModel: s.CPUModel(), Collected: s.Now}
	for _, f := range families {
		var samples []model.Sample
		var err error
		switch f {
		case model.FamilyCPU:
			samples, err = a.CPU(ctx, s)
		case model.FamilyMemory:
			samples, err = a.Memory(ctx, s)
		case model.FamilyThermal:
			samples, err = a.Thermal(ctx, s)
		case model.FamilyPower:
			samples, err = a.Power(ctx, s)
		default:
			continue
		}
		fr := model.FamilyResult{Family: f}
		switch {
		case errors.Is(err, ErrUnsupported) || errors.Is(err, ErrNotFound):
			fr.State, fr.Reason = model.StateUnsupported, trimErr(err)
		case err != nil:
			fr.State, fr.Reason = model.StateError, trimErr(err)
		case len(samples) == 0:
			fr.State, fr.Reason = model.StateUnsupported, "no reading returned"
		default:
			fr.State, fr.Samples = model.StateCollected, len(samples)
			for i := range samples {
				samples[i].Family = f
				if samples[i].Time.IsZero() {
					samples[i].Time = s.Now
				}
			}
			res.Samples = append(res.Samples, samples...)
		}
		res.Families = append(res.Families, fr)
	}
	return res
}

func trimErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// ----------------------------------------------------------- shared helpers
// These implement the DMTF-standard paths and are reused by every vendor.

// StdThermal reads Chassis/{id}/Thermal (classic) or ThermalSubsystem/
// ThermalMetrics + Sensors (2020+ schemas).
func StdThermal(ctx context.Context, s *Session) ([]model.Sample, error) {
	var out []model.Sample
	var lastErr error
	for _, ch := range s.Chassis {
		th, err := s.Client.Get(ctx, s.Target, ch+"/Thermal")
		if err == nil {
			for _, t := range Arr(th, "Temperatures") {
				if !Enabled(t) {
					continue
				}
				if v, ok := Num(t, "ReadingCelsius"); ok {
					out = append(out, model.Sample{Name: "temperature_c", Sensor: sensorName(t), Value: v, Unit: "celsius"})
				}
			}
			continue
		}
		lastErr = err
		// Newer schema: Sensors collection with ReadingType == Temperature.
		if sens, err2 := sensorsOf(ctx, s, ch); err2 == nil {
			for _, sn := range sens {
				if Str(sn, "ReadingType") == "Temperature" {
					if v, ok := Num(sn, "Reading"); ok {
						out = append(out, model.Sample{Name: "temperature_c", Sensor: sensorName(sn), Value: v, Unit: "celsius"})
					}
				}
			}
			lastErr = nil
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// StdPower reads Chassis/{id}/Power PowerControl[].PowerConsumedWatts, falling
// back to EnvironmentMetrics / Sensors (Power reading type).
func StdPower(ctx context.Context, s *Session) ([]model.Sample, error) {
	var out []model.Sample
	var lastErr error
	for _, ch := range s.Chassis {
		pw, err := s.Client.Get(ctx, s.Target, ch+"/Power")
		if err == nil {
			for _, pc := range Arr(pw, "PowerControl") {
				if v, ok := Num(pc, "PowerConsumedWatts"); ok {
					out = append(out, model.Sample{Name: "power_w", Sensor: sensorName(pc), Value: v, Unit: "watt"})
				}
			}
			if len(out) > 0 {
				continue
			}
		} else {
			lastErr = err
		}
		if env, err2 := s.Client.Get(ctx, s.Target, ch+"/EnvironmentMetrics"); err2 == nil {
			if v, ok := Num(env, "PowerWatts.Reading"); ok {
				out = append(out, model.Sample{Name: "power_w", Sensor: "chassis", Value: v, Unit: "watt"})
				lastErr = nil
				continue
			}
		}
		if sens, err2 := sensorsOf(ctx, s, ch); err2 == nil {
			for _, sn := range sens {
				if Str(sn, "ReadingType") == "Power" {
					if v, ok := Num(sn, "Reading"); ok {
						out = append(out, model.Sample{Name: "power_w", Sensor: sensorName(sn), Value: v, Unit: "watt"})
					}
				}
			}
			lastErr = nil
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// SensorsUtilization scans Chassis/{id}/Sensors for readings whose name
// mentions the given keyword and whose ReadingType/Units is a percentage.
// Used as a last resort for CPU/RAM usage on vendors without an OEM metric.
func SensorsUtilization(ctx context.Context, s *Session, keyword, name string) ([]model.Sample, error) {
	kw := strings.ToLower(keyword)
	var out []model.Sample
	for _, ch := range s.Chassis {
		sens, err := sensorsOf(ctx, s, ch)
		if err != nil {
			continue
		}
		for _, sn := range sens {
			n := strings.ToLower(sensorName(sn))
			isPct := Str(sn, "ReadingType") == "Percent" || Str(sn, "ReadingUnits") == "%"
			if strings.Contains(n, kw) && isPct {
				if v, ok := Num(sn, "Reading"); ok {
					out = append(out, model.Sample{Name: name, Sensor: sensorName(sn), Value: v, Unit: "percent"})
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrUnsupported
	}
	return out, nil
}

// sensorsOf expands a Sensors collection (one GET per member; cached per call).
func sensorsOf(ctx context.Context, s *Session, chassis string) ([]map[string]any, error) {
	col, err := s.Client.Get(ctx, s.Target, chassis+"/Sensors")
	if err != nil {
		return nil, err
	}
	// Many BMCs support $expand; try it first to avoid N round-trips.
	if exp, err := s.Client.Get(ctx, s.Target, chassis+"/Sensors?$expand=."); err == nil {
		if members := Arr(exp, "Members"); len(members) > 0 && Str(members[0], "ReadingType") != "" {
			return members, nil
		}
	}
	var out []map[string]any
	for _, id := range MembersOf(col) {
		if sn, err := s.Client.Get(ctx, s.Target, id); err == nil {
			out = append(out, sn)
		}
	}
	return out, nil
}

func sensorName(m map[string]any) string {
	for _, k := range []string{"Name", "MemberId", "Id"} {
		if v := Str(m, k); v != "" {
			return v
		}
	}
	return ""
}

// ParseRedfishTime converts a Redfish timestamp to time.Time (best effort).
func ParseRedfishTime(v string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05-07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// String implements fmt.Stringer for logging without the credential.
func (t Target) String() string { return fmt.Sprintf("%s (user %s)", t.BaseURL, t.Username) }
