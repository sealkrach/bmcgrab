package vendors

import (
	"context"
	"errors"
	"fmt"

	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
)

// Dell iDRAC9. CPU and memory usage come from the TelemetryService
// "SystemUsage" metric report (requires the iDRAC Datacenter license and
// telemetry enabled). Its MetricValues carry MetricId CPUUsage, MemoryUsage,
// IOUsage and SYSUsage, each in percent with a Timestamp. When the report is
// absent (Express/Enterprise license), the family is reported as unsupported
// with a clear reason so the operator knows it is a licensing matter.
type Dell struct{ Generic }

func (Dell) Vendor() string { return "dell" }
func (Dell) Matches(m string) bool {
	return matchAny(m, "dell")
}

const dellSystemUsage = "/redfish/v1/TelemetryService/MetricReports/SystemUsage"

func (Dell) CPU(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return dellUsage(ctx, s, "CPUUsage", "cpu_usage_percent")
}

func (Dell) Memory(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return dellUsage(ctx, s, "MemoryUsage", "memory_usage_percent")
}

func dellUsage(ctx context.Context, s *redfish.Session, metricID, name string) ([]model.Sample, error) {
	rep, err := s.Client.Get(ctx, s.Target, dellSystemUsage)
	if err != nil {
		if errors.Is(err, redfish.ErrNotFound) {
			return nil, fmt.Errorf("%w: SystemUsage report missing (iDRAC Datacenter license + telemetry required)", redfish.ErrUnsupported)
		}
		return nil, err
	}
	var out []model.Sample
	for _, mv := range redfish.Arr(rep, "MetricValues") {
		if redfish.Str(mv, "MetricId") != metricID {
			continue
		}
		v, ok := parseNumString(mv, "MetricValue")
		if !ok {
			continue
		}
		smp := model.Sample{Name: name, Sensor: "system", Value: v, Unit: "percent"}
		if t, ok := redfish.ParseRedfishTime(redfish.Str(mv, "Timestamp")); ok {
			smp.Time = t
		}
		out = append(out, smp)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s absent from SystemUsage report", redfish.ErrUnsupported, metricID)
	}
	// The report may hold several timestamps; keep the latest.
	latest := out[0]
	for _, o := range out[1:] {
		if o.Time.After(latest.Time) {
			latest = o
		}
	}
	return []model.Sample{latest}, nil
}

// parseNumString reads a value that Dell encodes as a JSON string ("12.5").
func parseNumString(m map[string]any, key string) (float64, bool) {
	if v, ok := redfish.Num(m, key); ok {
		return v, true
	}
	var f float64
	if _, err := fmt.Sscanf(redfish.Str(m, key), "%g", &f); err == nil {
		return f, true
	}
	return 0, false
}
