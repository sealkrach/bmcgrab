package vendors

import (
	"context"
	"errors"
	"fmt"

	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
)

// Lenovo XClarity Controller (XCC / XCC2, ThinkSystem). Thermal and power use
// the standard paths. Utilization is exposed through the Lenovo OEM metrics
// resource on the ComputerSystem:
//
//	/redfish/v1/Systems/1/Oem/Lenovo/Metrics  → CPUUsage, MemoryUsage (percent)
//
// Older XCC firmware instead publishes "CPU Utilization" / "Memory Utilization"
// percent sensors under Chassis/1/Sensors, which the generic scan finds.
type Lenovo struct{ Generic }

func (Lenovo) Vendor() string { return "lenovo" }
func (Lenovo) Matches(m string) bool {
	return matchAny(m, "lenovo", "ibm")
}

func (l Lenovo) CPU(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	if smp, err := lenovoMetric(ctx, s, "CPUUsage", "cpu_usage_percent"); err == nil {
		return smp, nil
	} else if !errors.Is(err, redfish.ErrUnsupported) {
		return nil, err
	}
	return l.Generic.CPU(ctx, s)
}

func (l Lenovo) Memory(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	if smp, err := lenovoMetric(ctx, s, "MemoryUsage", "memory_usage_percent"); err == nil {
		return smp, nil
	} else if !errors.Is(err, redfish.ErrUnsupported) {
		return nil, err
	}
	return l.Generic.Memory(ctx, s)
}

func lenovoMetric(ctx context.Context, s *redfish.Session, field, name string) ([]model.Sample, error) {
	path := redfish.ODataID(redfish.Obj(s.System, "Oem.Lenovo.Metrics"))
	if path == "" {
		path = s.SystemP + "/Oem/Lenovo/Metrics"
	}
	m, err := s.Client.Get(ctx, s.Target, path)
	if err != nil {
		if errors.Is(err, redfish.ErrNotFound) {
			return nil, redfish.ErrUnsupported
		}
		return nil, err
	}
	v, ok := redfish.Num(m, field)
	if !ok {
		return nil, fmt.Errorf("%w: %s absent from Oem/Lenovo/Metrics", redfish.ErrUnsupported, field)
	}
	return []model.Sample{{Name: name, Sensor: "system", Value: v, Unit: "percent"}}, nil
}
