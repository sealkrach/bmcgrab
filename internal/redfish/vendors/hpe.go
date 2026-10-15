package vendors

import (
	"context"
	"errors"
	"fmt"

	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
)

// HPE iLO 5 / iLO 6. Thermal and power follow the standard paths (iLO also
// keeps a FastPowerMeter history, not needed here). Utilization is exposed in
// the ComputerSystem OEM block on recent firmware:
//
//	Oem.Hpe.SystemUsage.CPUUtil      (percent)
//	Oem.Hpe.SystemUsage.MemoryBusUtil (percent, memory bus, not RAM fill)
//	Oem.Hpe.SystemUsage.IOBusUtil
//	Oem.Hpe.SystemUsage.JitterCount
//
// Older iLO 4 firmware does not carry SystemUsage; the family is then marked
// unsupported with the reason. Note that MemoryBusUtil is a bus utilization,
// the closest HPE offers to RAM usage over Redfish; it is stored under
// memory_usage_percent with sensor "memory_bus" so the UI can show it as such.
type HPE struct{ Generic }

func (HPE) Vendor() string { return "hpe" }
func (HPE) Matches(m string) bool {
	return matchAny(m, "hpe", "hewlett", "hp ")
}

func (HPE) CPU(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return hpeUsage(ctx, s, "CPUUtil", "cpu_usage_percent", "system")
}

func (HPE) Memory(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return hpeUsage(ctx, s, "MemoryBusUtil", "memory_usage_percent", "memory_bus")
}

func hpeUsage(ctx context.Context, s *redfish.Session, field, name, sensor string) ([]model.Sample, error) {
	usage := redfish.Obj(s.System, "Oem.Hpe.SystemUsage")
	if usage == nil {
		// The session's cached System may be stale; refetch once.
		sys, err := s.Client.Get(ctx, s.Target, s.SystemP)
		if err != nil {
			if errors.Is(err, redfish.ErrNotFound) {
				return nil, redfish.ErrUnsupported
			}
			return nil, err
		}
		usage = redfish.Obj(sys, "Oem.Hpe.SystemUsage")
	}
	if usage == nil {
		return nil, fmt.Errorf("%w: Oem.Hpe.SystemUsage absent (iLO 5 2.x+ required)", redfish.ErrUnsupported)
	}
	v, ok := redfish.Num(usage, field)
	if !ok {
		return nil, fmt.Errorf("%w: %s absent from SystemUsage", redfish.ErrUnsupported, field)
	}
	return []model.Sample{{Name: name, Sensor: sensor, Value: v, Unit: "percent"}}, nil
}
