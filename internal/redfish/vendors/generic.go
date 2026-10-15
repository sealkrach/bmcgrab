// Package vendors holds one adapter per manufacturer. Each adapter embeds the
// generic one and overrides only what the vendor does differently. The
// generic adapter is the last resort for Bull/Eviden, Supermicro and any
// unknown manufacturer: standard DMTF paths for thermal and power, and a
// best-effort scan of the Sensors collection for utilization readings.
package vendors

import (
	"context"
	"strings"

	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
)

// All returns the registry in priority order (generic last).
func All() *redfish.Registry {
	return redfish.NewRegistry(&Dell{}, &HPE{}, &Lenovo{}, &Supermicro{}, &Bull{}, &Generic{})
}

// Generic implements the pure-standard behaviour.
type Generic struct{}

func (Generic) Vendor() string      { return "generic" }
func (Generic) Matches(string) bool { return true }

// CPU: DMTF has no standard utilization metric; look for a percent sensor
// whose name contains "cpu".
func (Generic) CPU(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return redfish.SensorsUtilization(ctx, s, "cpu", "cpu_usage_percent")
}

// Memory: same strategy with "mem".
func (Generic) Memory(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return redfish.SensorsUtilization(ctx, s, "mem", "memory_usage_percent")
}

func (Generic) Thermal(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return redfish.StdThermal(ctx, s)
}

func (Generic) Power(ctx context.Context, s *redfish.Session) ([]model.Sample, error) {
	return redfish.StdPower(ctx, s)
}

// matchAny is a small helper for Matches implementations.
func matchAny(m string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(m, n) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------- Supermicro

// Supermicro BMCs (X11/X12/X13, AMI MegaRAC based) expose thermal and power
// through the standard paths. CPU/RAM utilization is not available over
// Redfish on most firmware: the family is reported as unsupported rather than
// guessed. Some newer firmware exposes utilization sensors; the generic scan
// picks those up when present.
type Supermicro struct{ Generic }

func (Supermicro) Vendor() string { return "supermicro" }
func (Supermicro) Matches(m string) bool {
	return matchAny(m, "supermicro", "super micro")
}

// ------------------------------------------------------------------- Bull

// Bull / Eviden (ex-Atos) Sequana and BullSequana servers run a Redfish
// service that follows the standard closely; no OEM utilization metric is
// documented, so the generic behaviour applies.
type Bull struct{ Generic }

func (Bull) Vendor() string { return "bull" }
func (Bull) Matches(m string) bool {
	return matchAny(m, "bull", "eviden", "atos")
}
