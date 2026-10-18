// Package model holds the types shared across bmcgrab: inventory entries,
// normalized metric samples and per-server collection results.
package model

import "time"

// Server is one entry of the external inventory.
type Server struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	BMCAddr  string `json:"bmc_ip"` // IP or DNS name of the BMC
	Region   string `json:"region"`
	Vendor   string `json:"vendor,omitempty"` // optional hint; detected otherwise
	// SecretRef points at this BMC's own CyberArk account ("safe/object" or
	// "object"). Empty means the shared default account. It is a pointer to a
	// secret, never the secret itself.
	SecretRef string `json:"secret_ref,omitempty"`
}

// Family groups metrics by what the operator enables in central config.
type Family string

const (
	FamilyCPU     Family = "cpu"
	FamilyMemory  Family = "memory"
	FamilyThermal Family = "thermal"
	FamilyPower   Family = "power"
)

// State of a metric family for one server during one cycle.
type State string

const (
	StateCollected   State = "collected"
	StateUnsupported State = "unsupported" // BMC/firmware does not expose it
	StateRejected    State = "rejected"    // value failed quality validation
	StateError       State = "error"       // transport or parse failure
)

// Sample is one normalized data point. Vendor adapters map OEM shapes onto it.
type Sample struct {
	Family Family  `json:"family"`
	Name   string  `json:"name"`   // cpu_usage_percent, memory_usage_percent, temperature_c, power_w
	Sensor string  `json:"sensor"` // e.g. "CPU1 Temp", "Inlet", "PSU1", "" for system-wide
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"` // percent, celsius, watt
	// Time reported by the BMC when available, else collection time.
	Time time.Time `json:"time"`
}

// FamilyResult records what happened for one family on one server.
type FamilyResult struct {
	Family  Family `json:"family"`
	State   State  `json:"state"`
	Reason  string `json:"reason,omitempty"` // human-readable, shown in the UI
	Samples int    `json:"samples"`
}

// Result is everything a worker returns for one server in one cycle.
type Result struct {
	Server    Server         `json:"server"`
	Vendor    string         `json:"vendor"`
	Model     string         `json:"model,omitempty"`
	CPUModel  string         `json:"cpu_model,omitempty"`
	CycleID   string         `json:"cycle_id"`
	Collected time.Time      `json:"collected_at"`
	Duration  time.Duration  `json:"duration"`
	Samples   []Sample       `json:"samples"`
	Families  []FamilyResult `json:"families"`
	Err       string         `json:"error,omitempty"` // whole-server failure (auth, timeout, breaker open)
}

// Status summarizes a Result for the heartbeat and UI: ok, partial, failed.
func (r *Result) Status() string {
	if r.Err != "" {
		return "failed"
	}
	ok, bad := 0, 0
	for _, f := range r.Families {
		switch f.State {
		case StateCollected:
			ok++
		case StateError, StateRejected:
			bad++
		}
	}
	switch {
	case ok == 0 && bad > 0:
		return "failed"
	case bad > 0:
		return "partial"
	default:
		return "ok"
	}
}
