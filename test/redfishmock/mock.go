// Package redfishmock is an in-process fake BMC used by tests and by
// `make demo`. One server per vendor profile; each profile mirrors the JSON
// shapes the corresponding adapter expects.
package redfishmock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"
)

// Profile selects the vendor behaviour of the fake.
type Profile string

const (
	ProfileDell       Profile = "dell"
	ProfileHPE        Profile = "hpe"
	ProfileLenovo     Profile = "lenovo"
	ProfileSupermicro Profile = "supermicro"
	ProfileGeneric    Profile = "generic"
)

// Server is the fake BMC.
type Server struct {
	*httptest.Server
	Profile  Profile
	User     string
	Password string
	Hits     atomic.Int64
	Fail     atomic.Bool // when set, every request returns 500
	BadTemp  bool        // emit an out-of-range temperature
}

// New starts a TLS fake BMC. Callers must set InsecureSkipVerify.
func New(p Profile, user, pass string) *Server {
	s := &Server{Profile: p, User: user, Password: pass}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.Hits.Add(1)
	if s.Fail.Load() {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	u, p, ok := r.BasicAuth()
	if !ok || u != s.User || p != s.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	var body any
	switch {
	case path == "/redfish/v1/Systems":
		body = map[string]any{"Members": []any{map[string]any{"@odata.id": "/redfish/v1/Systems/1"}}}
	case path == "/redfish/v1/Systems/1":
		body = s.system()
	case path == "/redfish/v1/Chassis/1/Thermal":
		temp := 41.0
		if s.BadTemp {
			temp = 999
		}
		body = map[string]any{"Temperatures": []any{
			map[string]any{"Name": "CPU1 Temp", "ReadingCelsius": temp, "Status": map[string]any{"State": "Enabled"}},
			map[string]any{"Name": "Inlet Temp", "ReadingCelsius": 22.0, "Status": map[string]any{"State": "Enabled"}},
			map[string]any{"Name": "Absent", "ReadingCelsius": 0, "Status": map[string]any{"State": "Absent"}},
		}}
	case path == "/redfish/v1/Chassis/1/Power":
		body = map[string]any{"PowerControl": []any{map[string]any{"Name": "System Power Control", "PowerConsumedWatts": 312.0}}}
	case path == "/redfish/v1/TelemetryService/MetricReports/SystemUsage" && s.Profile == ProfileDell:
		now := time.Now().UTC().Format(time.RFC3339)
		body = map[string]any{"MetricValues": []any{
			map[string]any{"MetricId": "CPUUsage", "MetricValue": "17.5", "Timestamp": now},
			map[string]any{"MetricId": "MemoryUsage", "MetricValue": "63", "Timestamp": now},
			map[string]any{"MetricId": "IOUsage", "MetricValue": "2", "Timestamp": now},
		}}
	case path == "/redfish/v1/Systems/1/Oem/Lenovo/Metrics" && s.Profile == ProfileLenovo:
		body = map[string]any{"CPUUsage": 23.0, "MemoryUsage": 51.0}
	case path == "/redfish/v1/Chassis/1/Sensors" && s.Profile == ProfileGeneric:
		if r.URL.Query().Get("$expand") != "" {
			body = map[string]any{"Members": []any{
				map[string]any{"Name": "CPU Utilization", "ReadingType": "Percent", "Reading": 9.0},
				map[string]any{"Name": "Memory Utilization", "ReadingType": "Percent", "Reading": 40.0},
			}}
		} else {
			body = map[string]any{"Members": []any{}}
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not found: " + path})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) system() map[string]any {
	sys := map[string]any{
		"@odata.id": "/redfish/v1/Systems/1", "Model": "FakeServer 9000",
		"ProcessorSummary": map[string]any{"Model": "Fake CPU 64c"},
		"Links":            map[string]any{"Chassis": []any{map[string]any{"@odata.id": "/redfish/v1/Chassis/1"}}},
	}
	switch s.Profile {
	case ProfileDell:
		sys["Manufacturer"] = "Dell Inc."
	case ProfileHPE:
		sys["Manufacturer"] = "HPE"
		sys["Oem"] = map[string]any{"Hpe": map[string]any{"SystemUsage": map[string]any{"CPUUtil": 12.0, "MemoryBusUtil": 7.0}}}
	case ProfileLenovo:
		sys["Manufacturer"] = "Lenovo"
	case ProfileSupermicro:
		sys["Manufacturer"] = "Supermicro"
	default:
		sys["Manufacturer"] = "Bull SAS"
	}
	return sys
}
