package vendors_test

import (
	"context"
	"testing"
	"time"

	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
	"github.com/sealkrach/bmcgrab/internal/redfish/vendors"
	"github.com/sealkrach/bmcgrab/test/redfishmock"
)

var allFamilies = []model.Family{model.FamilyCPU, model.FamilyMemory, model.FamilyThermal, model.FamilyPower}

func collect(t *testing.T, p redfishmock.Profile) (*model.Result, *redfishmock.Server) {
	t.Helper()
	bmc := redfishmock.New(p, "svc", "secret")
	t.Cleanup(bmc.Close)
	client, err := redfish.NewClient(redfish.ClientOptions{InsecureSkipVerify: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := client.Open(ctx, redfish.Target{BaseURL: bmc.URL, Username: "svc", Password: "secret"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	a := vendors.All().Resolve(s.Manufacturer())
	r := redfish.Collect(ctx, s, a, allFamilies)
	r.Vendor = a.Vendor()
	return r, bmc
}

func state(r *model.Result, f model.Family) model.State {
	for _, fr := range r.Families {
		if fr.Family == f {
			return fr.State
		}
	}
	return ""
}

func value(r *model.Result, name string) (float64, bool) {
	for _, s := range r.Samples {
		if s.Name == name {
			return s.Value, true
		}
	}
	return 0, false
}

func TestVendorMatrix(t *testing.T) {
	cases := []struct {
		profile  redfishmock.Profile
		vendor   string
		cpu, mem model.State
		cpuVal   float64
	}{
		{redfishmock.ProfileDell, "dell", model.StateCollected, model.StateCollected, 17.5},
		{redfishmock.ProfileHPE, "hpe", model.StateCollected, model.StateCollected, 12},
		{redfishmock.ProfileLenovo, "lenovo", model.StateCollected, model.StateCollected, 23},
		{redfishmock.ProfileSupermicro, "supermicro", model.StateUnsupported, model.StateUnsupported, 0},
		{redfishmock.ProfileGeneric, "bull", model.StateCollected, model.StateCollected, 9},
	}
	for _, c := range cases {
		t.Run(string(c.profile), func(t *testing.T) {
			r, _ := collect(t, c.profile)
			if r.Vendor != c.vendor {
				t.Errorf("vendor = %q, want %q", r.Vendor, c.vendor)
			}
			if got := state(r, model.FamilyCPU); got != c.cpu {
				t.Errorf("cpu state = %s, want %s (%+v)", got, c.cpu, r.Families)
			}
			if got := state(r, model.FamilyMemory); got != c.mem {
				t.Errorf("memory state = %s, want %s", got, c.mem)
			}
			if c.cpu == model.StateCollected {
				if v, ok := value(r, "cpu_usage_percent"); !ok || v != c.cpuVal {
					t.Errorf("cpu value = %v (%v), want %v", v, ok, c.cpuVal)
				}
			}
			// Thermal and power are standard on every profile.
			if state(r, model.FamilyThermal) != model.StateCollected || state(r, model.FamilyPower) != model.StateCollected {
				t.Errorf("thermal/power not collected: %+v", r.Families)
			}
			if v, _ := value(r, "power_w"); v != 312 {
				t.Errorf("power = %v, want 312", v)
			}
			// The Absent sensor must be skipped: 2 temperatures, not 3.
			n := 0
			for _, s := range r.Samples {
				if s.Name == "temperature_c" {
					n++
				}
			}
			if n != 2 {
				t.Errorf("temperature samples = %d, want 2", n)
			}
			if r.Model != "FakeServer 9000" || r.CPUModel != "Fake CPU 64c" {
				t.Errorf("model/cpu = %q/%q", r.Model, r.CPUModel)
			}
		})
	}
}

func TestUnauthorized(t *testing.T) {
	bmc := redfishmock.New(redfishmock.ProfileDell, "svc", "secret")
	defer bmc.Close()
	client, _ := redfish.NewClient(redfish.ClientOptions{InsecureSkipVerify: true, Timeout: 5 * time.Second})
	_, err := client.Open(context.Background(), redfish.Target{BaseURL: bmc.URL, Username: "svc", Password: "wrong"})
	if err == nil || err != redfish.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}
