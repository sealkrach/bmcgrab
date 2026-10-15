package quality

import (
	"testing"
	"time"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/model"
)

func TestApply(t *testing.T) {
	v := FromConfig(config.Default())
	now := time.Now().UTC()
	r := &model.Result{
		Samples: []model.Sample{
			{Family: model.FamilyThermal, Name: "temperature_c", Unit: "celsius", Value: 42, Time: now},
			{Family: model.FamilyThermal, Name: "temperature_c", Unit: "celsius", Value: 999, Time: now},
			{Family: model.FamilyPower, Name: "power_w", Unit: "watt", Value: -5, Time: now},
			{Family: model.FamilyCPU, Name: "cpu_usage_percent", Unit: "percent", Value: 50, Time: now.Add(time.Hour)},
			{Family: model.FamilyMemory, Name: "memory_usage_percent", Unit: "percent", Value: 10, Time: now},
		},
		Families: []model.FamilyResult{
			{Family: model.FamilyThermal, State: model.StateCollected},
			{Family: model.FamilyPower, State: model.StateCollected},
			{Family: model.FamilyCPU, State: model.StateCollected},
			{Family: model.FamilyMemory, State: model.StateCollected},
		},
	}
	rej := v.Apply(r, now)
	if len(rej) != 3 {
		t.Fatalf("rejected = %d, want 3: %+v", len(rej), rej)
	}
	if len(r.Samples) != 2 {
		t.Fatalf("kept = %d, want 2", len(r.Samples))
	}
	want := map[model.Family]model.State{
		model.FamilyThermal: model.StateCollected, // 1 of 2 kept
		model.FamilyPower:   model.StateRejected,
		model.FamilyCPU:     model.StateRejected, // future timestamp
		model.FamilyMemory:  model.StateCollected,
	}
	for _, f := range r.Families {
		if f.State != want[f.Family] {
			t.Errorf("%s state = %s, want %s (%s)", f.Family, f.State, want[f.Family], f.Reason)
		}
	}
	if r.Status() != "partial" {
		t.Errorf("status = %s, want partial", r.Status())
	}
}
