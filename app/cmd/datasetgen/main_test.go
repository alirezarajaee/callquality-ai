package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestScenariosAreStable(t *testing.T) {
	want := []string{"clean", "loss", "jitter", "latency", "reorder", "duplicate", "combined"}

	if len(scenarios) != len(want) {
		t.Fatalf("scenario count mismatch: got %d want %d", len(scenarios), len(want))
	}

	for i, scenario := range scenarios {
		if scenario.Name != want[i] {
			t.Fatalf("scenario %d mismatch: got %q want %q", i, scenario.Name, scenario)
		}

		if scenario.Description == "" {
			t.Fatalf("scenario %q has empty description", scenario.Name)
		}
	}
}

func TestRandomDurationIsBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	minimum := 3 * time.Millisecond
	maximum := 9 * time.Millisecond

	for i := 0; i < 100; i++ {
		value := randomDuration(rng, minimum, maximum)

		if value < minimum || value > maximum {
			t.Fatalf("duration outside bounds: got %v", value)
		}
	}
}

func TestCloneCaptureDoesNotAliasBytes(t *testing.T) {
	original := []rawPacket{
		{
			Timestamp: time.Unix(1, 0),
			Data:      []byte{1, 2, 3},
		},
	}

	clone := cloneCapture(original)
	clone[0].Data[0] = 9

	if original[0].Data[0] != 1 {
		t.Fatal("clone aliases original packet bytes")
	}
}

func TestV4SeverityBandsAreValid(t *testing.T) {
	if len(v4SeverityBands) != 5 {
		t.Fatalf("severity band count mismatch: got %d want 5", len(v4SeverityBands))
	}

	for i, band := range v4SeverityBands {
		if band.Name == "" {
			t.Fatalf("severity band %d has empty name", i)
		}

		if band.MinLoss < 0 || band.MaxLoss < band.MinLoss {
			t.Fatalf("invalid loss range for %q", band.Name)
		}

		if band.MinJitter < 0 || band.MaxJitter < band.MinJitter {
			t.Fatalf("invalid jitter range for %q", band.Name)
		}

		if band.MinLatency < 0 || band.MaxLatency < band.MinLatency {
			t.Fatalf("invalid latency range for %q", band.Name)
		}

		if band.MinReorder < 0 || band.MaxReorder < band.MinReorder {
			t.Fatalf("invalid reorder range for %q", band.Name)
		}

		if band.MinDuplicate < 0 || band.MaxDuplicate < band.MinDuplicate {
			t.Fatalf("invalid duplicate range for %q", band.Name)
		}

		if i > 0 {
			previous := v4SeverityBands[i-1]

			if band.MinLoss < previous.MinLoss ||
				band.MinJitter < previous.MinJitter ||
				band.MinLatency < previous.MinLatency {
				t.Fatalf("severity bands are not monotonic at %q", band.Name)
			}
		}
	}
}

func TestV4RecipeStringIsStable(t *testing.T) {
	recipe := v4Recipe{
		Primary:   "loss",
		Secondary: "jitter",
		Loss:      7,
		Jitter:    15 * time.Millisecond,
		Latency:   80 * time.Millisecond,
		Reorder:   2,
		Duplicate: 1,
	}

	got := recipe.String()

	want := "primary=loss;secondary=jitter;loss=7;jitter_ms=15;latency_ms=80;reorder=2;duplicate=1"

	if got != want {
		t.Fatalf("recipe string mismatch: got %q want %q", got, want)
	}
}

func TestApplyV4ScenarioIsDeterministic(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	base := []rawPacket{
		{Timestamp: start, Data: []byte{1}},
		{Timestamp: start.Add(time.Millisecond), Data: []byte{2}},
	}

	rngA := rand.New(rand.NewSource(1234))
	rngB := rand.New(rand.NewSource(1234))

	captureA, bandA, recipeA := applyV4Scenario(
		"loss",
		base,
		1,
		rngA,
	)

	captureB, bandB, recipeB := applyV4Scenario(
		"loss",
		base,
		1,
		rngB,
	)

	if bandA.Name != bandB.Name {
		t.Fatalf("band mismatch: %q vs %q", bandA.Name, bandB.Name)
	}

	if recipeA.String() != recipeB.String() {
		t.Fatalf("recipe mismatch: %q vs %q", recipeA.String(), recipeB.String())
	}

	if len(captureA) != len(captureB) {
		t.Fatalf("capture length mismatch: %d vs %d", len(captureA), len(captureB))
	}
}

func TestGenerateScenarioCaptureLegacyProfile(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	base := []rawPacket{
		{
			Timestamp: start,
			Data:      []byte{1, 2, 3},
		},
	}

	rng := rand.New(rand.NewSource(1))

	capture, band, recipe := generateScenarioCapture(
		"clean",
		base,
		0,
		rng,
		"legacy",
	)

	if band != "legacy" || recipe != "legacy" {
		t.Fatalf("legacy metadata mismatch: band=%q recipe=%q", band, recipe)
	}

	if len(capture) != len(base) {
		t.Fatalf("legacy capture length mismatch: got %d want %d", len(capture), len(base))
	}

	if !strings.Contains(defaultInput, "../samples/") {
		t.Fatalf("unexpected default input path: %q", defaultInput)
	}
}

func TestChooseSecondaryNeverReturnsPrimary(t *testing.T) {
	primaries := []string{
		"loss",
		"jitter",
		"latency",
		"reorder",
		"duplicate",
	}

	for _, primary := range primaries {
		rng := rand.New(rand.NewSource(42))

		for i := 0; i < 100; i++ {
			secondary := chooseSecondaryImpairment(primary, rng)

			if secondary == primary {
				t.Fatalf("secondary impairment matches primary %q", primary)
			}
		}
	}
}
