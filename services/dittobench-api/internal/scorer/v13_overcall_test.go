package scorer

import (
	"testing"

	"github.com/ditto-assistant/dittobench-datagen/gen"
	"github.com/ditto-assistant/dittobench-datagen/protocol"
)

func memCase(category string, called ...string) protocol.CaseScore {
	return protocol.CaseScore{Kind: protocol.KindMemory, Category: category, Observed: true, Called: called}
}

// TestDeclarativeAckIsAMemoryWriteFromV13 is the (b) repair. Keeping a value the
// user just stated is the declarative-acknowledgement case's own work, so the
// save call that does it must not be charged as a memory over-call.
func TestDeclarativeAckIsAMemoryWriteFromV13(t *testing.T) {
	for _, tool := range []string{"save_memory", "update_memory", "delete_memory"} {
		t.Run(tool, func(t *testing.T) {
			in := []protocol.CaseScore{
				memCase(gen.QTDeclarativeAck, tool),
				memCase("single-session-recall", tool),
			}
			// v13: the ack case stays in the rate but its write is exempt, so
			// only the recall half over-calls: 1/2.
			if got, want := memoryOverCallFactorWith(in, v7MemoryOverCallMaxPenalty, protocol.BenchVersionV13), round6(1.0-v7MemoryOverCallMaxPenalty/2); got != want {
				t.Fatalf("v13 declarative ack write must be exempt: got %.6f, want %.6f", got, want)
			}
			// v12 and earlier are unchanged: both halves over-call, which is the
			// defect being preserved for already-scored contracts.
			if got := memoryOverCallFactorWith(in, v7MemoryOverCallMaxPenalty, protocol.BenchVersionV12); got != 1.0-v7MemoryOverCallMaxPenalty {
				t.Fatalf("v12 rate changed: got %.6f", got)
			}
		})
	}
}

// TestDeclarativeAckStillChargesUnrelatedActionsAtV13 pins the boundary of the
// repair: only the memory writes are authorized on a declarative case, so a
// settings change or an email there is still an over-call at v13, alone or
// alongside a legitimate save.
func TestDeclarativeAckStillChargesUnrelatedActionsAtV13(t *testing.T) {
	for _, tool := range []string{"set_theme", "set_accent_color", "gmail_send"} {
		for _, called := range [][]string{{tool}, {"save_memory", tool}} {
			in := []protocol.CaseScore{memCase(gen.QTDeclarativeAck, called...)}
			for _, version := range []int{protocol.BenchVersionV12, protocol.BenchVersionV13} {
				if got := memoryOverCallFactorWith(in, v7MemoryOverCallMaxPenalty, version); got != 1.0-v7MemoryOverCallMaxPenalty {
					t.Errorf("v%d %v: got %.6f, want the full over-call penalty", version, called, got)
				}
			}
		}
	}
}

// TestDeclarativeAckExemptionChangesTheGateOnlyAtV13 shows the exemption moving
// a real score, and shows v8..v12 explicitly not moving.
func TestDeclarativeAckExemptionChangesTheGateOnlyAtV13(t *testing.T) {
	// A harness that saves every stated value and does nothing else wrong.
	in := []protocol.CaseScore{
		memCase(gen.QTDeclarativeAck, "save_memory"),
		memCase(gen.QTDeclarativeAck, "save_memory"),
		memCase("single-session-recall", "search_memories"),
	}
	v12 := memoryOverCallFactorWith(in, v7MemoryOverCallMaxPenalty, protocol.BenchVersionV12)
	v13 := memoryOverCallFactorWith(in, v7MemoryOverCallMaxPenalty, protocol.BenchVersionV13)
	if v13 != 1.0 {
		t.Fatalf("v13 must charge a correct harness nothing here, got %.6f", v13)
	}
	want := round6(1.0 - v7MemoryOverCallMaxPenalty*2.0/3.0)
	if v12 != want {
		t.Fatalf("v12 must keep its historical penalty %.6f, got %.6f", want, v12)
	}
}

// TestMemoryWriteCategoryScope pins which calls are exempt on which category at
// which contract, so widening the repair to v8..v12 cannot happen by accident:
// that is a rescore, and a separate decision.
func TestMemoryWriteCategoryScope(t *testing.T) {
	for category, want := range map[string]bool{
		gen.QTLifecycleWrite:    true,
		gen.QTDeclarativeAck:    false,
		gen.QTLifecycleRead:     false,
		"single-session-recall": false,
	} {
		if got := memoryWriteCategory(category); got != want {
			t.Errorf("memoryWriteCategory(%q) = %v, want %v", category, got, want)
		}
	}
	cases := []struct {
		category string
		call     string
		version  int
		want     bool
	}{
		{gen.QTDeclarativeAck, "save_memory", protocol.BenchVersionV3, false},
		{gen.QTDeclarativeAck, "save_memory", protocol.BenchVersionV8, false},
		{gen.QTDeclarativeAck, "save_memory", protocol.BenchVersionV12, false},
		{gen.QTDeclarativeAck, "update_memory", protocol.BenchVersionV12, false},
		{gen.QTDeclarativeAck, "save_memory", protocol.BenchVersionV13, true},
		{gen.QTDeclarativeAck, "update_memory", protocol.BenchVersionV13, true},
		{gen.QTDeclarativeAck, "delete_memory", protocol.BenchVersionV13, true},
		{gen.QTDeclarativeAck, "set_theme", protocol.BenchVersionV13, false},
		{gen.QTDeclarativeAck, "gmail_send", protocol.BenchVersionV13, false},
		{gen.QTLifecycleRead, "save_memory", protocol.BenchVersionV13, false},
		{gen.QTChitchat, "save_memory", protocol.BenchVersionV13, false},
		{"single-session-recall", "save_memory", protocol.BenchVersionV13, false},
	}
	for _, tc := range cases {
		if got := declarativeMemoryWrite(tc.category, tc.call, tc.version); got != tc.want {
			t.Errorf("declarativeMemoryWrite(%q, %q, v%d) = %v, want %v", tc.category, tc.call, tc.version, got, tc.want)
		}
	}
}

// TestCompositeGateV13ExemptionIsWiredThrough proves the version actually
// reaches the factor from the public entry point.
func TestCompositeGateV13ExemptionIsWiredThrough(t *testing.T) {
	in := []protocol.CaseScore{
		memCase(gen.QTDeclarativeAck, "save_memory"),
		memCase("single-session-recall", "search_memories"),
	}
	v12 := CompositeGateForVersion(in, protocol.BenchVersionV12)
	v13 := CompositeGateForVersion(in, protocol.BenchVersionV13)
	if v12 >= v13 {
		t.Fatalf("v13 gate %.6f should exceed the v12 gate %.6f for a harness that only saved a stated value", v13, v12)
	}
	// Pre-v7 contracts do not reach compositeGateV7 at all.
	if got := CompositeGateForVersion(in, protocol.BenchVersionV6); got != CompositeGateForVersion(in, protocol.BenchVersionV6) {
		t.Fatal("pre-v7 gate is not stable")
	}
}

// TestCompositeGateDeclarativeAckBoundary drives the public v13 entry point:
// a declarative case that saved, updated or deleted scores exactly like the
// no-call and memory-read baselines, one that took an unrelated action does
// not, and v12 scores every one of those writes as it always has.
func TestCompositeGateDeclarativeAckBoundary(t *testing.T) {
	gate := func(version int, called ...string) float64 {
		return CompositeGateForVersion([]protocol.CaseScore{
			memCase(gen.QTDeclarativeAck, called...),
			memCase("single-session-recall", "search_memories"),
		}, version)
	}
	v12Baseline := gate(protocol.BenchVersionV12)
	v13Baseline := gate(protocol.BenchVersionV13)
	if v12Baseline != v13Baseline || gate(protocol.BenchVersionV13, "search_memories") != v13Baseline {
		t.Fatalf("no-call/read baselines diverged: v12 %.6f, v13 %.6f", v12Baseline, v13Baseline)
	}
	v12Penalized := gate(protocol.BenchVersionV12, "set_theme")
	if v12Penalized >= v12Baseline {
		t.Fatalf("fixture does not exercise the over-call penalty: %.6f vs %.6f", v12Penalized, v12Baseline)
	}
	for _, tool := range []string{"save_memory", "update_memory", "delete_memory"} {
		if got := gate(protocol.BenchVersionV13, tool); got != v13Baseline {
			t.Errorf("v13 %s gate %.6f, want the baseline %.6f", tool, got, v13Baseline)
		}
		if got := gate(protocol.BenchVersionV12, tool); got != v12Penalized {
			t.Errorf("v12 %s gate %.6f, want the historical penalized %.6f", tool, got, v12Penalized)
		}
	}
	for _, tool := range []string{"set_theme", "set_accent_color", "gmail_send"} {
		if got := gate(protocol.BenchVersionV13, tool); got != v12Penalized {
			t.Errorf("v13 %s gate %.6f, want the penalized %.6f", tool, got, v12Penalized)
		}
		if got := gate(protocol.BenchVersionV13, "save_memory", tool); got != v12Penalized {
			t.Errorf("v13 save_memory+%s gate %.6f, want the penalized %.6f", tool, got, v12Penalized)
		}
	}
}
