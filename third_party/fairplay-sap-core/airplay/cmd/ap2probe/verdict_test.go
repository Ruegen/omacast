// SPDX-License-Identifier: BlueOak-1.0.0

package main

import (
	"strings"
	"testing"
)

// TestVerdictIsExhaustive walks all 27 combinations of the three trials.
//
// This function decides whether the project may claim hardware validation, so
// "proven" must be true for exactly one shape and no other. Enumerating rather
// than spot-checking is deliberate: the bug this replaced was a case nobody
// thought to spot-check.
func TestVerdictIsExhaustive(t *testing.T) {
	all := []outcome{outcomeAccepted, outcomeRejected, outcomeErrored}
	provenCount := 0

	for _, correct := range all {
		for _, flipped := range all {
			for _, zeroed := range all {
				text, proven := verdict(correct, flipped, zeroed)
				if text == "" {
					t.Fatalf("empty verdict for %v/%v/%v", correct, flipped, zeroed)
				}

				wantProven := correct == outcomeAccepted &&
					flipped == outcomeRejected &&
					zeroed == outcomeRejected
				if proven != wantProven {
					t.Errorf("verdict(correct=%v, flipped=%v, zeroed=%v) proven=%v, want %v\n  text: %s",
						correct, flipped, zeroed, proven, wantProven, text)
				}
				if proven {
					provenCount++
				}
			}
		}
	}
	if provenCount != 1 {
		t.Fatalf("exactly one of 27 combinations should be provable, got %d", provenCount)
	}
}

// TestErroredTrialNeverProves is the regression test for the bug this file was
// written to fix.
//
// The previous implementation stored each trial as a bool and set it to false
// on error. Since the verdict read "not accepted" as "the receiver rejected
// it", a transport error on the corrupted trials — a timeout, a reset, a
// rate-limit — combined with a successful correct trial printed PROVEN. A flaky
// network could manufacture a hardware-validation claim.
func TestErroredTrialNeverProves(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		correct, flipped, zeroed outcome
	}{
		{"flipped errored", outcomeAccepted, outcomeErrored, outcomeRejected},
		{"zeroed errored", outcomeAccepted, outcomeRejected, outcomeErrored},
		{"both corrupted errored", outcomeAccepted, outcomeErrored, outcomeErrored},
		{"correct errored", outcomeErrored, outcomeRejected, outcomeRejected},
	} {
		text, proven := verdict(tc.correct, tc.flipped, tc.zeroed)
		if proven {
			t.Errorf("%s: reported PROVEN despite an incomplete trial", tc.name)
		}
		if !strings.Contains(text, "INCOMPLETE") {
			t.Errorf("%s: should say the run was incomplete, got: %s", tc.name, text)
		}
	}
}

// TestAcceptingAWrongAnswerIsInconclusive covers the Shairport Sync case: a
// receiver that returns 200 to everything. Its acceptance of the correct
// response carries no information, and the verdict must say so rather than
// treating "correct was accepted" as a pass.
func TestAcceptingAWrongAnswerIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name            string
		flipped, zeroed outcome
	}{
		{"flipped also accepted", outcomeAccepted, outcomeRejected},
		{"zeroed also accepted", outcomeRejected, outcomeAccepted},
		{"everything accepted", outcomeAccepted, outcomeAccepted},
	} {
		text, proven := verdict(outcomeAccepted, tc.flipped, tc.zeroed)
		if proven {
			t.Errorf("%s: reported PROVEN by a receiver that accepts wrong answers", tc.name)
		}
		if !strings.Contains(text, "INCONCLUSIVE") {
			t.Errorf("%s: want INCONCLUSIVE, got: %s", tc.name, text)
		}
	}
}

// TestCorrectRejectedIsFailure covers a receiver that refuses the right answer.
func TestCorrectRejectedIsFailure(t *testing.T) {
	text, proven := verdict(outcomeRejected, outcomeRejected, outcomeRejected)
	if proven {
		t.Fatal("reported PROVEN when the correct response was refused")
	}
	if !strings.Contains(text, "FAILED") {
		t.Fatalf("want FAILED, got: %s", text)
	}
}

// TestTheProvenCase pins the one shape that may claim validation — the shape
// three HomePods actually produced.
func TestTheProvenCase(t *testing.T) {
	text, proven := verdict(outcomeAccepted, outcomeRejected, outcomeRejected)
	if !proven {
		t.Fatalf("the real HomePod result should be provable, got: %s", text)
	}
	if !strings.Contains(text, "PROVEN") {
		t.Fatalf("want PROVEN in the text, got: %s", text)
	}
}

// TestErroredOutcomeReadsAsNoVerdict checks the printed table does not call an
// errored trial "rejected", which would mislead a human reading the output even
// when the machine verdict is correct.
func TestErroredOutcomeReadsAsNoVerdict(t *testing.T) {
	if s := outcomeErrored.String(); !strings.Contains(s, "ERRORED") {
		t.Errorf("errored trial prints as %q; it must not look like a rejection", s)
	}
	if outcomeRejected.String() == outcomeErrored.String() {
		t.Error("rejected and errored print identically")
	}
}
