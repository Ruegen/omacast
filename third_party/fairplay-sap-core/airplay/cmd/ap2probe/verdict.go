// SPDX-License-Identifier: BlueOak-1.0.0

package main

import "fmt"

// outcome is what one control trial actually did.
//
// The three-way split is the point. An earlier version stored a bool, so a
// trial that *errored* was indistinguishable from one the receiver *rejected* —
// and since the verdict reads "not accepted" as "rejected", a timeout on the
// corrupted trials while the correct one succeeded printed PROVEN. That is a
// false claim of hardware validation produced by a flaky network, which is the
// worst failure this tool could have.
type outcome int

const (
	outcomeRejected outcome = iota // the receiver answered, and said no
	outcomeAccepted                // the receiver answered, and said yes
	outcomeErrored                 // the trial never completed; we know nothing
)

func (o outcome) String() string {
	switch o {
	case outcomeAccepted:
		return "ACCEPTED"
	case outcomeRejected:
		return "rejected"
	default:
		return "ERRORED (no verdict)"
	}
}

// verdict interprets a completed control run.
//
// proven is true only when every trial ran to completion, the correct response
// was accepted, and every deliberately wrong one was refused. Anything less is
// reported as what it is rather than rounded toward success.
func verdict(correct, flipped, zeroed outcome) (text string, proven bool) {
	// Any incomplete trial makes the whole run uninterpretable. Checked first,
	// because an errored corrupted-trial otherwise looks exactly like the
	// rejection we were hoping for.
	for _, o := range []outcome{correct, flipped, zeroed} {
		if o == outcomeErrored {
			return "INCOMPLETE: at least one trial did not finish, so this run proves nothing.\n" +
				"A trial that errored is not a trial the receiver rejected — rerun it.", false
		}
	}

	switch {
	case correct != outcomeAccepted:
		return "FAILED: the correct response was not accepted. Investigate before claiming anything.", false
	case flipped == outcomeAccepted || zeroed == outcomeAccepted:
		return "INCONCLUSIVE: the receiver accepted a knowingly WRONG response too.\n" +
			"It is not validating, so its acceptance of the correct one proves nothing.", false
	default:
		return "PROVEN: the receiver accepts the correct response and rejects wrong ones.\n" +
			"This is genuine hardware validation of the FairPlay SAP implementation.", true
	}
}

// errNotProven is returned so a script or CI job sees a non-zero exit. A
// validation tool that exits 0 on FAILED is worse than no tool.
var errNotProven = fmt.Errorf("control run did not prove validation")
