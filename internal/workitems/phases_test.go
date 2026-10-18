package workitems

import (
	"regexp"
	"testing"
)

// The SQL "open" list and IsTerminalPhase are two spellings of one rule:
// every valid phase is either in openPhasesSQL or terminal, never both.
func TestOpenPhasesSQLMatchesIsTerminalPhase(t *testing.T) {
	open := map[string]bool{}
	for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(openPhasesSQL, -1) {
		open[m[1]] = true
	}
	for _, p := range allPhases {
		if open[p] == IsTerminalPhase(p) {
			t.Errorf("phase %q: in openPhasesSQL=%v, IsTerminalPhase=%v", p, open[p], IsTerminalPhase(p))
		}
		delete(open, p)
	}
	for p := range open {
		t.Errorf("openPhasesSQL lists %q, which is not a valid phase", p)
	}
}
