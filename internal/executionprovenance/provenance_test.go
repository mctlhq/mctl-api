package executionprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorsDigest pins the exact bytes of the canonical vector file. mctl-agents
// vendors the file and pins the same value. Changing the file is a
// contract_version change.
const vectorsDigest = "9ab9cf04a5542004f5e851a0f32b87681249d3e6f7027386945ebe76a46ad24c"

type vectorFile struct {
	ContractVersion string `json:"contract_version"`
	Vectors         []struct {
		Name             string `json:"name"`
		Engine           string `json:"engine"`
		EngineRef        string `json:"engine_ref"`
		RootExecutionID  string `json:"root_execution_id"`
		AttemptCanonical string `json:"attempt_canonical"`
		AttemptID        string `json:"attempt_id"`
		LineageCanonical string `json:"lineage_canonical"`
		LineageRoot      string `json:"lineage_root"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) (vectorFile, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/execution_attempt_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f, raw
}

func TestVectorsReproduceByteForByte(t *testing.T) {
	f, _ := loadVectors(t)
	if f.ContractVersion != ContractVersion {
		t.Fatalf("contract version %q", f.ContractVersion)
	}
	if len(f.Vectors) < 8 {
		t.Fatalf("need at least 8 vectors, have %d", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ac := string(CanonicalStrings([]string{ContractVersion, "attempt", v.Engine, EngineRun(v.EngineRef)}))
			if ac != v.AttemptCanonical {
				t.Errorf("attempt canonical %s != %s", ac, v.AttemptCanonical)
			}
			if got := AttemptID(v.Engine, v.EngineRef); got != v.AttemptID {
				t.Errorf("attempt id %s != %s", got, v.AttemptID)
			}
			lc := string(CanonicalStrings([]string{ContractVersion, "lineage", v.RootExecutionID}))
			if lc != v.LineageCanonical {
				t.Errorf("lineage canonical %s != %s", lc, v.LineageCanonical)
			}
			if got := LineageRoot(v.RootExecutionID); got != v.LineageRoot {
				t.Errorf("lineage root %s != %s", got, v.LineageRoot)
			}
			if !AttemptIDRE.MatchString(v.AttemptID) || !LineageRootRE.MatchString(v.LineageRoot) {
				t.Error("id shape")
			}
		})
	}
}

func TestVectorFileDigestPinned(t *testing.T) {
	_, raw := loadVectors(t)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != vectorsDigest {
		t.Fatalf("vector file digest %s != pinned %s", got, vectorsDigest)
	}
}

func TestEngineRunTruncatesAtFirstHash(t *testing.T) {
	if EngineRun("wf#a#b") != "wf" || EngineRun("wf#") != "wf" || EngineRun("wf") != "wf" {
		t.Fatal("EngineRun must cut at the first #")
	}
	if AttemptID("argo", "wf#x") != AttemptID("argo", "wf#y") {
		t.Fatal("request suffix must not change the attempt")
	}
	if AttemptID("argo", "wf") == AttemptID("temporal", "wf") {
		t.Fatal("engine must change the attempt")
	}
}
