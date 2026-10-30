package deployplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderYAML renders values as canonical YAML: sorted keys (yaml.v3 sorts
// map keys) and a fixed two-space indent.
func RenderYAML(values map[string]any) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(values); err != nil {
		return "", fmt.Errorf("rendering values: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("rendering values: %w", err)
	}
	return buf.String(), nil
}

// SHA256Hex is the hex SHA-256 of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const (
	diffContext = 3
	// maxDiffCells bounds the LCS table; beyond it the diff degrades to a
	// full replacement rather than spending unbounded memory.
	maxDiffCells = 16 << 20
)

type diffOp struct {
	kind byte // ' ', '-', '+'
	text string
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func diffOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	var ops []diffOp
	if n*m > maxDiffCells {
		for _, l := range a {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range b {
			ops = append(ops, diffOp{'+', l})
		}
		return ops
	}
	// lcs[i][j] is the LCS length of a[i:] and b[j:].
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}

// UnifiedDiff returns a deterministic unified diff of before against after,
// or "" when they are equal.
func UnifiedDiff(before, after string) string {
	if before == after {
		return ""
	}
	ops := diffOps(splitLines(before), splitLines(after))

	// Mark the ops inside a context window of any change.
	keep := make([]bool, len(ops))
	for idx, op := range ops {
		if op.kind == ' ' {
			continue
		}
		for k := max(0, idx-diffContext); k <= min(len(ops)-1, idx+diffContext); k++ {
			keep[k] = true
		}
	}

	var out strings.Builder
	out.WriteString("--- before\n+++ after\n")
	aLine, bLine := 1, 1
	for idx := 0; idx < len(ops); {
		if !keep[idx] {
			if ops[idx].kind != '+' {
				aLine++
			}
			if ops[idx].kind != '-' {
				bLine++
			}
			idx++
			continue
		}
		end := idx
		aCount, bCount := 0, 0
		for end < len(ops) && keep[end] {
			if ops[end].kind != '+' {
				aCount++
			}
			if ops[end].kind != '-' {
				bCount++
			}
			end++
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aLine, aCount, bLine, bCount)
		for _, op := range ops[idx:end] {
			out.WriteByte(op.kind)
			out.WriteString(op.text)
			out.WriteByte('\n')
		}
		aLine += aCount
		bLine += bCount
		idx = end
	}
	return out.String()
}
