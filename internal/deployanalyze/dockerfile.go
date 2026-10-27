package deployanalyze

import (
	"strconv"
	"strings"
)

// Parser bounds. Input over them is a typed verdict, never a panic.
const (
	maxDockerfileInstructions = 4000
	maxLogicalLine            = 64 << 10
	maxStages                 = 64
)

// Port is one EXPOSEd TCP port; Unresolved marks a value that could not be
// determined statically (a variable without a default, or a range).
type Port struct {
	Value      int
	Unresolved bool
}

// Health is a stage's HEALTHCHECK.
type Health struct {
	None bool
	Cmd  string // raw text after CMD
}

// Stage is the interpreted subset of one build stage.
type Stage struct {
	Name      string
	Ports     []Port
	User      string
	UserSet   bool
	UserUnres bool
	Health    *Health
	Env       map[string]string
	args      map[string]string
}

// Dockerfile is the parsed result.
type Dockerfile struct {
	Stages []*Stage
}

// Final returns the last stage.
func (d *Dockerfile) Final() *Stage { return d.Stages[len(d.Stages)-1] }

// parseError carries the typed verdict for input the parser refuses.
type parseError struct{ reason Reason }

func (e *parseError) Error() string { return string(e.reason) }

type instruction struct {
	cmd  string
	rest string
}

// logicalInstructions joins continuations, drops comments and skips heredoc
// bodies.
func logicalInstructions(src []byte) ([]instruction, error) {
	if len(src) > MaxDockerfileBytes {
		return nil, &parseError{ReasonDockerfileTooLarge}
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")

	escape := byte('\\')
	// Parser directives: leading comment lines of the form "# key=value".
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "#") {
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(t, "#")), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "escape") {
			v = strings.TrimSpace(v)
			if len(v) == 1 && (v == "`" || v == "\\") {
				escape = v[0]
			}
		}
	}

	var out []instruction
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		var b strings.Builder
		cur := strings.TrimRight(lines[i], " \t")
		for {
			if len(cur) > 0 && cur[len(cur)-1] == escape {
				b.WriteString(cur[:len(cur)-1])
				b.WriteByte(' ')
				if b.Len() > maxLogicalLine {
					return nil, &parseError{ReasonDockerfileUnparseable}
				}
				i++
				// Skip comments and blank lines inside a continuation.
				for i < len(lines) {
					lt := strings.TrimSpace(lines[i])
					if lt == "" || strings.HasPrefix(lt, "#") {
						i++
						continue
					}
					break
				}
				if i >= len(lines) {
					break
				}
				cur = strings.TrimRight(lines[i], " \t")
				continue
			}
			b.WriteString(cur)
			break
		}
		line := strings.TrimSpace(b.String())
		if len(line) > maxLogicalLine {
			return nil, &parseError{ReasonDockerfileUnparseable}
		}
		if line == "" {
			continue
		}
		cmd, rest := line, ""
		if k := strings.IndexAny(line, " \t"); k >= 0 {
			cmd, rest = line[:k], strings.TrimSpace(line[k+1:])
		}
		cmd = strings.ToUpper(cmd)
		out = append(out, instruction{cmd: cmd, rest: rest})
		if len(out) > maxDockerfileInstructions {
			return nil, &parseError{ReasonDockerfileUnparseable}
		}
		// Heredoc bodies of RUN/COPY/ADD are skipped to their terminator.
		if cmd == "RUN" || cmd == "COPY" || cmd == "ADD" {
			for _, term := range heredocTerminators(rest) {
				found := false
				for i++; i < len(lines); i++ {
					if strings.TrimSpace(lines[i]) == term.name || (term.dash && strings.TrimLeft(lines[i], "\t") == term.name) {
						found = true
						break
					}
				}
				if !found {
					return nil, &parseError{ReasonDockerfileUnparseable}
				}
			}
		}
	}
	return out, nil
}

type heredoc struct {
	name string
	dash bool
}

func heredocTerminators(rest string) []heredoc {
	var out []heredoc
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] != '<' || rest[i+1] != '<' {
			continue
		}
		j := i + 2
		if j < len(rest) && rest[j] == '<' { // <<< here-string, not a heredoc
			i = j
			continue
		}
		dash := false
		if j < len(rest) && rest[j] == '-' {
			dash = true
			j++
		}
		if j < len(rest) && (rest[j] == '"' || rest[j] == '\'') {
			j++
		}
		k := j
		for k < len(rest) && (rest[k] == '_' || rest[k] >= '0' && rest[k] <= '9' || rest[k] >= 'A' && rest[k] <= 'Z' || rest[k] >= 'a' && rest[k] <= 'z') {
			k++
		}
		if k > j {
			out = append(out, heredoc{name: rest[j:k], dash: dash})
		}
		i = k
	}
	return out
}

// splitWords splits on whitespace, honouring quotes.
func splitWords(s string) []string {
	var out []string
	var b strings.Builder
	var q byte
	has := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else if c == '\\' && q == '"' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q, has = c, true
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
			has = true
		case c == ' ' || c == '\t':
			if has || b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
				has = false
			}
		default:
			b.WriteByte(c)
			has = true
		}
	}
	if has || b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// expand substitutes $X, ${X}, ${X:-d} and ${X-d}. ok is false when any
// variable could not be resolved.
func expand(s string, vars map[string]string) (string, bool) {
	var b strings.Builder
	ok := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", false
			}
			body := s[i+2 : i+end]
			i += end
			name, def, hasDef := body, "", false
			colon := false
			if k := strings.Index(body, ":-"); k >= 0 {
				name, def, hasDef, colon = body[:k], body[k+2:], true, true
			} else if k := strings.IndexByte(body, '-'); k >= 0 {
				name, def, hasDef = body[:k], body[k+1:], true
			}
			if !validVarName(name) {
				ok = false
				continue
			}
			v, set := vars[name]
			switch {
			case set && (v != "" || !colon):
				b.WriteString(v)
			case hasDef:
				d, dok := expand(def, vars)
				ok = ok && dok
				b.WriteString(d)
			case set:
				// empty and no default
			default:
				ok = false
			}
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '_' || s[j] >= '0' && s[j] <= '9' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z') {
			j++
		}
		if j == i+1 {
			b.WriteByte(c)
			continue
		}
		v, set := vars[s[i+1:j]]
		if !set {
			ok = false
		}
		b.WriteString(v)
		i = j - 1
	}
	return b.String(), ok
}

func validVarName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c == '_' || c >= '0' && c <= '9' && i > 0 || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

func (s *Stage) vars() map[string]string {
	m := make(map[string]string, len(s.args)+len(s.Env))
	for k, v := range s.args {
		m[k] = v
	}
	for k, v := range s.Env {
		m[k] = v
	}
	return m
}

// ParseDockerfile interprets FROM, ARG, ENV, EXPOSE, USER and HEALTHCHECK.
// It returns *parseError for input beyond its bounds.
func ParseDockerfile(src []byte) (*Dockerfile, error) {
	ins, err := logicalInstructions(src)
	if err != nil {
		return nil, err
	}
	d := &Dockerfile{}
	global := map[string]string{}
	var cur *Stage
	for _, in := range ins {
		switch in.cmd {
		case "FROM":
			if len(d.Stages) >= maxStages {
				return nil, &parseError{ReasonDockerfileUnparseable}
			}
			words := splitWords(in.rest)
			for len(words) > 0 && strings.HasPrefix(words[0], "--") {
				words = words[1:]
			}
			if len(words) == 0 {
				return nil, &parseError{ReasonDockerfileUnparseable}
			}
			image, _ := expand(words[0], global)
			st := &Stage{Env: map[string]string{}, args: map[string]string{}}
			if len(words) >= 3 && strings.EqualFold(words[1], "AS") {
				st.Name = strings.ToLower(words[2])
			}
			if parent := findStage(d.Stages, image); parent != nil {
				st.Ports = append(st.Ports, parent.Ports...)
				st.User, st.UserSet, st.UserUnres = parent.User, parent.UserSet, parent.UserUnres
				if parent.Health != nil {
					h := *parent.Health
					st.Health = &h
				}
				for k, v := range parent.Env {
					st.Env[k] = v
				}
			}
			d.Stages = append(d.Stages, st)
			cur = st
		case "ARG":
			for _, w := range splitWords(in.rest) {
				k, v, hasV := strings.Cut(w, "=")
				if !validVarName(k) {
					continue
				}
				if cur == nil {
					if hasV {
						ev, _ := expand(v, global)
						global[k] = ev
					}
					continue
				}
				if hasV {
					ev, ok := expand(v, cur.vars())
					if ok {
						cur.args[k] = ev
					}
				} else if gv, ok := global[k]; ok {
					cur.args[k] = gv
				}
			}
		case "ENV":
			if cur == nil {
				continue
			}
			words := splitWords(in.rest)
			if len(words) >= 2 && !strings.Contains(words[0], "=") {
				val, ok := expand(strings.Join(words[1:], " "), cur.vars())
				if ok && validVarName(words[0]) {
					cur.Env[words[0]] = val
				}
				continue
			}
			for _, w := range words {
				k, v, ok := strings.Cut(w, "=")
				if !ok || !validVarName(k) {
					continue
				}
				if ev, eok := expand(v, cur.vars()); eok {
					cur.Env[k] = ev
				}
			}
		case "EXPOSE":
			if cur == nil {
				continue
			}
			for _, w := range splitWords(in.rest) {
				ev, ok := expand(w, cur.vars())
				if !ok {
					cur.Ports = append(cur.Ports, Port{Unresolved: true})
					continue
				}
				for _, p := range strings.Fields(ev) {
					num, proto, _ := strings.Cut(p, "/")
					if proto != "" && !strings.EqualFold(proto, "tcp") {
						continue
					}
					n, err := strconv.Atoi(num)
					if err != nil || n < 1 || n > 65535 {
						cur.Ports = append(cur.Ports, Port{Unresolved: true})
						continue
					}
					cur.Ports = append(cur.Ports, Port{Value: n})
				}
			}
		case "USER":
			if cur == nil {
				continue
			}
			ev, ok := expand(strings.TrimSpace(in.rest), cur.vars())
			cur.UserSet, cur.User, cur.UserUnres = true, ev, !ok
		case "HEALTHCHECK":
			if cur == nil {
				continue
			}
			words := strings.Fields(in.rest)
			i := 0
			for i < len(words) && strings.HasPrefix(words[i], "--") {
				i++
			}
			if i >= len(words) {
				return nil, &parseError{ReasonDockerfileUnparseable}
			}
			if strings.EqualFold(words[i], "NONE") {
				cur.Health = &Health{None: true}
				continue
			}
			if !strings.EqualFold(words[i], "CMD") {
				cur.Health = &Health{Cmd: ""}
				continue
			}
			// Raw text after the CMD keyword.
			idx := strings.Index(strings.ToUpper(in.rest), "CMD")
			cur.Health = &Health{Cmd: strings.TrimSpace(in.rest[idx+3:])}
		}
	}
	if len(d.Stages) == 0 {
		return nil, &parseError{ReasonDockerfileUnparseable}
	}
	return d, nil
}

func findStage(stages []*Stage, ref string) *Stage {
	ref = strings.ToLower(ref)
	for _, s := range stages {
		if s.Name != "" && s.Name == ref {
			return s
		}
	}
	if n, err := strconv.Atoi(ref); err == nil && n >= 0 && n < len(stages) {
		return stages[n]
	}
	return nil
}
