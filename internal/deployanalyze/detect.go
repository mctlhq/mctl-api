package deployanalyze

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reason is the closed set of Unsupported reasons.
type Reason string

const (
	ReasonNoDockerfile          Reason = "no_dockerfile"
	ReasonDockerfileNotAFile    Reason = "dockerfile_not_a_file"
	ReasonDockerfileTooLarge    Reason = "dockerfile_too_large"
	ReasonDockerfileUnparseable Reason = "dockerfile_unparseable"
	ReasonComposeTooLarge       Reason = "compose_too_large"
	ReasonComposeUnparseable    Reason = "compose_unparseable"
	ReasonMultiService          Reason = "multi_service"
	ReasonPrivileged            Reason = "privileged"
	ReasonHostPorts             Reason = "host_ports"
	ReasonGPU                   Reason = "gpu"
	ReasonRunsAsRoot            Reason = "runs_as_root"
	ReasonPrivilegedPort        Reason = "privileged_port"
)

// messages are fixed templates; no repository content is ever interpolated.
var messages = map[Reason]string{
	ReasonNoDockerfile:          "No Dockerfile was found at the requested path.",
	ReasonDockerfileNotAFile:    "The Dockerfile path is not a regular file.",
	ReasonDockerfileTooLarge:    "The Dockerfile exceeds the size limit.",
	ReasonDockerfileUnparseable: "The Dockerfile could not be parsed within the analyzer's limits.",
	ReasonComposeTooLarge:       "A compose file exceeds the size limit.",
	ReasonComposeUnparseable:    "A compose file could not be parsed within the analyzer's limits.",
	ReasonMultiService:          "The compose file declares more than one service.",
	ReasonPrivileged:            "The compose file requests privileged capabilities, devices or host namespaces.",
	ReasonHostPorts:             "The compose file maps host ports.",
	ReasonGPU:                   "The compose file requests a GPU.",
	ReasonRunsAsRoot:            "The final image stage runs as root or does not set a non-root USER.",
	ReasonPrivilegedPort:        "Every exposed port is below 1024, which a non-root container cannot bind.",
}

// Message returns the fixed template for r.
func (r Reason) Message() string { return messages[r] }

// NeedsInput names a field the analyzer refuses to guess.
type NeedsInput struct {
	Field      string `json:"field"`
	Reason     string `json:"reason"`
	Candidates []any  `json:"candidates,omitempty"`
}

// detectUser reports whether the stage's effective user is non-root.
func detectUser(s *Stage) bool {
	if !s.UserSet || s.UserUnres {
		return false
	}
	u, _, _ := strings.Cut(strings.TrimSpace(s.User), ":")
	u = strings.TrimSpace(u)
	if u == "" || u == "root" {
		return false
	}
	if n, err := strconv.Atoi(u); err == nil && n == 0 {
		return false
	}
	return true
}

// detectPort returns the single usable port, a privileged-port verdict, or a
// needs_input entry.
func detectPort(s *Stage) (port int, reason Reason, need *NeedsInput) {
	seen := map[int]bool{}
	unresolved := false
	for _, p := range s.Ports {
		if p.Unresolved {
			unresolved = true
			continue
		}
		seen[p.Value] = true
	}
	var high []int
	low := 0
	for v := range seen {
		if v >= 1024 {
			high = append(high, v)
		} else {
			low++
		}
	}
	sort.Ints(high)
	if !unresolved && len(high) == 0 && low > 0 {
		return 0, ReasonPrivilegedPort, nil
	}
	if !unresolved && len(high) == 1 {
		return high[0], "", nil
	}
	n := &NeedsInput{Field: "runtime.port", Reason: "port_not_determined"}
	for _, h := range high {
		n.Candidates = append(n.Candidates, h)
	}
	return 0, "", n
}

var (
	healthURLRe  = regexp.MustCompile(`^http://(?:localhost|127\.0\.0\.1|\[::1\]):([0-9]{1,5})(/[^?#\s]*)?$`)
	healthPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,255}$`)
)

// healthArgs tokenises a HEALTHCHECK CMD without a shell.
func healthArgs(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, "[") {
		var a []string
		if err := json.Unmarshal([]byte(cmd), &a); err != nil {
			return nil
		}
		if len(a) >= 3 && (a[0] == "CMD-SHELL") {
			return nil
		}
		return a
	}
	for _, suffix := range []string{"|| exit 1", "|| false"} {
		cmd = strings.TrimSpace(strings.TrimSuffix(cmd, suffix))
	}
	if strings.ContainsAny(cmd, ";|&<>$`()\n{}") {
		return nil
	}
	return splitWords(cmd)
}

// detectHealth returns the health path of a plain HTTP GET check of the
// detected port on a loopback host.
func detectHealth(s *Stage, port int) (string, bool) {
	if port == 0 || s.Health == nil || s.Health.None || s.Health.Cmd == "" {
		return "", false
	}
	args := healthArgs(s.Health.Cmd)
	if len(args) < 2 {
		return "", false
	}
	var url string
	switch args[0] {
	case "curl":
		for i := 1; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-X" || a == "--request":
				if i+1 >= len(args) || !strings.EqualFold(args[i+1], "GET") {
					return "", false
				}
				i++
			case strings.HasPrefix(a, "--request="):
				if !strings.EqualFold(strings.TrimPrefix(a, "--request="), "GET") {
					return "", false
				}
			case strings.HasPrefix(a, "--data"), a == "--form", strings.HasPrefix(a, "--form="), a == "--upload-file", strings.HasPrefix(a, "--upload-file="), a == "--json", strings.HasPrefix(a, "--json="):
				return "", false
			case strings.HasPrefix(a, "--"):
			case strings.HasPrefix(a, "-") && len(a) > 1:
				if strings.ContainsAny(a[1:], "dFTX") {
					return "", false
				}
			default:
				if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
					if url != "" {
						return "", false
					}
					url = a
				}
			}
		}
	case "wget":
		for i := 1; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--method":
				if i+1 >= len(args) || !strings.EqualFold(args[i+1], "GET") {
					return "", false
				}
				i++
			case strings.HasPrefix(a, "--method="):
				if !strings.EqualFold(strings.TrimPrefix(a, "--method="), "GET") {
					return "", false
				}
			case strings.HasPrefix(a, "--post-"), strings.HasPrefix(a, "--body-"):
				return "", false
			case strings.HasPrefix(a, "-"):
			default:
				if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
					if url != "" {
						return "", false
					}
					url = a
				}
			}
		}
	default:
		return "", false
	}
	m := healthURLRe.FindStringSubmatch(url)
	if m == nil {
		return "", false
	}
	if p, err := strconv.Atoi(m[1]); err != nil || p != port {
		return "", false
	}
	path := m[2]
	if path == "" {
		path = "/"
	}
	if !healthPathRe.MatchString(path) {
		return "", false
	}
	return path, true
}

const (
	maxComposeNodes = 20000
	maxComposeDepth = 64
)

// detectCompose inspects root compose files and returns the first
// disqualifying reason, or "".
func detectCompose(files [][]byte) Reason {
	for _, data := range files {
		if r := detectOneCompose(data); r != "" {
			return r
		}
	}
	return ""
}

func composeNodesOK(n *yaml.Node, depth int, count *int) bool {
	*count++
	if *count > maxComposeNodes || depth > maxComposeDepth {
		return false
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	for _, c := range n.Content {
		if !composeNodesOK(c, depth+1, count) {
			return false
		}
	}
	return true
}

func detectOneCompose(data []byte) Reason {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return ReasonComposeUnparseable
	}
	if root.Kind == 0 {
		return ""
	}
	count := 0
	if !composeNodesOK(&root, 0, &count) {
		return ReasonComposeUnparseable
	}
	var doc map[string]any
	if err := root.Decode(&doc); err != nil {
		return ReasonComposeUnparseable
	}
	raw, ok := doc["services"]
	if !ok || raw == nil {
		return ""
	}
	services, ok := raw.(map[string]any)
	if !ok {
		return ReasonComposeUnparseable
	}
	if len(services) > 1 {
		return ReasonMultiService
	}
	names := make([]string, 0, len(services))
	for k := range services {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		svc, ok := services[name].(map[string]any)
		if !ok {
			return ReasonComposeUnparseable
		}
		if composePrivileged(svc) {
			return ReasonPrivileged
		}
		if composeHostPorts(svc) {
			return ReasonHostPorts
		}
		if composeGPU(svc) {
			return ReasonGPU
		}
	}
	return ""
}

func composePrivileged(svc map[string]any) bool {
	if b, _ := svc["privileged"].(bool); b {
		return true
	}
	if s, ok := svc["privileged"].(string); ok && strings.EqualFold(s, "true") {
		return true
	}
	if l, ok := svc["cap_add"].([]any); ok && len(l) > 0 {
		return true
	}
	if l, ok := svc["devices"].([]any); ok && len(l) > 0 {
		return true
	}
	for _, k := range []string{"network_mode", "pid", "ipc"} {
		if s, _ := svc[k].(string); s == "host" {
			return true
		}
	}
	return false
}

func composeHostPorts(svc map[string]any) bool {
	l, _ := svc["ports"].([]any)
	for _, p := range l {
		switch v := p.(type) {
		case string:
			if strings.Contains(v, ":") {
				return true
			}
		case map[string]any:
			if _, ok := v["published"]; ok {
				return true
			}
		}
	}
	return false
}

func composeGPU(svc map[string]any) bool {
	if _, ok := svc["gpus"]; ok {
		return true
	}
	if s, _ := svc["runtime"].(string); s == "nvidia" {
		return true
	}
	deploy, _ := svc["deploy"].(map[string]any)
	res, _ := deploy["resources"].(map[string]any)
	rsv, _ := res["reservations"].(map[string]any)
	if l, ok := rsv["devices"].([]any); ok && len(l) > 0 {
		return true
	}
	return false
}
