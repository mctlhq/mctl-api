package deployanalyze

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/ghtoken"
)

const sha40 = "0123456789abcdef0123456789abcdef01234567"

const goodDockerfile = `FROM node:20 AS build
RUN echo MARKER_UNIQUE_STRING
FROM node:20
EXPOSE 3000
USER node
HEALTHCHECK CMD curl -fsS http://localhost:3000/healthz
`

type fakeReader struct {
	commitErr error
	files     map[string]FileResult
	fileErr   error
}

func (f *fakeReader) Commit(context.Context, string, string) error { return f.commitErr }
func (f *fakeReader) File(_ context.Context, _, _, p string, _ int) (FileResult, error) {
	if f.fileErr != nil {
		return FileResult{}, f.fileErr
	}
	if r, ok := f.files[p]; ok {
		return r, nil
	}
	return FileResult{Absent: true}, nil
}

func file(s string) FileResult { return FileResult{Kind: "file", Data: []byte(s)} }

func analyze(t *testing.T, files map[string]FileResult, services ...string) *Result {
	t.Helper()
	res, err := Analyze(context.Background(), &fakeReader{files: files}, Request{
		Tenant: "acme", Repository: "Acme/My_App", Revision: sha40, BoundServices: services,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func df(body string) map[string]FileResult { return map[string]FileResult{"Dockerfile": file(body)} }

func TestVendoredSchemaPinned(t *testing.T) {
	sum := sha256.Sum256(schemaBytes)
	if hex.EncodeToString(sum[:]) != SchemaSHA256 {
		t.Fatalf("vendored schema hash %x != %s", sum, SchemaSHA256)
	}
	if _, err := compile(); err != nil {
		t.Fatal(err)
	}
}

func TestVendoredSchemaMatchesSource(t *testing.T) {
	src := os.Getenv("DEPLOY_INTENT_SCHEMA_SOURCE")
	if src == "" {
		t.Skip("DEPLOY_INTENT_SCHEMA_SOURCE not set")
	}
	want, err := os.ReadFile(src) //nolint:gosec // test-only path from CI
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, schemaBytes) {
		t.Fatal("vendored schema differs from " + SchemaSource)
	}
}

func TestConvergedTier0(t *testing.T) {
	res := analyze(t, df(goodDockerfile))
	if !res.Supported || res.Tier != "tier0" || len(res.NeedsInput) != 0 || res.DraftIntent == nil {
		t.Fatalf("%+v", res)
	}
	d := res.DraftIntent.(map[string]any)
	if err := Validate(d); err != nil {
		t.Fatal(err)
	}
	spec := d["spec"].(map[string]any)
	if spec["environment"] != "preview" || spec["exposure"].(map[string]any)["mode"] != "internal" ||
		spec["runtime"].(map[string]any)["replicas"] != 1 {
		t.Fatalf("%v", spec)
	}
	if d["metadata"].(map[string]any)["service"] != "my-app" {
		t.Fatalf("service: %v", d["metadata"])
	}
	raw, _ := json.Marshal(res)
	for _, bad := range []string{`"image"`, `"digest"`, "vault", "secret", "MARKER_UNIQUE_STRING"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(bad)) {
			t.Fatalf("result leaks %s: %s", bad, raw)
		}
	}
}

func dockerfileWith(lines ...string) string {
	return "FROM node:20\n" + strings.Join(lines, "\n") + "\n"
}

func TestPortDetector(t *testing.T) {
	user := "USER node"
	hc := func(p string) string { return "HEALTHCHECK CMD curl -f http://localhost:" + p + "/h" }
	cases := []struct {
		name       string
		body       string
		reason     Reason
		needsPort  bool
		candidates int
	}{
		{"privileged", dockerfileWith("EXPOSE 80", user), ReasonPrivilegedPort, false, 0},
		{"two", dockerfileWith("EXPOSE 3000 8080", user, hc("3000")), "", true, 2},
		{"none", dockerfileWith(user), "", true, 0},
		{"unset var", dockerfileWith("EXPOSE ${UNSET}", user), "", true, 0},
		{"arg default", dockerfileWith("ARG PORT=3000", "EXPOSE $PORT", user, hc("3000")), "", false, 0},
		{"udp ignored", dockerfileWith("EXPOSE 53/udp 3000/tcp", user, hc("3000")), "", false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, df(c.body))
			if res.Reason != c.reason {
				t.Fatalf("reason %q want %q", res.Reason, c.reason)
			}
			if c.reason != "" {
				return
			}
			var got *NeedsInput
			for i := range res.NeedsInput {
				if res.NeedsInput[i].Field == "runtime.port" {
					got = &res.NeedsInput[i]
				}
			}
			if (got != nil) != c.needsPort {
				t.Fatalf("needs_input %+v", res.NeedsInput)
			}
			if got != nil && len(got.Candidates) != c.candidates {
				t.Fatalf("candidates %v", got.Candidates)
			}
			if !c.needsPort && res.DraftIntent == nil {
				t.Fatalf("expected draft: %+v", res)
			}
		})
	}
}

func TestHealthDetector(t *testing.T) {
	base := func(h string) string { return dockerfileWith("EXPOSE 3000", "USER node", h) }
	ok := []string{
		"HEALTHCHECK CMD curl -fsS http://localhost:3000/healthz",
		"HEALTHCHECK --interval=5s CMD wget -qO- http://127.0.0.1:3000/ready",
		`HEALTHCHECK CMD ["curl","-f","http://[::1]:3000/up"]`,
		"HEALTHCHECK CMD curl -f http://localhost:3000/ || exit 1",
	}
	for _, h := range ok {
		if res := analyze(t, df(base(h))); res.DraftIntent == nil {
			t.Errorf("%q: %+v", h, res.NeedsInput)
		}
	}
	bad := []string{
		"HEALTHCHECK NONE",
		"",
		"HEALTHCHECK CMD curl -X POST http://localhost:3000/h",
		"HEALTHCHECK CMD curl -d x http://localhost:3000/h",
		"HEALTHCHECK CMD curl http://example.com:3000/h",
		"HEALTHCHECK CMD curl http://localhost:3001/h",
		"HEALTHCHECK CMD curl http://localhost:3000/h?x=1",
		"HEALTHCHECK CMD /bin/check",
		"HEALTHCHECK CMD wget --post-data=x http://localhost:3000/h",
		"HEALTHCHECK CMD curl http://localhost:3000/h; rm -rf /",
	}
	for _, h := range bad {
		res := analyze(t, df(base(h)))
		if res.DraftIntent != nil || len(res.NeedsInput) != 1 || res.NeedsInput[0].Field != "runtime.healthPath" {
			t.Errorf("%q: %+v", h, res)
		}
	}
}

func TestUserDetector(t *testing.T) {
	tail := "\nEXPOSE 3000\nHEALTHCHECK CMD curl -f http://localhost:3000/h\n"
	root := []string{
		"FROM a" + tail,
		"FROM a\nUSER root" + tail,
		"FROM a\nUSER 0" + tail,
		"FROM a\nUSER 0:0" + tail,
		"FROM a\nUSER $WHO" + tail,
		"FROM a AS b\nUSER node\nFROM c" + tail,
	}
	for _, b := range root {
		if res := analyze(t, df(b)); res.Reason != ReasonRunsAsRoot {
			t.Errorf("%q: %q", b, res.Reason)
		}
	}
	inherit := "FROM a AS builder\nUSER node\nFROM builder AS final" + tail
	if res := analyze(t, df(inherit)); !res.Supported || res.DraftIntent == nil {
		t.Fatalf("%+v", res)
	}
}

func TestComposeDetector(t *testing.T) {
	good := map[string]FileResult{"Dockerfile": file(goodDockerfile), "compose.yaml": file("services:\n  app:\n    build: .\n    ports:\n      - \"3000\"\n")}
	if res := analyze(t, good); !res.Supported {
		t.Fatalf("%+v", res)
	}
	cases := map[Reason]string{
		ReasonMultiService:       "services:\n  a: {}\n  b: {}\n",
		ReasonPrivileged:         "services:\n  a:\n    privileged: true\n",
		ReasonHostPorts:          "services:\n  a:\n    ports:\n      - \"8080:3000\"\n",
		ReasonGPU:                "services:\n  a:\n    gpus: all\n",
		ReasonComposeUnparseable: "services:\n  a: &x {}\n  b: *x\n",
	}
	extra := map[string]Reason{
		"services:\n  a:\n    cap_add: [NET_ADMIN]\n":                                                                                    ReasonPrivileged,
		"services:\n  a:\n    network_mode: host\n":                                                                                      ReasonPrivileged,
		"services:\n  a:\n    ports:\n      - published: 8080\n        target: 3000\n":                                                   ReasonHostPorts,
		"services:\n  a:\n    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n": ReasonGPU,
		"- [": ReasonComposeUnparseable,
	}
	for r, body := range cases {
		extra[body] = r
	}
	for body, want := range extra {
		f := map[string]FileResult{"Dockerfile": file(goodDockerfile), "docker-compose.yml": file(body)}
		if res := analyze(t, f); res.Reason != want {
			t.Errorf("%q: got %q want %q", body, res.Reason, want)
		}
	}
	f := map[string]FileResult{"Dockerfile": file(goodDockerfile), "compose.yml": {Kind: "file", TooLarge: true}}
	if res := analyze(t, f); res.Reason != ReasonComposeTooLarge {
		t.Errorf("%q", res.Reason)
	}
}

func TestDockerfileAvailability(t *testing.T) {
	if res := analyze(t, nil); res.Supported || res.Reason != ReasonNoDockerfile {
		t.Fatalf("%+v", res)
	}
	if res := analyze(t, map[string]FileResult{"Dockerfile": {Kind: "dir"}}); res.Reason != ReasonDockerfileNotAFile {
		t.Fatalf("%q", res.Reason)
	}
	if res := analyze(t, map[string]FileResult{"Dockerfile": {Kind: "file", TooLarge: true}}); res.Reason != ReasonDockerfileTooLarge {
		t.Fatalf("%q", res.Reason)
	}
	if res := analyze(t, df("# only comments\n")); res.Reason != ReasonDockerfileUnparseable {
		t.Fatalf("%q", res.Reason)
	}
}

func TestServiceName(t *testing.T) {
	if res := analyze(t, df(goodDockerfile), "one"); res.DraftIntent.(map[string]any)["metadata"].(map[string]any)["service"] != "one" {
		t.Fatalf("%+v", res)
	}
	res := analyze(t, df(goodDockerfile), "one", "two")
	if res.DraftIntent != nil || len(res.NeedsInput) != 1 || res.NeedsInput[0].Field != "metadata.service" || len(res.NeedsInput[0].Candidates) != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestReadFailuresAreErrors(t *testing.T) {
	boom := fmt.Errorf("%w: boom", ErrGitHubUnavailable)
	if _, err := Analyze(context.Background(), &fakeReader{fileErr: boom}, Request{Tenant: "a", Repository: "a/b", Revision: sha40}); !errors.Is(err, ErrGitHubUnavailable) {
		t.Fatal(err)
	}
	if _, err := Analyze(context.Background(), &fakeReader{commitErr: ErrRevisionUnreadable}, Request{Tenant: "a", Repository: "a/b", Revision: sha40}); !errors.Is(err, ErrRevisionUnreadable) {
		t.Fatal(err)
	}
}

func TestParseDockerfileBounds(t *testing.T) {
	if _, err := ParseDockerfile([]byte(strings.Repeat("a", MaxDockerfileBytes+1))); err == nil {
		t.Fatal("expected too large")
	}
	many := strings.Repeat("ENV A=b\n", maxDockerfileInstructions+1)
	if _, err := ParseDockerfile([]byte("FROM a\n" + many)); err == nil {
		t.Fatal("expected unparseable")
	}
	if _, err := ParseDockerfile([]byte(strings.Repeat("FROM a\n", maxStages+1))); err == nil {
		t.Fatal("expected too many stages")
	}
	hd := "FROM a\nRUN cat <<EOF\nEXPOSE 80\nEOF\nEXPOSE 3000\n"
	d, err := ParseDockerfile([]byte(hd))
	if err != nil || len(d.Final().Ports) != 1 || d.Final().Ports[0].Value != 3000 {
		t.Fatalf("%v %+v", err, d)
	}
}

func FuzzParseDockerfile(f *testing.F) {
	f.Add([]byte(goodDockerfile))
	f.Add([]byte("FROM a\nRUN <<EOF\nx\n"))
	f.Add([]byte("FROM a\nENV A=${B:-${C}}\nEXPOSE $A\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDockerfile(b)
		if err == nil && (len(d.Stages) == 0 || len(d.Stages) > maxStages) {
			t.Fatal("bounds violated")
		}
	})
}

// --- HTTP reader against a fake GitHub ---

func ghServer(t *testing.T, h http.HandlerFunc) *HTTPReader {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewHTTPReader(srv.URL, ghtoken.Static("secret-token"))
}

func contentsJSON(data string, size int) string {
	return fmt.Sprintf(`{"type":"file","size":%d,"encoding":"base64","content":%q}`, size, base64.StdEncoding.EncodeToString([]byte(data)))
}

func TestHTTPReaderCommit(t *testing.T) {
	ctx := context.Background()
	for status, want := range map[int]error{404: ErrRevisionUnreadable, 422: ErrRevisionUnreadable, 500: ErrGitHubUnavailable, 403: ErrGitHubUnavailable} {
		rd := ghServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		if err := rd.Commit(ctx, "a/b", sha40); !errors.Is(err, want) {
			t.Errorf("%d: %v", status, err)
		}
	}
	rd := ghServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/repos/a/b/git/commits/"+sha40 {
			w.WriteHeader(404)
			return
		}
		// A git commit object; the REST commit with a large diff is never read.
		_, _ = w.Write([]byte(`{"sha":"` + sha40 + `"}`))
	})
	if err := rd.Commit(ctx, "a/b", sha40); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{"malformed": `{`, "other sha": `{"sha":"` + strings.Repeat("f", 40) + `"}`, "over cap": strings.Repeat(" ", commitBodyCap+10)}
	for name, body := range bad {
		rd := ghServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		err := rd.Commit(ctx, "a/b", sha40)
		if !errors.Is(err, ErrGitHubMalformed) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-token") {
			t.Error("token leaked")
		}
	}
}

func TestHTTPReaderFile(t *testing.T) {
	ctx := context.Background()
	serve := func(status int, body string) *HTTPReader {
		return ghServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	}
	if r, err := serve(404, "").File(ctx, "a/b", sha40, "Dockerfile", 100); err != nil || !r.Absent {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := serve(200, contentsJSON("hello", 5)).File(ctx, "a/b", sha40, "x/Dockerfile", 100); err != nil || string(r.Data) != "hello" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := serve(200, `[{"type":"file"}]`).File(ctx, "a/b", sha40, "Dockerfile", 100); err != nil || r.Kind != "dir" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := serve(200, `{"type":"symlink","size":3}`).File(ctx, "a/b", sha40, "Dockerfile", 100); err != nil || r.Kind != "symlink" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := serve(200, `{"type":"file","size":1000}`).File(ctx, "a/b", sha40, "Dockerfile", 100); err != nil || !r.TooLarge {
		t.Fatalf("%+v %v", r, err)
	}
	// A real oversized answer carries its content; it must still read as too large.
	big := strings.Repeat("A", 300<<10)
	if r, err := serve(200, contentsJSON(big, len(big))).File(ctx, "a/b", sha40, "Dockerfile", MaxDockerfileBytes); err != nil || !r.TooLarge {
		t.Fatalf("300 KiB Dockerfile: %+v %v", r.TooLarge, err)
	}
	big = strings.Repeat("A", 1<<20)
	if r, err := serve(200, contentsJSON(big, len(big))).File(ctx, "a/b", sha40, "compose.yml", MaxComposeBytes); err != nil || !r.TooLarge {
		t.Fatalf("1 MiB compose: %+v %v", r.TooLarge, err)
	}
	for name, rd := range map[string]*HTTPReader{
		"length mismatch": serve(200, contentsJSON("hello", 9)),
		"no content":      serve(200, `{"type":"file","size":5,"encoding":"base64"}`),
		"bad json":        serve(200, `{`),
		"over cap":        serve(200, strings.Repeat(" ", contentsBodyCap+10)),
	} {
		if _, err := rd.File(ctx, "a/b", sha40, "Dockerfile", 100); !errors.Is(err, ErrGitHubMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, st := range []int{500, 502, 403} {
		if _, err := serve(st, "").File(ctx, "a/b", sha40, "Dockerfile", 100); !errors.Is(err, ErrGitHubUnavailable) {
			t.Errorf("%d: %v", st, err)
		}
	}
}
