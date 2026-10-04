package gitops

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ImageNamesFile is the reviewed list of reserved, shared and granted image
// names under ImageRegistry, relative to the checkout root. The deploy-service and
// preview-deploy validation and build-image.yaml apply the same list
// (platform-gitops/argo-workflows/scripts/check-image-name.sh); this is the
// API's copy of that rule, read from the same file.
const ImageNamesFile = "platform-gitops/argo-workflows/config/image-names.txt"

// ImageRegistry is where deploy-service and preview-deploy push and pull
// (their container_registry default; the API never sends another, because
// undeclared parameters are stripped). The list's `registry` line must name
// it: a list that governs another registry says nothing about this one.
const ImageRegistry = "ghcr.io/mctlhq"

// ImageNamePolicyMaxAge bounds how old the checkout may be when the policy
// is read. The checkout refreshes every minute; a last successful sync older
// than this means the API cannot see the current list or services, which is
// "could not observe", not "allowed".
const ImageNamePolicyMaxAge = 10 * time.Minute

// ImageNamePolicy decides which tenant may build into and run
// <registry>/<name>. Tenant builds push <registry>/<component_name> and
// tenant services run it, so a component name is an image name.
type ImageNamePolicy struct {
	registry       string
	grants         map[string]map[string]bool // name -> team -> granted
	reserved       map[string]bool
	reservedPrefix []string
	shared         map[string]bool
	// owners maps a name to the teams that have services/<team>/<name> or
	// run <registry>/<name> from a values.yaml under services/<team>/.
	owners map[string]map[string]bool
	// tenants are the teams with platform-gitops/tenants/<team>/.
	tenants map[string]bool
	// runsOther holds "team/name" for each services/<team>/<name>/values.yaml
	// that names an image and none of them is <registry>/<name>.
	runsOther map[string]bool
}

var imageNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// anyRepositoryRE matches any values.yaml line naming an image.
var anyRepositoryRE = regexp.MustCompile(`(?m)^[ \t\r\f\v]*repository:`)

// valuesRepositoryRE matches a values.yaml line running <registry>/<name>,
// line by line like the script's grep: [[:space:]] there never spans lines.
func valuesRepositoryRE(registry string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t\r\f\v]*repository:[ \t\r\f\v]*["']?` +
		regexp.QuoteMeta(registry) + `/([a-z0-9-]+)["']?[ \t\r\f\v]*$`)
}

// ErrImageNameRefused is wrapped by every refusal from Allowed.
var ErrImageNameRefused = errors.New("image name refused")

// ParseImageNames parses the list. Any line that is not a comment, blank, or
// one of `grant <team> <name>`, `reserved <name>`, `reserved-prefix <p>`,
// `shared <name>`, `registry <r>` is an error, as is a wildcard grant or
// anything but exactly one registry line: an unreadable policy must refuse,
// not allow.
func ParseImageNames(data []byte) (*ImageNamePolicy, error) {
	p := &ImageNamePolicy{
		grants:    map[string]map[string]bool{},
		reserved:  map[string]bool{},
		shared:    map[string]bool{},
		owners:    map[string]map[string]bool{},
		tenants:   map[string]bool{},
		runsOther: map[string]bool{},
	}
	registries := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case f[0] == "grant" && len(f) == 3 && f[1] != "*":
			if p.grants[f[2]] == nil {
				p.grants[f[2]] = map[string]bool{}
			}
			p.grants[f[2]][f[1]] = true
		case f[0] == "reserved" && len(f) == 2:
			p.reserved[f[1]] = true
		case f[0] == "reserved-prefix" && len(f) == 2:
			p.reservedPrefix = append(p.reservedPrefix, f[1])
		case f[0] == "shared" && len(f) == 2:
			p.shared[f[1]] = true
		case f[0] == "registry" && len(f) == 2:
			registries++
			p.registry = f[1]
		default:
			return nil, fmt.Errorf("%s line %d: unrecognised %q", ImageNamesFile, n, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if registries != 1 {
		return nil, fmt.Errorf("%s needs exactly one registry line, has %d", ImageNamesFile, registries)
	}
	if len(p.reserved) == 0 && len(p.reservedPrefix) == 0 {
		return nil, fmt.Errorf("%s reserves nothing", ImageNamesFile)
	}
	return p, nil
}

// AddOwner records that team has a service or runs an image named name.
func (p *ImageNamePolicy) AddOwner(name, team string) {
	if p.owners[name] == nil {
		p.owners[name] = map[string]bool{}
	}
	p.owners[name][team] = true
}

// AddRunsOther records that services/<team>/<name> runs an image other than
// <registry>/<name>.
func (p *ImageNamePolicy) AddRunsOther(team, name string) { p.runsOther[team+"/"+name] = true }

// RunsOtherImage reports whether the existing service team/name names an
// image in its values.yaml and none of them is <registry>/<name>. Building
// <registry>/<name> for it would push an image nothing runs, so
// deploy-service does not (tpl-validate-tenant's build decision).
func (p *ImageNamePolicy) RunsOtherImage(team, name string) bool { return p.runsOther[team+"/"+name] }

// DeployServiceBuilds is deploy-service's build decision (the `builds`
// output of tpl-validate-tenant's validate): never for update-config or
// without a dockerfile_repo; on onboard, unless the template is openclaw
// (whose services run a fixed image); on any other action, unless the
// existing service runs another image.
func (p *ImageNamePolicy) DeployServiceBuilds(action, dockerfileRepo, serviceTemplate, team, name string) bool {
	if action == "update-config" || dockerfileRepo == "" {
		return false
	}
	if action == "onboard" {
		return serviceTemplate != "openclaw"
	}
	return !p.RunsOtherImage(team, name)
}

// AddTenant records that team has platform-gitops/tenants/<team>/.
func (p *ImageNamePolicy) AddTenant(team string) { p.tenants[team] = true }

// Allowed reports whether tenant team may run ImageRegistry/<name>, and with
// build also push to it. It is check-image-name.sh run as `--tenant
// [--build] <checkout> ImageRegistry <team> <name>`, in the same order:
// the list must govern ImageRegistry; team must be an existing tenant and
// never "platform" (the API only checks tenant callers); then a grant
// allows; a reserved name or prefix refuses; a shared name allows a run and
// refuses a build; a name another team already has refuses; anything else
// is allowed.
func (p *ImageNamePolicy) Allowed(team, name string, build bool) error {
	if !imageNameRE.MatchString(team) || !imageNameRE.MatchString(name) {
		return fmt.Errorf("%w: invalid team %q or name %q", ErrImageNameRefused, team, name)
	}
	if p.registry != ImageRegistry {
		return fmt.Errorf("%w: %s governs %q, not %q", ErrImageNameRefused, ImageNamesFile, p.registry, ImageRegistry)
	}
	if team == "platform" || !p.tenants[team] {
		return fmt.Errorf("%w: team %q is not an existing tenant", ErrImageNameRefused, team)
	}
	if p.grants[name][team] {
		return nil
	}
	if p.reserved[name] {
		return fmt.Errorf("%w: image name %q is reserved for the platform", ErrImageNameRefused, name)
	}
	for _, prefix := range p.reservedPrefix {
		if strings.HasPrefix(name, prefix) {
			return fmt.Errorf("%w: image name %q is reserved for the platform", ErrImageNameRefused, name)
		}
	}
	if p.shared[name] {
		if build {
			return fmt.Errorf("%w: image name %q is shared; only a granted team may build it", ErrImageNameRefused, name)
		}
		return nil
	}
	for owner := range p.owners[name] {
		if owner != team {
			return fmt.Errorf("%w: image name %q belongs to team %q", ErrImageNameRefused, name, owner)
		}
	}
	return nil
}

// ImageNamePolicy reads ImageNamesFile, the tenants and the services tree
// from the same checkout, under one read lock. Every read error is returned: a missing list,
// an unreadable services directory, or an unreadable values.yaml is not an
// empty policy. So is a checkout that never synced, or whose last successful
// sync is older than ImageNamePolicyMaxAge.
func (r *Reader) ImageNamePolicy() (*ImageNamePolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	last := r.LastSync()
	if last.IsZero() {
		return nil, errors.New("gitops checkout has never synced")
	}
	if age := time.Since(last); age > ImageNamePolicyMaxAge {
		return nil, fmt.Errorf("gitops checkout last synced %s ago (limit %s)", age.Round(time.Second), ImageNamePolicyMaxAge)
	}

	data, err := os.ReadFile(filepath.Join(r.localPath, ImageNamesFile)) //nolint:gosec // fixed path inside the checkout
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ImageNamesFile, err)
	}
	p, err := ParseImageNames(data)
	if err != nil {
		return nil, err
	}

	tenants, err := os.ReadDir(filepath.Join(r.localPath, "platform-gitops", "tenants"))
	if err != nil {
		return nil, fmt.Errorf("reading tenants dir: %w", err)
	}
	for _, t := range tenants {
		if t.IsDir() {
			p.AddTenant(t.Name())
		}
	}

	repoRE := valuesRepositoryRE(p.registry)
	servicesDir := filepath.Join(r.localPath, "platform-gitops", "services")
	teams, err := os.ReadDir(servicesDir)
	if err != nil {
		return nil, fmt.Errorf("reading services dir: %w", err)
	}
	// Dot-entries are skipped as the script's globs skip them.
	for _, t := range teams {
		if !t.IsDir() || strings.HasPrefix(t.Name(), ".") {
			continue
		}
		apps, err := os.ReadDir(filepath.Join(servicesDir, t.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading services/%s: %w", t.Name(), err)
		}
		for _, a := range apps {
			if !a.IsDir() || strings.HasPrefix(a.Name(), ".") {
				continue
			}
			p.AddOwner(a.Name(), t.Name())
			values, err := os.ReadFile(filepath.Join(servicesDir, t.Name(), a.Name(), "values.yaml")) //nolint:gosec // path inside the checkout
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("reading services/%s/%s/values.yaml: %w", t.Name(), a.Name(), err)
			}
			runsOwn := false
			for _, m := range repoRE.FindAllSubmatch(values, -1) {
				p.AddOwner(string(m[1]), t.Name())
				runsOwn = runsOwn || string(m[1]) == a.Name()
			}
			if !runsOwn && anyRepositoryRE.Match(values) {
				p.AddRunsOther(t.Name(), a.Name())
			}
		}
	}
	return p, nil
}
