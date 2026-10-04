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

// ImageNamesFile is the reviewed list of reserved and granted image names
// under ghcr.io/mctlhq, relative to the checkout root. The deploy-service and
// preview-deploy validation and build-image.yaml apply the same list
// (platform-gitops/argo-workflows/scripts/check-image-name.sh); this is the
// API's copy of that rule, read from the same file.
const ImageNamesFile = "platform-gitops/argo-workflows/config/image-names.txt"

// ImageNamePolicyMaxAge bounds how old the checkout may be when the policy
// is read. The checkout refreshes every minute; a last successful sync older
// than this means the API cannot see the current list or services, which is
// "could not observe", not "allowed".
const ImageNamePolicyMaxAge = 10 * time.Minute

// ImageNamePolicy decides which team may build into and run
// ghcr.io/mctlhq/<name>. Tenant builds push ghcr.io/mctlhq/<component_name>
// and tenant services run it, so a component name is an image name.
type ImageNamePolicy struct {
	grants         map[string]map[string]bool // name -> team ("*" for any) -> granted
	reserved       map[string]bool
	reservedPrefix []string
	// owners maps a name to the teams that have services/<team>/<name> or
	// run ghcr.io/mctlhq/<name> from a values.yaml under services/<team>/.
	owners map[string]map[string]bool
}

var imageNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

var valuesRepositoryRE = regexp.MustCompile(`(?m)^[ \t]*repository:[ \t]*["']?ghcr\.io/mctlhq/([a-z0-9-]+)["']?[ \t]*$`)

// ErrImageNameRefused is wrapped by every refusal from Allowed.
var ErrImageNameRefused = errors.New("image name refused")

// ParseImageNames parses the list. Any line that is not a comment, blank, or
// one of `grant <team|*> <name>`, `reserved <name>`, `reserved-prefix <p>`
// is an error: an unreadable policy must refuse, not allow.
func ParseImageNames(data []byte) (*ImageNamePolicy, error) {
	p := &ImageNamePolicy{
		grants:   map[string]map[string]bool{},
		reserved: map[string]bool{},
		owners:   map[string]map[string]bool{},
	}
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
		case f[0] == "grant" && len(f) == 3:
			if p.grants[f[2]] == nil {
				p.grants[f[2]] = map[string]bool{}
			}
			p.grants[f[2]][f[1]] = true
		case f[0] == "reserved" && len(f) == 2:
			p.reserved[f[1]] = true
		case f[0] == "reserved-prefix" && len(f) == 2:
			p.reservedPrefix = append(p.reservedPrefix, f[1])
		default:
			return nil, fmt.Errorf("%s line %d: unrecognised %q", ImageNamesFile, n, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
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

// Allowed reports whether team may build into and run ghcr.io/mctlhq/<name>,
// in the same order as check-image-name.sh: a grant allows; a reserved name
// or prefix refuses; a name another team already has refuses; anything else
// is allowed.
func (p *ImageNamePolicy) Allowed(team, name string) error {
	if !imageNameRE.MatchString(team) || !imageNameRE.MatchString(name) {
		return fmt.Errorf("%w: invalid team %q or name %q", ErrImageNameRefused, team, name)
	}
	if g := p.grants[name]; g[team] || g["*"] {
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
	for owner := range p.owners[name] {
		if owner != team {
			return fmt.Errorf("%w: image name %q belongs to team %q", ErrImageNameRefused, name, owner)
		}
	}
	return nil
}

// ImageNamePolicy reads ImageNamesFile and the services tree from the same
// checkout, under one read lock. Every read error is returned: a missing list,
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

	servicesDir := filepath.Join(r.localPath, "platform-gitops", "services")
	teams, err := os.ReadDir(servicesDir)
	if err != nil {
		return nil, fmt.Errorf("reading services dir: %w", err)
	}
	for _, t := range teams {
		if !t.IsDir() {
			continue
		}
		apps, err := os.ReadDir(filepath.Join(servicesDir, t.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading services/%s: %w", t.Name(), err)
		}
		for _, a := range apps {
			if !a.IsDir() {
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
			for _, m := range valuesRepositoryRE.FindAllSubmatch(values, -1) {
				p.AddOwner(string(m[1]), t.Name())
			}
		}
	}
	return p, nil
}
