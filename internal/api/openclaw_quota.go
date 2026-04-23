// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"sync"
	"time"
)

// retryAfterSeconds converts a sub-second-resolution wait duration into the
// whole-second value advertised in the HTTP `Retry-After` header. Uses
// ceiling rounding so a 1.9s delay is reported as 2s, not 1s — a
// truncation would let the client retry before the limiter has actually
// refilled, producing a tight 429 loop.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}

// OpenClawQuotaConfig controls the soft caps enforced on skill/identity save
// handlers. Values are exposed as chart values on the mctl-api Helm chart so
// ops can tune without code changes — see helm/values.yaml. Zero values are
// replaced with OpenClawQuotaDefaults at router init.
type OpenClawQuotaConfig struct {
	// MaxPerSkillBytes is the hard cap on a single skill's content size.
	MaxPerSkillBytes int
	// MaxSkillsPerTenant is the hard cap on the number of skill files backed
	// up in gitops for one tenant. Protects the ConfigMap from ballooning past
	// the K8s 1 MiB object limit via many small files.
	MaxSkillsPerTenant int
	// MaxSkillsTotalBytes is the combined ceiling on all skill file contents
	// for one tenant, leaving headroom under the K8s 1 MiB ConfigMap limit
	// (default 900 KiB).
	MaxSkillsTotalBytes int
	// MaxIdentityFilesPerTenant is the hard cap on identity overrides (five
	// fixed names: AGENTS/SOUL/IDENTITY/USER/TOOLS.md).
	MaxIdentityFilesPerTenant int
	// MaxIdentityTotalBytes is the combined ceiling on identity override
	// contents for one tenant.
	MaxIdentityTotalBytes int
	// SaveRatePerHour is the number of save/delete writes allowed per hour per
	// (team, actor_user_id) pair. Applied to both skills and identity (they
	// share a rate-limit key so a user can't double the budget by alternating).
	SaveRatePerHour int
}

// OpenClawQuotaDefaults is the default tuning used when a field is left at its
// zero value. Values align with the plan in
// /Users/dmitriimashkov/.claude/plans/smooth-soaring-candy.md.
var OpenClawQuotaDefaults = OpenClawQuotaConfig{
	MaxPerSkillBytes:          100 * 1024,
	MaxSkillsPerTenant:        100,
	MaxSkillsTotalBytes:       900 * 1024,
	MaxIdentityFilesPerTenant: 5,
	MaxIdentityTotalBytes:     5 * 100 * 1024,
	SaveRatePerHour:           30,
}

// withDefaults returns a config where any zero field is filled in from
// OpenClawQuotaDefaults. Allows ops to override a single cap via chart values
// without having to enumerate every one.
func (c OpenClawQuotaConfig) withDefaults() OpenClawQuotaConfig {
	if c.MaxPerSkillBytes <= 0 {
		c.MaxPerSkillBytes = OpenClawQuotaDefaults.MaxPerSkillBytes
	}
	if c.MaxSkillsPerTenant <= 0 {
		c.MaxSkillsPerTenant = OpenClawQuotaDefaults.MaxSkillsPerTenant
	}
	if c.MaxSkillsTotalBytes <= 0 {
		c.MaxSkillsTotalBytes = OpenClawQuotaDefaults.MaxSkillsTotalBytes
	}
	if c.MaxIdentityFilesPerTenant <= 0 {
		c.MaxIdentityFilesPerTenant = OpenClawQuotaDefaults.MaxIdentityFilesPerTenant
	}
	if c.MaxIdentityTotalBytes <= 0 {
		c.MaxIdentityTotalBytes = OpenClawQuotaDefaults.MaxIdentityTotalBytes
	}
	if c.SaveRatePerHour <= 0 {
		c.SaveRatePerHour = OpenClawQuotaDefaults.SaveRatePerHour
	}
	return c
}

// saveRateBucket tracks recent save timestamps for a (team, actor) key.
// Kept deliberately simple (sliding window over a slice) because the working
// set is small (30/hour per user) and we don't need cross-instance sync for
// this granularity — per the plan, in-memory is fine.
type saveRateBucket struct {
	times []time.Time
}

// saveRateLimiter is an in-memory token-bucket-ish limiter shared by the skill
// and identity save/delete handlers. Keyed by team+actor so a single operator
// can't flood one tenant across two write paths.
type saveRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*saveRateBucket
	maxPerHour int
	ops        uint64           // #Allow calls since last sweep (guarded by mu)
	now        func() time.Time // injectable for deterministic testing
}

// sweepEveryOps is the number of Allow calls between opportunistic sweeps
// that evict buckets whose windows have fully emptied. Small enough that a
// long-lived process serving many one-off callers does not accumulate
// unbounded map state, large enough that the per-call overhead is amortized.
const sweepEveryOps = 128

func newSaveRateLimiter(maxPerHour int) *saveRateLimiter {
	return &saveRateLimiter{
		buckets:    make(map[string]*saveRateBucket),
		maxPerHour: maxPerHour,
		now:        time.Now,
	}
}

// Allow returns (true, 0) if the caller may perform a write now. When the
// limit has been reached it returns (false, retryAfter) with retryAfter set to
// the duration until the oldest recorded write falls out of the 1-hour window.
// On success the current timestamp is recorded so rapid bursts still cost
// budget even without cross-request coordination.
func (l *saveRateLimiter) Allow(key string) (bool, time.Duration) {
	if l == nil || l.maxPerHour <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-time.Hour)

	bucket, ok := l.buckets[key]
	if !ok {
		bucket = &saveRateBucket{}
		l.buckets[key] = bucket
	}
	// Trim expired entries (events older than one hour).
	trimmed := bucket.times[:0]
	for _, t := range bucket.times {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	bucket.times = trimmed

	defer l.maybeSweepLocked(cutoff)

	if len(bucket.times) >= l.maxPerHour {
		// Retry-After is the time until the oldest in-window entry expires.
		oldest := bucket.times[0]
		retry := oldest.Add(time.Hour).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	bucket.times = append(bucket.times, now)
	return true, 0
}

// maybeSweepLocked evicts buckets that have emptied since their last hit.
// Runs once every sweepEveryOps calls so one-off callers don't leave
// permanent `(team,user)` entries in the map for the lifetime of the
// process. Caller must hold l.mu.
func (l *saveRateLimiter) maybeSweepLocked(cutoff time.Time) {
	l.ops++
	if l.ops < sweepEveryOps {
		return
	}
	l.ops = 0
	for key, bucket := range l.buckets {
		trimmed := bucket.times[:0]
		for _, t := range bucket.times {
			if t.After(cutoff) {
				trimmed = append(trimmed, t)
			}
		}
		bucket.times = trimmed
		if len(bucket.times) == 0 {
			delete(l.buckets, key)
		}
	}
}
