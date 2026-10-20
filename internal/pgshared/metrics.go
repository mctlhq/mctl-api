// Copyright 2026 MCTL Authors
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

package pgshared

import (
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// The shared pool is the process's ceiling on concurrent database work, and
// /readyz deliberately probes outside it (OpenDedicated), so these series are
// the only signal that it is full: requests queueing on Acquire show up as
// empty_acquire and acquire_duration growing while acquired sits at max.
//
// Series are labelled by host and database only. The registry key is the
// connection string, which carries the password, so it never becomes a label.
// Pools whose strings differ only in parameters land on one label set and are
// summed, which keeps Collect from emitting a duplicate series.
//
// The counters are sums over pools open at scrape time, so closing one of
// several pools behind a label set makes them drop, which rate() and
// increase() read as a counter reset. In cmd/api the shared pools live for
// the whole process, so that happens only at shutdown.
var (
	poolLabels = []string{"host", "database"}

	descMaxConns = prometheus.NewDesc("mctl_api_db_pool_max_conns",
		"Configured maximum connections of the shared pools for this database.", poolLabels, nil)
	descTotalConns = prometheus.NewDesc("mctl_api_db_pool_total_conns",
		"Connections currently open in the shared pools for this database.", poolLabels, nil)
	descAcquiredConns = prometheus.NewDesc("mctl_api_db_pool_acquired_conns",
		"Connections currently checked out of the shared pools for this database.", poolLabels, nil)
	descIdleConns = prometheus.NewDesc("mctl_api_db_pool_idle_conns",
		"Idle connections in the shared pools for this database.", poolLabels, nil)
	descAcquires = prometheus.NewDesc("mctl_api_db_pool_acquires_total",
		"Successful connection acquires from the shared pools for this database.", poolLabels, nil)
	descEmptyAcquires = prometheus.NewDesc("mctl_api_db_pool_empty_acquires_total",
		"Acquires that found no idle connection and had to wait or dial.", poolLabels, nil)
	descCanceledAcquires = prometheus.NewDesc("mctl_api_db_pool_canceled_acquires_total",
		"Acquires abandoned because their context ended while waiting.", poolLabels, nil)
	descAcquireSeconds = prometheus.NewDesc("mctl_api_db_pool_acquire_duration_seconds_total",
		"Total time spent waiting for connections from the shared pools for this database.", poolLabels, nil)
)

func init() {
	prometheus.MustRegister(collector{})
}

// PoolInfo describes one shared pool for the startup log.
type PoolInfo struct {
	Host     string
	Database string
	MaxConns int32
}

// Pools lists the shared pools open right now, ordered by host and database.
// It reports nothing while sharing is off.
func Pools() []PoolInfo {
	out := make([]PoolInfo, 0)
	for _, p := range sharedPools() {
		cc := p.Config().ConnConfig
		out = append(out, PoolInfo{Host: cc.Host, Database: cc.Database, MaxConns: p.Config().MaxConns})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Database < out[j].Database
	})
	return out
}

// sharedPools snapshots the registry so Stat runs without holding mu.
func sharedPools() []*pgxpool.Pool {
	mu.Lock()
	defer mu.Unlock()
	pools := make([]*pgxpool.Pool, 0, len(byPool))
	for p := range byPool {
		pools = append(pools, p)
	}
	return pools
}

type collector struct{}

func (collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descMaxConns, descTotalConns, descAcquiredConns, descIdleConns,
		descAcquires, descEmptyAcquires, descCanceledAcquires, descAcquireSeconds} {
		ch <- d
	}
}

type poolKey struct{ host, database string }

type poolTotals struct {
	maxConns, total, acquired, idle float64
	acquires, empty, canceled       float64
	acquireSeconds                  float64
}

func (collector) Collect(ch chan<- prometheus.Metric) {
	sums := map[poolKey]*poolTotals{}
	for _, p := range sharedPools() {
		cc := p.Config().ConnConfig
		k := poolKey{cc.Host, cc.Database}
		t := sums[k]
		if t == nil {
			t = &poolTotals{}
			sums[k] = t
		}
		s := p.Stat()
		t.maxConns += float64(s.MaxConns())
		t.total += float64(s.TotalConns())
		t.acquired += float64(s.AcquiredConns())
		t.idle += float64(s.IdleConns())
		t.acquires += float64(s.AcquireCount())
		t.empty += float64(s.EmptyAcquireCount())
		t.canceled += float64(s.CanceledAcquireCount())
		t.acquireSeconds += s.AcquireDuration().Seconds()
	}
	for k, t := range sums {
		for _, m := range []struct {
			d *prometheus.Desc
			t prometheus.ValueType
			v float64
		}{
			{descMaxConns, prometheus.GaugeValue, t.maxConns},
			{descTotalConns, prometheus.GaugeValue, t.total},
			{descAcquiredConns, prometheus.GaugeValue, t.acquired},
			{descIdleConns, prometheus.GaugeValue, t.idle},
			{descAcquires, prometheus.CounterValue, t.acquires},
			{descEmptyAcquires, prometheus.CounterValue, t.empty},
			{descCanceledAcquires, prometheus.CounterValue, t.canceled},
			{descAcquireSeconds, prometheus.CounterValue, t.acquireSeconds},
		} {
			ch <- prometheus.MustNewConstMetric(m.d, m.t, m.v, k.host, k.database)
		}
	}
}
