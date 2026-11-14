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

package agentregistry

import (
	"context"
	"errors"
	"testing"
)

// fakeRows serves n rows. The row at scanFailAt (if >= 0) fails to scan
// while Next keeps going, so a reader that skips the bad row and carries on
// is caught even without pgx closing the stream; streamErr is what Err
// reports after the last row.
type fakeRows struct {
	n, scanFailAt int
	streamErr     error
	i             int
}

func (f *fakeRows) Next() bool { f.i++; return f.i <= f.n }

func (f *fakeRows) Scan(dest ...any) error {
	if f.i-1 == f.scanFailAt {
		return errors.New("cannot scan NULL into *string")
	}
	if id, ok := dest[0].(*int); ok {
		*id = f.i
	}
	return nil
}

func (f *fakeRows) Err() error { return f.streamErr }

var errStream = errors.New("conn closed mid-stream")

func TestListReaders_PartialReadIsAnError(t *testing.T) {
	readers := map[string]func(listRows) (int, error){
		"versions": func(r listRows) (int, error) {
			v, err := collectVersions(r)
			return len(v), err
		},
		"promotions": func(r listRows) (int, error) {
			p, err := collectPromotions(r)
			return len(p), err
		},
	}
	cases := map[string]struct {
		rows    *fakeRows
		wantErr error
	}{
		"row fails to scan":     {rows: &fakeRows{n: 3, scanFailAt: 1}},
		"stream ends in error":  {rows: &fakeRows{n: 2, scanFailAt: -1, streamErr: errStream}, wantErr: errStream},
		"stream fails at start": {rows: &fakeRows{n: 0, scanFailAt: -1, streamErr: errStream}, wantErr: errStream},
	}
	for rname, read := range readers {
		for cname, tc := range cases {
			t.Run(rname+"/"+cname, func(t *testing.T) {
				rows := *tc.rows
				n, err := read(&rows)
				if err == nil {
					t.Fatalf("got %d rows and no error, want the read to fail", n)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("err = %v, want it to wrap %v", err, tc.wantErr)
				}
				if n != 0 {
					t.Errorf("a failed read returned %d rows", n)
				}
			})
		}
		t.Run(rname+"/complete read", func(t *testing.T) {
			n, err := read(&fakeRows{n: 3, scanFailAt: -1})
			if err != nil || n != 3 {
				t.Fatalf("got %d rows, err %v; want 3 rows", n, err)
			}
		})
	}
}

// TestListVersionsAndPromotions_UnscannableRowFailsAgainstPostgres drives
// the same failure through real pgx: a NULL in a column read into a string.
// The NOT NULL constraints are lifted for the test only, to make that row
// possible.
func TestListVersionsAndPromotions_UnscannableRowFailsAgainstPostgres(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "mentor", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if _, err := s.PublishVersion(ctx, newVersion("mentor", v)); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
		if _, err := s.PromoteRelease(ctx, "mentor", EnvironmentProduction, v, "promote "+v, "mashkovd"); err != nil {
			t.Fatalf("promote %s: %v", v, err)
		}
	}
	if got, err := s.ListVersions(ctx, "mentor"); err != nil || len(got) != 3 {
		t.Fatalf("baseline ListVersions: %d rows, %v", len(got), err)
	}
	if got, err := s.ListPromotions(ctx, "mentor", EnvironmentProduction); err != nil || len(got) != 3 {
		t.Fatalf("baseline ListPromotions: %d rows, %v", len(got), err)
	}

	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `UPDATE agent_versions SET git_sha = '' WHERE git_sha IS NULL`)
		_, _ = s.pool.Exec(ctx, `UPDATE agent_promotions SET reason = '' WHERE reason IS NULL`)
		_, _ = s.pool.Exec(ctx, `ALTER TABLE agent_versions ALTER COLUMN git_sha SET NOT NULL`)
		_, _ = s.pool.Exec(ctx, `ALTER TABLE agent_promotions ALTER COLUMN reason SET NOT NULL`)
	})
	for _, stmt := range []string{
		`ALTER TABLE agent_versions ALTER COLUMN git_sha DROP NOT NULL`,
		`ALTER TABLE agent_promotions ALTER COLUMN reason DROP NOT NULL`,
		`UPDATE agent_versions SET git_sha = NULL WHERE agent = 'mentor' AND version = '1.1.0'`,
		`UPDATE agent_promotions SET reason = NULL WHERE agent = 'mentor' AND to_version = '1.1.0'`,
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	if got, err := s.ListVersions(ctx, "mentor"); err == nil || got != nil {
		t.Errorf("ListVersions with an unscannable row: got %d rows, err %v; want no rows and an error", len(got), err)
	}
	if got, err := s.ListPromotions(ctx, "mentor", EnvironmentProduction); err == nil || got != nil {
		t.Errorf("ListPromotions with an unscannable row: got %d rows, err %v; want no rows and an error", len(got), err)
	}
}
