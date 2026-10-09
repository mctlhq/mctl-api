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

package erpactsites

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListSites_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sites/shared" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("got Authorization %q, want Bearer tok", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"erpact-shared-stteam.mctl.ai","enabled":true},{"name":"erpact-acme.mctl.ai","enabled":true,"status":"ACTIVE"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	sites, err := c.ListSites(context.Background())
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 2 || sites[1].Status != "ACTIVE" {
		t.Fatalf("unexpected sites: %+v", sites)
	}
}

func TestListSites_ServerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`boom`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	if _, err := c.ListSites(context.Background()); err == nil {
		t.Fatal("ListSites: want error on 500, got nil")
	}
}

func TestListSites_UnauthenticatedIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Invalid token or expired token."}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "bad")
	_, err := c.ListSites(context.Background())
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("got %v, want ErrUnauthenticated", err)
	}
}

func TestCreateSite_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/site/new" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok","host":"erpact-acme.mctl.ai","temp_login_url":"https://erpact-acme.mctl.ai/x"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	host, err := c.CreateSite(context.Background(), "erpact-acme")
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if host != "erpact-acme.mctl.ai" {
		t.Fatalf("got host %q, want erpact-acme.mctl.ai", host)
	}
}

func TestCreateSite_AlreadyExistsIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"Site app template already exists"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	_, err := c.CreateSite(context.Background(), "erpact-acme")
	if !errors.Is(err, ErrSiteExists) {
		t.Fatalf("got %v, want ErrSiteExists", err)
	}
}

func TestCreateSite_BusyIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"Deployer is busy. Try again later"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	_, err := c.CreateSite(context.Background(), "erpact-acme")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
}

// The deployer's wording has only been seen on 400, but the sentinels must
// not depend on it: a real conflict misread as a generic failure invites a
// pointless retry.
func TestCreateSite_SentinelsDoNotDependOnHTTP400(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"exists on 409", http.StatusConflict, `{"detail":"Site app template already exists"}`, ErrSiteExists},
		{"busy on 503", http.StatusServiceUnavailable, `{"detail":"Deployer is busy. Try again later"}`, ErrBusy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			_, err := NewClient(srv.URL, "tok").CreateSite(context.Background(), "erpact-acme")
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// A create whose answer never arrives is ErrOutcomeUnknown: the deployer may
// have pushed the site already. A read that times out is a plain failure.
func TestCreateSite_TimeoutIsOutcomeUnknown(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := NewClient(srv.URL, "tok")
	c.createClient.Timeout = 50 * time.Millisecond
	c.httpClient.Timeout = 50 * time.Millisecond

	if _, err := c.CreateSite(context.Background(), "acme"); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("CreateSite: want ErrOutcomeUnknown, got %v", err)
	}
	if _, err := c.ListSites(context.Background()); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("ListSites: want a plain error, got %v", err)
	}
}

// A refused connection means nothing was sent: that is a failure, not unknown.
func TestCreateSite_ConnectionRefusedIsNotUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := NewClient(url, "tok")
	_, err := c.CreateSite(context.Background(), "acme")
	if err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("want a plain error, got %v", err)
	}
}

// A timeout while still connecting means no request byte was sent, so nothing
// can be running on the deployer: a plain failure, not unknown. Only a timeout
// after the request went out is unknown.
func TestCreateSite_DialTimeoutIsNotUnknown(t *testing.T) {
	c := NewClient("http://deployer.invalid", "tok")
	c.createClient = &http.Client{
		Timeout: 50 * time.Millisecond,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	}

	_, err := c.CreateSite(context.Background(), "acme")
	if err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("want a plain error for a dial timeout, got %v", err)
	}
}
