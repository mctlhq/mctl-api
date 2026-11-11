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

package live

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// TokenSource supplies the Glovo access token. The adapter never stores,
// logs or returns it. Token returns the current token. Refresh obtains a new
// one after the provider answered 401; the adapter calls it at most once per
// request and never loops.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Refresh(ctx context.Context) (string, error)
}

// Delivery is the owner's delivery context sent as request headers. The
// coordinates stay inside the adapter: they are never part of any returned
// type, error or log line.
type Delivery struct {
	CountryCode string // ISO 3166-1 alpha-2, e.g. "ME"
	CityCode    string
	Latitude    string
	Longitude   string
}

// Config configures a Reader or Writer.
type Config struct {
	// BaseURL is the Glovo API origin, e.g. https://api.glovoapp.com. It is
	// the only host the adapter will contact. https is required; plain http
	// is accepted for loopback hosts only (httptest).
	BaseURL string
	// Currency is the ISO 4217 code all amounts are read as. A payload that
	// names another currency is schema drift.
	Currency string
	Delivery Delivery
	// Language is the Glovo-Language-Code header (default "en").
	Language string
	// ExtraHeaders are sent on every request (device urn and similar, from
	// the session custody). Authorization, Host and the consent header are
	// refused.
	ExtraHeaders map[string]string
	// AuthScheme prefixes the token in the Authorization header. Upstream
	// sends the raw token, so the default is empty (unverified).
	AuthScheme string
	// RequestTimeout bounds one HTTP exchange (default 10s). The caller's
	// context deadline still applies when it is shorter.
	RequestTimeout time.Duration
	// MaxResponseBytes caps one response body (default 1 MiB).
	MaxResponseBytes int64
	// Transport overrides the HTTP transport (tests). The host guard wraps it.
	Transport http.RoundTripper
}

const (
	defaultTimeout  = 10 * time.Second
	defaultMaxBytes = 1 << 20
	// PageSize is the largest page the orders-list endpoint serves (upstream
	// api.mjs getAllOrderCards caps at 15).
	ordersPageSize = 15
)

var (
	reCountry  = regexp.MustCompile(`^[A-Z]{2}$`)
	reCity     = regexp.MustCompile(`^[A-Z0-9_-]{2,16}$`)
	reCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
	reCoord    = regexp.MustCompile(`^-?\d{1,3}(\.\d{1,10})?$`)
)

func (c Config) normalize() (Config, *url.URL, error) {
	bad := func(what string) (Config, *url.URL, error) {
		return c, nil, fmt.Errorf("glovolive: invalid config: %s", what)
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return bad("base_url")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return bad("base_url must be https")
		}
	default:
		return bad("base_url scheme")
	}
	u.Path = ""
	c.Currency = strings.ToUpper(c.Currency)
	if !reCurrency.MatchString(c.Currency) {
		return bad("currency")
	}
	d := &c.Delivery
	d.CountryCode, d.CityCode = strings.ToUpper(d.CountryCode), strings.ToUpper(d.CityCode)
	if !reCountry.MatchString(d.CountryCode) || !reCity.MatchString(d.CityCode) ||
		!reCoord.MatchString(d.Latitude) || !reCoord.MatchString(d.Longitude) {
		return bad("delivery")
	}
	if c.Language == "" {
		c.Language = "en"
	}
	for k := range c.ExtraHeaders {
		switch strings.ToLower(k) {
		case "authorization", "host", "content-type", "glovo-perseus-consent":
			return bad("extra header " + strings.ToLower(k) + " not allowed")
		}
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = defaultMaxBytes
	}
	return c, u, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
