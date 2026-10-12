// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func Test_AdminAPI_Routes(t *testing.T) {
	routes := new(adminAPI).Routes()
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if routes[0].Pattern != "/dynamic_dns/check" {
		t.Errorf("pattern = %q, want %q", routes[0].Pattern, "/dynamic_dns/check")
	}
}

// Test_AdminAPI_IsDiscoverable mirrors how Caddy collects admin routes
// (see admin.newAdminHandler): it iterates the modules in the "admin.api"
// namespace and type-asserts each to caddy.AdminRouter. A wrong namespace
// or a missing interface would silently drop the route.
func Test_AdminAPI_IsDiscoverable(t *testing.T) {
	var found bool
	for _, m := range caddy.GetModules("admin.api") {
		if m.ID != "admin.api.dynamic_dns" {
			continue
		}
		found = true
		if _, ok := m.New().(caddy.AdminRouter); !ok {
			t.Errorf("module %s does not implement caddy.AdminRouter", m.ID)
		}
	}
	if !found {
		t.Fatal(`module "admin.api.dynamic_dns" is not registered`)
	}
}

// apiErrStatus returns the HTTP status of err if it is a caddy.APIError.
func apiErrStatus(err error) (int, bool) {
	var apiErr caddy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.HTTPStatus, true
	}
	return 0, false
}

func Test_AdminAPI_Check_MethodNotAllowed(t *testing.T) {
	a := &adminAPI{app: &App{}}
	err := a.handleCheck(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/dynamic_dns/check", nil))

	status, ok := apiErrStatus(err)
	if !ok {
		t.Fatalf("expected a caddy.APIError, got %v", err)
	}
	if status != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func Test_AdminAPI_Check_NotConfigured(t *testing.T) {
	a := new(adminAPI) // no app: dynamic_dns is not configured

	err := a.handleCheck(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/dynamic_dns/check", nil))

	status, ok := apiErrStatus(err)
	if !ok {
		t.Fatalf("expected a caddy.APIError, got %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", status, http.StatusServiceUnavailable)
	}
}

func Test_AdminAPI_Check_AllIPSourcesFailed(t *testing.T) {
	app, cancel := testApp(t, failingIPSource{})
	defer cancel()

	a := &adminAPI{app: app, log: zap.NewNop()}
	err := a.handleCheck(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/dynamic_dns/check", nil))

	status, ok := apiErrStatus(err)
	if !ok {
		t.Fatalf("expected a caddy.APIError, got %v", err)
	}
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", status, http.StatusBadGateway)
	}
}

func Test_AdminAPI_Check_Success(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()

	prov.seed("example.com", "@", "192.0.2.99") // a stale value, so the check has work to do

	a := &adminAPI{app: app, log: zap.NewNop()}
	rec := httptest.NewRecorder()
	if err := a.handleCheck(rec,
		httptest.NewRequest(http.MethodPost, "/dynamic_dns/check", nil)); err != nil {
		t.Fatalf("handleCheck: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got CheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body %q: %v", rec.Body.String(), err)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "203.0.113.7" {
		t.Errorf("IPs = %v, want [203.0.113.7]", got.IPs)
	}
	if len(got.Updated) != 1 {
		t.Fatalf("Updated = %v, want 1 record", got.Updated)
	}
	if got.Updated[0].Zone != "example.com" || got.Updated[0].Name != "@" || got.Updated[0].Type != "A" {
		t.Errorf("unexpected record: %+v", got.Updated[0])
	}
	if rec, ok := prov.record("example.com", "@"); !ok || rec.IP.String() != "203.0.113.7" {
		t.Errorf("provider holds %v, want 203.0.113.7", rec)
	}
}

func Test_AdminAPI_Check_Cooldown(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.Cooldown = durationPtr(time.Hour)

	a := &adminAPI{app: app, log: zap.NewNop()}

	// The first request runs the check.
	first := httptest.NewRecorder()
	if err := a.handleCheck(first,
		httptest.NewRequest(http.MethodPost, "/dynamic_dns/check", nil)); err != nil {
		t.Fatalf("first handleCheck: %v", err)
	}
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}

	// An immediate second request must be rejected, not queued.
	second := httptest.NewRecorder()
	err := a.handleCheck(second,
		httptest.NewRequest(http.MethodPost, "/dynamic_dns/check", nil))

	status, ok := apiErrStatus(err)
	if !ok {
		t.Fatalf("expected a caddy.APIError, got %v", err)
	}
	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
	retryAfter := second.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Retry-After header is missing")
	} else if secs, err := strconv.Atoi(retryAfter); err != nil || secs < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", retryAfter)
	}
	if n := prov.setCount(); n != 1 {
		t.Errorf("SetRecords called %d times, want 1 (throttled request must do nothing)", n)
	}
}
