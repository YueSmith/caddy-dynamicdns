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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_NormalizeProviders(t *testing.T) {
	provider1 := json.RawMessage(`{"name":"test_dummy","arg":"one"}`)
	provider2 := json.RawMessage(`{"name":"test_dummy","arg":"two"}`)
	domains1 := map[string][]string{"example.com": {"@"}}
	domains2 := map[string][]string{"example.org": {"@", "www"}}

	tests := []struct {
		name    string
		app     App
		want    []Provider
		wantErr bool
	}{
		{
			name: "legacy: top-level provider and domains",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "legacy top-level provider combined with providers list",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains fold into a sole provider without domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "providers list only",
			app: App{
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains1},
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains conflict with per-provider domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains2},
				},
			},
			wantErr: true,
		},
		{
			name: "top-level domains with multiple providers",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
					{DNSProviderRaw: provider2},
				},
			},
			wantErr: true,
		},
		{
			name:    "no provider",
			app:     App{Domains: domains1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.app.normalizeProviders()
			if err != nil {
				if !tt.wantErr {
					t.Errorf("normalizeProviders() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("normalizeProviders() expected error, got none")
			}
			if diff := cmp.Diff(tt.app.Providers, tt.want, cmp.AllowUnexported(Provider{})); diff != "" {
				t.Errorf("normalizeProviders() diff(-got +want):\n%s", diff)
			}
		})
	}
}

func Test_IPRanges_Contains(t *testing.T) {
	type args struct {
		include []string
		exclude []string
	}
	tests := []struct {
		name    string
		ranges  args
		ip      string
		want    bool
		nilRecv bool
	}{
		// With no ranges configured, the default policy applies: only
		// global unicast, non-private addresses are allowed. This is the
		// case at runtime, where IPSettings embeds IPRanges by value, so
		// the receiver is never nil even though nothing was configured.
		{name: "default: public ipv4", ip: "1.2.3.4", want: true},
		{name: "default: public ipv6", ip: "2606:4700::1111", want: true},
		{name: "default: rejects ipv6 link-local", ip: "fe80::1234", want: false},
		{name: "default: rejects ipv4 link-local", ip: "169.254.1.1", want: false},
		{name: "default: rejects ipv6 loopback", ip: "::1", want: false},
		{name: "default: rejects ipv4 loopback", ip: "127.0.0.1", want: false},
		{name: "default: rejects ipv6 unique local", ip: "fc00::1", want: false},
		{name: "default: rejects ipv4 private", ip: "192.168.1.10", want: false},
		{name: "default: rejects ipv4 private 10/8", ip: "10.0.0.5", want: false},

		// Explicit excludes override the default and are applied as-is.
		{name: "exclude only: allows public", ranges: args{exclude: []string{"192.168.0.0/16"}}, ip: "1.2.3.4", want: true},
		{name: "exclude only: rejects excluded", ranges: args{exclude: []string{"192.168.0.0/16"}}, ip: "192.168.1.10", want: false},
		{name: "exclude only: rejects link-local when excluded", ranges: args{exclude: []string{"fe80::/10"}}, ip: "fe80::1234", want: false},

		// Include-only: anything outside the include list is rejected.
		{name: "include only: allows included", ranges: args{include: []string{"192.168.0.0/16"}}, ip: "192.168.1.10", want: true},
		{name: "include only: rejects outside", ranges: args{include: []string{"192.168.0.0/16"}}, ip: "1.2.3.4", want: false},

		// Most specific match wins.
		{name: "include and exclude: exclude is more specific", ranges: args{include: []string{"192.168.0.0/16"}, exclude: []string{"192.168.10.0/24"}}, ip: "192.168.10.5", want: false},
		{name: "include and exclude: inside include only", ranges: args{include: []string{"192.168.0.0/16"}, exclude: []string{"192.168.10.0/24"}}, ip: "192.168.1.5", want: true},

		// The documented nil-receiver default must keep working for
		// callers that hold a *IPRanges.
		{name: "nil receiver: rejects link-local", nilRecv: true, ip: "fe80::1234", want: false},
		{name: "nil receiver: allows public", nilRecv: true, ip: "1.2.3.4", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			r := IPRanges{}
			for _, cidr := range tt.ranges.include {
				r.Include = append(r.Include, netip.MustParsePrefix(cidr))
			}
			for _, cidr := range tt.ranges.exclude {
				r.Exclude = append(r.Exclude, netip.MustParsePrefix(cidr))
			}

			var got bool
			if tt.nilRecv {
				var nilR *IPRanges
				got = nilR.Contains(ip)
			} else {
				got = r.Contains(ip)
			}
			if got != tt.want {
				t.Errorf("IPRanges.Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}

			// The same result must be produced through IPSettings, which
			// is how IP sources actually invoke it. This is the regression
			// guard for the default policy being silently disabled by the
			// value-embedded receiver never being nil.
			if !tt.nilRecv {
				settings := IPSettings{r, IPVersions{}}
				if got := settings.Contains(ip); got != tt.want {
					t.Errorf("IPSettings.Contains(%s) = %v, want %v", tt.ip, got, tt.want)
				}
			}
		})
	}
}

// countingIPSource is an IPSource that counts how many times it was asked
// for IPs, letting tests observe whether the checker loop is running.
type countingIPSource struct {
	mu    sync.Mutex
	calls int
}

func (s *countingIPSource) GetIPs(_ context.Context, _ IPSettings) ([]netip.Addr, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
}

func (s *countingIPSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.test_counting",
		New: func() caddy.Module { return new(countingIPSource) },
	}
}

func (s *countingIPSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// waitFor polls cond until it returns true or the deadline elapses.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// durationPtr returns a pointer to a caddy.Duration, for the Cooldown field.
func durationPtr(d time.Duration) *caddy.Duration {
	v := caddy.Duration(d)
	return &v
}

// testApp returns an App that is assembled the way Provision would, except
// that the cooldown is switched off so that the reconciliation tests are
// deterministic. Cooldown behaviour is covered separately.
func testApp(t *testing.T, src IPSource) (*App, context.CancelFunc) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	return &App{
		ctx:           ctx,
		logger:        zap.NewNop(),
		CheckInterval: caddy.Duration(10 * time.Millisecond),
		Cooldown:      durationPtr(0),
		ipSources:     []IPSource{src},
		checks:        new(checkerState),
	}, cancel
}

// assertStopped checks that the checker loop makes no further progress.
func assertStopped(t *testing.T, src *countingIPSource, when string) {
	t.Helper()
	// give any in-flight check a chance to finish before sampling
	time.Sleep(50 * time.Millisecond)
	before := src.count()
	time.Sleep(200 * time.Millisecond)
	if after := src.count(); after != before {
		t.Errorf("checker loop still running %s: call count went %d -> %d", when, before, after)
	}
}

func Test_App_StopStopsCheckerLoop(t *testing.T) {
	src := new(countingIPSource)
	app, cancel := testApp(t, src)
	defer cancel()

	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(t, func() bool { return src.count() >= 3 }) {
		t.Fatalf("checker loop did not run after Start (calls=%d)", src.count())
	}

	// Stop must stop the loop on its own, without relying on the context
	// being cancelled: Caddy calls Stop on apps that were already started
	// when another app fails to start, and does not cancel ctx there.
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	assertStopped(t, src, "after Stop")

	// Stop must be idempotent.
	if err := app.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	assertStopped(t, src, "after second Stop")

	// Start on an already-started app must not launch a second loop, and
	// must not resurrect one that was stopped.
	if err := app.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	assertStopped(t, src, "after a second Start")
}

func Test_App_CtxCancelStopsCheckerLoop(t *testing.T) {
	src := new(countingIPSource)
	app, cancel := testApp(t, src)

	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(t, func() bool { return src.count() >= 3 }) {
		t.Fatalf("checker loop did not run after Start (calls=%d)", src.count())
	}

	cancel()
	assertStopped(t, src, "after ctx cancellation")
}

func Test_App_StopWithoutStart(t *testing.T) {
	src := new(countingIPSource)
	app, cancel := testApp(t, src)
	defer cancel()

	// Stop before Start must be a no-op, not a panic.
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	assertStopped(t, src, "after Stop before Start")
}

// failingIPSource is an IPSource that always fails, so tests can exercise
// the "all IP sources failed" path.
type failingIPSource struct{}

func (failingIPSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.test_failing",
		New: func() caddy.Module { return failingIPSource{} },
	}
}

func (failingIPSource) GetIPs(_ context.Context, _ IPSettings) ([]netip.Addr, error) {
	return nil, fmt.Errorf("no network")
}

// recordingProvider is a stand-in DNS provider that behaves like a server:
// it remembers the records it holds, so GetRecords reports whatever
// SetRecords last wrote. Either operation can be made to fail.
type recordingProvider struct {
	mu       sync.Mutex
	existing map[string]libdns.Address // absolute name -> record
	setCalls int
	getCalls int
	getErr   error
	setErr   error
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{existing: make(map[string]libdns.Address)}
}

// seed makes the provider already hold a record, as if it had been set by
// something other than this app.
func (p *recordingProvider) seed(zone, name, ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.existing[libdns.AbsoluteName(name, zone)] = libdns.Address{
		Name: name,
		TTL:  10 * time.Minute,
		IP:   netip.MustParseAddr(ip),
	}
}

func (p *recordingProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getCalls++
	if p.getErr != nil {
		return nil, p.getErr
	}
	recs := make([]libdns.Record, 0, len(p.existing))
	for _, rec := range p.existing {
		recs = append(recs, rec)
	}
	return recs, nil
}

func (p *recordingProvider) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setCalls++
	if p.setErr != nil {
		return nil, p.setErr
	}
	for _, rec := range recs {
		addr, ok := rec.(libdns.Address)
		if !ok {
			continue
		}
		p.existing[libdns.AbsoluteName(addr.Name, zone)] = addr
	}
	return recs, nil
}

// record returns what the provider currently holds for a name.
func (p *recordingProvider) record(zone, name string) (libdns.Address, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.existing[libdns.AbsoluteName(name, zone)]
	return rec, ok
}

func (p *recordingProvider) setCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.setCalls
}

// providerApp returns an App ready to run a check against prov. Its IP
// source reports 203.0.113.7.
func providerApp(t *testing.T, prov *recordingProvider, domains map[string][]string) (*App, context.CancelFunc) {
	t.Helper()
	app, cancel := testApp(t, &countingIPSource{})
	app.TTL = caddy.Duration(time.Hour)
	app.Providers = []Provider{{Domains: domains, dnsProvider: prov}}
	return app, cancel
}

func Test_CheckIPAndUpdateDNS_WritesMissingRecords(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@", "www"}})
	defer cancel()

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}

	if diff := cmp.Diff(result.IPs, []string{"203.0.113.7"}); diff != "" {
		t.Errorf("IPs diff (-got +want):\n%s", diff)
	}
	want := []UpdatedRecord{
		{Zone: "example.com", Name: "@", Type: "A", IP: "203.0.113.7", TTL: "1h0m0s"},
		{Zone: "example.com", Name: "www", Type: "A", IP: "203.0.113.7", TTL: "1h0m0s"},
	}
	if diff := cmp.Diff(result.Updated, want); diff != "" {
		t.Errorf("Updated diff (-got +want):\n%s", diff)
	}
	if len(result.Errors) != 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}

	// The zone is now correct, so a second check must not write anything.
	result2, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("second checkIPAndUpdateDNS: %v", err)
	}
	if len(result2.Updated) != 0 {
		t.Errorf("expected no updates on second check, got %v", result2.Updated)
	}
	if n := prov.setCount(); n != 1 {
		t.Errorf("SetRecords called %d times, want 1", n)
	}
}

func Test_CheckIPAndUpdateDNS_LeavesCorrectRecordsAlone(t *testing.T) {
	prov := newRecordingProvider()
	prov.seed("example.com", "@", "203.0.113.7") // already the current IP
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if len(result.Updated) != 0 {
		t.Errorf("expected no updates, got %v", result.Updated)
	}
	if n := prov.setCount(); n != 0 {
		t.Errorf("SetRecords called %d times, want 0", n)
	}
}

// Test_CheckIPAndUpdateDNS_RepairsOutOfBandChange covers the reason for
// reading the provider on every check: the zone is the source of truth,
// not anything this process remembers, so a record edited by hand (or by
// another tool) is noticed and put back.
func Test_CheckIPAndUpdateDNS_RepairsOutOfBandChange(t *testing.T) {
	prov := newRecordingProvider()
	prov.seed("example.com", "@", "192.0.2.99")
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if len(result.Updated) != 1 || result.Updated[0].IP != "203.0.113.7" {
		t.Fatalf("expected the record to be repaired, got %v", result.Updated)
	}
	rec, ok := prov.record("example.com", "@")
	if !ok || rec.IP.String() != "203.0.113.7" {
		t.Errorf("provider holds %v, want 203.0.113.7", rec)
	}
}

func Test_CheckIPAndUpdateDNS_UpdateOnlyDoesNotCreateMissingRecords(t *testing.T) {
	prov := newRecordingProvider() // the record does not exist
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.UpdateOnly = true

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if len(result.Updated) != 0 {
		t.Errorf("update_only must not create records, but updated %v", result.Updated)
	}
	if len(result.Errors) != 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
	if n := prov.setCount(); n != 0 {
		t.Errorf("SetRecords called %d times, want 0", n)
	}
}

func Test_CheckIPAndUpdateDNS_UpdateOnlyUpdatesExistingRecords(t *testing.T) {
	prov := newRecordingProvider()
	prov.seed("example.com", "@", "192.0.2.99")
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.UpdateOnly = true

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if len(result.Updated) != 1 {
		t.Fatalf("expected the existing record to be updated, got %v", result.Updated)
	}
}

// Test_CheckIPAndUpdateDNS_ReadFailureSkipsZone: when a zone cannot be
// read, nothing is known about it, so it must be left alone rather than
// treated as empty.
func Test_CheckIPAndUpdateDNS_ReadFailureSkipsZone(t *testing.T) {
	prov := newRecordingProvider()
	prov.getErr = fmt.Errorf("provider unavailable")
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if n := prov.setCount(); n != 0 {
		t.Errorf("SetRecords called %d times after a failed read, want 0", n)
	}
	if len(result.Updated) != 0 {
		t.Errorf("expected no updates, got %v", result.Updated)
	}
	if len(result.Errors) != 1 || result.Errors[0].Zone != "example.com" {
		t.Errorf("expected one error for example.com, got %v", result.Errors)
	}
}

func Test_CheckIPAndUpdateDNS_WriteFailureIsReportedAndRetried(t *testing.T) {
	prov := newRecordingProvider()
	prov.setErr = fmt.Errorf("zone not found")
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()

	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if len(result.Updated) != 0 {
		t.Errorf("expected no updated records on failure, got %v", result.Updated)
	}
	if len(result.Errors) != 1 || result.Errors[0].Zone != "example.com" {
		t.Fatalf("expected one error for example.com, got %v", result.Errors)
	}

	// The failed update must be attempted again on the next check.
	if _, err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("second checkIPAndUpdateDNS: %v", err)
	}
	if n := prov.setCount(); n != 2 {
		t.Errorf("SetRecords called %d times, want 2 (failed update must be retried)", n)
	}
}

func Test_CheckIPAndUpdateDNS_AllSourcesFailed(t *testing.T) {
	app, cancel := testApp(t, failingIPSource{})
	defer cancel()

	if _, err := app.checkIPAndUpdateDNS(); err == nil {
		t.Fatal("expected an error when all IP sources fail")
	}
}

func Test_CheckIPAndUpdateDNS_Cooldown(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.Cooldown = durationPtr(time.Hour)

	if _, err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("first check should run: %v", err)
	}
	if n := prov.setCount(); n != 1 {
		t.Fatalf("SetRecords called %d times, want 1", n)
	}

	// A second check right away must be skipped, not performed.
	_, err := app.checkIPAndUpdateDNS()
	if !errors.Is(err, ErrCooldown) {
		t.Fatalf("second check: got %v, want ErrCooldown", err)
	}
	var cdErr cooldownError
	if !errors.As(err, &cdErr) || cdErr.remaining <= 0 || cdErr.remaining > time.Hour {
		t.Errorf("cooldownError remaining = %v, want something in (0, 1h]", cdErr.remaining)
	}
	if n := prov.setCount(); n != 1 {
		t.Errorf("SetRecords called %d times, want 1 (throttled check must do nothing)", n)
	}
}

func Test_CheckIPAndUpdateDNS_CooldownZeroDisablesThrottle(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.Cooldown = durationPtr(0)

	if _, err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("first check: %v", err)
	}

	// The record drifts, and a second check right away must still repair it:
	// with the throttle disabled there is no cooldown to wait out.
	prov.seed("example.com", "@", "192.0.2.99")
	result, err := app.checkIPAndUpdateDNS()
	if err != nil {
		t.Fatalf("second check should not be throttled: %v", err)
	}
	if len(result.Updated) != 1 {
		t.Errorf("expected the drift to be repaired immediately, got %v", result.Updated)
	}
}

// Test_CheckIPAndUpdateDNS_CooldownIsPerInstance documents that the cooldown
// belongs to an app instance: a config reload builds a new one, whose first
// check therefore runs rather than being throttled by the previous config.
func Test_CheckIPAndUpdateDNS_CooldownIsPerInstance(t *testing.T) {
	prov := newRecordingProvider()

	first, cancelFirst := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancelFirst()
	first.Cooldown = durationPtr(time.Hour)
	if _, err := first.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("first instance check: %v", err)
	}

	// A different instance must not be affected by the first one's cooldown.
	second, cancelSecond := providerApp(t, prov, map[string][]string{"example.com": {"www"}})
	defer cancelSecond()
	second.Cooldown = durationPtr(time.Hour)
	if _, err := second.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("second instance check should not be throttled: %v", err)
	}
}

// Test_CheckNow_IgnoresCooldown covers the first check after a config load.
func Test_CheckNow_IgnoresCooldown(t *testing.T) {
	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.Cooldown = durationPtr(time.Hour)

	if _, err := app.checkNow(); err != nil {
		t.Fatalf("checkNow: %v", err)
	}
	// Even though the cooldown has just started, a config-load check runs.
	prov.seed("example.com", "@", "192.0.2.99")
	result, err := app.checkNow()
	if err != nil {
		t.Fatalf("second checkNow: %v", err)
	}
	if len(result.Updated) != 1 {
		t.Errorf("expected checkNow to ignore the cooldown, got %v", result.Updated)
	}
}

// readOnlyProvider implements libdns.RecordGetter but not RecordSetter.
type readOnlyProvider struct{}

func (readOnlyProvider) GetRecords(context.Context, string) ([]libdns.Record, error) {
	return nil, nil
}

// writeOnlyProvider implements libdns.RecordSetter but not RecordGetter.
type writeOnlyProvider struct{}

func (writeOnlyProvider) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// acmeOnlyProvider mimics the ACME-only providers (dode, ednsde, nanelo,
// google_domains): it can append and delete challenge records, but neither
// read nor set them, so it is unusable for dynamic DNS.
type acmeOnlyProvider struct{}

func (acmeOnlyProvider) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func (acmeOnlyProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func Test_AsDNSProvider_RequiresBothReadAndWrite(t *testing.T) {
	both := newRecordingProvider()
	prov, err := asDNSProvider(both)
	if err != nil {
		t.Fatalf("a provider supporting both operations must be accepted: %v", err)
	}
	if prov != dnsProvider(both) {
		t.Error("asDNSProvider returned a different provider")
	}

	for name, val := range map[string]any{
		"read only":      readOnlyProvider{},
		"write only":     writeOnlyProvider{},
		"neither (ACME)": acmeOnlyProvider{},
	} {
		_, err := asDNSProvider(val)
		if err == nil {
			t.Errorf("%s: expected an error, got none", name)
			continue
		}
		t.Logf("%s -> %v", name, err)
	}
}

func Test_IsCtxError(t *testing.T) {
	ctxErrs := []error{context.Canceled, context.DeadlineExceeded}
	for _, err := range ctxErrs {
		if !isCtxError(err) {
			t.Errorf("isCtxError(%v) = false, want true", err)
		}
		// the app wraps IP source failures
		if !isCtxError(fmt.Errorf("all IP sources failed: %w", err)) {
			t.Errorf("isCtxError(wrapped %v) = false, want true", err)
		}
	}

	otherErrs := []error{nil, fmt.Errorf("provider unavailable"), ErrCooldown}
	for _, err := range otherErrs {
		if isCtxError(err) {
			t.Errorf("isCtxError(%v) = true, want false", err)
		}
	}
}

// Test_LogCheckFailure covers that a check interrupted by a reload or shutdown
// is not reported as an error.
func Test_LogCheckFailure(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)

	prov := newRecordingProvider()
	app, cancel := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	defer cancel()
	app.logger = zap.New(core)

	readLogs := func() *observer.ObservedLogs {
		return logs.FilterMessage("unable to read DNS records")
	}

	// A genuine failure is an error.
	prov.getErr = fmt.Errorf("provider unavailable")
	if _, err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if n := readLogs().FilterLevelExact(zapcore.ErrorLevel).Len(); n != 1 {
		t.Errorf("genuine read failure: got %d error-level entries, want 1 (%v)",
			n, readLogs().AllUntimed())
	}

	// A context cancellation is only informational.
	logs.TakeAll()
	prov.getErr = context.Canceled
	if _, err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if n := readLogs().FilterLevelExact(zapcore.ErrorLevel).Len(); n != 0 {
		t.Errorf("cancelled read logged at error level: %v", readLogs().AllUntimed())
	}
	if n := readLogs().FilterLevelExact(zapcore.InfoLevel).Len(); n != 1 {
		t.Errorf("cancelled read: got %d info-level entries, want 1 (%v)",
			n, readLogs().AllUntimed())
	}

	// So is an ordinary error raised while the app is being torn down. This is
	// what actually happens on a reload: Caddy cancels the context with a
	// "stopping apps" cause, so the failure is not a context.Canceled value.
	logs.TakeAll()
	app2, cancel2 := providerApp(t, prov, map[string][]string{"example.com": {"@"}})
	app2.logger = zap.New(core)
	cancel2()
	prov.getErr = fmt.Errorf(`Post "https://dnspod.tencentcloudapi.com": stopping apps`)
	if _, err := app2.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("checkIPAndUpdateDNS: %v", err)
	}
	if n := readLogs().FilterLevelExact(zapcore.ErrorLevel).Len(); n != 0 {
		t.Errorf("a check interrupted by teardown logged at error level: %v", readLogs().AllUntimed())
	}
	if n := readLogs().FilterLevelExact(zapcore.InfoLevel).Len(); n != 1 {
		t.Errorf("interrupted check: got %d info-level entries, want 1 (%v)",
			n, readLogs().AllUntimed())
	}
	if n := prov.setCount(); n != 0 {
		t.Errorf("an interrupted check must not write anything, SetRecords called %d times", n)
	}
}
