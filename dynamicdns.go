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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that keeps your DNS records updated with the public
// IP address of your instance. It updates A and AAAA records.
type App struct {
	// The sources from which to get the server's public IP address.
	// Multiple sources can be specified for redundancy.
	// Default: simple_http
	IPSourcesRaw []json.RawMessage `json:"ip_sources,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`

	// The configuration for the DNS provider with which the DNS
	// records will be updated. If set, it is treated as a single
	// entry in Providers, together with the top-level Domains.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The record names, keyed by DNS zone, for which to update the A/AAAA records.
	// Record names are relative to the zone. The zone is usually your registered
	// domain name. To refer to the zone itself, use the record name of "@".
	//
	// For example, assuming your zone is example.com, and you want to update A/AAAA
	// records for "example.com" and "www.example.com" so that they resolve to this
	// Caddy instance, configure like so: `"example.com": ["@", "www"]`
	//
	// These domains belong to the DNS provider configured by dns_provider.
	// When using multiple providers, configure domains per entry in Providers
	// instead.
	Domains map[string][]string `json:"domains,omitempty"`

	// The list of DNS providers, each managing its own set of domains.
	// This allows updating DNS records across multiple DNS providers, or
	// multiple accounts of the same provider. The dns_provider and domains
	// fields above are equivalent to a single entry in this list.
	Providers []Provider `json:"providers,omitempty"`

	// If enabled, no new DNS records will be created. Only existing records will be updated.
	// This means that the A or AAAA records need to be created manually ahead of time.
	UpdateOnly bool `json:"update_only,omitempty"`

	// If enabled, the "http" app's config will be scanned to assemble the list
	// of domains for which to enable dynamic DNS updates.
	DynamicDomains bool `json:"dynamic_domains,omitempty"`

	// The IP versions to enable. By default, both "ipv4" and "ipv6" will be enabled.
	// To disable IPv6, specify {"ipv6": false}.
	Versions IPVersions `json:"versions,omitempty"`

	// The IP ranges to include and exclude
	IPRanges `json:",omitzero"`

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The minimum time between two IP checks, so that repeated requests
	// cannot hammer the DNS provider. A check that arrives sooner than this
	// is skipped, and the admin API answers with 429 Too Many Requests. The
	// first check after a config load always runs, regardless. Set to 0 to
	// disable the throttle. Default: 30s
	Cooldown *caddy.Duration `json:"cooldown,omitempty"`

	// The TTL to set on DNS records.
	TTL caddy.Duration `json:"ttl,omitempty"`

	ipSources []IPSource

	ctx    caddy.Context
	logger *zap.Logger

	// done is closed to tell checkerLoop to exit. It is derived from ctx
	// by Start, so cancelling ctx (e.g. when Caddy unloads the config)
	// closes it too. Stop closes it via cancel, which matters because
	// Caddy calls Stop on apps that were already started when a different
	// app fails to start, and that code path does not cancel ctx.
	done   <-chan struct{}
	cancel context.CancelFunc

	// checks serializes checks and enforces the cooldown between them. It is
	// a pointer because App is copied by value in several places.
	checks *checkerState
}

// Provider associates a DNS provider with the record names,
// keyed by DNS zone, that it manages.
type Provider struct {
	// The configuration for the DNS provider with which the DNS
	// records will be updated.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The record names, keyed by DNS zone, for which to update the A/AAAA records.
	// Record names are relative to the zone. The zone is usually your registered
	// domain name. To refer to the zone itself, use the record name of "@".
	//
	// For example, assuming your zone is example.com, and you want to update A/AAAA
	// records for "example.com" and "www.example.com" so that they resolve to this
	// Caddy instance, configure like so: `"example.com": ["@", "www"]`
	Domains map[string][]string `json:"domains,omitempty"`

	dnsProvider dnsProvider
}

// dnsProvider is the set of capabilities the app requires of a DNS
// provider. Both are needed: every check compares the zone against the
// provider's own view of it, so a provider must be able to read the
// current records as well as write new ones.
type dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordSetter
}

// asDNSProvider validates that a loaded DNS provider module has the
// capabilities this app requires.
//
// Providers that cannot both read and write records are rejected here so
// that using one is a clear error while loading the config, rather than a
// panic or a silently half-working setup. This notably covers the ACME-only
// providers (e.g. dode, ednsde, nanelo, google_domains), which can only
// append and delete _acme-challenge TXT records.
func asDNSProvider(val any) (dnsProvider, error) {
	if prov, ok := val.(dnsProvider); ok {
		return prov, nil
	}

	var caps []string
	if _, ok := val.(libdns.RecordGetter); ok {
		caps = append(caps, "read")
	}
	if _, ok := val.(libdns.RecordSetter); ok {
		caps = append(caps, "write")
	}
	supported := "can neither read nor write records"
	switch len(caps) {
	case 1:
		supported = "can only " + caps[0] + " records"
	case 2:
		supported = "can read and write records"
	}

	return nil, fmt.Errorf("DNS provider %q cannot be used with dynamic_dns: it %s, "+
		"but dynamic_dns needs a provider that implements both libdns.RecordGetter "+
		"and libdns.RecordSetter so it can compare records before updating them",
		moduleName(val), supported)
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app module.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger(a)
	a.checks = new(checkerState)

	if err := a.normalizeProviders(); err != nil {
		return err
	}

	// set up the DNS provider modules
	for i := range a.Providers {
		if len(a.Providers[i].DNSProviderRaw) == 0 {
			return fmt.Errorf("provider %d: a DNS provider is required", i)
		}
		val, err := ctx.LoadModule(&a.Providers[i], "DNSProviderRaw")
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %v", err)
		}
		prov, err := asDNSProvider(val)
		if err != nil {
			return err
		}
		a.Providers[i].dnsProvider = prov
	}

	// set up the IP source module or use a default
	if a.IPSourcesRaw != nil {
		vals, err := ctx.LoadModule(a, "IPSourcesRaw")
		if err != nil {
			return fmt.Errorf("loading IP source module: %v", err)
		}
		for _, val := range vals.([]any) {
			a.ipSources = append(a.ipSources, val.(IPSource))
		}
	}
	if len(a.ipSources) == 0 {
		var sh SimpleHTTP
		if err := sh.Provision(ctx); err != nil {
			return err
		}
		a.ipSources = []IPSource{sh}
	}

	// make sure a check interval is set
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(defaultCheckInterval)
	}
	if time.Duration(a.CheckInterval) < time.Second {
		return fmt.Errorf("check interval must be at least 1 second")
	}

	if a.Cooldown != nil && time.Duration(*a.Cooldown) < 0 {
		return fmt.Errorf("cooldown cannot be negative")
	}
	if cd := a.cooldown(); cd >= time.Duration(a.CheckInterval) {
		a.logger.Warn("cooldown is not shorter than the check interval; periodic checks will be skipped",
			zap.Duration("cooldown", cd),
			zap.Duration("check_interval", time.Duration(a.CheckInterval)))
	}

	return nil
}

// normalizeProviders folds the legacy single-provider config (top-level
// dns_provider and domains) into the providers list and validates the
// result.
func (a *App) normalizeProviders() error {
	if len(a.DNSProviderRaw) > 0 {
		a.Providers = append([]Provider{{DNSProviderRaw: a.DNSProviderRaw, Domains: a.Domains}}, a.Providers...)
	} else if len(a.Domains) > 0 {
		// top-level domains without a top-level provider can only belong
		// to a sole provider that has no domains of its own
		if len(a.Providers) == 1 && a.Providers[0].Domains == nil {
			a.Providers[0].Domains = a.Domains
		} else {
			return fmt.Errorf("with multiple providers, domains must be configured per provider")
		}
	}
	if len(a.Providers) == 0 {
		return fmt.Errorf("a DNS provider is required")
	}
	return nil
}

// Start starts the app module. It launches the checker loop, which runs
// until Stop is called or the app's context is cancelled.
//
// Start is idempotent: calling it again on an already-started app does
// nothing, so the checker loop can never be started more than once.
func (a *App) Start() error {
	if a.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.done = ctx.Done()
	a.cancel = cancel
	go a.checkerLoop()
	return nil
}

// Stop stops the app module's checker loop. It is idempotent and safe to
// call even if Start was never called, since context.CancelFunc is
// idempotent and safe for concurrent use.
func (a *App) Stop() error {
	if a.cancel != nil {
		a.cancel()
	}
	return nil
}

// checkerLoop checks the public IP address at every check
// interval. It stops when a.ctx is cancelled or Stop is called.
func (a App) checkerLoop() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()

	// Initial check with retry on failure (e.g., network not ready on boot)
	const (
		initialBackoff = 5 * time.Second
		maxBackoff     = 5 * time.Minute
	)
	backoff := initialBackoff

initLoop:
	for {
		// The first check after a config load runs unconditionally, so that
		// loading a config takes effect immediately instead of waiting out a
		// cooldown left over from the previous config.
		if _, err := a.checkNow(); err == nil {
			break initLoop
		} else if a.checkInterrupted(err) {
			// The app is being stopped or reloaded; the select below returns.
			a.logger.Info("initial IP lookup interrupted", zap.Error(err))
		} else {
			a.logger.Warn("initial IP lookup failed, will retry",
				zap.Duration("in", backoff),
				zap.Error(err))
		}

		select {
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		case <-ticker.C:
			// Regular interval hit during retry - reset backoff and try immediately
			backoff = initialBackoff
		case <-a.done:
			return
		}
	}

	for {
		select {
		case <-ticker.C:
			if _, err := a.checkIPAndUpdateDNS(); err != nil {
				if errors.Is(err, ErrCooldown) {
					a.logger.Debug("skipping check; cooldown is in effect", zap.Error(err))
				} else {
					a.logCheckFailure("checking IP address", err)
				}
			}
		case <-a.done:
			return
		}
	}
}

// CheckResult is the outcome of a single IP check and DNS update pass.
// It is also the JSON body returned by the /dynamic_dns/check admin
// endpoint.
type CheckResult struct {
	// IPs are the public IP addresses used for this check.
	IPs []string `json:"ips"`

	// Updated lists the DNS records that were written, sorted by zone,
	// name and type. It is empty if every record was already correct.
	Updated []UpdatedRecord `json:"updated,omitempty"`

	// Errors lists per-zone failures: a zone whose records could not be
	// read, or whose records could not be written. Failing one zone does
	// not stop the others, so a check can partially succeed.
	Errors []ZoneError `json:"errors,omitempty"`
}

// UpdatedRecord describes a DNS record that was written.
type UpdatedRecord struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Type string `json:"type"`
	IP   string `json:"ip"`
	TTL  string `json:"ttl,omitempty"`
}

// ZoneError describes a zone that could not be reconciled, either because
// its records could not be read or because the update could not be written.
type ZoneError struct {
	Zone  string `json:"zone"`
	Error string `json:"error"`
}

// ErrCooldown is returned (wrapped) when a check is skipped because the
// configured cooldown has not yet elapsed.
var ErrCooldown = errors.New("cooldown in effect")

// cooldownError reports how much of the cooldown is left.
type cooldownError struct {
	remaining time.Duration
}

func (e cooldownError) Error() string {
	return fmt.Sprintf("%s: try again in %s", ErrCooldown, e.remaining.Round(time.Second))
}

func (e cooldownError) Unwrap() error { return ErrCooldown }

// checkerState is the per-instance state that serializes checks and records
// when the last one ran, so that the cooldown can be enforced.
type checkerState struct {
	mu      sync.Mutex
	lastRun time.Time
}

// cooldown returns the minimum time between checks. A nil Cooldown selects
// the default; an explicit 0 disables the throttle.
func (a App) cooldown() time.Duration {
	if a.Cooldown == nil {
		return defaultCooldown
	}
	return time.Duration(*a.Cooldown)
}

// checkIPAndUpdateDNS reconciles the DNS records with the current public IP
// addresses, unless the cooldown is still in effect, in which case nothing
// is done and a cooldownError is returned.
//
// The periodic loop and the admin endpoint both go through here, so neither
// can hammer the DNS provider with repeated checks.
func (a App) checkIPAndUpdateDNS() (CheckResult, error) {
	checks := a.checkerState()

	checks.mu.Lock()
	defer checks.mu.Unlock()

	if cooldown := a.cooldown(); cooldown > 0 {
		if remaining := cooldown - time.Since(checks.lastRun); remaining > 0 {
			return CheckResult{}, cooldownError{remaining: remaining}
		}
	}

	return a.check(checks)
}

// checkNow reconciles the DNS records unconditionally, ignoring the cooldown.
// It is used for the first check after a config load, which must take effect
// immediately.
func (a App) checkNow() (CheckResult, error) {
	checks := a.checkerState()

	checks.mu.Lock()
	defer checks.mu.Unlock()

	return a.check(checks)
}

// checkerState returns the app's checker state. The fallback only applies to
// an app that was never provisioned (which happens when one is assembled
// directly, as in tests).
func (a App) checkerState() *checkerState {
	if a.checks == nil {
		return new(checkerState)
	}
	return a.checks
}

// check is the actual work of a check. The caller must hold checks.mu, and is
// responsible for having applied the cooldown.
func (a App) check(checks *checkerState) (CheckResult, error) {
	checks.lastRun = time.Now()

	a.logger.Debug("beginning IP address check")

	currentIPs, err := a.currentIPs()
	if err != nil {
		return CheckResult{}, err
	}

	result := CheckResult{IPs: make([]string, len(currentIPs))}
	for i, ip := range currentIPs {
		result.IPs[i] = ip.String()
	}

	var unchanged, skipped int
	for i := range a.Providers {
		u, s := a.reconcileProvider(&a.Providers[i], currentIPs, &result)
		unchanged += u
		skipped += s
	}

	// keep the reported order deterministic regardless of map ordering
	slices.SortFunc(result.Updated, func(a, b UpdatedRecord) int {
		if c := strings.Compare(a.Zone, b.Zone); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Type, b.Type)
	})

	a.logger.Info("finished updating DNS",
		zap.Strings("current_ips", result.IPs),
		zap.Int("updated", len(result.Updated)),
		zap.Int("unchanged", unchanged),
		zap.Int("skipped", skipped),
		zap.Int("failed", len(result.Errors)),
	)

	return result, nil
}

// currentIPs returns the public IP addresses reported by the first IP
// source that succeeds, or an error if they all fail.
func (a App) currentIPs() ([]netip.Addr, error) {
	var lastErr error
	for _, ipSrc := range a.ipSources {
		ipSettings := IPSettings{a.IPRanges, a.Versions}
		ips, err := ipSrc.GetIPs(a.ctx, ipSettings)
		if err == nil && len(ips) > 0 {
			return removeDuplicateIPs(ips), nil
		}
		if err == nil {
			err = fmt.Errorf("no IP addresses returned")
		}
		lastErr = err
		a.logCheckFailure("looking up IP address", err,
			zap.String("ip_source", moduleName(ipSrc)))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no IP sources are configured")
	}
	return nil, fmt.Errorf("all IP sources failed: %w", lastErr)
}

// reconcileProvider brings the records of every zone managed by p in line
// with currentIPs. It returns how many record decisions came out as "already
// correct" and as "skipped". Failures are logged and reported in result.
func (a App) reconcileProvider(p *Provider, currentIPs []netip.Addr, result *CheckResult) (unchanged, skipped int) {
	for zone, names := range a.allDomainsFor(p) {
		// The provider is the only authority on what currently exists, so
		// ask it once per zone per check. If the read fails we know nothing
		// about the zone and must leave it alone: treating it as empty
		// could recreate records that were deleted on purpose, or overwrite
		// records that are already correct.
		observed, err := a.readZone(p, zone)
		if err != nil {
			a.logCheckFailure("unable to read DNS records", err, zap.String("zone", zone))
			if result != nil {
				result.Errors = append(result.Errors, ZoneError{Zone: zone, Error: err.Error()})
			}
			continue
		}
		u, s := a.reconcileZone(p, zone, names, observed, currentIPs, result)
		unchanged += u
		skipped += s
	}
	return unchanged, skipped
}

// zoneRecords is a zone as the provider reports it: absolute record name,
// then record type, to IP address.
type zoneRecords map[string]map[string]netip.Addr

// readZone returns the provider's current view of a zone.
func (a App) readZone(p *Provider, zone string) (zoneRecords, error) {
	recs, err := p.dnsProvider.GetRecords(a.ctx, zone)
	if err != nil {
		return nil, err
	}

	observed := make(zoneRecords)
	for _, rec := range recs {
		addr, ok := rec.(libdns.Address)
		if !ok {
			// not an A/AAAA record, so not one of ours
			continue
		}
		ip := addr.IP.Unmap()
		name := libdns.AbsoluteName(addr.Name, zone)
		if observed[name] == nil {
			observed[name] = make(map[string]netip.Addr)
		}
		observed[name][recordType(ip)] = ip
		a.logger.Debug("found existing DNS record",
			zap.String("zone", zone),
			zap.String("name", addr.Name),
			zap.String("type", recordType(ip)),
			zap.String("ip", ip.String()))
	}
	return observed, nil
}

// reconcileZone writes the records of one zone that differ from what the
// provider currently reports. It returns how many of the zone's records were
// already correct and how many were skipped because update_only is set.
func (a App) reconcileZone(p *Provider, zone string, names []string, observed zoneRecords, currentIPs []netip.Addr, result *CheckResult) (unchanged, skipped int) {
	var toSet []libdns.Address
	for _, ip := range currentIPs {
		recType := recordType(ip)
		for _, name := range names {
			existing, exists := observed[libdns.AbsoluteName(name, zone)][recType]
			switch {
			case !exists && a.UpdateOnly:
				skipped++
				a.logger.Info("record doesn't exist; skipping update",
					zap.String("zone", zone),
					zap.String("name", name),
					zap.String("type", recType),
				)
				continue
			case exists && existing == ip:
				unchanged++
				a.logger.Info("DNS record is already up to date",
					zap.String("zone", zone),
					zap.String("name", name),
					zap.String("type", recType),
					zap.String("ip", ip.String()),
				)
				continue
			}

			toSet = append(toSet, libdns.Address{
				Name: name,
				TTL:  time.Duration(a.TTL),
				IP:   ip,
			})
		}
	}

	if len(toSet) == 0 {
		a.logger.Debug("no DNS records need updating", zap.String("zone", zone))
		return unchanged, skipped
	}

	records := make([]libdns.Record, len(toSet))
	for i, rec := range toSet {
		a.logger.Info("updating DNS record",
			zap.String("zone", zone),
			zap.String("type", recordType(rec.IP)),
			zap.String("name", rec.Name),
			zap.String("ip", rec.IP.String()),
			zap.Duration("ttl", rec.TTL),
		)
		records[i] = rec
	}

	if _, err := p.dnsProvider.SetRecords(a.ctx, zone, records); err != nil {
		a.logCheckFailure("failed setting DNS record(s) with new IP address(es)", err,
			zap.String("zone", zone))
		if result != nil {
			result.Errors = append(result.Errors, ZoneError{Zone: zone, Error: err.Error()})
		}
		return unchanged, skipped
	}

	if result != nil {
		for _, rec := range toSet {
			result.Updated = append(result.Updated, UpdatedRecord{
				Zone: zone,
				Name: rec.Name,
				Type: recordType(rec.IP),
				IP:   rec.IP.String(),
				TTL:  rec.TTL.String(),
			})
		}
	}

	return unchanged, skipped
}

func (a App) lookupManagedDomains() ([]string, error) {
	cai, err := a.ctx.App("http")
	if err != nil {
		return nil, err
	}
	var hosts []string
	ca := cai.(*caddyhttp.App)
	for _, s := range ca.Servers {
		for _, r := range s.Routes {
			for _, ms := range r.MatcherSets {
				for _, rm := range ms {
					if hs, ok := rm.(caddyhttp.MatchHost); ok {
						for _, h := range hs {
							hosts = append(hosts, h)
						}
					}
				}
			}
		}
	}
	return hosts, nil
}

// allDomainsFor returns the domains managed by the provider, including
// domains discovered from the "http" app's config if DynamicDomains is
// enabled.
func (a App) allDomainsFor(p *Provider) map[string][]string {
	if !a.DynamicDomains {
		return p.Domains
	}

	// Read hosts from config.
	m, err := a.lookupManagedDomains()
	if err != nil {
		return p.Domains
	}

	a.logger.Info("Loaded dynamic domains", zap.Strings("domains", m))
	d := make(map[string][]string)
	for zone, domains := range p.Domains {
		d[zone] = domains
		for _, h := range m {
			name, ok := func() (string, bool) {
				if h == zone {
					return "@", true
				}
				suffix := "." + zone
				if n := strings.TrimSuffix(h, suffix); n != h {
					return n, true
				}
				return "", false
			}()
			if !ok {
				// Not in this zone.
				continue
			}
			a.logger.Info("Adding dynamic domain", zap.String("domain", name))
			d[zone] = append(d[zone], name)
		}
	}
	return d
}

// isCtxError reports whether err is a context cancellation or deadline
// exceeded.
func isCtxError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// checkInterrupted reports whether a failure during a check means the check
// was interrupted — Caddy reloading the config or stopping — rather than
// something going wrong.
//
// An in-flight request is aborted with the context's cancellation cause, which
// is implementation-specific: Caddy cancels with "stopping apps", not with
// context.Canceled, so the app's own context has to be consulted rather than
// the error alone.
func (a App) checkInterrupted(err error) bool {
	if isCtxError(err) {
		return true
	}
	// caddy.Context embeds a context.Context; guard against the zero value,
	// which an app that was never provisioned has.
	return a.ctx.Context != nil && a.ctx.Err() != nil
}

// logCheckFailure logs a failure that happened during a check. A failure that
// merely means the check was interrupted is logged at info level instead of
// error level, since it is the normal consequence of a config reload or
// shutdown rather than anything going wrong.
func (a App) logCheckFailure(msg string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	if a.checkInterrupted(err) {
		a.logger.Info(msg, fields...)
		return
	}
	a.logger.Error(msg, fields...)
}

// moduleName returns the name of a Caddy module for use in log messages and
// errors. It avoids asserting that the value is a Caddy module, so a value
// that isn't one cannot panic the caller.
func moduleName(val any) string {
	if mod, ok := val.(caddy.Module); ok {
		return mod.CaddyModule().ID.Name()
	}
	return fmt.Sprintf("%T", val)
}

// recordType returns the DNS record type associated with the version of ip.
func recordType(addr netip.Addr) string {
	if addr.Is4() {
		return recordTypeA
	}
	return recordTypeAAAA
}

// removeDuplicateIPs returns ips without duplicates. Addresses are
// normalized to their unmapped form first, so that an IPv4 address written
// as an IPv4-in-IPv6 address is not treated as a distinct IPv6 address.
func removeDuplicateIPs(ips []netip.Addr) []netip.Addr {
	uniqueIPs := make(map[string]netip.Addr)
	for _, ip := range ips {
		ip = ip.Unmap()
		uniqueIPs[ip.String()] = ip
	}
	clean := make([]netip.Addr, 0, len(uniqueIPs))
	for _, ip := range uniqueIPs {
		clean = append(clean, ip)
	}
	return clean
}

// IPRanges is the set of IP ranges to include and exclude for dynamic
// DNS, where the most specific match "wins".
// If no ranges are configured then the default behaviour is to include
// global unicast ranges and exclude private ranges.
type IPRanges struct {
	Include Subnets `json:"include,omitempty"`
	Exclude Subnets `json:"exclude,omitempty"`
}

// Contains returns true if ip is allowed by these ranges.
//
// When no ranges are configured at all, a default policy is applied:
// only global unicast addresses that are not private are allowed. This
// filters out link-local (e.g. fe80::/10 and 169.254.0.0/16), loopback,
// unique local (fc00::/7) and private addresses, which an IP source such
// as "interface" would otherwise pick up.
//
// Note that, in practice, this method is never called on a nil receiver:
// IPRanges is embedded by value in IPSettings, so a zero-value IPRanges
// (no include/exclude configured) must be handled explicitly rather than
// relying on a nil check.
func (r *IPRanges) Contains(ip netip.Addr) bool {
	if r == nil || (len(r.Include) == 0 && len(r.Exclude) == 0) {
		return !ip.IsPrivate() && ip.IsGlobalUnicast()
	}
	includeSize := r.Include.largestContainingMaskSize(ip)
	excludeSize := r.Exclude.largestContainingMaskSize(ip)
	return (includeSize > excludeSize) || (excludeSize == -1 && len(r.Include) == 0)
}

// A list of IP ranges.
type Subnets []netip.Prefix

// Get the size of the subnet with the largest mask which contains the IP.
func (r Subnets) largestContainingMaskSize(ip netip.Addr) int {
	matchSize := -1
	for _, subet := range r {
		size := subet.Bits()
		if size >= matchSize && subet.Contains(ip) {
			matchSize = size
		}
	}
	return matchSize
}

// Unmarshal from a list of CIDR strings.
func (r *Subnets) UnmarshalJSON(data []byte) error {
	var cidrRanges []string
	json.Unmarshal(data, &cidrRanges)

	for _, cidrRange := range cidrRanges {
		prefix, err := netip.ParsePrefix(cidrRange)
		if err != nil {
			return err
		}
		*r = append(*r, prefix)
	}
	return nil
}

// Marshal to a list of CIDR strings.
func (r *Subnets) MarshalJSON() ([]byte, error) {
	var strings []string
	for _, ipRange := range *r {
		strings = append(strings, ipRange.String())
	}
	return json.Marshal(strings)
}

// IPVersions is the IP versions to enable for dynamic DNS.
// Versions are enabled if true or nil, set to false to disable.
type IPVersions struct {
	IPv4 *bool `json:"ipv4,omitempty"`
	IPv6 *bool `json:"ipv6,omitempty"`
}

// V4Enabled returns true if IPv4 is enabled.
func (ip IPVersions) V4Enabled() bool {
	return ip.IPv4 == nil || *ip.IPv4
}

// V6Enabled returns true if IPv6 is enabled.
func (ip IPVersions) V6Enabled() bool {
	return ip.IPv6 == nil || *ip.IPv6
}

// defaultCooldown is the minimum time between checks when none is configured.
const defaultCooldown = 30 * time.Second

const (
	recordTypeA    = "A"
	recordTypeAAAA = "AAAA"
)

const defaultCheckInterval = 30 * time.Minute

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
