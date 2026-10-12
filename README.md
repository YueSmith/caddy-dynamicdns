Dynamic DNS app for Caddy
=========================

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider. It supports multiple IPs, including IPv4 and IPv6, as well as redundant IP sources.

IP sources and DNS providers are modular. This app comes with IP source modules. However, you'll need to plug in [a DNS provider module from caddy-dns](https://github.com/caddy-dns) so that your DNS records can be updated.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

> [!IMPORTANT]
> **This is a fork.** It is based on [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns)
> but behaves differently in places. Read the sections at the end of this document first, in
> particular [How records are updated](#how-records-are-updated).
>
> **AI disclosure.** The changes in this fork were written with the help of an AI coding agent
> (OpenCode), and were then reviewed and verified by a human, including live tests against a real
> DNS provider's API. This does not change the license: the fork is under the same license as
> upstream, see [LICENSE](LICENSE).

### Sample configurations

<details>
<summary>Minimal example config</summary>

Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
	}
}
```

(For subdmoains, see the next example.)

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			}
		}
	}
}
```

This updates DNS records for `example.com` via Cloudflare's API. (Notice how the DNS zone is separate from record names/subdomains.)
</details>


<details>
<summary>Complex example config</summary>

Here's a more filled-out config, will all the options used.

This config prefers to get the IP address locally via UPnP (if edge router has UPnP enabled, of course), but if that fails, will fall back to querying `icanhazip.com` for the IP address. If those fail, it will try to find the IP address from the eth0 interface. It then updates records for `example.com`, `www.example.com`, and `subdomain.example.net`. Notice how the zones and subdomains are separate; this eliminates ambiguity since we don't have to try to be clever and figure out the zone via recursive, authoritative DNS lookups. We also check every 5 minutes instead of 30 minutes (default), and set a TTL of 1 hour for the records.

The interface option will return at most 1 IPv4 and 1 IPv6 address. It will only return addresses that are not [private according to RFC 1918 (IPv4) and RFC 4193 (IPv6)](https://pkg.go.dev/net#IP.IsPrivate), and is a [global unicast address according to RFC 1122, RFC 4632, and RFC 4291 with the exception of IPv4 directed broadcast addresses](https://pkg.go.dev/net#IP.IsGlobalUnicast).

Note that it's redundant to specify both IP versions in the config, since the default is to enable both IPv4 and IPv6. It's purpose is to allow disabling one or the other if your server is only reachable via one of the versions. It's included in this config example for posterity.

Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @ www
			example.net subdomain
		}
		ip_source upnp
		ip_source simple_http https://icanhazip.com
		ip_source simple_http https://api64.ipify.org
		ip_source interface eth0
		check_interval 5m
		versions ipv4 ipv6
		ttl 1h
	}
}
```

(Notice how the syntax is: `<zone> [ @ | <subdomains...> ]` -- zone first, then any subdomains; if no subdomains, then "@" is implied; if you do list subdomains and you want the zone root to be included, you have to add "@" explicitly.)

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"domains": {
				"example.com": ["@", "www"],
				"example.net": ["subdomain"]
			},
			"ip_sources": [
				{
					"source": "upnp"
				},
				{
					"source": "simple_http",
					"endpoints": ["https://icanhazip.com", "https://api64.ipify.org"]
				},
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"check_interval": "5m",
			"versions": {
				"ipv4": true,
				"ipv6": true
			},
			"ttl": "1h",
			"dynamic_domains": false
		}
	}
}
```
</details>

<details>
<summary>Multiple providers</summary>

The `provider` directive can be repeated to update domains across multiple DNS providers, or across multiple accounts of the same provider (e.g. different API credentials per domain). Each provider's domains are configured with a `domains` block *inside* that provider's block:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN} {
			domains {
				example.com @ www
			}
		}
		provider duckdns {env.DUCKDNS_API_TOKEN} {
			domains {
				example.duckdns.org @
			}
		}
		check_interval 5m
	}
}
```

Inside a provider's block, the name `domains` is reserved for this app; everything else belongs to the DNS provider module as usual (whether inline arguments or block subdirectives). All other options (`ip_source`, `check_interval`, `cooldown`, `versions`, `include`/`exclude`, `ttl`, `update_only`, `dynamic_domains`) remain global and apply to all providers.

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"providers": [
				{
					"dns_provider": {
						"name": "cloudflare",
						"api_token": "{env.CLOUDFLARE_API_TOKEN}"
					},
					"domains": {
						"example.com": ["@", "www"]
					}
				},
				{
					"dns_provider": {
						"name": "duckdns",
						"api_token": "{env.DUCKDNS_API_TOKEN}"
					},
					"domains": {
						"example.duckdns.org": ["@"]
					}
				}
			],
			"check_interval": "5m"
		}
	}
}
```

Note that repeating the whole `dynamic_dns` global option does **not** work — Caddy keeps only the last occurrence. Use multiple `provider` blocks within a single `dynamic_dns` option instead.
</details>

<details>
<summary>Disabling IPv4</summary>

To disable IPv4 lookups and use your unique global unicast IPv6 address, specify only IPv6 as the version you want enabled and use your machine interface to get the IP address:

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		versions ipv6
		ip_source interface eth0
	}
}
```

Equivalent JSON config; you may omit the other version you want to keep enabled (omission is assumed to mean enabled):

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"ip_sources": [
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"versions": {
				"ipv4": false
			}
		}
	}
}
```
</details>


<details>
<summary>Disabling IPv6</summary>

To disable IPv6 lookups, specify only IPv4 as the version you want enabled:

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		versions ipv4
	}
}
```

Equivalent JSON config; you may omit the other version you want to keep enabled (omission is assumed to mean enabled):

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"versions": {
				"ipv6": false
			}
		}
	}
}
```
</details>

<details>
<summary>Dynamic Domains</summary>

There is an option `dynamic_domains` that can scan through the configured domains configured in this Caddy instance and will try to manage the DNS of those domains. 

Note:
* Only host matchers at the top-level of server routes will get managed.
* [`on_demand`](https://caddyserver.com/docs/automatic-https#on-demand-tls) is not supported because the hostname isn't known at config time.

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @ www
			example.net subdomain
		}
		dynamic_domains
	}
}

# This domain will be managed.
cool.example.com {
	redir http://google.com
}

# This domain will *NOT* be managed because it's not configured in dynamic_dns.
another.host.com {
	redir http://youtube.com
}
```

Equivalent JSON config:
```jsonc
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@", "www"],
				"example.net": ["subdomain"]
			},
			"dynamic_domains": true,
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "topsecret"
			},
		},
		"servers": {
			"srv0": {
				"routes": [{
					// omitted
					"match": [{
						"host": [
							// This domain will be managed.
							"cool.example.com"
						]
					}]
				}, {
					// omitted
					"match": [{
						"host": [
							// This domain will *NOT* be managed because it's not configured in dynamic_dns.
							"another.host.com"
						]
					}]
				}]
			}
		}
	}
}
```
</details>

### Cooldown

`cooldown` is the minimum time between two IP checks, so that repeated requests can't hammer
your DNS provider (or the API of your IP source). A check that arrives sooner than this is
skipped: the periodic check skips that round, and the admin API answers
`429 Too Many Requests` with a `Retry-After` header.

The first check after a config load always runs, so loading a config takes effect immediately
instead of waiting out a cooldown left over from the previous config.

The default is `30s`. Set it to `0` to disable the throttle. If it is not shorter than
`check_interval`, periodic checks will mostly be skipped, and the app warns about that at
startup.

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		cooldown 1m
	}
}
```

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"cooldown": "1m"
		}
	}
}
```

### Admin API

The app registers one route on the [Caddy admin API](https://caddyserver.com/docs/api):

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/dynamic_dns/check` | Run an IP check immediately |

The route is registered whenever this module is compiled in, whether or not the app is
configured. It reports the addresses that were found and the records that were written:

```
$ curl -X POST http://localhost:2019/dynamic_dns/check
{"ips":["203.0.113.7"],"updated":[{"zone":"example.com","name":"@","type":"A","ip":"203.0.113.7","ttl":"1h0m0s"}]}
```

| Status | Meaning |
| ------ | ------- |
| `200` | The check ran. Zones that failed appear in `errors`. |
| `405` | The request was not a `POST`. |
| `429` | A check ran less than `cooldown` ago; see the `Retry-After` header. |
| `502` | Every IP source failed, so no address could be determined. |
| `503` | The `dynamic_dns` app is not configured. |

Mind that the admin API is unauthenticated and only listens on localhost by default.

### How records are updated

Every check — periodic or on demand — does the same thing:

1. Ask the IP sources for the machine's public IP addresses.
2. Ask the DNS provider what the zone currently contains.
3. Write a record only where what the provider reports differs from what it should be.

The provider is the only authority on what exists, so it is read on every check rather than
trusting anything the process remembered. Some consequences worth knowing before you upgrade:

- **Records changed or deleted outside this app are noticed and put back.** Editing a record by
  hand, or deleting it, is corrected on the next check — unless `update_only` is set. To have a
  record left alone, remove it from `domains`.
- **A failed read never causes a write.** If a zone can't be read (network problem, API error,
  rate limit), it is skipped for that round and reported in `errors`; nothing is created or
  overwritten on a guess.
- **`update_only` means "update existing records, never create".** Records that don't exist are
  left missing and have to be created by hand, as documented. (Upstream did not actually behave
  this way: a missing record was created regardless.)
- **A check costs one read per zone**, plus any writes. With the default `check_interval` of 30m
  that is negligible; with a very short interval, mind your provider's rate limits, and note that
  `cooldown` caps how often a check may run.
- **Only the record names listed in `domains` are managed.** Every other record in the zone is
  ignored and never deleted — including other types for the same name, such as an `AAAA` record
  when only IPv4 is enabled.

#### Provider requirements

A provider must support **both reading and writing** records (both `libdns.RecordGetter` and
`libdns.RecordSetter`), because the app compares against what the provider reports. A provider
that can't is rejected with an error while the config is loaded, so a mistake is caught at
startup — and a reload that introduces one is rejected, leaving the running config alone —
rather than at the first check.

This rules out the ACME-only providers, such as `dode`, `ednsde`, `nanelo` and
`google_domains`, which can only add and remove `_acme-challenge` TXT records and therefore
can't be used with `dynamic_dns` at all. Every provider published under
[caddy-dns](https://github.com/caddy-dns) that can write records also supports reading, so in
practice only the ACME-only ones are affected; a third-party provider that implements only
`SetRecords` is rejected too.

Note also that a provider only sees what its API exposes. For example, the Tencent Cloud
provider reads and writes only the default ("默认") record line, so records on ISP-specific
lines are invisible to it.

#### IP sources and private addresses

By default only addresses that are both *not private* and *global unicast* are used. Link-local
(`fe80::/10`, `169.254.0.0/16`), loopback, unique-local (`fc00::/7`) and RFC 1918 addresses are
ignored. This is why `ip_source interface` typically yields nothing on a machine behind NAT,
whose interface carries only a private IPv4: such an address is meaningless in public DNS. Use
`simple_http` (or another service) to learn the address the internet sees, or a host that really
does hold a public address on the interface.

The `include` and `exclude` options take CIDR ranges and override that policy, with the most
specific match winning: an address is used if it matches an `include` range and not a more
specific `exclude` range. If only `exclude` is given, everything else is allowed. For example,
`include 0.0.0.0/0 ::/0` accepts everything the source reports.
