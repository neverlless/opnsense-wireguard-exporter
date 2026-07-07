# OPNsense WireGuard Exporter — Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix data-correctness bugs, add missing metrics from already-available API fields, harden reliability/security, and modernize infra for the OPNsense WireGuard Prometheus exporter.

**Architecture:** Keep the current background-goroutine + interval collection model, but call `Reset()` on every `GaugeVec` at the start of each cycle to eliminate stale label series. Extract pure parsing helpers for TDD. Interface byte totals become real Counters via a small dedicated `prometheus.Collector` fed by the background snapshot. Add health/`up` metrics and graceful shutdown.

**Tech Stack:** Go 1.23, prometheus/client_golang, sirupsen/logrus, oschwald/geoip2-golang (local GeoLite2 DB).

## Global Constraints

- Go version unified to **1.23** across `go.mod`, `Dockerfile`, and CI.
- `METRICS_UPDATE_INTERVAL_SECONDS` env var is **preserved** (background model kept).
- TLS verification default: **insecure** (`OPNSENSE_TLS_INSECURE` default `"true"`) — backward compatible with self-signed OPNsense certs.
- No new third-party runtime deps beyond what's in `go.mod`.
- Metric name backward compatibility: do NOT rename existing metrics; only add new ones and fix their emission. Interface byte metrics keep names `interfaces_received_bytes_total` / `interfaces_transmitted_bytes_total` but become Counter type.
- All existing tests must keep passing; new logic gets tests.

---

## Verified API facts (OPNsense core, 24.1+)

`GET /api/wireguard/service/show` → `{total,rowCount,current,rows:[...]}`. Each row:
`if`, `type` (`interface`|`peer`), `public-key`, `endpoint`, `allowed-ips` (comma-separated), `latest-handshake` (int, 0 if never), `latest-handshake-age` (int|null), `transfer-rx`, `transfer-tx`, `persistent-keepalive` (`off`|int seconds), `peer-status` (`online`|`stale`|`offline`), `name`, `ifname`, and for `type=interface`: `status` (`up`|`down`).

`GET /api/diagnostics/traffic/interface` → `{interfaces:{<id>:{device,"bytes received","bytes transmitted",name}},time}`.

---

### Task 1: Unify Go version to 1.23

**Files:**
- Modify: `go.mod` (`go 1.21.4` → `go 1.23.0`)
- Modify: `Dockerfile:1` (already `golang:1.23.1`, keep)
- Modify: `.github/workflows/go.yml` (`go-version: 1.22` → `1.23`)

- [ ] Set `go 1.23.0` in go.mod, `go-version: '1.23'` in go.yml.
- [ ] Run `go build ./... && go vet ./...` — expect success.
- [ ] Commit: `chore: unify Go toolchain version to 1.23`

---

### Task 2: Pure parsing helpers (TDD)

**Files:**
- Create: `pkg/wireguard/parse.go`
- Test: `pkg/wireguard/parse_test.go`

**Produces:**
- `func endpointHost(endpoint string) string` — returns bare host from a `host:port` or `[v6]:port` endpoint; `""` for empty / `(none)`.
- `func splitAllowedIPs(raw string) []string` — comma-split, strips `/mask`, trims, drops empty/`(none)`.
- `func parseKeepalive(raw string) float64` — `off`/`""` → 0, numeric seconds otherwise.

- [ ] **Step 1: Failing tests** covering: IPv4 `1.2.3.4:51820`→`1.2.3.4`; IPv6 `[2001:db8::1]:51820`→`2001:db8::1`; `(none)`→``; ``→``; allowed-ips `10.0.0.2/32,10.0.0.3/32`→`[10.0.0.2 10.0.0.3]`; single `10.0.0.2/32`→`[10.0.0.2]`; `(none)`→empty; keepalive `off`→0, `25`→25, ``→0.
- [ ] **Step 2:** `go test ./pkg/wireguard/ -run TestParse -v` → FAIL (undefined).
- [ ] **Step 3:** Implement helpers using `net.SplitHostPort` with fallback (`strings.LastIndex(":")`), `strings.Trim(host, "[]")`, `strings.Split`, `strconv.ParseFloat`.
- [ ] **Step 4:** tests PASS.
- [ ] **Step 5:** Commit `feat: add IPv6-safe endpoint and allowed-ips parsing helpers`.

---

### Task 3: Extend models with new API fields

**Files:**
- Modify: `pkg/wireguard/models.go`

**Produces:** `PeerStatus` gains `LatestHandshakeAge *int64 \`json:"latest-handshake-age"\``, `PersistentKeepalive string \`json:"persistent-keepalive"\``, `PeerStatus string \`json:"peer-status"\``, `Status string \`json:"status"\``.

- [ ] Add the four fields.
- [ ] `go build ./...` → success.
- [ ] Commit `feat: model new WireGuard API fields (handshake-age, keepalive, status)`.

---

### Task 4: Refactor client — Reset(), TLS config, parse helpers, drop 45-cap

**Files:**
- Modify: `pkg/wireguard/client.go`

**Interfaces consumed:** `endpointHost`, `splitAllowedIPs` from Task 2; new model fields from Task 3.

Changes:
- `NewClient`: read `OPNSENSE_TLS_INSECURE` (default `"true"`) → `InsecureSkipVerify`.
- Add `resetMetrics()` calling `.Reset()` on every GaugeVec; call it at start of `UpdateMetrics`.
- `updateWireGuardMetrics`: use `endpointHost(row.Endpoint)`; loop over `splitAllowedIPs(row.AllowedIPs)` emitting one series each; remove the `[:min(len,45)]` cap (local DB, no rate limit).
- Add `Close()` method → `geoDB.Close()`.

- [ ] Implement changes.
- [ ] `go build ./... && go vet ./... && go test ./...` → success.
- [ ] Commit `fix: reset stale series, IPv6 endpoints, all allowed-ips, configurable TLS`.

---

### Task 5: New peer & interface metrics

**Files:**
- Modify: `pkg/wireguard/client.go` (or new `pkg/wireguard/metrics.go`)

New metrics:
- `wireguard_peer_last_handshake_age_seconds{interface,peer_name,public_key}` — set from `*LatestHandshakeAge` when non-nil.
- `wireguard_peer_persistent_keepalive_seconds{interface,peer_name,public_key}` — `parseKeepalive`.
- `wireguard_interface_status{interface,name}` — for `type=interface`: 1 if `status=="up"` else 0.

- [ ] Register + emit; include in `resetMetrics()`.
- [ ] `go test ./...` → success.
- [ ] Commit `feat: add handshake-age, keepalive, and interface-status metrics`.

---

### Task 6: Health/up metrics + interface counters (#5, #8)

**Files:**
- Modify: `pkg/wireguard/client.go`
- Create: `pkg/wireguard/interface_collector.go`

- `wireguard_up` (Gauge) = 1 on fully successful `UpdateMetrics`, else 0.
- `wireguard_scrape_errors_total` (Counter) — inc on any fetch/parse error.
- `wireguard_last_scrape_timestamp_seconds` (Gauge) — unix time of last successful cycle.
- Interface byte totals: replace the two GaugeVecs with an `interfaceCollector` implementing `prometheus.Collector` that holds the latest `map[string]InterfaceData` under a `sync.RWMutex` and emits `NewConstMetric(..., CounterValue, ...)` on scrape — keeps `_total` names with correct Counter type.

- [ ] Implement, register collector, wire background loop to update snapshot.
- [ ] Tests: a unit test asserting `wireguard_up`==0 after a failed fetch and counters exposed via `testutil.CollectAndCount`/`GatherAndCompare` where practical.
- [ ] `go test ./...` → success.
- [ ] Commit `feat: add wireguard_up/scrape-error metrics and proper interface counters`.

---

### Task 7: Graceful shutdown, server timeouts, version (#9)

**Files:**
- Modify: `main.go`

- `var version = "dev"` (overridable via `-ldflags "-X main.version=..."`).
- `http.Server` with `ReadHeaderTimeout: 5s`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`.
- `signal.NotifyContext(SIGINT,SIGTERM)`; on cancel: `server.Shutdown(ctx)` + `client.Close()`.
- Log version at startup.

- [ ] Implement; `go build ./...` → success.
- [ ] Manual: run binary, `curl :9486/metrics`, send SIGTERM, verify clean exit.
- [ ] Commit `feat: graceful shutdown, HTTP server timeouts, version flag`.

---

### Task 8: Dockerfile hardening

**Files:**
- Modify: `Dockerfile`

- Add non-root `USER` (create `appuser`), keep GeoLite path readable.
- Add `HEALTHCHECK` hitting `/metrics`.
- Pass version via build arg + ldflags.
- Keep third-party GeoLite mirror (out of scope per user).

- [ ] Update Dockerfile; `docker build .` if Docker available, else `go build` sanity.
- [ ] Commit `chore: harden Docker image (non-root user, healthcheck, version)`.

---

### Task 9: CI test workflow on PRs (#14)

**Files:**
- Create: `.github/workflows/test.yml`

- Trigger on `pull_request` + `push` to non-tag branches.
- Steps: checkout, setup-go 1.23, `go vet ./...`, `go test ./... -race -cover`, `go build ./...`.

- [ ] Add workflow.
- [ ] Commit `ci: run vet/test/build on pull requests`.

---

### Task 10: Docs + dashboard

**Files:**
- Modify: `README.md`
- Modify: `grafana/WireGuard Dashboard-1729676220092.json` (add panels for new metrics if straightforward)

- Document `OPNSENSE_TLS_INSECURE`; list new metrics; note IPv6/allowed-ips fixes; update TODO.
- [ ] Update README env table + metrics section.
- [ ] Commit `docs: document new metrics and TLS option`.

---

## Deliberately NOT doing
- **#12** GeoLite2 mirror change — excluded per user.
- Metric renames — avoided for backward compatibility (only additive changes + type fix that preserves names).
