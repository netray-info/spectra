# Changelog

All notable changes to spectra are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.2] - 2026-05-01

### Security
- Bump rustls-webpki to 0.103.13 (RUSTSEC-2026-{0098,0099,0104})
- Bump frontend lockfile for postcss XSS (GHSA-qx2v-qp2m-jg93)

### Fixed
- Hoist analyze_reporting and format_http_version above their `#[cfg(test)]` modules; drop unused `mut` and replace `len() >= 1` with `!is_empty()` (newer clippy)

### Changed
- Bump @netray-info/common-frontend to 0.5.2
- Bump netray-common to 0.8.1

## [0.2.1] - 2026-04-11

### Changed
- Migrate to standardized ecosystem/backend config (092da2b)
- Bump netray-common to 0.7.0 (dff0ea7)

## [0.2.0] - 2026-04-10

### Changed
- Bump netray-common to 0.6.0 (9ea2a1d)
- Assign unique dev ports: backend 8083, metrics 9093, vite 5176 (0b6a175)

## [0.1.0] - 2026-04-10

### Added
- HTTP header inspection and security audit service (HTTP/HTTPS/CORS three-probe analysis)
- CSP directive parsing and scoring
- HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP checks
- Cookie attribute inspection (Secure, HttpOnly, SameSite)
- CDN detection, caching header analysis, fingerprint leak detection
- Quality verdict engine (Pass/Warn/Fail) with per-check and aggregate scores
- IP enrichment integration via ifconfig-rs
- Prometheus metrics: spectra_inspect_duration_ms, spectra_inspect_requests_total, spectra_probe_failures_total
- OpenAPI 3.1 docs at /docs (Scalar UI)
- SolidJS 1.9 embedded frontend

### Fixed
- SSRF via redirect chain: redirect destinations are now validated before following
- Shell injection in deploy workflow: jq --arg used for JSON payload construction
- Referrer-Policy: risky values (origin, unsafe-url) now produce Warn instead of Pass
- Cookie attribute parsing is now case-insensitive per RFC 6265
- Prometheus counter namespace: all metrics use spectra_ prefix
