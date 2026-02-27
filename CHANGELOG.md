# Changelog

All notable changes to VulnRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **CVE List V5 download resilience** — `get_latest_cvelist_zip_url` now falls
  back to scanning the 5 most recent GitHub releases when the `/releases/latest`
  endpoint returns a release without the midnight bulk ZIP (e.g. the
  `at_end_of_day` release published by CVEProject/cvelistV5). This eliminates
  recurring ETL failures around 00:00–02:00 UTC.

## [0.2.0] - 2025-02-11

### Added

- NVD data feed enrichment (CVSS v2/v3, CWE, CPE counts) via yearly bulk JSON feeds.
- `--skip-nvd` flag to bypass NVD downloads for faster runs.
- NVD data caching with `--nvd-cache` to avoid re-downloading unchanged feeds.
- PatchThis intelligence feed integration for exploit-availability prioritization.
- Async parallel downloaders (`--parallel` flag) using aiohttp.
- Notification providers: Discord, Slack, Microsoft Teams, GitHub Issues (with Projects v2).
- Alert deduplication via `StateManager` — only notify on genuinely new CVEs.
- Jinja2-based Markdown report template (`vulnradar/templates/report.md.j2`).
- `--include-kev-outside-window` to pull KEVs older than the scan window.
- Pre-commit hooks (ruff, mypy, trailing-whitespace, etc.).
- Comprehensive test suite (323 tests).
- Full documentation site under `docs/`.

### Changed

- Refactored downloaders into `vulnradar/downloaders.py` with tenacity retry logic.
- Switched from flat-script ETL to a proper Python package (`vulnradar/`).

## [0.1.0] - 2025-01-15

### Added

- Initial release.
- CVE List V5 bulk export download and parsing.
- CISA KEV enrichment.
- EPSS score enrichment.
- Watchlist-based filtering (vendors and products).
- Markdown report generation.
- GitHub Actions workflow for scheduled hourly updates.
