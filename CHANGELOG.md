# Changelog

All notable changes to ProxyLoom will be documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and will use semantic versioning once public releases begin.

## [Unreleased]

### Added

- Initial public deployment-preview source tree.
- Lossless sing-box ingestion and same-format publication.
- Mihomo/Clash, Surge, Loon, Quantumult X, URI, and Base64 subscription ingestion.
- Collections, pipelines, remote templates, managed outputs, stable duplicate naming, and background rebuilds.
- Node health checks with failure suppression and last-known-good artifact retention.
- Persistent source refresh retries with bounded backoff, `Retry-After` handling, and an independent snapshot stale window.
- Administrator setup, session authentication, encrypted storage, managed backups, and the Vue management interface.

### Fixed

- Archived sources now retire their node occurrences and are excluded from node listings, manual probes, health capacity, snapshot synchronization, and retention queues.

### Security

- Non-root read-only container defaults, CSRF protection, encrypted sensitive blobs, SSRF controls, and separate master-key storage.
