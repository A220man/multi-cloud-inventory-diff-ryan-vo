# Changelog

## 1.2.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.1.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-12

### Added
- Snapshot pair comparator enabling pairwise drift analysis between arbitrary baseline and target inventory snapshots.
- Historical diff query endpoint `GET /api/diffs` supporting pagination (`limit`, `offset`) and snapshot filtering (`snapshot_id`).
- Recent Comparison Runs table on the Snapshots page linking directly to detailed diff inspections.
- Frontend and backend test coverage for pairwise comparison workflows, validation of distinct snapshots, and diff history retrieval.

### Fixed
- Demo login client now forwards the selected role/username and maps the backend `access_token` envelope to `AuthState` (`token`, `isAuthenticated`), restoring an authenticated session after local demo sign-in.

## [1.0.0] - 2026-10-09

### Added
- Unified multi-cloud asset export parser and canonical normalizer for AWS Config / Resource Explorer, GCP Cloud Asset Inventory, and Azure Resource Graph.
- Deterministic snapshot diffing engine calculating added, removed, and modified assets with field-level attribute delta tracking.
- Exposure escalation and ownership grouping algorithms clustering drift by team/owner and network blast radius.
- Supervised machine learning drift severity classifier (LOW, MEDIUM, HIGH, CRITICAL) and configuration anomaly scoring engine.
- Reproducible offline ML benchmark evaluation script and labeled validation dataset measuring precision, recall, F1, and confusion matrix.
- Opt-in LLM remediation advisory synthesis supporting OpenAI-compatible, Anthropic, Gemini, and Ollama providers with strict grounding and credential redaction.
- OIDC authorization-code PKCE authentication architecture integrated with Keycloak and SAML identity brokering support.
- Role-based authorization (`viewer`, `operator`, `admin`) on all data endpoints with local demo mode safeguards.
- SQLite persistent relational storage, transactional mutations, pagination, and audit logging.
- React TypeScript Vite frontend dashboard featuring snapshot management, interactive visual diff inspections, ML risk metrics, and audit log exploration.
- Containerized packaging with nonroot Dockerfiles, Docker Compose environment, and GitHub Actions CI workflow.
