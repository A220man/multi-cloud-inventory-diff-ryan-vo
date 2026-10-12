# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

diff-history-and-pair-comparison

## Roadmap

### multi-cloud-normalization — Cross-Cloud Resource Schema Normalizer

Status: done

Acceptance:
- Normalize AWS Config, GCP Cloud Asset Inventory, and Azure Resource Graph exports into CanonicalAsset schema
- Extract standardized exposure levels, network configurations, and IAM privileges

Implementation: `backend/app/services/normalizer.py`

Tests: `backend/tests/test_normalizer.py`

### deterministic-diff-engine — Deterministic Multi-Cloud Inventory Diff Engine

Status: done

Acceptance:
- Detect added, removed, and modified cross-cloud resources between snapshots
- Identify security-relevant property drifts including exposure escalations and unowned assets

Implementation: `backend/app/services/diff_engine.py`

Tests: `backend/tests/test_diff_engine.py`

### ml-drift-risk-classifier — Supervised Drift Risk Severity Classifier

Status: done

Acceptance:
- Classify configuration drift into LOW, MEDIUM, HIGH, and CRITICAL severity tiers
- Provide offline benchmark evaluation exceeding naive rule-based baseline on macro F1

Implementation: `backend/app/ml/classifier.py`, `backend/app/ml/dataset.py`, `backend/app/ml/evaluate.py`

Tests: `backend/tests/test_ml_classifier.py`

### grounded-llm-remediation-advisor — Grounded LLM Remediation Advisor

Status: done

Acceptance:
- Generate multi-cloud remediation recommendations grounded in actual diff records
- Support pluggable LLM adapters with graceful offline deterministic fallback

Implementation: `backend/app/services/llm_advisor.py`

Tests: `backend/tests/test_api_workflows.py`

### oidc-and-demo-security — Role-Based Access Control and OIDC Authentication

Status: done

Acceptance:
- Enforce viewer, operator, and admin role authorization across data endpoints
- Provide local-only demo authentication mode while rejecting unauthenticated access

Implementation: `backend/app/core/auth.py`

Tests: `backend/tests/test_auth_and_security.py`

### react-drift-dashboard — Interactive Multi-Cloud Inventory Frontend

Status: done

Acceptance:
- Visualize inventory statistics, diff deltas, and ML risk evaluation breakdowns
- Support sample snapshot loading, offline benchmark viewing, and audit logs

Implementation: `frontend/src/App.tsx`, `frontend/src/components/Dashboard.tsx`, `frontend/src/components/DiffPage.tsx`, `frontend/src/components/MLPage.tsx`

Tests: `frontend/src/test/app.test.tsx`

### diff-history-and-pair-comparison — Diff History API and Snapshot Pair Comparator

Status: done

Acceptance:
- List historical comparison runs via GET /api/diffs with pagination and snapshot filtering
- Allow operators to select arbitrary base and target snapshot pairs in the UI
- Validate selection against identical snapshots and render recent comparison history

Implementation: `backend/app/api/endpoints.py`, `backend/app/models/schemas.py`, `frontend/src/services/api.ts`, `frontend/src/components/SnapshotsPage.tsx`

Tests: `backend/tests/test_api_workflows.py`, `frontend/src/test/app.test.tsx`

### real-time-webhook-ingestion — Real-Time Cloud Inventory Webhook Ingestion

Status: planned

Acceptance:
- Receive asset change notifications via HMAC-authenticated webhook
- Trigger automated diff calculation against the latest baseline snapshot

### policy-as-code-opa-rules — Open Policy Agent Rego Compliance Evaluation

Status: planned

Acceptance:
- Evaluate custom Open Policy Agent Rego rules against normalized canonical assets
- Surface policy compliance violations alongside ML severity classifications

### exportable-compliance-audit-bundle — Exportable Signed Compliance Audit Bundles

Status: planned

Acceptance:
- Generate signed JSON-LD and CSV compliance audit report bundles
- Include complete snapshot lineage, diff evidence, and reviewer approval signatures

