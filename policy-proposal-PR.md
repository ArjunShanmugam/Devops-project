# 🛡️ Zero-Trust Policy Sync Proposal (GitOps PR Preview)

**Generated at:** 2026-11-12 06:38:18 UTC
**Target Branch:** `policy-sync-20261112-120818`

## Summary of Changes Required

### 1. [service-b] 🔴 OVER_PERMISSIVE (HIGH Severity)
- **Action:** `- REMOVE RULE`
- **Details:** Enforced policy allows cluster.local/ns/default/sa/service-c-sa → service-b [POST] but no matching inferred rule exists. Rule has been stale for 10 consecutive observation window(s).
- **Affected Principal:** `cluster.local/ns/default/sa/service-c-sa`
- **Methods:** `['POST']`

### 2. [service-c] 🔴 UNDER_PERMISSIVE (HIGH Severity)
- **Action:** `+ ADD RULE`
- **Details:** Inferred policy requires cluster.local/ns/default/sa/service-a-sa → service-c [GET] but no matching enforced rule exists (breakage risk).
- **Affected Principal:** `cluster.local/ns/default/sa/service-a-sa`
- **Methods:** `['GET']`

---

> **Important:** This PR was generated autonomously by observed service-mesh telemetry.
> Human review and sign-off is required before merging. No live cluster rules were altered.