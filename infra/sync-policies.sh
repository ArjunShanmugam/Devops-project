#!/usr/bin/env bash
# infra/sync-policies.sh
# Manually synchronizes merged AuthorizationPolicies from policy-repo/authz-policies/
# to the live Kubernetes cluster.
# Per Architecture.md §3 and §9.4.

set -euo pipefail

POLICY_DIR="${POLICY_DIR:-policy-repo/authz-policies}"
NAMESPACE="${K8S_NAMESPACE:-default}"

if [ ! -d "$POLICY_DIR" ]; then
    echo "Directory $POLICY_DIR does not exist. Nothing to apply."
    exit 0
fi

echo "Applying AuthorizationPolicies from $POLICY_DIR to namespace $NAMESPACE..."
for f in "$POLICY_DIR"/*.yaml; do
    if [ -f "$f" ]; then
        echo "Applying $f..."
        kubectl apply -n "$NAMESPACE" -f "$f"
    fi
done

echo "Policy sync complete."
