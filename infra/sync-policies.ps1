# infra/sync-policies.ps1
# Manually synchronizes merged AuthorizationPolicies from policy-repo/authz-policies/
# to the live Kubernetes cluster.
$ErrorActionPreference = "Stop"

$PolicyDir = if ($env:POLICY_DIR) { $env:POLICY_DIR } else { "policy-repo\authz-policies" }
$Namespace = if ($env:K8S_NAMESPACE) { $env:K8S_NAMESPACE } else { "default" }

if (-not (Test-Path $PolicyDir)) {
    Write-Host "Directory $PolicyDir does not exist. Nothing to apply."
    exit 0
}

Write-Host "Applying AuthorizationPolicies from $PolicyDir to namespace $Namespace..."
Get-ChildItem -Path $PolicyDir -Filter "*.yaml" | ForEach-Object {
    Write-Host "Applying $($_.FullName)..."
    kubectl apply -n $Namespace -f $_.FullName
}

Write-Host "Policy sync complete."
