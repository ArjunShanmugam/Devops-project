"""
policy_fetcher/fetch_policies.py
Compatibility wrapper for fetch_enforced.
"""
import os
from pathlib import Path
from typing import Any, List, Dict
from policy_fetcher.fetch_enforced import fetch_and_write, ENFORCED_POLICY_DIR

def fetch_policies(output_dir: Any = ENFORCED_POLICY_DIR, namespace: str = "default") -> List[Dict[str, Any]]:
    """Fetch live AuthorizationPolicies from Kubernetes and normalize them."""
    out_path = Path(output_dir)
    return fetch_and_write(namespace=namespace, output_dir=out_path)
