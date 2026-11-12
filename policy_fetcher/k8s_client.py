"""
policy_fetcher/k8s_client.py
Kubernetes API client wrapper for fetching AuthorizationPolicy CRDs.
Per Architecture.md §9.3.1
"""
import logging
from kubernetes import client, config

logger = logging.getLogger(__name__)


def get_k8s_custom_api():
    """Load kube config and return a CustomObjectsApi client."""
    try:
        config.load_kube_config()
    except Exception:
        try:
            config.load_incluster_config()
        except Exception as e:
            logger.warning("Could not load k8s config: %s", e)
            raise
    return client.CustomObjectsApi()


def list_authorization_policies(namespace: str = "default") -> list[dict]:
    """
    List all AuthorizationPolicy objects in the given namespace.
    Returns raw K8s API objects. Returns empty list if none exist or K8s unavailable.
    """
    try:
        api = get_k8s_custom_api()
        result = api.list_namespaced_custom_object(
            group="security.istio.io",
            version="v1",
            namespace=namespace,
            plural="authorizationpolicies",
        )
        return result.get("items", [])
    except Exception as e:
        logger.warning("Could not list AuthorizationPolicies (K8s unavailable?): %s", e)
        return []
