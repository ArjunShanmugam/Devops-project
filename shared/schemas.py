# shared/schemas.py
# Shared data schemas used across all modules.
from dataclasses import dataclass, field
from typing import List


@dataclass
class TrafficEdge:
    source_workload: str
    destination_workload: str
    method: str
    response_code: str
    request_count: int
    last_seen: str


@dataclass
class TrafficGraph:
    window_start: str
    window_end: str
    edges: List[TrafficEdge] = field(default_factory=list)


@dataclass
class PolicyRule:
    source_principal: str
    methods: List[str]


@dataclass
class InferredPolicy:
    service: str
    namespace: str
    rules: List[PolicyRule] = field(default_factory=list)


@dataclass
class DriftFinding:
    service: str
    type: str           # "over_permissive" or "under_permissive"
    detail: str
    severity: str       # "high" or "medium"
    suggested_action: str  # "add_rule" or "remove_rule"
    source_principal: str
    methods: List[str]


@dataclass
class PatchProposal:
    generated_at: str
    findings: List[DriftFinding] = field(default_factory=list)
