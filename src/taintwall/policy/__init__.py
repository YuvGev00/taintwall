"""L2: the taint-tracking policy guard (SPEC.md section 4)."""

from taintwall.policy.registry import ToolSpec, load_registry
from taintwall.policy.rules import TaintPolicy

__all__ = ["TaintPolicy", "ToolSpec", "load_registry"]
