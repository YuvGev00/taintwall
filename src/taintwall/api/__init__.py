"""HTTP service around L1 (detector) and L2 (taint policy), SPEC.md section 8."""

from taintwall.api.app import create_app

__all__ = ["create_app"]
