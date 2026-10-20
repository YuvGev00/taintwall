"""Rule v1: block a side-effecting call whose sensitive argument came only from untrusted data.

- A value found in the user's request or in trusted tool output is allowed.
- A value found only in untrusted tool output is tainted, so the call is blocked.
- A value found nowhere was produced by the agent itself (e.g. a computed
  amount), so it is allowed: an attacker's value has to arrive through a tool
  output to exist at all.
- A tool missing from the registry is blocked (fail closed).
"""

from __future__ import annotations

from collections.abc import Sequence

from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatMessage

from taintwall.policy.provenance import Provenance, flatten
from taintwall.policy.registry import Registry


class TaintPolicy:
    def __init__(self, registry: Registry) -> None:
        self.registry = registry

    def check(self, call: FunctionCall, user_prompt: str, messages: Sequence[ChatMessage]) -> str | None:
        """Return None to allow the call, or the reason it is blocked."""
        spec = self.registry.get(call.function)
        if spec is None:
            return f"tool {call.function!r} is not in the registry"
        if spec.effect is None or not spec.sensitive:
            return None
        provenance = Provenance.from_history(user_prompt, messages, self.registry)
        for arg in spec.sensitive:
            for value in flatten(call.args.get(arg)):
                if provenance.origin(value) == "untrusted":
                    return f"{arg}={value!r} appears only in untrusted tool output"
        return None
