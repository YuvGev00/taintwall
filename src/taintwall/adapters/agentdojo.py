"""Build AgentDojo pipelines for any model, independent of AgentDojo's dated ModelsEnum.

Week 1 only supports `defense="none"`. The detector (L1) and policy guard (L2)
plug in here later; see SPEC.md section 5.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

import openai
from agentdojo import models as agentdojo_models
from agentdojo.agent_pipeline import (
    AgentPipeline,
    BasePipelineElement,
    InitQuery,
    OpenAILLM,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage

Provider = Literal["ollama", "openai-compatible"]
Defense = Literal["none"]

OLLAMA_BASE_URL = "http://localhost:11434/v1"
_EMPTY_ENV = EmptyEnv()


class DeterministicOpenAILLM(OpenAILLM):
    """OpenAILLM that really sends temperature=0.

    agentdojo 0.1.35 sends `temperature or NOT_GIVEN`, so 0.0 is dropped and the
    server default (often 0.6-0.8) is used instead. See DECISIONS.md, 2026-10-19.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = _EMPTY_ENV,  # type: ignore[assignment]  # same default as upstream
        messages: Sequence[ChatMessage] = (),
        extra_args: dict[str, Any] = {},  # noqa: B006 - matches the AgentDojo signature
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [_message_to_openai(m, self.model) for m in messages],
        }
        tools = [_function_to_openai(t) for t in runtime.functions.values()]
        if tools:
            request |= {"tools": tools, "tool_choice": "auto"}
        if self.temperature is not None:
            request["temperature"] = self.temperature
        if self.reasoning_effort is not None:
            request["reasoning_effort"] = self.reasoning_effort
        completion = self.client.chat.completions.create(**request)
        output = _openai_to_assistant_message(completion.choices[0].message)
        return query, runtime, env, [*messages, output], extra_args


@dataclass(frozen=True)
class ModelSpec:
    provider: Provider
    model: str
    prose_name: str
    """How attacks address the model, e.g. "Qwen". Registered in AgentDojo's MODEL_NAMES."""
    think: bool = True
    """Ollama only: keep the model's reasoning mode on."""


def register_model_name(model: str, prose_name: str) -> None:
    """Let name-aware attacks (important_instructions) address a model the enum doesn't know."""
    agentdojo_models.MODEL_NAMES[model] = prose_name


def make_llm(spec: ModelSpec) -> DeterministicOpenAILLM:
    if spec.provider == "ollama":
        client = openai.OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
        # think=False ("none") is ~8x faster but Qwen3 then narrates a plan and stops
        # without calling tools (0/2 on the banking smoke test). See DECISIONS.md.
        effort = None if spec.think else "none"
        return DeterministicOpenAILLM(client, spec.model, reasoning_effort=effort, temperature=0.0)  # type: ignore[arg-type]
    if spec.provider == "openai-compatible":
        client = openai.OpenAI(
            base_url=os.environ["TAINTWALL_BASE_URL"],
            api_key=os.environ["TAINTWALL_API_KEY"],
        )
        return DeterministicOpenAILLM(client, spec.model, temperature=0.0)
    raise ValueError(f"unknown provider: {spec.provider}")


def build_pipeline(spec: ModelSpec, defense: Defense = "none", llm: BasePipelineElement | None = None) -> AgentPipeline:
    """Assemble the same pipeline AgentDojo builds for `defense=None`, with our LLM element."""
    if defense != "none":
        raise NotImplementedError(f"defense {defense!r} lands in a later week")
    register_model_name(spec.model, spec.prose_name)
    llm = llm if llm is not None else make_llm(spec)
    tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), llm, tools_loop],
    )
    # Attacks find the model's prose name by substring-matching pipeline.name;
    # AgentDojo also caches traces under it, so it must differ per config.
    pipeline.name = run_name(spec, defense)
    return pipeline


def run_name(spec: ModelSpec, defense: str) -> str:
    return f"{spec.model}{'' if spec.think else '-nothink'}-{defense}"
