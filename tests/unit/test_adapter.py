from types import SimpleNamespace
from typing import Any

import pytest
from agentdojo.attacks import base_attacks
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import ChatUserMessage, text_content_block_from_string
from openai.types.chat import ChatCompletionMessage

from taintwall.adapters.agentdojo import DeterministicOpenAILLM, ModelSpec, build_pipeline, run_name


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        msg = ChatCompletionMessage(role="assistant", content="done", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def _user(text: str) -> ChatUserMessage:
    return ChatUserMessage(role="user", content=[text_content_block_from_string(text)])


def test_temperature_zero_is_actually_sent() -> None:
    client = FakeClient()
    llm = DeterministicOpenAILLM(client, "m", temperature=0.0)  # type: ignore[arg-type]
    llm.query("q", FunctionsRuntime([]), messages=[_user("hi")])
    assert client.calls[0]["temperature"] == 0.0


def test_build_pipeline_registers_model_and_names_pipeline() -> None:
    spec = ModelSpec(provider="ollama", model="test-model:1b", prose_name="Testy")
    pipeline = build_pipeline(spec, llm=DeterministicOpenAILLM(FakeClient(), spec.model))  # type: ignore[arg-type]
    assert pipeline.name == "test-model:1b-none"
    assert base_attacks.get_model_name_from_pipeline(pipeline) == "Testy"


def test_think_flag_changes_run_name() -> None:
    spec = ModelSpec(provider="ollama", model="m", prose_name="M", think=False)
    assert run_name(spec, "none") == "m-nothink-none"


def test_unknown_defense_is_rejected() -> None:
    spec = ModelSpec(provider="ollama", model="m", prose_name="M")
    with pytest.raises(NotImplementedError):
        build_pipeline(spec, defense="detector", llm=DeterministicOpenAILLM(FakeClient(), "m"))  # type: ignore[arg-type]
