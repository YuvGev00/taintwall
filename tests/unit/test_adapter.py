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
        build_pipeline(spec, defense="taintwall", llm=DeterministicOpenAILLM(FakeClient(), "m"))  # type: ignore[arg-type]


class FakeStream:
    def __init__(self, message: Any) -> None:
        self.message = message

    def __enter__(self) -> "FakeStream":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> Any:
        return self.message


class FakeAnthropic:
    def __init__(self, message: Any) -> None:
        self.requests: list[dict[str, Any]] = []
        self.messages = SimpleNamespace(stream=self._stream)
        self._message = message

    def _stream(self, **kwargs: Any) -> FakeStream:
        self.requests.append(kwargs)
        return FakeStream(self._message)


def _claude_message(stop_reason: str = "end_turn") -> Any:
    from anthropic.types import Message, TextBlock, Usage

    return Message.model_construct(
        id="msg_1",
        type="message",
        role="assistant",
        model="claude-haiku-5-5",
        content=[TextBlock(type="text", text="done", citations=None)],
        stop_reason=stop_reason,
        stop_sequence=None,
        usage=Usage(input_tokens=1, output_tokens=1),
    )


def test_claude_request_has_no_sampling_params_and_explicit_effort() -> None:
    from taintwall.adapters.agentdojo import ClaudeLLM

    client = FakeAnthropic(_claude_message())
    llm = ClaudeLLM(client, "claude-haiku-5-5", effort="medium")  # type: ignore[arg-type]
    _, _, _, messages, _ = llm.query("q", FunctionsRuntime([]), messages=[_user("hi")])
    request = client.requests[0]
    assert "temperature" not in request and "top_p" not in request
    assert request["thinking"] == {"type": "adaptive"}
    assert request["output_config"] == {"effort": "medium"}
    assert messages[-1]["role"] == "assistant"


def test_claude_refusal_becomes_a_final_answer() -> None:
    from taintwall.adapters.agentdojo import ClaudeLLM

    llm = ClaudeLLM(FakeAnthropic(_claude_message("refusal")), "claude-haiku-5-5")  # type: ignore[arg-type]
    _, _, _, messages, _ = llm.query("q", FunctionsRuntime([]), messages=[_user("hi")])
    assert messages[-1]["tool_calls"] is None


def test_spotlighting_pipeline_delimits_tool_output() -> None:
    spec = ModelSpec(provider="ollama", model="m", prose_name="M")
    pipeline = build_pipeline(spec, defense="spotlighting", llm=DeterministicOpenAILLM(FakeClient(), "m"))  # type: ignore[arg-type]
    system, *_, loop = list(pipeline.elements)
    executor = next(iter(loop.elements))
    assert "<<" in system.system_message
    assert executor.output_formatter("x").startswith("<<")
    assert pipeline.name == "m-spotlighting"


def test_anthropic_run_name_includes_effort() -> None:
    spec = ModelSpec(provider="anthropic", model="claude-haiku-5-5", prose_name="Claude", effort="low")
    assert run_name(spec, "none") == "claude-haiku-5-5-low-none"
