"""The OpenAI-compatible backend of openbus/llm.py (TMUXRC_LLM_BASE_URL).

No network: llm._http is swapped for an httpx client on a MockTransport, so these pin the
request we send and how the reply maps onto the Gemini-shaped response the rest of the
module reads (text, usage, cost, errors).
"""

import json
import time

import httpx
import pytest

from openbus import llm


@pytest.fixture
def openai_backend(monkeypatch):
    """Point llm at a fake chat-completions endpoint; yields the list of sent bodies and a
    setter for the next reply."""
    sent: list[dict] = []
    reply = {"status": 200, "json": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        sent.append(json.loads(request.content))
        return httpx.Response(reply["status"], json=reply["json"])

    client = httpx.Client(
        base_url="https://llm.test/v1", transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr(llm, "_OPENAI_BASE", "https://llm.test/v1")
    monkeypatch.setattr(llm, "_http", lambda: client)
    monkeypatch.setattr(llm, "_client", lambda: pytest.fail("must not touch Vertex"))
    llm._backoff.update(delay=0.0, until=0.0)
    llm.last_error["msg"] = None

    def set_reply(status=200, content="{}", usage=None):
        reply["status"] = status
        reply["json"] = {
            "choices": [{"message": {"content": content}}],
            "usage": usage or {},
        }

    yield sent, set_reply
    # The 429/401 cases arm the module-global backoff; later test files must not inherit it.
    llm._backoff.update(delay=0.0, until=0.0)
    llm.last_error["msg"] = None


def test_classify_sends_system_json_mode_and_parses(openai_backend):
    sent, set_reply = openai_backend
    set_reply(
        content='{"activity": "testing"}',
        usage={
            "prompt_tokens": 1000,
            "completion_tokens": 100,
            "prompt_tokens_details": {"cached_tokens": 400},
        },
    )
    before = llm._totals["in_tokens"]
    assert llm.classify_text("SYS", "$ npm test") == {"activity": "testing"}
    body = sent[0]
    assert body["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "$ npm test"},
    ]
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0.0
    assert llm._totals["in_tokens"] - before == 1000  # usage mapped onto Gemini names


def test_cost_discounts_cached_tokens(openai_backend):
    _, set_reply = openai_backend
    set_reply(usage={"prompt_tokens": 1000, "completion_tokens": 0,
                     "prompt_tokens_details": {"cached_tokens": 1000}})
    resp = llm._openai_generate("s", "t", None, json_mode=True)
    _, cached, _, cost = llm._tokens_cost(resp)
    assert cached == 1000
    assert cost == pytest.approx(1000 * 0.1 / 1e6 * llm._IN_PER_M)


def test_image_rides_as_data_url(openai_backend):
    sent, set_reply = openai_backend
    set_reply()
    llm.classify_text("s", "screen", image_png=b"\x89PNG")
    content = sent[0]["messages"][1]["content"]
    assert content[0] == {"type": "text", "text": "screen"}
    assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")


def test_extra_body_is_merged(openai_backend, monkeypatch):
    sent, set_reply = openai_backend
    set_reply()
    monkeypatch.setenv("TMUXRC_LLM_EXTRA_BODY", '{"reasoning_effort": "low"}')
    llm.classify_text("s", "t")
    assert sent[0]["reasoning_effort"] == "low"


def test_summarize_is_plain_text_without_json_mode(openai_backend):
    sent, set_reply = openai_backend
    set_reply(content="  Ran the tests.  ")
    assert llm.summarize_events(["ran npm test"]) == "Ran the tests."
    assert "response_format" not in sent[0]
    assert sent[0]["messages"][0]["role"] == "user"


def test_429_arms_backoff(openai_backend):
    _, set_reply = openai_backend
    set_reply(status=429)
    assert llm.classify_text("s", "t") is None
    assert "429" in llm.last_error["msg"]
    assert llm._backoff["until"] > time.time()


@pytest.mark.parametrize("status", [401, 403])
def test_refused_credentials_arm_backoff(openai_backend, status):
    _, set_reply = openai_backend
    set_reply(status=status)
    assert llm.classify_text("s", "t") is None
    assert f"refused credentials ({status})" in llm.last_error["msg"]
    assert llm._backoff["until"] > time.time()


def test_timeout_message_names_no_vendor(openai_backend):
    assert llm._handle_llm_error(httpx.ReadTimeout("slow")) == "LLM request timed out"
