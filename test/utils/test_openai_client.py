from unittest.mock import patch

from auditor.utils.openai_client import OpenAIChatClient

RESPONSE = {
    "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
    "usage": {"completion_tokens": 120, "completion_tokens_details": {"reasoning_tokens": 100}},
}

def test_reasoning_config_is_sent_with_each_request():
    client = OpenAIChatClient("https://example.test/v1", "key", reasoning={"max_tokens": 8000})
    with patch.object(client, "_post", return_value=RESPONSE) as post:
        client.chat(model="m", messages=[{"role": "user", "content": "hi"}], options={"num_predict": 32768})
    payload = post.call_args.args[1]
    assert payload["reasoning"] == {"max_tokens": 8000}
    assert payload["max_tokens"] == 32768

def test_no_reasoning_field_by_default():
    client = OpenAIChatClient("https://example.test/v1", "key")
    with patch.object(client, "_post", return_value=RESPONSE) as post:
        client.chat(model="m", messages=[{"role": "user", "content": "hi"}])
    assert "reasoning" not in post.call_args.args[1]

def test_response_reports_token_usage():
    client = OpenAIChatClient("https://example.test/v1", "key")
    with patch.object(client, "_post", return_value=RESPONSE):
        resp = client.chat(model="m", messages=[{"role": "user", "content": "hi"}])
    assert (resp.completion_tokens, resp.reasoning_tokens) == (120, 100)
