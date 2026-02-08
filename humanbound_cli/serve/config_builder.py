"""Build bot-config JSON from a tunnel URL and detected runtime info."""

from .runtime_detector import RuntimeInfo


def build_bot_config(public_url: str, runtime: RuntimeInfo) -> dict:
    """Build the endpoint source config (same shape as clientbot.py integration).

    Payload heuristics:
    - LangGraph: ``{"input": {"messages": [{"role": "user", "content": "$PROMPT"}]}}``
    - Route contains "completions": OpenAI messages format
    - Otherwise: ``{"content": "$PROMPT"}``
    """
    chat_url = f"{public_url}{runtime.chat_route}"

    # Choose payload shape based on framework / route
    if runtime.framework == "langgraph":
        payload = {
            "input": {
                "messages": [{"role": "user", "content": "$PROMPT"}]
            }
        }
    elif "completion" in runtime.chat_route.lower():
        payload = {
            "messages": [{"role": "user", "content": "$PROMPT"}],
            "stream": False,
        }
    else:
        payload = {"content": "$PROMPT"}

    return {
        "streaming": False,
        "thread_auth": {
            "endpoint": "",
            "headers": {},
            "payload": {},
        },
        "thread_init": {
            "endpoint": "",
            "headers": {},
            "payload": {},
        },
        "chat_completion": {
            "endpoint": chat_url,
            "headers": {"Content-Type": "application/json"},
            "payload": payload,
        },
    }
