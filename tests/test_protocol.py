import json
import pytest
from ida_mcp.protocol import (
    JsonRpcRequest,
    JsonRpcResponse,
    DEFAULT_HOST,
    DEFAULT_PORT,
    ERROR_METHOD_NOT_FOUND,
)


def test_request_serialization():
    req = JsonRpcRequest(method="ping", params={"arg1": "value1"}, id=42)
    raw = req.to_bytes()
    assert raw.endswith(b"\n")
    data = json.loads(raw.decode("utf-8"))
    assert data["jsonrpc"] == "2.0"
    assert data["method"] == "ping"
    assert data["params"] == {"arg1": "value1"}
    assert data["id"] == 42


def test_response_success():
    resp = JsonRpcResponse.success(id=1, result={"status": "ok"})
    assert not resp.is_error
    raw = resp.to_bytes()
    data = json.loads(raw.decode("utf-8"))
    assert data["result"] == {"status": "ok"}
    assert data["id"] == 1


def test_response_failure():
    resp = JsonRpcResponse.failure(id=2, code=ERROR_METHOD_NOT_FOUND, message="Method not found")
    assert resp.is_error
    raw = resp.to_bytes()
    data = json.loads(raw.decode("utf-8"))
    assert data["error"]["code"] == ERROR_METHOD_NOT_FOUND
    assert data["error"]["message"] == "Method not found"
    assert data["id"] == 2


def test_response_from_bytes():
    payload = b'{"jsonrpc": "2.0", "result": "pong", "id": 1}\n'
    resp = JsonRpcResponse.from_bytes(payload)
    assert not resp.is_error
    assert resp.result == "pong"
    assert resp.id == 1
