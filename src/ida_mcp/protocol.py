from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
BUFFER_SIZE = 1024 * 1024

ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL = -32603
ERROR_IDA_NOT_READY = -32000
ERROR_DECOMPILER_UNAVAILABLE = -32001


@dataclass
class JsonRpcRequest:
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: int | str = 1

    def to_bytes(self) -> bytes:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": self.method,
            "params": self.params,
            "id": self.id,
        })
        return payload.encode("utf-8") + b"\n"


@dataclass
class JsonRpcResponse:
    id: int | str | None = None
    result: Any = None
    error: dict[str, Any] | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> JsonRpcResponse:
        obj = json.loads(data.decode("utf-8"))
        return cls(
            id=obj.get("id"),
            result=obj.get("result"),
            error=obj.get("error"),
        )

    @classmethod
    def success(cls, id: int | str, result: Any) -> JsonRpcResponse:
        return cls(id=id, result=result)

    @classmethod
    def failure(cls, id: int | str | None, code: int, message: str, data: Any = None) -> JsonRpcResponse:
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return cls(id=id, error=err)

    def to_bytes(self) -> bytes:
        obj: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            obj["error"] = self.error
        else:
            obj["result"] = self.result
        return json.dumps(obj).encode("utf-8") + b"\n"

    @property
    def is_error(self) -> bool:
        return self.error is not None
