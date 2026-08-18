from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from .protocol import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    BUFFER_SIZE,
    JsonRpcRequest,
    JsonRpcResponse,
)

logger = logging.getLogger(__name__)


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class IdaRpcClient:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        if self._writer is not None:
            return
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self._host, self._port
            )
            logger.info("Connected to IDA at %s:%d", self._host, self._port)
        except (ConnectionRefusedError, OSError) as e:
            raise RpcError(-1, f"Cannot connect to IDA at {self._host}:{self._port}: {e}")

    async def disconnect(self) -> None:
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def _ensure_connected(self) -> None:
        if self._writer is None or self._writer.is_closing():
            self._writer = None
            self._reader = None
            await self.connect()

    async def call(self, method: str, **params: Any) -> Any:
        async with self._lock:
            await self._ensure_connected()

            self._request_id += 1
            request = JsonRpcRequest(method=method, params=params, id=self._request_id)

            try:
                self._writer.write(request.to_bytes())
                await self._writer.drain()

                line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=120.0,
                )

                if not line:
                    await self.disconnect()
                    raise RpcError(-1, "Connection closed by IDA")

                response = JsonRpcResponse.from_bytes(line)

                if response.is_error:
                    raise RpcError(
                        response.error["code"],
                        response.error["message"],
                        response.error.get("data"),
                    )

                return response.result

            except asyncio.TimeoutError:
                await self.disconnect()
                raise RpcError(-1, "Request timed out waiting for IDA response")
            except (ConnectionError, BrokenPipeError) as e:
                await self.disconnect()
                raise RpcError(-1, f"Connection lost: {e}")

    async def ping(self) -> bool:
        try:
            result = await self.call("ping")
            return result == "pong"
        except RpcError:
            return False
