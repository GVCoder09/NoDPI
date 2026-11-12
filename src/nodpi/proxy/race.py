"""Racing several upstream connections for the first server reply to a ClientHello"""

import asyncio
from typing import Awaitable, Callable, List, Optional, Sequence, Tuple

from nodpi.proxy.desync import send_with

Connection = Tuple[asyncio.StreamReader, asyncio.StreamWriter]
Winner = Tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes, str]

READ_CHUNK = 65536


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except BaseException:
        pass


async def _attempt(
    connect: Callable[[], Awaitable[Connection]],
    parts: List[bytes],
    method: str,
    on_sent: Callable[[int], None],
) -> Winner:
    reader, writer = await connect()
    try:
        await send_with(writer, parts, method)
        on_sent(sum(len(p) for p in parts))
        first = await reader.read(READ_CHUNK)
        if not first:
            raise ConnectionError("closed by server")
        return reader, writer, first, method
    except BaseException:
        await _close(writer)
        raise


def _succeeded(task: asyncio.Task) -> bool:
    return task.done() and not task.cancelled() and task.exception() is None


async def _first_success(tasks: List[asyncio.Task], timeout: float) -> Optional[Winner]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(timeout, 0)
    for t in tasks:
        if _succeeded(t):
            return t.result()
    pending = {t for t in tasks if not t.done()}
    while pending:
        left = deadline - loop.time()
        if left <= 0:
            return None
        done, pending = await asyncio.wait(
            pending, timeout=left, return_when=asyncio.FIRST_COMPLETED
        )
        for t in done:
            if _succeeded(t):
                return t.result()
    return None


async def race_client_hello(
    first_connection: Connection,
    connect: Callable[[], Awaitable[Connection]],
    parts: List[bytes],
    methods: Sequence[str],
    schedule: Sequence[float],
    timeout: float,
    on_sent: Callable[[int], None],
) -> Tuple[Optional[Winner], int]:
    """Start attempts at schedule offsets; return the first replying one and attempts count"""

    loop = asyncio.get_running_loop()
    start = loop.time()
    tasks: List[asyncio.Task] = []
    winner: Optional[Winner] = None

    async def reuse_first() -> Connection:
        return first_connection

    try:
        for i, offset in enumerate(schedule):
            if offset >= timeout:
                break
            if tasks:
                winner = await _first_success(tasks, start + offset - loop.time())
                if winner:
                    return winner, len(tasks)
            method = methods[i % len(methods)]
            tasks.append(
                asyncio.ensure_future(
                    _attempt(reuse_first if i == 0 else connect, parts, method, on_sent)
                )
            )

        winner = await _first_success(tasks, start + timeout - loop.time())
        return winner, len(tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for t in tasks:
            if _succeeded(t) and t.result() is not winner:
                await _close(t.result()[1])
        if winner is None or winner[1] is not first_connection[1]:
            await _close(first_connection[1])
