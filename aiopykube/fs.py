"""
Asynchronous filesystem I/O operations.
"""
import asyncio
import os
from concurrent.futures.thread import ThreadPoolExecutor
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Union, TypeVar, Callable

FilePath = Union[os.PathLike, Path, str, bytes]

# Using a separate executor because we don't want IO operations to block us.
_fs_executor = ThreadPoolExecutor()

_R = TypeVar("_R")


async def _run(f: Callable[..., _R], *args) -> _R:
    """
    Runs the provided function asynchronously using the executor dedicated to
    filesystem operations.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_fs_executor, f, *args)


async def read_text(path: Path) -> str:
    """Asynchronously fetches and decode (from UTF-8) the content of a file."""
    return await _run(path.read_text)


async def read_bytes(path: Path) -> bytes:
    """Asynchronously fetches the raw content (bytes) of a file."""
    return await _run(path.read_bytes)


async def create_temporary_file() -> NamedTemporaryFile:
    """
    Asynchronously creates and returns a tempfile.NamedTemporaryFile.

    That file will *not* be deleted automatically.
    """
    return await _run(lambda: NamedTemporaryFile(delete=False))


async def write_text(path: Path, text: str) -> None:
    """
    Asynchronously writes *text* in the file at *path*, overwriting existing
    content.
    """
    await _run(path.write_text, text)


async def write_bytes(path: Path, data: bytes) -> None:
    """
    Asynchronously writes *data* in the file at *path*, overwriting existing
    content.
    """
    await _run(path.write_bytes, data)


async def unlink(path: Path) -> None:
    """Asynchronously removes the file at *path*."""
    await _run(path.unlink)
