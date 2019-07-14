import asyncio
import inspect
import posixpath
import ssl
import sys
import warnings
from typing import Optional, Dict, Any, Tuple, Union
from urllib.parse import urlparse

import aiohttp

from . import __version__
from . import errors
from .config import KubeConfig, BytesOrFile

Response = aiohttp.ClientResponse

DEFAULT_HTTP_TIMEOUT = 10  # seconds


class HTTPClient:
    """
    Client for interfacing with the Kubernetes API.

    This object can be used either directly (as in synchronous pykube) or as
    an asynchronous context manager (``async with``).
    As a context manager, it will properly close the connection pool for you.
    If you use it without a context manager, you should call :meth:`close` after use.
    """

    def __init__(
        self,
        config: KubeConfig,
        *,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        session: Optional[aiohttp.ClientSession] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        if inspect.iscoroutine(config):
            raise ValueError(f"should be awaited: {config.__qualname__}")
        if default_headers is None:
            default_headers = {}
        self.config = config
        self.timeout = timeout
        self.session = session
        self.kwargs: Optional[Dict[str, Any]] = None
        self.default_headers = {
            "User-Agent": f"aiopykube/{__version__}",
            **default_headers,
        }

    async def __aenter__(self) -> "HTTPClient":
        if self.session is None:
            self.session = await self._make_session()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    def __del__(self) -> None:
        if self.session is None:
            return

        # We can't close the session from a non-async method, but we can warn.
        context = {
            "message": f"aiopykube: Unclosed {self.__class__.__name__} instance!",
            "http_client": self,
        }

        kwargs = {}
        if sys.version_info >= (3, 6):
            kwargs = {"source": self}
        warnings.warn(context["message"], ResourceWarning, **kwargs)

        self.session.loop.call_exception_handler(context)

    async def close(self) -> None:
        if self.session is None:
            return
        await self.session.close()
        self.session = None
        # See:
        # https://aiohttp.readthedocs.io/en/stable/client_advanced.html#graceful-shutdown
        await asyncio.sleep(0.250)

    async def _make_session(self) -> aiohttp.ClientSession:
        kwargs = await self._prepare_session_kwargs()
        headers = {**self.default_headers, **kwargs.pop("headers", {})}
        connector = aiohttp.TCPConnector(ssl=kwargs.pop("ssl", None))
        return aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
            **kwargs,
        )

    async def _prepare_session_kwargs(self) -> Dict[str, Any]:
        kwargs = {"headers": {}}

        # Setup certificate verification.
        if "certificate-authority" in self.config.cluster:
            ca: BytesOrFile = self.config.cluster["certificate-authority"]
            ca_path = await ca.path()
            kwargs["ssl"] = ssl.create_default_context(cafile=str(ca_path))
        elif "insecure-skip-tls-verify" in self.config.cluster:
            kwargs["ssl"] = not self.config.cluster["insecure-skip-tls-verify"]

        # Setup cluster API authentication.
        if self.config.user.get("token"):
            kwargs["headers"]["Authorization"] = f"Bearer {self.config.user['token']}"
        elif "auth-provider" in self.config.user:
            raise NotImplementedError("auth-provider in kubeconfig")
        elif "client-certificate" in self.config.user:
            kwargs.setdefault("ssl", ssl.create_default_context())
            if kwargs["ssl"] is not False:  # from "insecure-skip-tls-verify"
                ca_path, key_path = await asyncio.gather(
                    self.config.user["client-certificate"].path(),
                    self.config.user["client-key"].path(),
                )
                kwargs["ssl"].load_cert_chain(str(ca_path), str(key_path))
        elif self.config.user.get("username") and self.config.user.get("password"):
            kwargs["auth"] = aiohttp.BasicAuth(
                login=self.config.user["username"],
                password=self.config.user["password"],
            )

        return kwargs

    @property
    def url(self) -> str:
        return self.config.cluster["server"]

    @url.setter
    def url(self, value: str) -> None:
        self.config.cluster["server"] = urlparse(value).geturl()

    async def version(self) -> Tuple[int, int]:
        """
        Get the Kubernetes API version.
        """
        resp = await self.get(version="", base="/version")
        await raise_for_status(resp)
        data = await resp.json()
        return data["major"], data["minor"]

    async def resource_list(self, api_version) -> dict:
        """
        The
        :param api_version:
        :return:
        """
        cached_attr = f"_cached_resource_list_{api_version}"
        if not hasattr(self, cached_attr):
            resp = await self.get(version=api_version)
            await raise_for_status(resp)
            setattr(self, cached_attr, await resp.json())
        return getattr(self, cached_attr)

    def _convert_kwargs(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Converts aiopykube kwargs to aiohttp kwargs.
        """
        if version == "v1":
            base = base or "/api"
        elif "/" in version:
            base = base or "/apis"
        elif not base:
            raise TypeError("unknown API version; please provide a 'base' kwarg")
        bits = [base, version]

        # Overwrite the (default) namespace from context if it was set.
        if namespace is not None:
            if not namespace:
                namespace = self.config.namespace
            if namespace:
                bits.extend(["namespaces", namespace])

        if url.startswith("/"):
            url = url[1:]
        bits.append(url)

        kwargs["url"] = self.url + posixpath.join(*bits)

        if timeout is None:
            kwargs["timeout"] = self.timeout
        elif isinstance(timeout, float):
            kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout)
        else:
            kwargs["timeout"] = timeout

        return kwargs

    async def get(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Executes an HTTP GET request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.get(
            headers=headers,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def options(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Executes an HTTP OPTIONS request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.options(
            headers=headers,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def head(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Executes an HTTP HEAD request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.head(
            headers=headers,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def post(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[dict] = None,
    ) -> Response:
        """Executes an HTTP POST request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.post(
            headers=headers,
            json=json,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def put(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[dict] = None,
    ) -> Response:
        """Executes an HTTP PUT request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.put(
            headers=headers,
            json=json,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def patch(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[dict] = None,
    ) -> Response:
        """Executes an HTTP PATCH request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.patch(
            headers=headers,
            json=json,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )

    async def delete(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        url: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[dict] = None,
    ) -> Response:
        """Executes an HTTP DELETE request against the API server."""
        if self.session is None:
            self.session = await self._make_session()
        return await self.session.delete(
            headers=headers,
            json=json,
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                url=url,
                timeout=timeout,
            ),
        )


def ok(resp: Response) -> bool:
    """
    Returns True if (and only if) *resp.status* is not between 400 (included)
    and 600 (excluded).
    """
    return not (400 <= resp.status < 600)


async def raise_for_status(resp: Response) -> None:
    """
    If :meth:`ok` returns True, do nothing. Otherwise, raises an
    :class:`errors.HTTPError` describing the error.
    """
    # We don't rely on aiohttp's raise_for_status because it calls
    # resp.release before we're done with the body.
    if ok(resp):
        return

    details: Optional[str] = None
    try:
        if resp.content_type == "application/json":
            payload = await resp.json()
            if payload.get("kind") == "Status":
                details = payload.get("message")
    except Exception:  # We're just trying to gather more information.
        pass

    resp.release()
    raise errors.HTTPError(
        code=resp.status, message=details or resp.reason, request=resp.request_info
    )
