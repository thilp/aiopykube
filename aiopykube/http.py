import asyncio
import inspect
import posixpath
import ssl
from typing import Optional, Dict, Any, Tuple, Union
from urllib.parse import urlparse

import aiohttp

from . import __version__
from .config import KubeConfig, BytesOrFile
from .errors import HTTPError

Response = aiohttp.ClientResponse

DEFAULT_HTTP_TIMEOUT = 10  # seconds


class HTTPClient:
    """
    Client for interfacing with the Kubernetes API.
    """

    def __init__(
        self,
        config: KubeConfig,
        *,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> None:
        if inspect.iscoroutine(config):
            raise ValueError(f"should be awaited: {config.__qualname__}")
        self.config = config
        self.timeout = timeout
        self.default_headers = {"User-Agent": f"aiopykube/{__version__}"}
        self.session = session
        self.kwargs: Optional[Dict[str, Any]] = None

    def __enter__(self) -> None:
        raise TypeError(
            f"use 'async with' instead of 'with' on {self.__class__.__qualname__}"
        )

    __exit__ = None

    async def __aenter__(self) -> "HTTPClient":
        kwargs = await self._prepare_kwargs()
        headers = {**self.default_headers, **kwargs.pop("headers", {})}
        connector = aiohttp.TCPConnector(ssl=kwargs.pop("ssl", None))
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
            **kwargs,
        )
        return self

    async def __aexit__(self, *_) -> None:
        await self.session.close()
        self.session = None
        # See:
        # https://aiohttp.readthedocs.io/en/stable/client_advanced.html#graceful-shutdown
        await asyncio.sleep(0.250)

    async def _prepare_kwargs(self) -> Dict[str, Any]:
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
        await self.raise_for_status(resp)
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
            await self.raise_for_status(resp)
            setattr(self, cached_attr, await resp.json())
        return getattr(self, cached_attr)

    def _convert_kwargs(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
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

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]
        bits.append(endpoint)

        kwargs["url"] = self.url + posixpath.join(*bits)

        if timeout is None:
            kwargs["timeout"] = self.timeout
        elif isinstance(timeout, float):
            kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout)
        else:
            kwargs["timeout"] = timeout

        return kwargs

    async def raise_for_status(self, resp: Response) -> None:
        """
        Wraps :meth:`aiohttp.ClientResponse.raise_for_status` by raising a
        :class:`aiopykube.errors.HTTPError` (with details from the response)
        when possible.
        Otherwise, the intercepted exception is raised again.
        """
        try:
            resp.raise_for_status()
        except aiohttp.ClientResponseError as err:
            if resp.headers["content-type"] == "application/json" and not resp.closed:
                payload = await resp.json()
                if payload.get("kind") == "Status":
                    raise HTTPError(
                        code=resp.status, message=payload.get("message", "")
                    ) from err
            raise

    async def get(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP GET request against the API server."""
        return await self.session.get(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def options(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP OPTIONS request against the API server."""
        return await self.session.options(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def head(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP HEAD request against the API server."""
        return await self.session.head(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def post(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP POST request against the API server."""
        return await self.session.post(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def put(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP PUT request against the API server."""
        return await self.session.put(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def patch(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP PATCH request against the API server."""
        return await self.session.patch(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )

    async def delete(
        self,
        *,
        version: Optional[str] = "v1",
        base: str = "",
        namespace: Optional[str] = None,
        endpoint: str = "",
        timeout: Union[None, aiohttp.ClientTimeout, float] = None,
    ) -> Response:
        """Executes an HTTP DELETE request against the API server."""
        return await self.session.delete(
            **self._convert_kwargs(
                version=version,
                base=base,
                namespace=namespace,
                endpoint=endpoint,
                timeout=timeout,
            )
        )
