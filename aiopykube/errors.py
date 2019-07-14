from typing import Optional

import aiohttp


class KubernetesError(Exception):
    """Base exception for all Kubernetes-related errors."""


class PyKubeError(KubernetesError):
    """Base exception for all errors raised by PyKube."""


class HTTPError(PyKubeError):
    """
    Generic exception signaling that an error HTTP status code was received
    in response to a request from PyKube to a remote service.
    """

    def __init__(
        self, *, code: int, message: str, request: aiohttp.RequestInfo
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request = request

    def __str__(self) -> str:
        req = f"{self.request.method} {self.request.real_url}"
        return f"{self.code}: {self.message} (request was: {req})"

    def __repr__(self) -> str:
        fields = [f"{a}={getattr(self, a)!r}" for a in ("code", "message", "request")]
        return f"{self.__class__.__qualname__}({', '.join(fields)})"


class PotentialWaitSignal(Exception):
    """
    Raised by functions to signal to tenacity that they want to wait.
    """


class ObjectDoesNotExist(PyKubeError, PotentialWaitSignal):
    """
    A PyKube query was expected to return at least one Kubernetes resource,
    but no such resource exists.
    """

    def __init__(self, o) -> None:
        super().__init__(str(o))
