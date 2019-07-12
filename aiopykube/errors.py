class KubernetesError(Exception):
    """Base exception for all Kubernetes-related errors."""


class PyKubeError(KubernetesError):
    """Base exception for all errors raised by PyKube."""


class HTTPError(PyKubeError):
    """
    Generic exception signaling that an error HTTP status code was received
    in response to a request from PyKube to a remote service.
    """

    def __init__(self, code, message) -> None:
        super().__init__(message)
        self.code = code


class ObjectDoesNotExist(PyKubeError):
    """
    A PyKube query was expected to return at least one Kubernetes resource,
    but no such resource exists.
    """
