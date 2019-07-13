"""
Asynchronous Python client for Kubernetes, adapted from pykube-ng.
"""

__version__ = "0.2.0"

from .config import KubeConfig  # noqa
from .errors import KubernetesError, PyKubeError, HTTPError, ObjectDoesNotExist  # noqa
from .http import HTTPClient  # noqa
