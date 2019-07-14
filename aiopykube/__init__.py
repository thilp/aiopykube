"""
Asynchronous Python client for Kubernetes, adapted from pykube-ng.
"""

__version__ = "0.2.0"

from .config import KubeConfig  # noqa
from .errors import KubernetesError, PyKubeError, HTTPError, ObjectDoesNotExist  # noqa
from .http import HTTPClient  # noqa
from .objects import APIObject, NamespacedAPIObject, KindInfo, object_factory  # noqa
from .objects import (  # noqa
    ClusterRole,
    ClusterRoleBinding,
    ConfigMap,
    CronJob,
    CustomResourceDefinition,
    DaemonSet,
    Deployment,
    Endpoint,
    Event,
    HorizontalPodAutoscaler,
    Ingress,
    Job,
    LimitRange,
    Namespace,
    Node,
    PersistentVolume,
    PersistentVolumeClaim,
    Pod,
    PodDisruptionBudget,
    PodSecurityPolicy,
    ReplicaSet,
    ReplicationController,
    ResourceQuota,
    Role,
    RoleBinding,
    Secret,
    Service,
    ServiceAccount,
    StatefulSet,
    ThirdPartyResource,
)
