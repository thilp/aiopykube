import enum
import posixpath
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union, Type
from urllib.parse import urlencode

from aiopykube import waiting
from aiopykube.mixins import ReplicatedMixin, ScalableMixin
from . import http, errors
from .http import HTTPClient
from .patches import PatchType, Patch


class CascadingDeletionPolicy(enum.Enum):
    """
    Cascading deletion policy for :meth:`APIObject.delete`.
    This corresponds to the ``propagationPolicy`` of a Kubernetes DeleteOptions.
    """

    ORPHAN = "Orphan"
    FOREGROUND = "Foreground"
    BACKGROUND = "Background"


class APIObject:
    """Abstract base class for all Kubernetes API resources."""

    def __init_subclass__(
        cls,
        *,
        version: str,
        kind: Optional[str] = None,
        plural: Optional[str] = None,
        base: Optional[str] = None,
        **_,
    ) -> None:
        cls.kind = kind or cls.__name__
        cls.plural = plural or cls.kind.lower() + "s"
        cls.version = version
        cls.base = base

    def __init__(self, api: HTTPClient, obj: dict) -> None:
        self.api = api
        self._set_obj(obj)

    def _set_obj(self, obj: dict) -> None:
        if "metadata" not in obj:
            t = self.__class__.__name__
            raise ValueError(f"missing 'metadata' field for {t} in {obj!r}")
        obj = deepcopy(obj)
        obj.update(kind=self.kind, apiVersion=self.version)
        self.obj = obj
        self._original_obj = deepcopy(obj)

    def __repr__(self) -> str:
        return f"<{self.kind} {self.name}>"

    def __str__(self) -> str:
        return f"{self.kind} {self.name!r}"

    @property
    def name(self) -> str:
        """Name of the Kubernetes resource (``metadata.name``)."""
        return self.obj["metadata"]["name"]

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.obj["metadata"]

    @property
    def labels(self) -> Dict[str, str]:
        """Labels of the Kubernetes resource (``metadata.labels``)."""
        return self.obj["metadata"].setdefault("labels", {})

    @property
    def annotations(self) -> Dict[str, str]:
        """Annotations of the Kubernetes resource (``metadata.annotations``)."""
        return self.obj["metadata"].setdefault("annotations", {})

    def _default_kwargs(
        self,
        *,
        specific_resource: bool = True,
        operation: str = "",
        params: Optional[str] = None,
    ) -> dict:
        kwargs = {}

        if specific_resource:
            kwargs["url"] = posixpath.join(self.plural, self.name, operation)
        else:
            kwargs["url"] = self.plural

        if params is not None:
            query_string = urlencode(params)
            if query_string:
                kwargs["url"] += f"?{query_string}"

        if self.base:
            kwargs["base"] = self.base

        kwargs["version"] = self.version

        return kwargs

    async def exists(self, raising: bool = False) -> bool:
        """
        Whether the Kubernetes resource already exists in the cluster.

        :param raising: Whether to raise :class:`errors.ObjectDoesNotExist`
            instead of returning False. Note that this method can always raise
            :class:`errors.HTTPError` if the API server returns an error other
            than 404, regardless of this parameter.
        :raise errors.ObjectDoesNotExist: If *raising* is True and the resource
            does not exist in the cluster.
        :raise errors.HTTPError: If the API server returns an error other than 404.
        """
        resp = await self.api.get(**self._default_kwargs())
        if http.ok(resp):
            return True
        if resp.status != 404:
            await http.raise_for_status(resp)
        if raising:
            raise errors.ObjectDoesNotExist(self)
        return False

    async def create(self, wait: waiting.Strategy = waiting.NEVER) -> None:
        """
        Creates the Kubernetes resource in the cluster.

        :param wait: Whether and how to wait for :meth:`exists` to return True.
        :raise errors.HTTPError: If the API server returns an error.
        """
        resp = await self.api.post(
            **self._default_kwargs(specific_resource=True), json=self.obj
        )
        await http.raise_for_status(resp)
        self._set_obj(await resp.json())
        if wait is not None:
            await wait(self.exists)(raising=True)

    async def reload(self) -> None:
        """
        Replaces *self.obj* with the cluster's current definition of this resource.

        :raise errors.HTTPError: If the API server returns an error.
        """
        resp = await self.api.get(**self._default_kwargs())
        await http.raise_for_status(resp)
        self._set_obj(await resp.json())

    async def patch(
        self, patch: Union[dict, list, Patch], *, type: PatchType = PatchType.STRATEGIC
    ) -> None:
        """
        Patches the Kubernetes resource in the cluster.

        :param patch: Patch describing the changes, in the format of *type*.
        :param type: Format of *patch*.
            Equivalent to the ``--type`` option of ``kubectl patch``.
        """
        if not patch:
            return

        if isinstance(patch, Patch):
            type = patch.type
            body = patch.body
        else:
            body = patch

        resp = await self.api.patch(
            **self._default_kwargs(), headers={"Content-Type": type.value}, json=body
        )
        await http.raise_for_status(resp)
        print(">>> status =", resp.status, resp.reason)
        self._set_obj(await resp.json())

    async def update(self) -> None:
        """
        Patches the Kubernetes resource in the cluster so that it is equivalent
        to *self.obj*.
        """
        await self.patch(Patch.from_diff(old=self._original_obj, new=self.obj))

    async def delete(
        self, propagation_policy: Optional[CascadingDeletionPolicy] = None
    ) -> None:
        """
        Deletes the Kubernetes resource from the cluster.

        :param propagation_policy: Whether and how the resource’s dependents
            are also deleted automatically.
        """
        opts = {}
        if propagation_policy is not None:
            opts = {"propagationPolicy": propagation_policy.value}

        resp = await self.api.delete(**self._default_kwargs(), json=opts)
        if resp.status != 404:
            await http.raise_for_status(resp)


class NamespacedAPIObject(APIObject, kind=None, plural=None, version=None):
    def __init_subclass__(
        cls,
        *,
        version: str,
        kind: Optional[str] = None,
        plural: Optional[str] = None,
        base: Optional[str] = None,
        **kwargs,
    ) -> None:
        super().__init_subclass__(
            kind=kind, plural=plural, version=version, base=base, **kwargs
        )

    @property
    def namespace(self) -> str:
        return self.obj["metadata"].get("namespace") or self.api.config.namespace

    def _default_kwargs(
        self,
        *,
        specific_resource: bool = True,
        operation: str = "",
        params: Optional[str] = None,
    ) -> dict:
        kwargs = super()._default_kwargs(
            specific_resource=specific_resource, operation=operation, params=params
        )
        kwargs.update(namespace=self.namespace)
        return kwargs


@dataclass(frozen=True)
class KindInfo:
    version: str
    kind: str
    plural: str
    namespaced: bool

    def api_object_class(self) -> Type[APIObject]:
        """
        Returns a Python class inheriting from :class:`APIObject` for manipulating
        this resource kind with aiopykube like any built-in APIObject resource.

        Compared to :meth:`object_factory`, this method does not require cluster
        access (via an HTTPClient instance), so it is handy for defining top-level
        types, but the user must provide more information about the kind.
        """
        base = NamespacedAPIObject if self.namespaced else APIObject
        return type(
            name=self.kind,
            bases=(base,),
            dict={},
            version=self.version,
            kind=self.kind,
            plural=self.plural,
        )

    @classmethod
    async def fetch(cls, api: HTTPClient, api_version: str, kind: str) -> "KindInfo":
        """
        Creates a :class:`KindInfo` by fetching the necessary information from
        a Kubernetes API server.
        """
        resource_list = await api.resource_list(api_version)
        try:
            resource = next(r for r in resource_list["resources"] if r["kind"] == kind)
        except StopIteration:
            name = f"{api_version}/{kind}"
            raise ValueError(f"unknown resource kind {name!r} in cluster") from None
        return KindInfo(
            version=api_version,
            kind=kind,
            plural=resource["name"],
            namespaced=resource["namespaced"],
        )


async def object_factory(
    api: HTTPClient, api_version: str, kind: str
) -> Type[APIObject]:
    """
    Cluster-assisted building of an APIObject subclass for the specified
    resource kind.
    That subclass can then be used like built-in APIObject subclasses, such as Pod.

    This function stitches together :meth:`KindInfo.fetch` and
    :meth:`KindInfo.api_object_class`, so that the user only needs to provide
    *api_version* and *kind*: the remaining required information is read from
    the API server.
    """
    info = await KindInfo.fetch(api, api_version, kind)
    return info.api_object_class()


class ConfigMap(NamespacedAPIObject, version="v1"):
    pass


class CronJob(NamespacedAPIObject, version="batch/v1beta1"):
    pass


class DaemonSet(NamespacedAPIObject, version="apps/v1"):
    pass


class Deployment(NamespacedAPIObject, ReplicatedMixin, version="apps/v1"):
    @property
    def ready(self) -> bool:
        return (
            self.obj["status"]["observedGeneration"]
            >= self.obj["metadata"]["generation"]
            and self.obj["status"]["updatedReplicas"] == self.replicas
        )

    # TODO: Replace me with a dedicated object or maybe a context manager.
    async def rollout_undo(self, target_revision: str = None) -> str:
        """
        Equivalent to the ``kubectl rollout undo deployment`` command.

        :param target_revision: Equivalent to the kubectl ``--to-revision`` option.
        :return: The API server response.
        """
        revision = {}
        if target_revision is not None:
            revision["revision"] = target_revision

        params = dict(
            kind="DeploymentRollback",
            apiVersion=self.version,
            name=self.name,
            rollbackTo=revision,
        )
        kwargs = dict(
            version=self.version, namespace=self.namespace, operation="rollback"
        )
        resp = await self.api.post(**self._default_kwargs(), json=params, **kwargs)
        await http.raise_for_status(resp)
        return await resp.text()


class Endpoint(NamespacedAPIObject, version="v1"):
    pass


class Event(NamespacedAPIObject, version="v1"):
    pass


class LimitRange(NamespacedAPIObject, version="v1"):
    pass


class ResourceQuota(NamespacedAPIObject, version="v1"):
    pass


class ServiceAccount(NamespacedAPIObject, version="v1"):
    pass


class Ingress(NamespacedAPIObject, version="extensions/v1beta1", plural="ingresses"):
    pass


class ThirdPartyResource(APIObject, version="extensions/v1beta1"):
    pass


class Job(
    NamespacedAPIObject, ScalableMixin, version="batch/v1", scalable_attr="parallelism"
):
    @property
    def parallelism(self) -> int:
        return self.obj["spec"]["parallelism"]

    @parallelism.setter
    def parallelism(self, value: int) -> None:
        self.obj["spec"]["parallelism"] = value


class Namespace(APIObject, version="v1"):
    pass


class Node(APIObject, version="v1"):
    @property
    def schedulable(self) -> bool:
        return not self.obj["spec"].get("unschedulable")

    async def set_schedulable(self, value: bool) -> None:
        self.obj["spec"]["unschedulable"] = not value
        await self.update()

    async def cordon(self) -> None:
        await self.set_schedulable(False)

    async def uncordon(self) -> None:
        await self.set_schedulable(True)


class Pod(NamespacedAPIObject, version="v1"):
    @property
    def ready(self) -> bool:
        conditions = self.obj["status"].get("conditions", [])
        try:
            cond_ready = next(c for c in conditions if c["type"] == "Ready")
        except StopIteration:
            return False
        return cond_ready["status"] == "True"

    # TODO: Replace with a dedicated object, support streaming ("follow").
    async def logs(
        self,
        *,
        container: Optional[str] = None,
        pretty: bool = False,
        previous: bool = False,
        since_seconds: Optional[int] = None,
        timestamps: bool = False,
        tail_lines: Optional[int] = None,
        limit_bytes: Optional[int] = None,
    ):
        params = dict(
            pretty=_kube_bool(pretty),
            previous=_kube_bool(previous),
            timestamps=_kube_bool(timestamps),
        )
        if container is not None:
            params["container"] = container
        if since_seconds is not None:
            params["sinceSeconds"] = since_seconds
        if tail_lines is not None:
            params["tailLines"] = tail_lines
        if limit_bytes is not None:
            params["limitBytes"] = limit_bytes

        query_string = urlencode(params)
        op = "log"
        if query_string:
            op += f"?{query_string}"

        resp = await self.api.get(**self._default_kwargs(operation=op))
        await http.raise_for_status(resp)
        return await resp.text()


def _kube_bool(b: bool) -> str:
    return str(b).lower()


class ReplicationController(NamespacedAPIObject, ReplicatedMixin, version="v1"):
    @property
    def ready(self) -> bool:
        return (
            self.obj["status"]["observedGeneration"]
            >= self.obj["metadata"]["generation"]
            and self.obj["status"]["readyReplicas"] == self.replicas
        )


class ReplicaSet(NamespacedAPIObject, ReplicatedMixin, version="apps/v1"):
    pass


class Secret(NamespacedAPIObject, version="v1"):
    pass


class Service(NamespacedAPIObject, version="v1"):
    pass


class PersistentVolume(APIObject, version="v1"):
    pass


class PersistentVolumeClaim(NamespacedAPIObject, version="v1"):
    pass


class HorizontalPodAutoscaler(NamespacedAPIObject, version="autoscaling/v1"):
    pass


class StatefulSet(NamespacedAPIObject, ReplicatedMixin, version="apps/v1"):
    pass


class Role(NamespacedAPIObject, version="rbac.authorization.k8s.io/v1"):
    pass


class RoleBinding(NamespacedAPIObject, version="rbac.authorization.k8s.io/v1"):
    pass


class ClusterRole(APIObject, version="rbac.authorization.k8s.io/v1"):
    pass


class ClusterRoleBinding(APIObject, version="rbac.authorization.k8s.io/v1"):
    pass


class PodSecurityPolicy(
    APIObject, version="extensions/v1beta1", plural="podsecuritypolicies"
):
    pass


class PodDisruptionBudget(APIObject, version="policy/v1beta1"):
    pass


class CustomResourceDefinition(APIObject, version="apiextensions.k8s.io/v1beta1"):
    pass
