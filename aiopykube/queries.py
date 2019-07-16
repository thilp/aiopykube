import enum
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import (
    Optional,
    TypeVar,
    Generic,
    Type,
    overload,
    Union,
    AsyncIterator,
    Mapping,
    List,
)
from urllib.parse import urlencode

from . import selectors as sel, http, errors
from .http import HTTPClient
from .objects import APIObject, NamespacedAPIObject
from .selectors import Selector, ExtendedSelector

Obj = TypeVar("Obj", bound=APIObject)
NamespacedObj = TypeVar("NamespacedObj", bound=NamespacedAPIObject)
T = TypeVar("T")


@dataclass
class WatchEvent(Generic[Obj]):
    """Represents a single event to a watched resource."""

    type: str
    object: Obj


class Namespaces(enum.Enum):
    ALL = enum.auto()
    NONE = enum.auto()


Namespace = Union[
    str,  # Selects this particular namespace only.
    Namespaces,  # Selects either all or no namespaces.
]


class ResourceVersions(enum.Enum):
    FIRST = enum.auto()  # Beginning of the history.
    CURRENT = enum.auto()  # Current resourceVersion of an object.


ResourceVersion = Union[
    str,  # The resourceVersion associated to this value.
    ResourceVersions,  # A resourceVersion specified by a ResourceVersions field.
]

_NOT_PROVIDED = object()


class ObjectIterator:
    """
    Created when iterating on a :class:`Query` (i.e. by :meth:`Query.__aiter__`).
    Do not create it yourself, as this type is not part of aiopykube's public API.
    (It is only provided in case someone would need it for type annotations.)
    """

    def __init__(self, q: "Query") -> None:
        self._query = q
        self._objects = None

    async def __anext__(self):
        if self._objects is None:
            self._objects = await self._query._objects()
        try:
            return self._objects.pop()
        except IndexError:
            raise StopAsyncIteration from None


@dataclass
class Query(Generic[Obj]):
    """
    Selects and fetches Kubernetes resources based on user-provided criteria.
    """

    api: HTTPClient
    resource_type: Type[Obj]
    label_selector: Selector
    field_selector: Selector
    namespace: Namespace = Namespaces.ALL
    _cached_response_json: Optional[dict] = None

    @overload
    def filter(
        self: Obj,
        *,
        namespace: Optional[Namespace] = None,
        selector: Optional[ExtendedSelector] = None,
        field_selector: Optional[ExtendedSelector] = None,
    ) -> "Query[Obj]":
        ...

    @overload  # noqa
    def filter(
        self: NamespacedObj,
        *,  # no namespace kwarg
        selector: Optional[ExtendedSelector] = None,
        field_selector: Optional[ExtendedSelector] = None,
    ) -> "Query[NamespacedObj]":
        ...

    def filter(  # noqa
        self,
        *,
        namespace: Optional[Namespace] = None,
        selector: Optional[ExtendedSelector] = None,
        field_selector: Optional[ExtendedSelector] = None,
    ) -> "Query[Obj]":
        """
        Filters Kubernetes objects by namespace, labels, or fields.

        *selector* and *field_selector* can be one of:

          - a string, meaning that the corresponding label/field name must simply
          exist on the resource, regardless of its value;

          - a mapping ``{A: B, ...}``, meaning:

            - if ``A`` has the form ``K__OP`` (for some values of ``K`` and
              ``OP``), then the value of the label/field ``K`` must verify the
              predicate ``OP`` with respect to the reference ``B``.
              Possible ``OP`` are:

                - ``eq``, ``=``, ``==`` (equality);
                - ``neq``, ``!=`` (inequality);
                - ``in`` (inclusion in a set of values);
                - ``notin`` (exclusion from a set of values).

              With ``in`` and ``notin``, ``B`` is supposed to be an iterable of
              expected values.

              Read more about these predicates at:
              https://kubernetes.io/docs/concepts/overview/working-with-objects/labels

            - if ``B`` is :attr:`selectors.Is.PRESENT` or :attr:`selectors.Is.ABSENT`,
              then the label/field ``A`` must (respectively) exist or not exist in
              the resource (so :attr:`selectors.Is.PRESENT` is a more general form
              of the "string argument" usage mentioned above).

            - otherwise, the value of the label/field ``A`` must be equal to ``B``
              (so ``A`` is equivalent to ``A__eq``).

        :param namespace: Restrict search in this particular namespace.
            Use :attr:`Namespaces.ALL` (the default) or :attr:`Namespaces.NONE`
            when you are not targeting a namespace.
            Using this argument on queries on non-namespaced resource types
            raises a :class:`TypeError`.
        :param selector: Label selector.
        :param field_selector: Field selector.
        :return: A new, refined :class:`Query`.
        :raise TypeError: If *namespace* is specified for a non-namespaced
            resource type.
        """

        new_namespace = self.namespace
        if namespace:
            if not issubclass(self.resource_type, NamespacedAPIObject):
                r = self.resource_type.__qualname__
                raise TypeError(f"can't filter by namespace: {r} is not namespaced")
            new_namespace = namespace

        new_label_selector = self.label_selector
        if selector is not None:
            new_label_selector = sel.merge(
                old=new_label_selector, new=sel.normalize(selector)
            )

        new_field_selector = self.field_selector
        if field_selector is not None:
            new_field_selector = sel.merge(
                old=new_field_selector, new=sel.normalize(field_selector)
            )

        return self.__class__(
            api=self.api,
            resource_type=self.resource_type,
            label_selector=new_label_selector,
            field_selector=new_field_selector,
            namespace=new_namespace,
        )

    async def _get_by_name(self, name: str) -> Obj:
        kwargs = {}
        if isinstance(self.namespace, str):
            kwargs["namespace"] = self.namespace

        resp = await self.api.get(
            url=f"{self.resource_type.plural}/{name}",
            version=self.resource_type.version,
            **kwargs,
        )
        if resp.status == 404:
            raise errors.ObjectDoesNotExist(self)
        await http.raise_for_status(resp)
        return self.resource_type(api=self.api, obj=await resp.json())

    @overload
    async def get(self, *, name: str = "") -> Obj:
        ...

    @overload  # noqa
    async def get(self, *, name: str = "", default: T) -> Union[Obj, T]:
        ...

    async def get(self, *, name="", default=_NOT_PROVIDED):  # noqa
        """
        Fetches a Kubernetes resource matching this :class:`Query`.

        :param name: If provided, disregards all objects with a different
            ``metadata.name`` field.
        :param default: If provided and there are no objects matching this query,
            the *default* value is returned, instead of raising an error.
        :raise errors.ObjectDoesNotExist: If *default* is not provided and
            no objects match this query.
        :raise ValueError: If more than one object matches this query.
        """
        if name:
            try:
                return await self._get_by_name(name)
            except errors.ObjectDoesNotExist:
                if default is _NOT_PROVIDED:
                    raise
                return default
        objects = await self._objects()
        if len(objects) == 1:
            return self.resource_type(api=self.api, obj=objects[0])
        if len(objects) > 1:
            raise ValueError("several objects match this query; iterate or use filter")
        if default is _NOT_PROVIDED:
            raise errors.ObjectDoesNotExist(self)
        return default

    def __aiter__(self) -> ObjectIterator:
        return ObjectIterator(self)

    async def watch(
        self, since: ResourceVersion = ResourceVersions.FIRST
    ) -> AsyncIterator[WatchEvent]:
        params = dict(watch=True)
        if since is ResourceVersions.CURRENT:
            obj = await self._response_json()
            params["resourceVersion"] = obj["metadata"]["resourceVersion"]
        elif since is not ResourceVersions.FIRST:
            params["resourceVersion"] = since

        namespace = None
        if isinstance(self.namespace, str):
            namespace = self.namespace

        resp = await self.api.get(
            url=self._url(params),
            version=self.resource_type.version,
            namespace=namespace,
        )
        await http.raise_for_status(resp)
        async for line in resp.content:
            event = json.loads(line.decode())
            yield WatchEvent(
                type=event["type"],
                object=self.resource_type(api=self.api, obj=event["object"]),
            )

    def _url(self, params: Optional[Mapping[str, str]] = None) -> str:
        params = dict(params) if params else {}
        if self.label_selector:
            params["labelSelector"] = sel.serialize(self.label_selector)
        if self.field_selector:
            params["fieldSelector"] = sel.serialize(self.field_selector)
        base_url = self.resource_type.plural
        if params:
            query_string = urlencode(params)
            return f"{base_url}?{query_string}"
        return base_url

    async def _objects(self) -> List[dict]:
        doc = await self._response_json()
        return doc.get("items") or []

    async def _response_json(self) -> dict:
        if self._cached_response_json is None:
            namespace = None
            if isinstance(self.namespace, str):
                namespace = self.namespace
            resp = await self.api.get(
                url=self._url(), version=self.resource_type.version, namespace=namespace
            )
            await http.raise_for_status(resp)
            self._cached_response_json = await resp.json()
        return self._cached_response_json

    def __copy__(self) -> "Query":
        return self.__class__(
            api=self.api,
            resource_type=self.resource_type,
            namespace=self.namespace,
            label_selector=self.label_selector,
            field_selector=self.field_selector,
        )

    def __deepcopy__(self, memodict: dict) -> "Query":
        return self.__class__(
            api=self.api,
            resource_type=self.resource_type,
            namespace=self.namespace,
            label_selector=deepcopy(self.label_selector, memodict),
            field_selector=deepcopy(self.field_selector, memodict),
        )
