import abc
from typing import Optional

from aiopykube.errors import PotentialWaitSignal
from . import waiting


class ScalableMixin(abc.ABC):
    """
    Augments classes that define a *scalable_attr* attribute with :meth:`scale`.
    """

    def __init_subclass__(cls, *, scalable_attr: str, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if not isinstance(scalable_attr, str) or not scalable_attr:
            raise TypeError("'scalable_attr' must be a non-empty string")
        cls.scalable_attr = scalable_attr

    @abc.abstractmethod
    async def exists(self, raising: bool) -> bool:
        ...

    @abc.abstractmethod
    async def update(self) -> None:
        ...

    @abc.abstractmethod
    async def reload(self) -> None:
        ...

    @property
    def _current_count(self) -> int:
        return getattr(self, self.scalable_attr)

    @_current_count.setter
    def _current_count(self, value: int):
        setattr(self, self.scalable_attr, value)

    async def scale(
        self, count: Optional[int] = None, wait: waiting.Strategy = waiting.FOREVER
    ) -> None:
        """
        Requests that this object is scaled up or down to *count* copies, and
        waits for this to happen.

        This method relies on the object's field described by *scalable_attr*.
        For instance, if *scalable_attr* is "x", then :meth:`scale` will use
        *self.x* to read and write *count* to *self.obj*.

        :param count: Desired number of copies.
        :param wait: How this method should wait for the operation to be complete
            (see :mod:`wait`).
        """
        if count is None:
            count = self._current_count

        await self.exists(raising=True)

        if self._current_count == count:
            return

        self._current_count = count
        await self.update()

        @wait
        async def _ensure():
            await self.reload()
            if self._current_count != count:
                raise PotentialWaitSignal()

        await _ensure()


class ReplicatedMixin(ScalableMixin, abc.ABC, scalable_attr="replicas"):
    """
    Augments objects that have a "replicas" field with :meth:`ScalableMixin.scale`.
    """

    @property
    def replicas(self) -> int:
        return self.obj["spec"][self.scalable_attr]

    @replicas.setter
    def replicas(self, value: int):
        self.obj["spec"][self.scalable_attr] = value
