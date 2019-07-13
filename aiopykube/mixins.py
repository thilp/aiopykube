from typing import Optional

from . import retries
from .retries import RetryStrategy, RetrySignal


class ScalableMixin:
    """
    Augments classes that define a *scalable_attr* attribute with :meth:`scale`.
    """

    @property
    def _current_count(self) -> int:
        return getattr(self, self.scalable_attr)

    @_current_count.setter
    def _current_count(self, value: int):
        setattr(self, self.scalable_attr, value)

    async def scale(
        self, count: Optional[int] = None, retry: RetryStrategy = retries.FOREVER
    ) -> None:
        """
        Requests that this object is scaled up or down to *count* copies, and
        waits for this to happen.

        This method relies on the object's field described by *scalable_attr*.
        For instance, if *scalable_attr* is "x", then :meth:`scale` will use
        *self.x* to read and write *count* to *self.obj*.

        :param count: Desired number of copies.
        :param retry: Retry strategy to apply (see :mod:`retries`).
        """
        if count is None:
            count = self._current_count

        await self.exists(ensure=True)

        if self._current_count == count:
            return

        self._current_count = count
        await self.update()

        @retry
        def _ensure():
            await self.reload()
            if self._current_count != count:
                raise RetrySignal()

        _ensure()


class ReplicatedMixin(ScalableMixin):
    """
    Augments objects that have a "replicas" field with :meth:`ScalableMixin.scale`.
    """

    scalable_attr = "replicas"

    @property
    def replicas(self) -> int:
        return self.obj["spec"][self.scalable_attr]

    @replicas.setter
    def replicas(self, value: int):
        self.obj["spec"][self.scalable_attr] = value
