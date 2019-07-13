"""
Some aiopykube functions perform actions that may fail and must be repeated,
or that take time to complete and must be awaited. (Both cases are equivalent.)
This module provides strategies defining how to retry these actions.
Users can pass them as argument to adapt the default strategy of aiopykube to
their own needs.

Retry strategies are defined with `Tenacity`_ (they are the result of
:meth:`tenacity.retry`, so technically they are function decorators).
If you decide to implement your own strategy for aiopykube, keep in mind that
aiopykube functions that want to retry raise a :class:`RetrySignal` exception.
Your custom strategy should probably retry only when this particular exception
type is raised, but by default Tenacity will retry for any exception, unless
you use :meth:`tenacity.retry_if_exception_type` in the *retry* keyword-argument
of :meth:`tenacity.retry`.

.. _Tenacity: https://tenacity.readthedocs.io/
"""
from typing import Callable

import tenacity as t

RetryStrategy = Callable[[callable], callable]


class RetrySignal(Exception):
    """
    Raised by functions to signal to tenacity that they want to retry.
    """


FOREVER: RetryStrategy = t.retry(
    wait=t.wait_random(0, 2), retry=t.retry_if_exception_type(RetrySignal)
)

NEVER: RetryStrategy = lambda x: x
