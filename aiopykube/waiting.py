"""
Some aiopykube functions perform actions that may fail and must be repeated,
or that take time to complete and must be awaited. (Both cases are equivalent.)
This module provides strategies defining how to await and retry these actions.
Users can pass them as argument to adapt aiopykube's default strategy to their
own needs.

Waiting strategies are defined with `Tenacity`_ (they are the result of
:meth:`tenacity.retry`, so technically they are function decorators).
If you decide to implement your own wait strategy for aiopykube, keep in mind that
aiopykube functions that want to wait more raise an :class:`errors.PotentialWaitSignal`
exception. Your custom strategy should probably wait only when this particular
exception type is raised, but by default Tenacity will listen for any exception,
unless you use :meth:`tenacity.retry_if_exception_type` in the *retry*
keyword-argument of :meth:`tenacity.retry`.
You can use :meth:`strategy` to take care of that.

.. _Tenacity: https://tenacity.readthedocs.io/
"""
from typing import Callable

import tenacity as t

from .errors import PotentialWaitSignal

Strategy = Callable[[callable], callable]


def strategy(*, wait: t.wait.wait_base) -> Strategy:
    return t.retry(wait=wait, retry=t.retry_if_exception_type(PotentialWaitSignal))


FOREVER: Strategy = strategy(wait=t.wait_random(0, 1))

ONCE: Strategy = lambda x: x


def _never(_):
    return


NEVER: Strategy = _never
