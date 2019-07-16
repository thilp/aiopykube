import enum
from typing import Mapping, Union, Iterable


class SelectorScope(enum.Enum):
    LABELS = "labelSelector"
    FIELDS = "fieldSelector"


class Is(enum.Enum):
    PRESENT = enum.auto()
    ABSENT = enum.auto()


Selector = Mapping[str, Union[str, Iterable[str], Is]]
ExtendedSelector = Union[Selector, str]

_SELECTOR_PREDICATE_SEPARATOR = "__"


def normalize(selector: ExtendedSelector) -> Selector:
    if isinstance(selector, str):
        selector = {selector: Is.PRESENT}
    return selector


def serialize(selector: Selector) -> str:
    """
    # Equality:
    >>> serialize({"a": "b", "c__neq": "d"})
    'a=b,c!=d'

    # Inclusion:
    >>> serialize({"a__in": {"x", "y"}, "b__notin": ("z",)})
    'a in (x,y),b notin (z)'

    # Existence:
    >>> serialize({"a": Is.PRESENT, "b": Is.ABSENT})
    'a,!b'

    # More equality operators:
    >>> serialize({"a__=": "b", "c__==": "d", "e__!=": "f"})
    'a=b,c=d,e!=f'
    """
    if isinstance(selector, str):
        # labels="abc" => Label "abc" must exist, whatever its value.
        # A simple way to assert existence (but requires multiple filters).
        # A more flexible way is to use the Is enum members as dict values.
        return selector
    s = []
    for key, value in dict(selector).items():
        if value is Is.PRESENT:
            s.append(key)
        elif value is Is.ABSENT:
            s.append(f"!{key}")
        else:
            if _SELECTOR_PREDICATE_SEPARATOR in key:
                label, op = key.rsplit(_SELECTOR_PREDICATE_SEPARATOR, 1)
            else:
                label, op = key, "eq"

            if op in {"eq", "=", "=="}:
                s.append(f"{label}={value}")
            elif op in {"neq", "!="}:
                s.append(f"{label}!={value}")
            elif op in {"in", "notin"}:
                s.append(f"{label} {op} ({','.join(sorted(value))})")
            else:
                raise ValueError(f"unknown selector requirement: {op!r}")
    return ",".join(s)


def merge(*, old: Selector, new: Selector) -> Selector:
    return {**old, **new}
