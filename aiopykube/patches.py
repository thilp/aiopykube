import enum
from dataclasses import dataclass
from typing import Any, List, Union
import jsonpatch


class PatchType(enum.Enum):
    """
    Format of Kubernetes resource patch expected by the API server.
    The default for ``kubectl patch`` is :attr:`STRATEGIC`.
    """

    # From https://tools.ietf.org/html/rfc6902#section-3:
    JSON = "application/json-patch+json"
    # From https://tools.ietf.org/html/rfc7386#page-3:
    MERGE = "application/merge-patch+json"
    # From the output of kubectl with the -v=9 option:
    STRATEGIC = "application/strategic-merge-patch+json"


@dataclass
class Patch:
    type: PatchType
    body: Union[dict, List[dict]]

    @classmethod
    def from_diff(cls, *, old: dict, new: dict) -> "Patch":
        return cls(type=PatchType.JSON, body=jsonpatch.make_patch(old, new).patch)

    def __bool__(self) -> bool:
        # This assumes that a JSON Patch with only "test" operations is not empty.
        return len(self.body) > 0

    def __str__(self) -> str:
        patch_type = self.type.value.split("/", 1)[1].split("+", 1)[0]
        return f"{patch_type} {self.body!r}"
