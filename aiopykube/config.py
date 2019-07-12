import base64
import binascii
import enum
import os
from copy import deepcopy
from pathlib import Path
from typing import Optional, Dict, Any, Union

import yaml

from aiopykube import errors, fs

__all__ = ["KubeConfig", "SerializationError", "BytesOrFile"]


class KubeConfig:
    """
    Data access layer for configuration stored in kubeconfig format.
    """

    @classmethod
    async def from_service_account(
        cls, path: fs.FilePath = "/var/run/secrets/kubernetes.io/serviceaccount"
    ) -> "KubeConfig":
        """
        Builds a KubeConfig instance from the kubeconfig of an in-cluster
        service account.

        :raise exceptions.PyKubeError: If neither PYKUBE_KUBERNETES_SERVICE_HOST
            nor KUBERNETES_SERVICE_HOST, or neither PYKUBE_KUBERNETES_SERVICE_PORT
            nor KUBERNETES_SERVICE_PORT, is available as environment variable.
        """
        try:
            host, port = [
                os.getenv(
                    f"PYKUBE_KUBERNETES_SERVICE_{k}",
                    os.environ[f"KUBERNETES_SERVICE_{k}"],
                )
                for k in ("HOST", "PORT")
            ]
        except KeyError as err:
            raise errors.PyKubeError(f"missing env variable: {err}") from None

        token = await fs.read_text(Path(path, "token"))
        doc = {
            "clusters": [
                {
                    "name": "self",
                    "cluster": {
                        "server": f"https://{host}:{port}",
                        "certificate-authority": str(Path(path, "ca.crt")),
                    },
                }
            ],
            "users": [{"name": "self", "user": {"token": token}}],
            "contexts": [
                {"name": "self", "context": {"cluster": "self", "user": "self"}}
            ],
            "current-context": "self",
        }
        return cls(doc)

    @classmethod
    async def from_file(cls, path: Optional[fs.FilePath] = None) -> "KubeConfig":
        """
        Builds a KubeConfig instance from a kubeconfig file.

        Later updates to that file are not reflected in this instance.
        Similarly, updates to this instance are not written to this file,
        except via :meth:`persist`.

        :param path: Full path to a kubeconfig file. If None, defaults to the
            value of the KUBECONFIG environment variable. If that variable is
            undefined, defaults to ``$HOME/.kube/config``.
        """
        if path is None:
            path = os.getenv("KUBECONFIG", Path.home().joinpath(".kube", "config"))
        path = Path(path)
        try:
            doc = yaml.safe_load(await fs.read_text(path))
        except (OSError, yaml.YAMLError) as err:
            raise errors.PyKubeError(f"couldn't load kubeconfig file {path}") from err
        return cls(doc, path=path)

    @classmethod
    def from_url(cls, url: str) -> "KubeConfig":
        """
        Builds a KubeConfig instance from a single URL (useful for interacting
        with ``kubectl proxy``).
        """
        return cls(
            {
                "clusters": [{"name": "self", "cluster": {"server": url}}],
                "contexts": [{"name": "self", "context": {"cluster": "self"}}],
                "current-context": "self",
            }
        )

    def __init__(
        self,
        doc: dict,
        *,
        current_context: Optional[str] = None,
        path: Optional[Path] = None,
    ) -> None:
        self._doc = deepcopy(doc)
        self.path = path

        if current_context is None:
            current_context = self._doc.get("current-context") or None
        self._current_context = current_context

        self._clusters = None
        self._users = None
        self._contexts = None

    @property
    def current_context(self) -> str:
        """
        The current context defined in the configuration, if any.

        https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#context

        :raise exceptions.PyKubeError: If no current context is set.
        """
        if self._current_context is None:
            raise errors.PyKubeError("current context not set")
        return self._current_context

    @current_context.setter
    def current_context(self, context: str) -> None:
        """
        Set the current context.
        It will not be persisted in the original data source from which this
        KubeConfig instance has been created.

        https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#context

        :raise exceptions.PyKubeError: If the provided context name is invalid.
        """
        if not context:
            raise errors.PyKubeError(f"invalid context: {context!r}")

        if context not in self.contexts:
            joined = ", ".join(repr(name) for name in self.contexts)
            raise errors.PyKubeError(
                f"unknown context {context!r}; choose among {joined}"
            )

        self._current_context = context

    @property
    def clusters(self) -> Dict[str, dict]:
        """All configured clusters in a read-only mapping."""
        if self._clusters is None:
            clusters = {}
            for elem in self._doc.get("clusters", []):
                clusters[elem["name"]] = c = elem["cluster"]
                c.setdefault("server", "http://localhost")
                _set_optional_field_as_bof(c, "certificate-authority")
            self._clusters = clusters
        return self._clusters

    @property
    def users(self) -> Dict[str, dict]:
        """All configured users in a read-only mapping."""
        if self._users is None:
            users = {}
            for elem in self._doc.get("users", []):
                users[elem["name"]] = u = elem["user"]
                _set_optional_field_as_bof(u, "client-certificate")
                _set_optional_field_as_bof(u, "client-key")
            self._users = users
        return self._users

    @property
    def contexts(self) -> Dict[str, dict]:
        """All configured contexts in a read-only mapping."""
        if self._contexts is None:
            contexts = {}
            for elem in self._doc.get("contexts", []):
                contexts[elem["name"]] = elem["context"]
            self._contexts = contexts
        return self._contexts

    @property
    def cluster(self) -> Dict[str, Any]:
        """The cluster of the current context, in a read-only mapping."""
        return self.clusters[self.contexts[self.current_context]["cluster"]]

    @property
    def user(self) -> Dict[str, Any]:
        # Variation from the other similar properties because of:
        # https://github.com/hjacobs/pykube/commit/9b201feadd6b8f2a65866aa320e478ab2b4dec2d
        return self.users.get(self.contexts[self.current_context].get("user", ""), {})

    @property
    def namespace(self) -> str:
        """The current context namespace."""
        return self.contexts[self.current_context].get("namespace", "default")

    def as_dict(self) -> Dict[str, Any]:
        """
        A copy of the configuration that would be persisted by :meth:`persist`.

        This is equal to the *doc* constructor argument, potentially updated with
        default values and user operations via this instance's properties.
        """
        return {
            "clusters": [
                {
                    "name": name,
                    "cluster": {
                        k: str(v.original) if isinstance(v, BytesOrFile) else v
                        for k, v in fields.items()
                    },
                }
                for name, fields in self.clusters.items()
            ],
            "users": [
                {
                    "name": name,
                    "user": {
                        k: str(v.original) if isinstance(v, BytesOrFile) else v
                        for k, v in fields.items()
                    },
                }
                for name, fields in self.users.items()
            ],
            "contexts": [
                {"name": name, "context": {k: v for k, v in fields.items()}}
                for name, fields in self.contexts.items()
            ],
        }

    async def persist(self, path: Optional[fs.FilePath] = None) -> None:
        """
        Write this configuration to path or (if path is None) self.path.

        :raise SerializationError: If the configuration cannot be written to
            self.path.
        """
        if path is None:
            if self.path is None:
                raise SerializationError("no path associated to this config")
            path = self.path
        try:
            await fs.write_bytes(
                Path(path),
                yaml.safe_dump(
                    self.as_dict(),
                    encoding="utf-8",
                    allow_unicode=True,
                    default_flow_style=False,
                ),
            )
        except (IOError, yaml.YAMLError) as err:
            raise SerializationError("failed to persist the config") from err


class SerializationError(errors.PyKubeError):
    """Raised when a KubeConfig instance cannot be persisted."""


def _set_optional_field_as_bof(d: Dict[str, Any], field: str) -> None:
    try:
        bof = BytesOrFile.from_dict_key(d, field)
    except KubeConfigFieldError:
        return
    d[field] = bof
    d.pop(f"{field}-data", None)


class KubeConfigFieldError(errors.PyKubeError):
    """Raised when trying to access a non-existent kubeconfig field."""


class DataFormat(enum.Enum):
    PATH = enum.auto()
    BASE64 = enum.auto()


class BytesOrFile:
    """
    Represents the same data both as bytes and as a file.

    Some kubeconfig elements can be provided either as base64 data, or as a
    path to a file containing that data.
    That distinction is only a matter of user convenience, and is abstracted
    away by this class.
    """

    @classmethod
    def from_dict_key(cls, d: Dict[str, str], field: str) -> "BytesOrFile":
        """
        Build a BytesOrFile for the value of the provided field in d.

        :raise ValueError: If field is not found in d.
        """
        path_key = field
        data_key = f"{field}-data"
        if data_key in d:
            return cls(data=d[data_key])
        if path_key in d:
            return cls(path=d[path_key])
        raise KubeConfigFieldError(f"no key {path_key!r} or {data_key!r} in dict")

    def __init__(self, *, path: fs.FilePath = None, data: str = None) -> None:
        """
        :param path: Path to a file containing the data.
        :param data: Data encoded in Base64.
        """
        self._path: Optional[Path] = None
        self._bytes: Optional[bytes] = None
        self._temporary_file = None

        if path is not None and data is not None:
            raise TypeError("'path' or 'data' must be specified, but not both")
        if path is not None:
            path = Path(path)
            if not path.is_file():
                raise errors.PyKubeError(f"{path} is not a regular file")
            self._path = path
            self._origin_format = DataFormat.PATH
        elif data is not None:
            try:
                self._bytes = base64.b64decode(data, validate=True)
            except binascii.Error as err:
                raise errors.PyKubeError("failed to decode base64 value") from err
            self._origin_format = DataFormat.BASE64
        else:
            raise TypeError("one of 'path' or 'data' kwargs must be specified")

    async def bytes(self) -> bytes:
        """
        The underlying data as bytes.
        """
        if self._bytes is None:
            self._bytes = await fs.read_bytes(self._path)
        return self._bytes

    async def path(self) -> Path:
        """The path of a file containing the underlying data."""
        if self._path is None:
            self._temporary_file = await fs.create_temporary_file()
            self._path = Path(self._temporary_file.name)
            await fs.write_bytes(self._path, self._bytes)
        return self._path

    @property
    def original(self) -> Union[str, Path]:
        """
        The underlying data, in the format it used when this instance was created.
        """
        if self._origin_format is DataFormat.BASE64:
            return base64.b64encode(self._bytes).decode()
        if self._origin_format is DataFormat.PATH:
            return self._path
        raise NotImplementedError(f"unsupported data format {self._origin_format}")

    async def cleanup(self) -> None:
        """
        Deletes the associated temporary file, if any.

        Another temporary file will be created if :meth:`path` is called again.
        """
        # Be a good citizen and make sure the temporary file is deleted after use.
        if self._temporary_file is not None:
            await fs.unlink(Path(self._temporary_file.name))
            self._temporary_file = None
            self._path = None
