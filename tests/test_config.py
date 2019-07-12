import base64
from copy import deepcopy
from pathlib import Path
from typing import Mapping, Any

import pytest
import yaml

from aiopykube import config, errors
from aiopykube.config import BytesOrFile, KubeConfigFieldError


class TestKubeConfig:
    @pytest.fixture
    def dummy_doc(self, tmp_path: Path):
        client_key_path = tmp_path / "client.key"
        client_key_path.write_text("opaque client key data")
        return {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {
                    "name": "self",
                    "cluster": {
                        "server": f"https://1.2.3.4:99999",
                        "certificate-authority-data": base64.b64encode(
                            b"opaque certificate authority data"
                        ),
                    },
                }
            ],
            "users": [
                {
                    "name": "self",
                    "user": {
                        "client-certificate-data": base64.b64encode(
                            b"opaque client certificate data"
                        ),
                        "client-key": str(client_key_path),
                    },
                }
            ],
            "contexts": [
                {"name": "self", "context": {"cluster": "self", "user": "self"}}
            ],
            "current-context": "self",
        }

    class TestFromServiceAccount:
        @pytest.fixture
        def service_account_path(self, tmp_path: Path) -> Path:
            (tmp_path / "token").write_text("some token")
            (tmp_path / "ca.crt").write_text("some cert")
            (tmp_path / "namespace").write_text("some-namespace")
            return tmp_path

        @pytest.mark.asyncio
        async def test_no_file(self, tmp_path: Path, monkeypatch):
            monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "x")
            monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "0")
            with pytest.raises(FileNotFoundError):
                await config.KubeConfig.from_service_account(tmp_path)

        @pytest.mark.asyncio
        async def test_no_pykube_env_var(self, service_account_path, monkeypatch):
            monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "x")
            monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "0")
            monkeypatch.delenv("PYKUBE_KUBERNETES_SERVICE_HOST", raising=False)
            monkeypatch.delenv("PYKUBE_KUBERNETES_SERVICE_PORT", raising=False)

            cfg = await config.KubeConfig.from_service_account(service_account_path)
            assert cfg.cluster["server"] == "https://x:0"
            assert cfg.user["token"] == "some token"

        @pytest.mark.asyncio
        async def test_with_pykube_env_var(self, service_account_path, monkeypatch):
            monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "x")
            monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "0")
            monkeypatch.setenv("PYKUBE_KUBERNETES_SERVICE_HOST", "z")
            monkeypatch.setenv("PYKUBE_KUBERNETES_SERVICE_PORT", "1")

            cfg = await config.KubeConfig.from_service_account(service_account_path)
            assert cfg.cluster["server"] == "https://z:1"
            assert cfg.user["token"] == "some token"

        @pytest.mark.asyncio
        async def test_no_env_var(self, service_account_path, monkeypatch):
            monkeypatch.delenv("PYKUBE_KUBERNETES_SERVICE_HOST", raising=False)
            monkeypatch.delenv("PYKUBE_KUBERNETES_SERVICE_PORT", raising=False)
            monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
            monkeypatch.delenv("KUBERNETES_SERVICE_PORT", raising=False)

            with pytest.raises(errors.PyKubeError, match="missing env variable"):
                await config.KubeConfig.from_service_account(service_account_path)

    class TestFromFile:
        @staticmethod
        def build_kubeconfig(path: Path, doc: dict) -> Path:
            kube_path = path / ".kube"
            kube_path.mkdir()
            cfg_path = kube_path / "config"
            cfg_path.write_text(yaml.safe_dump(doc))
            return cfg_path

        @pytest.fixture
        def all_possible_kubeconfigs(
            self, monkeypatch, tmp_path: Path, dummy_doc
        ) -> dict:
            """
            Builds a different kubeconfig files in 3 places: a custom path,
            a path pointed by the KUBECONFIG environment variable, and a path
            directly under $HOME.

            This allows to check that KubeConfig.from_file doesn't e.g. select
            the path passed as argument just because there is no KUBECONFIG
            env variable defined.
            """
            record = {}

            doc = deepcopy(dummy_doc)
            doc["clusters"][0]["cluster"]["server"] = "https://custom:9999"
            a = tmp_path / "custom"
            a.mkdir()
            record["custom"] = {"doc": doc, "path": self.build_kubeconfig(a, doc)}

            doc = deepcopy(dummy_doc)
            doc["clusters"][0]["cluster"]["server"] = "https://env:9998"
            b = tmp_path / "env"
            b.mkdir()
            monkeypatch.setenv("KUBECONFIG", str(self.build_kubeconfig(b, doc)))
            record["env"] = {"doc": doc}

            doc = deepcopy(dummy_doc)
            doc["clusters"][0]["cluster"]["server"] = "https://home:9997"
            c = tmp_path / "home"
            c.mkdir()
            self.build_kubeconfig(c, doc)
            monkeypatch.setenv("HOME", str(c))
            record["home"] = {"doc": doc}

            return record

        @pytest.mark.asyncio
        async def test_with_path_it_selects_that_path(self, all_possible_kubeconfigs):
            doc = all_possible_kubeconfigs["custom"]["doc"]
            cfg_path = all_possible_kubeconfigs["custom"]["path"]
            cfg = await config.KubeConfig.from_file(cfg_path)
            assert (
                cfg.clusters["self"]["server"]
                == doc["clusters"][0]["cluster"]["server"]
            )

        @pytest.mark.asyncio
        async def test_without_path_it_selects_env_kubeconfig(
            self, all_possible_kubeconfigs
        ):
            doc = all_possible_kubeconfigs["env"]["doc"]
            cfg = await config.KubeConfig.from_file()
            assert (
                cfg.clusters["self"]["server"]
                == doc["clusters"][0]["cluster"]["server"]
            )

        @pytest.mark.asyncio
        async def test_without_path_nor_env_var_it_selects_home_kubeconfig(
            self, monkeypatch, all_possible_kubeconfigs
        ):
            monkeypatch.delenv("KUBECONFIG")  # set by all_possible_kubeconfigs
            doc = all_possible_kubeconfigs["home"]["doc"]
            cfg = await config.KubeConfig.from_file()
            assert (
                cfg.clusters["self"]["server"]
                == doc["clusters"][0]["cluster"]["server"]
            )

        @pytest.mark.asyncio
        async def test_it_raises_if_file_is_not_found(self, tmp_path: Path):
            with pytest.raises(errors.PyKubeError):
                await config.KubeConfig.from_file(tmp_path / "nonexistent")

        @pytest.mark.asyncio
        async def test_it_raises_if_file_is_directory(self, tmp_path: Path):
            with pytest.raises(errors.PyKubeError):
                await config.KubeConfig.from_file(tmp_path)

        @pytest.mark.asyncio
        async def test_it_raises_if_file_is_not_yaml(self, tmp_path: Path, dummy_doc):
            cfg_path = self.build_kubeconfig(tmp_path, dummy_doc)
            cfg_path.write_text("{ this is not yaml")  # overwrite
            with pytest.raises(errors.PyKubeError):
                await config.KubeConfig.from_file(cfg_path)

        @pytest.mark.asyncio
        async def test_it_sets_path_attribute(self, tmp_path: Path, dummy_doc):
            cfg_path = self.build_kubeconfig(tmp_path, dummy_doc)
            cfg = await config.KubeConfig.from_file(cfg_path)
            assert cfg.path == cfg_path

    class TestFromUrl:
        def test_it_sets_the_provided_url_as_server(self):
            cfg = config.KubeConfig.from_url("xyz")
            assert cfg.cluster["server"] == "xyz"

    class TestInit:
        def test_it_doesnt_change_when_source_doc_changes(self, dummy_doc):
            old_server = dummy_doc["clusters"][0]["cluster"]["server"]
            new_server = "http://changed"
            assert old_server != new_server

            cfg = config.KubeConfig(dummy_doc)
            dummy_doc["clusters"][0]["cluster"]["server"] = new_server
            assert cfg.cluster["server"] == old_server

        def test_source_doc_doesnt_change_when_instance_changes(self, dummy_doc):
            old_server = dummy_doc["clusters"][0]["cluster"]["server"]
            new_server = "http://changed"
            assert old_server != new_server

            old_doc = deepcopy(dummy_doc)
            cfg = config.KubeConfig(dummy_doc)
            cfg.cluster["server"] = new_server
            assert dummy_doc == old_doc

        def test_it_has_a_path_when_path_kwarg_is_provided(self, dummy_doc):
            path = Path("abc")
            cfg = config.KubeConfig(dummy_doc, path=path)
            assert cfg.path == path

        def test_it_has_a_none_path_when_path_kwarg_is_not_provided(self, dummy_doc):
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.path is None

    class TestCurrentContext:
        def test_it_has_a_current_context_when_current_context_is_set_in_source_doc(
            self, dummy_doc
        ):
            assert dummy_doc["current-context"]
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.current_context == dummy_doc["current-context"]

        def test_it_has_no_current_context_when_current_context_is_not_set_in_source_doc(
            self, dummy_doc
        ):
            del dummy_doc["current-context"]
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="current context"):
                assert cfg.current_context

        def test_it_raises_if_empty_context_is_set(self, dummy_doc):
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="invalid context"):
                cfg.current_context = ""
            with pytest.raises(errors.PyKubeError, match="invalid context"):
                cfg.current_context = None

        def test_it_raises_if_unknown_context_is_set(self, dummy_doc):
            assert len(dummy_doc["contexts"]) == 1
            unknown_context_name = "xyz"
            assert dummy_doc["contexts"][0]["name"] != unknown_context_name
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="unknown context"):
                cfg.current_context = unknown_context_name

        def test_it_records_new_context(self, dummy_doc):
            dummy_doc["contexts"].append({"name": "xyz", "context": {}})
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.current_context != "xyz"
            cfg.current_context = "xyz"
            assert cfg.current_context == "xyz"

        def test_it_has_the_current_context_provided_as_init_argument(self, dummy_doc):
            dummy_doc["contexts"] = [
                {"name": "context-A", "context": {"cluster": "A"}},
                {"name": "context-B", "context": {"cluster": "B"}},
            ]
            dummy_doc["current-context"] = "context-A"
            cfg = config.KubeConfig(dummy_doc, current_context="context-B")
            assert cfg.current_context == "context-B"

    class TestClusters:
        def test_it_returns_a_dict_of_all_clusters_by_name(self, dummy_doc):
            dummy_doc["clusters"] = [
                {"name": "A", "cluster": {"x": "y"}},
                {"name": "B", "cluster": {"y": "z"}},
            ]
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.clusters.keys() == {"A", "B"}
            assert cfg.clusters["A"]["x"] == "y"
            assert cfg.clusters["B"]["y"] == "z"

        def test_it_sets_localhost_as_default_server(self, dummy_doc):
            dummy_doc["clusters"] = [
                {"name": "A", "cluster": {"x": "y"}},
                {"name": "B", "cluster": {"server": "S"}},
            ]
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.clusters["A"]["server"] == "http://localhost"
            assert cfg.clusters["B"]["server"] == "S"

        def test_it_makes_bof_the_certificate_authority_if_present(
            self, dummy_doc, tmp_path: Path
        ):
            ca_path = tmp_path / "ca"
            ca_path.write_text("in-file")

            ca = "certificate-authority"
            dummy_doc["clusters"] = [
                {"name": "A", "cluster": {"x": "y"}},
                {"name": "B", "cluster": {ca: str(ca_path)}},
                {"name": "C", "cluster": {f"{ca}-data": base64.b64encode(b"inline")}},
            ]
            cfg = config.KubeConfig(dummy_doc)

            assert ca not in cfg.clusters["A"], "field not created if absent"
            for cluster_name in "BC":
                assert isinstance(cfg.clusters[cluster_name][ca], config.BytesOrFile)
                assert f"{ca}-data" not in cfg.clusters[cluster_name]

        def test_it_only_reads_the_underlying_dict_the_first_time(self, dummy_doc):
            cfg = config.KubeConfig(dummy_doc)
            first_id = id(cfg.clusters)
            second_id = id(cfg.clusters)
            assert first_id == second_id

    class TestUsers:
        def test_it_returns_a_dict_of_all_users_by_name(self, dummy_doc):
            dummy_doc["users"] = [
                {"name": "A", "user": {"x": "y"}},
                {"name": "B", "user": {"y": "z"}},
            ]
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.users.keys() == {"A", "B"}
            assert cfg.users["A"]["x"] == "y"
            assert cfg.users["B"]["y"] == "z"

        @pytest.mark.parametrize("field", ("client-certificate", "client-key"))
        def test_it_makes_bof_the_client_certificate_and_key_if_present(
            self, field, dummy_doc, tmp_path: Path
        ):
            path = tmp_path / "file"
            path.write_text("in-file")

            dummy_doc["users"] = [
                {"name": "A", "user": {"x": "y"}},
                {"name": "B", "user": {field: str(path)}},
                {"name": "C", "user": {f"{field}-data": base64.b64encode(b"inline")}},
            ]
            cfg = config.KubeConfig(dummy_doc)

            assert field not in cfg.users["A"], "field not created if absent"
            for user_name in "BC":
                assert isinstance(cfg.users[user_name][field], config.BytesOrFile)
                assert f"{field}-data" not in cfg.users[user_name]

        def test_it_only_reads_the_underlying_dict_the_first_time(self, dummy_doc):
            cfg = config.KubeConfig(dummy_doc)
            first_id = id(cfg.users)
            second_id = id(cfg.users)
            assert first_id == second_id

    class TestContexts:
        def test_it_returns_a_dict_of_all_contexts_by_name(self, dummy_doc):
            dummy_doc["contexts"] = [
                {"name": "A", "context": {"x": "y"}},
                {"name": "B", "context": {"y": "z"}},
            ]
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.contexts.keys() == {"A", "B"}
            assert cfg.contexts["A"]["x"] == "y"
            assert cfg.contexts["B"]["y"] == "z"

    class TestCluster:
        @pytest.mark.parametrize(
            "selected,expected", [("context-X", {"a": "b"}), ("context-Y", {"b": "c"})]
        )
        def test_it_returns_the_currently_selected_cluster(
            self, selected, expected, dummy_doc
        ):
            dummy_doc["clusters"] = [
                {"name": "cluster-A", "cluster": {"a": "b"}},
                {"name": "cluster-B", "cluster": {"b": "c"}},
            ]
            dummy_doc["contexts"] = [
                {"name": "context-X", "context": {"cluster": "cluster-A"}},
                {"name": "context-Y", "context": {"cluster": "cluster-B"}},
            ]
            dummy_doc["current-context"] = selected
            cfg = config.KubeConfig(dummy_doc)
            assert mapping_issubset(expected, cfg.cluster)

        def test_it_raises_when_there_is_no_current_context(self, dummy_doc):
            del dummy_doc["current-context"]
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="current context not set"):
                _ = cfg.cluster

    class TestUser:
        @pytest.mark.parametrize(
            "selected,expected", [("context-X", {"a": "b"}), ("context-Y", {"b": "c"})]
        )
        def test_it_returns_the_currently_selected_cluster(
            self, selected, expected, dummy_doc
        ):
            dummy_doc["users"] = [
                {"name": "user-A", "user": {"a": "b"}},
                {"name": "user-B", "user": {"b": "c"}},
            ]
            dummy_doc["contexts"] = [
                {"name": "context-X", "context": {"user": "user-A"}},
                {"name": "context-Y", "context": {"user": "user-B"}},
            ]
            dummy_doc["current-context"] = selected
            cfg = config.KubeConfig(dummy_doc)
            assert mapping_issubset(expected, cfg.user)

        def test_it_raises_when_there_is_no_current_context(self, dummy_doc):
            dummy_doc.pop("current-context", None)
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="current context not set"):
                _ = cfg.user

    class TestNamespace:
        def test_it_is_default_when_not_specified(self, dummy_doc):
            dummy_doc["contexts"] = [{"name": "X", "context": {}}]
            dummy_doc["current-context"] = "X"
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.namespace == "default"

        def test_it_is_the_current_contexts_namespace(self, dummy_doc):
            dummy_doc["contexts"] = [{"name": "X", "context": {"namespace": "N"}}]
            dummy_doc["current-context"] = "X"
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.namespace == "N"

        def test_it_raises_when_there_is_no_current_context(self, dummy_doc):
            dummy_doc["contexts"] = [{"name": "X", "context": {"namespace": "N"}}]
            dummy_doc.pop("current-context", None)
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(errors.PyKubeError, match="current context not set"):
                _ = cfg.namespace

    class TestAsDict:
        @pytest.mark.parametrize(
            "doc,expected",
            [
                (
                    {"clusters": [{"name": "A", "cluster": {"X": "Y"}}]},
                    {
                        "clusters": [
                            {
                                "name": "A",
                                "cluster": {"X": "Y", "server": "http://localhost"},
                            }
                        ],
                        "users": [],
                        "contexts": [],
                    },
                ),
                # FIXME: more cases
            ],
        )
        def test_it_is_the_input_plus_default_fields(self, doc, expected):
            assert mapping_issubset(doc, expected)
            assert config.KubeConfig(doc).as_dict() == expected

    @pytest.mark.asyncio
    class TestPersist:
        async def test_it_raises_without_path_as_arg_or_attribute(self, dummy_doc):
            cfg = config.KubeConfig(dummy_doc)
            assert cfg.path is None
            with pytest.raises(config.SerializationError, match="no path associated"):
                await cfg.persist()

        async def test_it_writes_to_the_path_attributes_without_path_arg(
            self, dummy_doc, tmp_path: Path
        ):
            cfg = config.KubeConfig(dummy_doc)
            cfg.path = tmp_path / "A"
            await cfg.persist()
            assert yaml.safe_load(cfg.path.read_text()) == cfg.as_dict()

        @pytest.mark.parametrize(
            "with_attr",
            [
                pytest.param(False, id="without path attribute"),
                pytest.param(True, id="with path attribute"),
            ],
        )
        async def test_it_writes_to_the_path_arg(
            self, with_attr: bool, dummy_doc, tmp_path: Path
        ):
            cfg = config.KubeConfig(dummy_doc)

            if with_attr:
                cfg.path = tmp_path / "A"
            else:
                cfg.path = None

            path = tmp_path / "P"

            await cfg.persist(path)
            assert yaml.safe_load(path.read_text()) == cfg.as_dict()

            if with_attr:
                assert not cfg.path.exists()

        async def test_it_raises_if_the_config_cant_be_converted_to_yaml(
            self, dummy_doc, tmp_path: Path
        ):
            cfg = config.KubeConfig(dummy_doc)
            cfg.cluster["w"] = object()  # can't be serialized natively
            with pytest.raises(config.SerializationError, match="failed to persist"):
                await cfg.persist(tmp_path / "P")

        async def test_it_raises_if_the_path_is_invalid(
            self, dummy_doc, tmp_path: Path
        ):
            cfg = config.KubeConfig(dummy_doc)
            with pytest.raises(config.SerializationError):
                await cfg.persist(tmp_path)  # a directory


class TestBytesOrFile:
    @pytest.fixture
    def raw_data(self) -> bytes:
        return b"some \0 data"

    @pytest.fixture
    def path(self, raw_data, tmp_path) -> Path:
        p = tmp_path / "file.dat"
        p.write_bytes(raw_data)
        return p

    @pytest.fixture
    def b64_data(self, raw_data: bytes) -> str:
        return base64.b64encode(raw_data).decode()

    class TestFromDictKey:
        def test_it_raises_if_field_is_not_in_d(self):
            with pytest.raises(KubeConfigFieldError):
                BytesOrFile.from_dict_key({"a": "b"}, "x")

        def test_it_selects_data_if_there_is_a_data_key(self, b64_data):
            bof = BytesOrFile.from_dict_key({"x-data": b64_data}, "x")
            assert bof.original == b64_data

        def test_it_selects_path_if_there_is_a_non_data_key(self, path):
            bof = BytesOrFile.from_dict_key({"x": str(path)}, "x")
            assert bof.original == path

        def test_it_selects_data_if_there_are_both_key_types(self, b64_data, path):
            bof = BytesOrFile.from_dict_key({"x": str(path), "x-data": b64_data}, "x")
            assert bof.original == b64_data

    class TestInit:
        def test_it_raises_if_neither_path_nor_data_is_provided(self):
            with pytest.raises(TypeError):
                BytesOrFile()

        def test_it_raises_if_both_path_and_data_are_provided(self, path, b64_data):
            with pytest.raises(TypeError):
                BytesOrFile(path=path, data=b64_data)

        def test_it_raises_if_path_doesnt_exist(self, tmp_path):
            with pytest.raises(errors.PyKubeError):
                BytesOrFile(path=tmp_path / "nonexistent")

        def test_it_raises_if_path_is_a_directory(self, tmp_path):
            with pytest.raises(errors.PyKubeError):
                BytesOrFile(path=tmp_path)

        def test_it_raises_if_data_is_not_base64_encoded(self):
            with pytest.raises(errors.PyKubeError, match="base64"):
                BytesOrFile(data="~")

    @pytest.mark.asyncio
    class TestBytes:
        async def test_it_returns_the_decoded_bytes_if_built_with_data(self, b64_data):
            expected_bytes = base64.b64decode(b64_data)
            assert await BytesOrFile(data=b64_data).bytes() == expected_bytes

        async def test_it_returns_the_bytes_contents_if_built_with_path(self, path):
            assert await BytesOrFile(path=path).bytes() == path.read_bytes()

    @pytest.mark.asyncio
    class TestPath:
        async def test_it_returns_the_path_if_built_with_path(self, path):
            assert await BytesOrFile(path=path).path() == path

        async def test_it_returns_tempfile_with_data_if_built_with_data(self, b64_data):
            expected_bytes = base64.b64decode(b64_data)
            assert (
                await BytesOrFile(data=b64_data).path()
            ).read_bytes() == expected_bytes

    class TestOriginal:
        def test_it_returns_b64_if_built_with_data(self, b64_data):
            assert BytesOrFile(data=b64_data).original == b64_data

        def test_it_returns_the_same_path_if_built_with_path(self, path):
            assert BytesOrFile(path=path).original == path

    @pytest.mark.asyncio
    class TestCleanup:
        async def test_it_removes_the_associated_temporary_file(self, b64_data):
            bof = BytesOrFile(data=b64_data)
            path = await bof.path()
            assert path.exists(), "the temporary file should exist at this point"
            await bof.cleanup()
            assert (
                path.exists() is False
            ), "the temporary file should not exist after cleanup"

        async def test_it_does_not_prevent_further_path_calls(self, b64_data):
            bof = BytesOrFile(data=b64_data)
            await bof.path()
            await bof.cleanup()
            new_path = await bof.path()
            assert new_path.exists()
            assert new_path.read_bytes() == base64.b64decode(b64_data)

        async def test_it_does_nothing_if_path_has_never_been_called(self, b64_data):
            bof = BytesOrFile(data=b64_data)
            await bof.cleanup()  # should just have no side-effects


def mapping_issubset(subset: Mapping, superset: Mapping) -> bool:
    for k, v in subset.items():
        if k not in superset or not any_issubset(subset[k], superset[k]):
            return False
    return True


def list_issubset(subset: list, superset: list) -> bool:
    for x in subset:
        for y in superset:
            if not any_issubset(x, y):
                return False
    return True


def any_issubset(subset: Any, superset: Any) -> bool:
    if isinstance(subset, list) and isinstance(superset, list):
        return list_issubset(subset, superset)
    if isinstance(subset, dict) and isinstance(superset, dict):
        return mapping_issubset(subset, superset)
    if subset != superset:
        return False
    return True
