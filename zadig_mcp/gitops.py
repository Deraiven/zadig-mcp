import argparse
import asyncio
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .client import ZadigAPIError, environment_prefix, path_name, service_prefix
from .server import (
    DEFAULT_SNAPSHOT_SECTIONS,
    assert_no_redacted_placeholders,
    build_template_desired_payload,
    build_template_items_from_payload,
    client,
    code_scan_name_from_payload,
    zadig_code_scan_apply,
    zadig_code_scan_delete,
    zadig_code_scan_diff,
    test_desired_payload,
    test_name_from_payload,
    zadig_test_apply,
    zadig_test_delete,
    zadig_test_diff,
    environment_service_gitops_document,
    environment_service_index_item,
    first_present,
    redact_sensitive,
    summarize_build_template,
    zadig_environment_apply,
    zadig_environment_delete,
    zadig_environment_diff,
    zadig_environment_service_apply,
    zadig_environment_service_delete,
    zadig_project_snapshot,
    zadig_project_apply_plan,
    zadig_build_apply,
    zadig_build_template_apply,
    zadig_build_template_delete,
    zadig_build_template_diff,
    zadig_workflow_apply,
    zadig_workflow_delete,
    zadig_workflow_diff,
)
from .service_ops import iter_services


class LiteralString(str):
    pass


def literal_string_representer(dumper: yaml.SafeDumper, data: LiteralString) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.SafeDumper.add_representer(LiteralString, literal_string_representer)


def safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return safe.strip("-") or "unnamed"


def prefer_literal_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: prefer_literal_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [prefer_literal_strings(item) for item in value]
    if isinstance(value, str) and "\n" in value:
        return LiteralString(value)
    return value


def write_data(path: Path, value: Any, output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    path.write_text(
        yaml.safe_dump(
            prefer_literal_strings(value),
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=True,
            width=120,
        ),
        encoding="utf-8",
    )


def data_filename(name: str, output_format: str) -> str:
    suffix = "json" if output_format == "json" else "yaml"
    return f"{name}.{suffix}"


def code_scan_name(item: dict[str, Any], index: int) -> str:
    name = first_present(item, "name", "scan_name", "scanName", "code_scan_name", "codeScanName")
    if name not in (None, ""):
        return str(name)
    identifier = first_present(item, "id", "scan_id", "scanId")
    if identifier not in (None, ""):
        return str(identifier)
    return f"unnamed-{index}"


def code_scan_gitops_document(project: str, item: dict[str, Any], index: int) -> dict[str, Any]:
    """Keep scan configuration separate from server-generated runtime metadata."""
    name = code_scan_name(item, index)
    runtime_keys = {
        "id",
        "scan_id",
        "scanId",
        "created_at",
        "createdAt",
        "updated_at",
        "updatedAt",
        "statistics",
    }
    spec = {key: copy.deepcopy(value) for key, value in item.items() if key not in runtime_keys}
    spec.setdefault("name", name)
    live = {key: copy.deepcopy(value) for key, value in item.items() if key in runtime_keys and key in item}
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "CodeScan",
        "metadata": {
            "project": project,
            "name": name,
        },
        "spec": spec,
        "live": live,
    }


def load_data(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def workflow_payload_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"workflow file {path} must contain a mapping")
    if data.get("kind") == "Workflow":
        return expand_workflow_refs(data, path)
    detail = data.get("detail")
    if isinstance(detail, dict):
        return detail
    return data


def desired_workflow_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def workflow_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    name = metadata.get("name") or spec.get("workflow_name") or spec.get("workflow_key") or spec.get("name")
    if not name:
        raise ValueError("workflow document must contain metadata.name or spec.workflow_name")
    return str(name)


def workflow_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("workflow document must contain spec")
    return copy.deepcopy(spec)


def service_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"service file {path} must contain a mapping")
    if data.get("kind") != "Service":
        raise ValueError(f"service file {path} must have kind: Service")
    return data


def project_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"project file {path} must contain a mapping")
    if data.get("kind") != "Project":
        raise ValueError(f"project file {path} must have kind: Project")
    return data


def build_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"build file {path} must contain a mapping")
    if data.get("kind") != "Build":
        raise ValueError(f"build file {path} must have kind: Build")
    return data


def build_template_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"build template file {path} must contain a mapping")
    if data.get("kind") == "BuildTemplate":
        return data
    if isinstance(data.get("detail"), dict):
        detail = data["detail"]
        return {
            "apiVersion": "zadig.storehub.io/v1alpha1",
            "kind": "BuildTemplate",
            "metadata": {
                "name": data.get("name") or detail.get("name"),
                "id": detail.get("id"),
            },
            "spec": detail,
            "live": data,
        }
    raise ValueError(f"build template file {path} must have kind: BuildTemplate")


def environment_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"environment file {path} must contain a mapping")
    if data.get("kind") != "Environment":
        raise ValueError(f"environment file {path} must have kind: Environment")
    return data


def environment_service_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"environment service file {path} must contain a mapping")
    if data.get("kind") != "EnvironmentService":
        raise ValueError(f"environment service file {path} must have kind: EnvironmentService")
    return data


def build_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    name = metadata.get("name") or spec.get("name") or document.get("build_name")
    if not name:
        raise ValueError("build document must contain metadata.name or spec.name")
    return str(name)


def build_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("build document must contain spec")
    return spec


def build_template_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    name = metadata.get("name") or spec.get("name") or document.get("template_name")
    if not name:
        raise ValueError("build template document must contain metadata.name or spec.name")
    return str(name)


def build_template_id_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    template_id = metadata.get("id") or spec.get("id") or spec.get("_id") or document.get("template_id")
    return str(template_id) if template_id else ""


def build_template_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("build template document must contain spec")
    return spec


def environment_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    name = metadata.get("name") or spec.get("env_key") or spec.get("env_name")
    if not name:
        raise ValueError("environment document must contain metadata.name or spec.env_key")
    return str(name)


def environment_production_from_document(document: dict[str, Any]) -> bool:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return bool(metadata.get("production", False))


def environment_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("environment document must contain spec")
    return spec


def environment_service_env_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    env_name = metadata.get("env") or spec.get("env_key") or spec.get("env_name")
    if not env_name:
        raise ValueError("environment service document must contain metadata.env")
    return str(env_name)


def environment_service_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    service_name = metadata.get("service") or spec.get("service_name") or spec.get("name")
    if not service_name:
        raise ValueError("environment service document must contain metadata.service or spec.service_name")
    return str(service_name)


def environment_service_production_from_document(document: dict[str, Any]) -> bool:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return bool(metadata.get("production", False))


def environment_service_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("environment service document must contain spec")
    return spec


def template_script_ref_path(template_name: str, script_name: str) -> str:
    return f"templates/build-templates/scripts/{safe_name(template_name)}/{script_name}"


def normalize_script(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_root_for(path: Path) -> Path:
    for parent in [path if path.is_dir() else path.parent, *path.parents]:
        if (parent / "projects").is_dir():
            return parent
    return Path.cwd()


def default_config_dir(project: str, *parts: str) -> Path:
    cwd = Path.cwd()
    candidates = [
        cwd / "zadig-config",
        cwd.parent / "zadig-config",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate / "projects" / safe_name(project) / Path(*parts)
    return candidates[0] / "projects" / safe_name(project) / Path(*parts)


def build_script_ref_path(project: str, script_name: str) -> str:
    return f"projects/{safe_name(project)}/builds/scripts/{script_name}"


def workflow_script_ref_path(project: str, workflow_name: str, script_name: str) -> str:
    return f"projects/{safe_name(project)}/workflows/scripts/{safe_name(workflow_name)}/{script_name}"


def expand_build_script_ref(document: dict[str, Any], document_path: Path) -> dict[str, Any]:
    spec = copy.deepcopy(build_spec_from_document(document))
    script_ref = spec.pop("build_script_ref", None)
    if not isinstance(script_ref, dict):
        return spec

    ref_path = script_ref.get("path")
    if not ref_path:
        raise ValueError(f"{document_path} spec.build_script_ref requires path")
    ref = Path(str(ref_path))
    if ref.is_absolute():
        raise ValueError(f"{document_path} spec.build_script_ref.path must be relative")

    root = config_root_for(document_path)
    script_path = (root / ref).resolve()
    if not script_path.is_file():
        fallback = (document_path.parent / ref).resolve()
        if fallback.is_file():
            script_path = fallback
        else:
            raise ValueError(f"{document_path} references missing build script {ref_path}")

    script = normalize_script(script_path.read_text(encoding="utf-8"))
    checksum = script_ref.get("checksum")
    if checksum:
        expected = str(checksum).replace("sha256:", "")
        actual = sha256_text(script)
        if expected != actual:
            raise ValueError(
                f"{document_path} build script checksum mismatch for {ref_path}: expected sha256:{expected}, got sha256:{actual}"
            )
    spec["build_script"] = script
    return spec


def read_ref_text(document_path: Path, ref_path: str, checksum: str = "") -> str:
    ref = Path(str(ref_path))
    if ref.is_absolute():
        raise ValueError(f"{document_path} reference path must be relative: {ref_path}")

    root = config_root_for(document_path)
    target_path = (root / ref).resolve()
    if not target_path.is_file():
        fallback = (document_path.parent / ref).resolve()
        if fallback.is_file():
            target_path = fallback
        else:
            raise ValueError(f"{document_path} references missing file {ref_path}")

    text = normalize_script(target_path.read_text(encoding="utf-8"))
    if checksum:
        expected = str(checksum).replace("sha256:", "")
        actual = sha256_text(text)
        if expected != actual:
            raise ValueError(
                f"{document_path} reference checksum mismatch for {ref_path}: "
                f"expected sha256:{expected}, got sha256:{actual}"
            )
    return text


def expand_workflow_refs(document: dict[str, Any], document_path: Path) -> dict[str, Any]:
    spec = workflow_spec_from_document(document)
    notifications_ref = spec.pop("notifications_ref", None)
    spec.pop("triggers_ref", None)

    if isinstance(notifications_ref, dict):
        ref_path = notifications_ref.get("path")
        if not ref_path:
            raise ValueError(f"{document_path} spec.notifications_ref requires path")
        notification_doc = load_data((config_root_for(document_path) / str(ref_path)).resolve())
        if isinstance(notification_doc, dict):
            notification_spec = notification_doc.get("spec") if isinstance(notification_doc.get("spec"), dict) else {}
            if "notify_ctls" in notification_spec:
                spec["notify_ctls"] = notification_spec["notify_ctls"]

    def expand_in_mapping(mapping: dict[str, Any], location: str) -> None:
        for key, value in list(mapping.items()):
            if key.endswith("_ref") and isinstance(value, dict):
                target_key = key.removesuffix("_ref")
                ref_path = value.get("path")
                if not ref_path:
                    raise ValueError(f"{document_path} {location}.{key} requires path")
                mapping[target_key] = read_ref_text(document_path, str(ref_path), str(value.get("checksum") or ""))
                mapping.pop(key, None)
                continue
            if isinstance(value, dict):
                expand_in_mapping(value, f"{location}.{key}" if location else str(key))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        expand_in_mapping(item, f"{location}.{key}[{index}]" if location else f"{key}[{index}]")

    expand_in_mapping(spec, "spec")
    return spec


def expand_template_script_refs(document: dict[str, Any], document_path: Path) -> dict[str, Any]:
    spec = copy.deepcopy(build_template_spec_from_document(document))

    def expand_in_mapping(mapping: dict[str, Any], location: str) -> None:
        for key, value in list(mapping.items()):
            if key.endswith("_ref") and isinstance(value, dict):
                target_key = key.removesuffix("_ref")
                ref_path = value.get("path")
                if not ref_path:
                    raise ValueError(f"{document_path} {location}.{key} requires path")
                ref = Path(str(ref_path))
                if ref.is_absolute():
                    raise ValueError(f"{document_path} {location}.{key}.path must be relative")

                root = config_root_for(document_path)
                script_path = (root / ref).resolve()
                if not script_path.is_file():
                    fallback = (document_path.parent / ref).resolve()
                    if fallback.is_file():
                        script_path = fallback
                    else:
                        raise ValueError(f"{document_path} references missing template script {ref_path}")

                script = normalize_script(script_path.read_text(encoding="utf-8"))
                checksum = value.get("checksum")
                if checksum:
                    expected = str(checksum).replace("sha256:", "")
                    actual = sha256_text(script)
                    if expected != actual:
                        raise ValueError(
                            f"{document_path} template script checksum mismatch for {ref_path}: "
                            f"expected sha256:{expected}, got sha256:{actual}"
                        )
                mapping[target_key] = script
                mapping.pop(key, None)
                continue

            if isinstance(value, dict):
                expand_in_mapping(value, f"{location}.{key}" if location else str(key))
                continue
            if isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        expand_in_mapping(item, f"{location}.{key}[{index}]" if location else f"{key}[{index}]")

    expand_in_mapping(spec, "spec")
    return spec


def service_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    name = metadata.get("name") or document.get("service_name")
    if not name:
        raise ValueError("service document must contain metadata.name")
    return str(name)


def service_production_from_document(document: dict[str, Any]) -> bool:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return bool(metadata.get("production", False))


def service_spec_from_document(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if not spec:
        raise ValueError("service document must contain spec")
    return spec


def service_create_payload(project: str, service_name: str, spec: dict[str, Any], production: bool) -> tuple[str, dict[str, Any]]:
    service_type = spec.get("type") or "helm"
    source = spec.get("source") or ""
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}

    if service_type == "helm" and source == "chartTemplate":
        template_name = template.get("name")
        if not template_name:
            raise ValueError(f"helm chartTemplate service {service_name!r} requires spec.template.name")
        return (
            "/openapi/service/template/load/helm",
            {
                "project_key": project,
                "service_name": service_name,
                "production": production,
                "template_name": template_name,
                "values_yaml": template.get("valuesYaml") or template.get("values_yaml") or "",
                "variables": template.get("variables") or [],
                "auto_sync": bool(template.get("autoSync", False)),
            },
        )

    yaml_text = spec.get("yaml") or ""
    if not yaml_text:
        raise ValueError(f"service {service_name!r} requires spec.yaml for non-template create/update")
    return (
        service_prefix(production),
        {
            "service_name": service_name,
            "type": service_type,
            "yaml": yaml_text,
        },
    )


def desired_service_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file())


def desired_build_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file())


def desired_build_template_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def desired_environment_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def desired_environment_service_files(path: Path, env_name: str = "") -> list[Path]:
    if path.is_file():
        return [path]
    if not path.exists():
        return []
    if env_name and (path / env_name).is_dir():
        path = path / env_name
    if (path / "services").is_dir():
        path = path / "services"
        if env_name and (path / env_name).is_dir():
            path = path / env_name
    if env_name and (path / "environments" / "services" / env_name).is_dir():
        path = path / "environments" / "services" / env_name
    if (path / "environments" / "services").is_dir():
        path = path / "environments" / "services"
        if env_name and (path / env_name).is_dir():
            path = path / env_name
    if any(item.is_dir() for item in path.iterdir()):
        return sorted(
            item
            for child in path.iterdir()
            if child.is_dir()
            for item in child.glob("*.yaml")
            if item.is_file() and item.name != "index.yaml"
        )
    return sorted(item for item in path.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def desired_code_scan_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def desired_test_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    items_dir = path / "items" if (path / "items").is_dir() else path
    return sorted(item for item in items_dir.glob("*.yaml") if item.is_file() and item.name != "index.yaml")


def test_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"test file {path} must contain a mapping")
    if data.get("kind") not in {None, "Test"}:
        raise ValueError(f"test file {path} must have kind: Test")
    return data


def code_scan_document_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"code scan file {path} must contain a mapping")
    if data.get("kind") != "CodeScan":
        raise ValueError(f"code scan file {path} must have kind: CodeScan")
    return data


async def live_build_names(project: str) -> set[str]:
    payload = await client().request(
        "GET",
        "/openapi/build",
        project_key=project,
        params={"pageNum": 1, "pageSize": 500},
    )
    builds = payload.get("builds", []) if isinstance(payload, dict) else []
    return {str(item.get("name")) for item in builds if isinstance(item, dict) and item.get("name")}


async def delete_build(project: str, build_name: str, *, dry_run: bool, confirm: bool) -> dict[str, Any]:
    result = {
        "build_name": build_name,
        "action": "delete",
        "applied": False,
        "dry_run": dry_run,
    }
    if dry_run or not confirm:
        return result
    result["result"] = await client().request("DELETE", "/openapi/build", params={"name": build_name}, project_key=project)
    result["applied"] = True
    return result


async def live_service_names(project: str, production: bool) -> set[str]:
    payload = await client().request("GET", f"{service_prefix(production)}/services", project_key=project)
    return {
        str(item.get("service_name") or item.get("name"))
        for item in iter_services(payload)
        if item.get("service_name") or item.get("name")
    }


async def live_environment_names(project: str, production: bool) -> set[str]:
    payload = await client().request("GET", environment_prefix(production), project_key=project)
    items = payload if isinstance(payload, list) else []
    return {
        str(first_present(item, "env_key", "env_name", "name"))
        for item in items
        if isinstance(item, dict)
        if first_present(item, "env_key", "env_name", "name")
    }


async def live_service_detail(project: str, service_name: str, production: bool) -> dict[str, Any] | None:
    try:
        payload = await client().request(
            "GET",
            f"{service_prefix(production)}/{path_name(service_name)}",
            project_key=project,
        )
        return payload if isinstance(payload, dict) else {}
    except ZadigAPIError as exc:
        if "no documents in result" in str(exc) or "HTTP 404" in str(exc):
            return None
        raise


def plan_service_update(service_name: str, spec: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    yaml_text = spec.get("yaml") or ""
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    variables_present = "variables" in template
    variables = template.get("variables") if isinstance(template.get("variables"), list) else []

    actions: list[dict[str, Any]] = []
    if yaml_text and yaml_text != (live.get("yaml") or ""):
        actions.append({"action": "update_yaml", "service_name": service_name})
    live_variables = live.get("service_variable_kvs") if isinstance(live.get("service_variable_kvs"), list) else []
    if variables_present and variables != live_variables:
        actions.append({"action": "update_variables", "service_name": service_name})

    if not actions:
        return {
            "action": "none",
            "service_name": service_name,
            "reason": "service exists and no supported mutable fields changed",
        }
    return {"action": "update", "service_name": service_name, "steps": actions}


async def apply_service_document(
    project: str,
    path: Path,
    *,
    dry_run: bool,
    confirm: bool,
    allow_redacted: bool,
) -> dict[str, Any]:
    document = service_document_from_file(path)
    if confirm and not dry_run:
        assert_no_redacted_placeholders(document, allow_redacted)
    service_name = service_name_from_document(document)
    production = service_production_from_document(document)
    spec = service_spec_from_document(document)
    live = await live_service_detail(project, service_name, production)

    if live is None:
        endpoint, payload = service_create_payload(project, service_name, spec, production)
        result = {
            "file": str(path),
            "service_name": service_name,
            "production": production,
            "action": "create",
            "endpoint": endpoint,
            "payload": payload,
            "applied": False,
            "dry_run": dry_run,
        }
        if dry_run or not confirm:
            return result
        result["result"] = await client().request("POST", endpoint, project_key=project, json_body=payload)
        result["applied"] = True
        return result

    update_plan = plan_service_update(service_name, spec, live)
    result = {
        "file": str(path),
        "service_name": service_name,
        "production": production,
        "action": update_plan["action"],
        "plan": update_plan,
        "applied": False,
        "dry_run": dry_run,
    }
    if update_plan["action"] == "none" or dry_run or not confirm:
        return result

    applied_steps = []
    for step in update_plan.get("steps", []):
        if step["action"] == "update_yaml":
            response = await client().request(
                "PUT",
                f"{service_prefix(production)}/{path_name(service_name)}",
                project_key=project,
                json_body={"type": spec.get("type") or live.get("type") or "k8s", "yaml": spec.get("yaml") or ""},
            )
            applied_steps.append({"action": "update_yaml", "result": response})
        elif step["action"] == "update_variables":
            template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
            response = await client().request(
                "PUT",
                f"{service_prefix(production)}/{path_name(service_name)}/variable",
                project_key=project,
                json_body={"service_variable_kvs": template.get("variables") or []},
            )
            applied_steps.append({"action": "update_variables", "result": response})
    result["applied"] = bool(applied_steps)
    result["result"] = applied_steps
    return result


async def delete_service(project: str, service_name: str, production: bool, *, dry_run: bool, confirm: bool) -> dict[str, Any]:
    result = {
        "service_name": service_name,
        "production": production,
        "action": "delete",
        "applied": False,
        "dry_run": dry_run,
    }
    if dry_run or not confirm:
        return result
    result["result"] = await client().request(
        "DELETE",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
    )
    result["applied"] = True
    return result


def build_template_gitops_document(
    template_id: str,
    template_name: str,
    detail: dict[str, Any],
) -> dict[str, Any]:
    spec = build_template_desired_payload(detail)
    spec.setdefault("name", template_name)
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "BuildTemplate",
        "metadata": {
            "name": template_name,
            "id": template_id,
        },
        "spec": spec,
        "live": {
            "summary": summarize_build_template({"id": template_id, **detail}),
        },
    }


def extract_project_build_scripts(
    project: str,
    build_details: dict[str, Any],
    project_dir: Path,
    output_format: str,
) -> dict[str, Any]:
    script_groups: dict[str, dict[str, Any]] = {}
    for build_name, document in build_details.items():
        if not isinstance(document, dict):
            continue
        spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
        script = spec.get("build_script")
        if not isinstance(script, str) or not script:
            continue
        normalized = normalize_script(script)
        checksum = sha256_text(normalized)
        script_groups.setdefault(checksum, {"script": normalized, "builds": []})
        script_groups[checksum]["builds"].append(str(build_name))

    if not script_groups:
        return {}

    refs_by_build: dict[str, dict[str, str]] = {}
    scripts_index: list[dict[str, Any]] = []
    for checksum, group in sorted(script_groups.items(), key=lambda item: sorted(item[1]["builds"])[0]):
        builds = sorted(group["builds"])
        if len(builds) == 1:
            script_name = f"{safe_name(builds[0])}.sh"
        else:
            script_name = f"shared-{checksum[:12]}.sh"
        ref_path = build_script_ref_path(project, script_name)
        script_file = project_dir / "builds" / "scripts" / script_name
        script_file.parent.mkdir(parents=True, exist_ok=True)
        script_file.write_text(group["script"], encoding="utf-8")

        meta = {
            "name": script_name.removesuffix(".sh"),
            "project": project,
            "checksum": f"sha256:{checksum}",
            "used_by": builds,
            "change_policy": {
                "impact_note_required": len(builds) > 1,
            },
        }
        write_data(
            project_dir / "builds" / "scripts" / data_filename(script_name.removesuffix(".sh") + ".meta", output_format),
            meta,
            output_format,
        )
        scripts_index.append({"path": ref_path, **meta})
        for build_name in builds:
            refs_by_build[build_name] = {
                "path": ref_path,
                "checksum": f"sha256:{checksum}",
            }

    write_data(
        project_dir / "builds" / "scripts" / data_filename("index", output_format),
        {
            "count": len(scripts_index),
            "items": scripts_index,
        },
        output_format,
    )

    for build_name, document in build_details.items():
        script_ref = refs_by_build.get(str(build_name))
        if not script_ref or not isinstance(document, dict):
            continue
        spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
        spec.pop("build_script", None)
        spec["build_script_ref"] = script_ref

        live = document.get("live") if isinstance(document.get("live"), dict) else {}
        detail = live.get("detail") if isinstance(live.get("detail"), dict) else {}
        detail.pop("build_script", None)
        detail["build_script_ref"] = script_ref

    return {
        "count": len(scripts_index),
        "items": scripts_index,
    }


def extract_build_template_scripts(
    details: dict[str, dict[str, Any]],
    template_dir: Path,
    output_format: str,
) -> dict[str, Any]:
    scripts_index: list[dict[str, Any]] = []

    def extract_from_mapping(template_name: str, mapping: dict[str, Any], field_path: str) -> None:
        for key, value in list(mapping.items()):
            current_path = f"{field_path}.{key}" if field_path else str(key)
            if isinstance(value, dict):
                extract_from_mapping(template_name, value, current_path)
                continue
            if isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        extract_from_mapping(template_name, item, f"{current_path}[{index}]")
                continue
            if key != "scripts" and not key.endswith("_scripts"):
                continue
            if not isinstance(value, str) or not value.strip():
                continue

            normalized = normalize_script(value)
            checksum = sha256_text(normalized)
            script_name = f"{safe_name(current_path)}.sh"
            ref_path = template_script_ref_path(template_name, script_name)
            script_file = template_dir / "scripts" / safe_name(template_name) / script_name
            script_file.parent.mkdir(parents=True, exist_ok=True)
            script_file.write_text(normalized, encoding="utf-8")

            script_ref = {
                "path": ref_path,
                "checksum": f"sha256:{checksum}",
            }
            mapping.pop(key, None)
            mapping[f"{key}_ref"] = script_ref
            scripts_index.append(
                {
                    "template": template_name,
                    "field": current_path,
                    "path": ref_path,
                    "checksum": f"sha256:{checksum}",
                }
            )

    for template_id, item in details.items():
        detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
        if not detail:
            continue
        template_name = str(item.get("name") or detail.get("name") or template_id)
        extract_from_mapping(template_name, detail, "spec")

    if not scripts_index:
        return {}

    scripts_index = sorted(scripts_index, key=lambda item: (str(item["template"]), str(item["field"])))
    write_data(
        template_dir / "scripts" / data_filename("index", output_format),
        {
            "count": len(scripts_index),
            "items": scripts_index,
        },
        output_format,
    )
    return {
        "count": len(scripts_index),
        "items": scripts_index,
    }


def workflow_summary(workflow_name: str, detail: dict[str, Any]) -> dict[str, Any]:
    stages = detail.get("stages") if isinstance(detail.get("stages"), list) else []
    params = detail.get("params") if isinstance(detail.get("params"), list) else []
    notify_ctls = detail.get("notify_ctls") if isinstance(detail.get("notify_ctls"), list) else []
    job_count = 0
    for stage in stages:
        if isinstance(stage, dict) and isinstance(stage.get("jobs"), list):
            job_count += len(stage["jobs"])
    return {
        "name": workflow_name,
        "display_name": first_present(detail, "display_name", "name", "workflow_name"),
        "concurrency_limit": detail.get("concurrency_limit"),
        "param_count": len(params),
        "stage_count": len(stages),
        "job_count": job_count,
        "notification_count": len(notify_ctls),
        "created_by": detail.get("created_by"),
        "updated_by": detail.get("updated_by"),
        "create_time": detail.get("create_time"),
        "update_time": detail.get("update_time"),
    }


def workflow_gitops_document(
    project: str,
    workflow_name: str,
    detail: dict[str, Any],
) -> dict[str, Any]:
    spec = copy.deepcopy(detail)
    spec.pop("create_time", None)
    spec.pop("update_time", None)
    spec.pop("created_by", None)
    spec.pop("updated_by", None)
    spec.pop("hash", None)
    spec.setdefault("project_key", project)
    spec.setdefault("name", workflow_name)
    spec.setdefault("workflow_name", workflow_name)
    spec.setdefault("workflow_key", workflow_name)
    spec.setdefault("display_name", workflow_name)
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "Workflow",
        "metadata": {
            "project": project,
            "name": workflow_name,
            "type": detail.get("type") or detail.get("workflow_type") or "custom",
        },
        "spec": spec,
        "live": {
            "summary": workflow_summary(workflow_name, detail),
        },
    }


def workflow_notifications_document(project: str, workflow_name: str, notify_ctls: list[Any]) -> dict[str, Any]:
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "WorkflowNotifications",
        "metadata": {
            "project": project,
            "workflow": workflow_name,
        },
        "spec": {
            "notify_ctls": notify_ctls,
        },
    }


def workflow_trigger_payload(project: str, workflow_name: str, trigger: Any) -> Any:
    if not isinstance(trigger, dict):
        return trigger
    payload = copy.deepcopy(trigger)
    payload.pop("workflow_arg", None)
    payload["workflow_ref"] = {
        "path": f"projects/{safe_name(project)}/workflows/items/{safe_name(workflow_name)}.yaml",
    }
    return payload


def workflow_triggers_document(project: str, workflow_name: str, detail: dict[str, Any]) -> dict[str, Any]:
    preset = detail.get("raw", {}).get("preset") if isinstance(detail.get("raw"), dict) else None
    webhooks = detail.get("raw", {}).get("webhooks") if isinstance(detail.get("raw"), dict) else None
    spec = {
        "preset": workflow_trigger_payload(project, workflow_name, preset),
        "webhooks": [
            workflow_trigger_payload(project, workflow_name, webhook)
            for webhook in webhooks
            if isinstance(webhooks, list)
        ] if isinstance(webhooks, list) else webhooks,
    }
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "WorkflowTriggers",
        "metadata": {
            "project": project,
            "workflow": workflow_name,
        },
        "spec": {key: value for key, value in spec.items() if value is not None},
        "live": {
            "summary": {
                "preset_count": detail.get("preset_count"),
                "webhook_count": detail.get("webhook_count"),
                "preset_items": detail.get("preset_items", []),
                "webhook_items": detail.get("webhook_items", []),
            },
        },
    }


def split_workflow_assets(
    project: str,
    workflow_details: dict[str, Any],
    webhooks: dict[str, Any],
    project_dir: Path,
    output_format: str,
) -> dict[str, Any]:
    workflow_index_items: list[dict[str, Any]] = []
    script_index_items: list[dict[str, Any]] = []
    notification_index_items: list[dict[str, Any]] = []
    trigger_index_items: list[dict[str, Any]] = []

    def extract_scripts(workflow_name: str, mapping: dict[str, Any], path_parts: list[str]) -> None:
        for key, value in list(mapping.items()):
            current_parts = [*path_parts, str(key)]
            if key == "script" and isinstance(value, str) and value.strip():
                normalized = normalize_script(value)
                checksum = sha256_text(normalized)
                script_name = f"{safe_name('.'.join(current_parts))}.sh"
                ref_path = workflow_script_ref_path(project, workflow_name, script_name)
                script_file = project_dir / "workflows" / "scripts" / safe_name(workflow_name) / script_name
                script_file.parent.mkdir(parents=True, exist_ok=True)
                script_file.write_text(normalized, encoding="utf-8")
                script_ref = {
                    "path": ref_path,
                    "checksum": f"sha256:{checksum}",
                }
                mapping.pop(key, None)
                mapping["script_ref"] = script_ref
                script_index_items.append(
                    {
                        "workflow": workflow_name,
                        "field": ".".join(current_parts),
                        "path": ref_path,
                        "checksum": f"sha256:{checksum}",
                    }
                )
                continue
            if isinstance(value, dict):
                extract_scripts(workflow_name, value, current_parts)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        extract_scripts(workflow_name, item, [*current_parts, str(index)])

    for workflow_name, detail in workflow_details.items():
        if not isinstance(detail, dict):
            continue
        document = workflow_gitops_document(project, str(workflow_name), detail)
        spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}

        notify_ctls = spec.pop("notify_ctls", None)
        if isinstance(notify_ctls, list):
            notification_path = f"projects/{safe_name(project)}/workflows/notifications/{safe_name(str(workflow_name))}.yaml"
            spec["notifications_ref"] = {"path": notification_path}
            write_data(
                project_dir / "workflows" / "notifications" / data_filename(safe_name(str(workflow_name)), output_format),
                workflow_notifications_document(project, str(workflow_name), notify_ctls),
                output_format,
            )
            notification_index_items.append(
                {
                    "workflow": str(workflow_name),
                    "path": notification_path,
                    "count": len(notify_ctls),
                }
            )

        if workflow_name in webhooks:
            trigger_path = f"projects/{safe_name(project)}/workflows/triggers/{safe_name(str(workflow_name))}.yaml"
            spec["triggers_ref"] = {"path": trigger_path}
            write_data(
                project_dir / "workflows" / "triggers" / data_filename(safe_name(str(workflow_name)), output_format),
                workflow_triggers_document(project, str(workflow_name), webhooks[str(workflow_name)]),
                output_format,
            )
            trigger_index_items.append(
                {
                    "workflow": str(workflow_name),
                    "path": trigger_path,
                    "preset_count": webhooks[str(workflow_name)].get("preset_count"),
                    "webhook_count": webhooks[str(workflow_name)].get("webhook_count"),
                }
            )

        extract_scripts(str(workflow_name), spec, ["spec"])
        write_data(
            project_dir / "workflows" / "items" / data_filename(safe_name(str(workflow_name)), output_format),
            document,
            output_format,
        )
        workflow_index_items.append(
            {
                "name": str(workflow_name),
                "type": document.get("metadata", {}).get("type"),
                "file": f"items/{safe_name(str(workflow_name))}.yaml",
                "script_dir": f"scripts/{safe_name(str(workflow_name))}",
                "triggers_file": f"triggers/{safe_name(str(workflow_name))}.yaml" if workflow_name in webhooks else "",
                "notifications_file": (
                    f"notifications/{safe_name(str(workflow_name))}.yaml" if isinstance(notify_ctls, list) else ""
                ),
                **workflow_summary(str(workflow_name), detail),
            }
        )

    if script_index_items:
        write_data(
            project_dir / "workflows" / "scripts" / data_filename("index", output_format),
            {
                "count": len(script_index_items),
                "items": sorted(script_index_items, key=lambda item: (str(item["workflow"]), str(item["field"]))),
            },
            output_format,
        )
    if notification_index_items:
        write_data(
            project_dir / "workflows" / "notifications" / data_filename("index", output_format),
            {
                "count": len(notification_index_items),
                "items": sorted(notification_index_items, key=lambda item: str(item["workflow"])),
            },
            output_format,
        )
    if trigger_index_items:
        write_data(
            project_dir / "workflows" / "triggers" / data_filename("index", output_format),
            {
                "count": len(trigger_index_items),
                "items": sorted(trigger_index_items, key=lambda item: str(item["workflow"])),
            },
            output_format,
        )

    return {
        "count": len(workflow_index_items),
        "items": sorted(workflow_index_items, key=lambda item: str(item["name"])),
        "script_count": len(script_index_items),
        "notification_count": len(notification_index_items),
        "trigger_count": len(trigger_index_items),
    }


def split_snapshot(snapshot: dict[str, Any], output_dir: Path, output_format: str) -> None:
    project = snapshot.get("metadata", {}).get("project_key") or "unknown-project"
    project_dir = output_dir / "projects" / safe_name(str(project))
    snapshot_dir = project_dir / "_snapshot"
    write_data(snapshot_dir / data_filename("metadata", output_format), snapshot.get("metadata", {}), output_format)
    write_data(snapshot_dir / data_filename("errors", output_format), snapshot.get("errors", []), output_format)

    if "project" in snapshot:
        write_data(project_dir / data_filename("project", output_format), snapshot["project"], output_format)

    if "iterations" in snapshot:
        write_data(project_dir / "iterations" / data_filename("index", output_format), snapshot["iterations"], output_format)

    workflow_details = snapshot.get("workflow_details", {}).get("items", {})
    webhooks = snapshot.get("webhooks", {}).get("items", {})
    if workflow_details:
        workflow_index = split_workflow_assets(project, workflow_details, webhooks, project_dir, output_format)
        source_index = snapshot.get("workflows") if isinstance(snapshot.get("workflows"), dict) else {}
        workflow_index["source"] = {
            key: value
            for key, value in source_index.items()
            if key not in {"items"}
        }
        write_data(project_dir / "workflows" / data_filename("index", output_format), workflow_index, output_format)
    elif "workflows" in snapshot:
        write_data(project_dir / "workflows" / data_filename("index", output_format), snapshot["workflows"], output_format)

    if "builds" in snapshot:
        builds = snapshot["builds"] if isinstance(snapshot["builds"], dict) else {}
        build_details = builds.get("details") if isinstance(builds.get("details"), dict) else {}
        build_scripts = extract_project_build_scripts(project, build_details, project_dir, output_format)
        build_index = {
            key: value
            for key, value in builds.items()
            if key not in {"details"}
        }
        if build_scripts:
            build_index["scripts"] = build_scripts
        write_data(project_dir / "builds" / data_filename("index", output_format), build_index, output_format)
        for build_name, detail in build_details.items():
            write_data(
                project_dir / "builds" / "items" / data_filename(safe_name(str(build_name)), output_format),
                detail,
                output_format,
            )

    if "tests" in snapshot:
        tests = snapshot["tests"] if isinstance(snapshot["tests"], dict) else {}
        test_items = tests.get("items") if isinstance(tests.get("items"), list) else []
        test_details = tests.get("details") if isinstance(tests.get("details"), dict) else {}
        if test_details:
            test_items = [item for item in test_details.values() if isinstance(item, dict)]
        index_items = []
        for item in test_items:
            if not isinstance(item, dict):
                continue
            name = test_name_from_payload(item)
            document = {
                "apiVersion": "zadig.storehub.io/v1alpha1",
                "kind": "Test",
                "metadata": {"project": str(project), "name": name},
                "spec": copy.deepcopy(item),
            }
            document["spec"].pop("live", None)
            index_items.append({
                "name": name,
                "file": f"items/{data_filename(safe_name(name), output_format)}",
                "repository_count": len(item.get("repos") or item.get("repositories") or []),
                "environment_count": len(item.get("envs") or item.get("environments") or []),
            })
            write_data(project_dir / "tests" / "items" / data_filename(safe_name(name), output_format), document, output_format)
        write_data(
            project_dir / "tests" / data_filename("index", output_format),
            {"apiVersion": "zadig.storehub.io/v1alpha1", "kind": "TestIndex", "project": str(project), "count": len(index_items), "items": sorted(index_items, key=lambda item: str(item["name"]))},
            output_format,
        )

    if "code_scans" in snapshot:
        code_scans = snapshot["code_scans"] if isinstance(snapshot["code_scans"], dict) else {}
        scan_items = code_scans.get("items") if isinstance(code_scans.get("items"), list) else []
        index_items = []
        for index, item in enumerate(scan_items):
            if not isinstance(item, dict):
                continue
            name = code_scan_name(item, index)
            index_items.append(
                {
                    "name": name,
                    "file": f"items/{data_filename(safe_name(name), output_format)}",
                    "id": first_present(item, "id", "scan_id", "scanId"),
                    "repository_count": len(item.get("repos") or item.get("repositories") or []),
                }
            )
            write_data(
                project_dir / "code-scans" / "items" / data_filename(safe_name(name), output_format),
                code_scan_gitops_document(str(project), item, index),
                output_format,
            )
        index_items.sort(key=lambda item: str(item["name"]))
        write_data(
            project_dir / "code-scans" / data_filename("index", output_format),
            {
                "apiVersion": "zadig.storehub.io/v1alpha1",
                "kind": "CodeScanIndex",
                "project": str(project),
                "count": len(index_items),
                "items": index_items,
            },
            output_format,
        )

    if "services" in snapshot:
        services = snapshot["services"] if isinstance(snapshot["services"], dict) else {}
        service_index = {
            key: value
            for key, value in services.items()
            if key not in {"details"}
        }
        write_data(project_dir / "services" / data_filename("index", output_format), service_index, output_format)
        for service_name, detail in (services.get("details") or {}).items():
            write_data(
                project_dir / "services" / "items" / data_filename(safe_name(str(service_name)), output_format),
                detail,
                output_format,
            )

    if "environments" in snapshot:
        environments = snapshot["environments"] if isinstance(snapshot["environments"], dict) else {}
        environment_index = {
            key: value
            for key, value in environments.items()
            if key not in {"details"}
        }
        write_data(project_dir / "environments" / data_filename("index", output_format), environment_index, output_format)
        for env_name, document in (environments.get("details") or {}).items():
            if not isinstance(document, dict):
                continue
            spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
            live = document.get("live") if isinstance(document.get("live"), dict) else {}
            summary = live.get("summary") if isinstance(live.get("summary"), dict) else {}
            production = bool(
                document.get("metadata", {}).get("production")
                if isinstance(document.get("metadata"), dict)
                else summary.get("production", False)
            )
            detail_services = []
            detail = live.get("detail") if isinstance(live.get("detail"), dict) else {}
            if isinstance(detail.get("services"), list):
                detail_services = detail["services"]
            elif isinstance(spec.get("services"), list):
                detail_services = spec["services"]
            elif isinstance(document.get("services"), list):
                detail_services = document["services"]

            environment_document = copy.deepcopy(document)
            environment_live = environment_document.get("live") if isinstance(environment_document.get("live"), dict) else {}
            environment_live.pop("detail", None)
            environment_document["live"] = environment_live
            write_data(
                project_dir / "environments" / "items" / data_filename(safe_name(str(env_name)), output_format),
                environment_document,
                output_format,
            )

            service_items = [
                environment_service_index_item(str(env_name), service)
                for service in detail_services
                if isinstance(service, dict)
            ]
            service_dir = project_dir / "environments" / "services" / safe_name(str(env_name))
            write_data(
                service_dir / data_filename("index", output_format),
                {
                    "count": len(service_items),
                    "project_key": project,
                    "env": str(env_name),
                    "production": production,
                    "items": service_items,
                },
                output_format,
            )
            for service in detail_services:
                if not isinstance(service, dict):
                    continue
                service_name = first_present(service, "service_name", "name")
                if not service_name:
                    continue
                write_data(
                    service_dir / data_filename(safe_name(str(service_name)), output_format),
                    environment_service_gitops_document(project, str(env_name), service, production),
                    output_format,
                )

    if "releases" in snapshot:
        write_data(project_dir / "releases" / data_filename("index", output_format), snapshot["releases"], output_format)


async def run_snapshot(args: argparse.Namespace) -> None:
    snapshot = await zadig_project_snapshot(
        project_key=args.project,
        sections=args.sections,
        workflow_names=args.workflow,
        max_workflows=args.max_workflows,
        include_workflow_raw_list=args.include_workflow_raw_list,
    )
    output_dir = Path(args.output).expanduser().resolve()
    split_snapshot(snapshot, output_dir, args.format)
    project = snapshot.get("metadata", {}).get("project_key")
    error_count = snapshot.get("metadata", {}).get("error_count", 0)
    print(f"wrote snapshot for project={project} to {output_dir}")
    print(f"sections={','.join(snapshot.get('metadata', {}).get('sections', []))}")
    print(f"error_count={error_count}")


async def run_snapshot_template(args: argparse.Namespace) -> None:
    output_dir = Path(args.output).expanduser().resolve()
    template_dir = output_dir / "templates" / "build-templates"
    errors: list[dict[str, Any]] = []

    payload = await client().request(
        "GET",
        "/api/aslan/template/build",
        params={"pageNum": args.page_num, "pageSize": args.page_size},
    )
    template_items = build_template_items_from_payload(payload)
    needle = args.query.lower().strip()
    selected = []
    for item in template_items:
        template_id = str(first_present(item, "id", "_id") or "")
        template_name = str(first_present(item, "name", "template_name", "templateName") or "")
        if args.template and args.template not in {template_id, template_name}:
            continue
        if needle and needle not in json.dumps(item, ensure_ascii=False).lower():
            continue
        selected.append((template_id, template_name, item))

    details: dict[str, dict[str, Any]] = {}
    for template_id, template_name, item in selected:
        if not template_id:
            errors.append(
                {
                    "section": "build_templates",
                    "template_name": template_name,
                    "type": "MissingID",
                    "message": "template list item did not include id",
                }
            )
            continue
        try:
            detail_payload = await client().request(
                "GET",
                f"/api/aslan/template/build/{path_name(template_id)}",
            )
            detail = redact_sensitive(detail_payload)
            details[template_id] = {
                "name": template_name or str(first_present(detail, "name", "template_name", "templateName") or template_id),
                "detail": detail,
                "list": redact_sensitive(item),
            }
        except Exception as exc:
            errors.append(
                {
                    "section": "build_templates",
                    "template_id": template_id,
                    "template_name": template_name,
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                }
            )

    script_index = extract_build_template_scripts(details, template_dir, args.format)
    index = {
        "count": len(details),
        "scope": "all" if not args.template and not args.query else "filtered",
        "summary": [
            summarize_build_template({"id": template_id, **item["detail"]})
            for template_id, item in details.items()
            if isinstance(item.get("detail"), dict)
        ],
    }
    if script_index:
        index["scripts"] = script_index
    write_data(template_dir / data_filename("index", args.format), index, args.format)
    for template_id, item in details.items():
        template_name = item.get("name") or template_id
        detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
        write_data(
            template_dir / data_filename(f"{safe_name(str(template_name))}.{safe_name(str(template_id))}", args.format),
            build_template_gitops_document(str(template_id), str(template_name), detail),
            args.format,
        )

    snapshot_dir = output_dir / "_snapshot"
    write_data(
        snapshot_dir / data_filename("build-template-metadata", args.format),
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": ["build_templates"],
            "redacted": True,
            "count": len(details),
            "script_count": script_index.get("count", 0) if script_index else 0,
            "error_count": len(errors),
        },
        args.format,
    )
    write_data(snapshot_dir / data_filename("build-template-errors", args.format), errors, args.format)

    print(f"wrote build template snapshot to {template_dir}")
    print(f"count={len(details)}")
    print(f"error_count={len(errors)}")


async def run_apply(args: argparse.Namespace) -> None:
    if args.entity == "project":
        result = await run_apply_project(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "build":
        result = await run_apply_build(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "template":
        result = await run_apply_template(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "environment":
        result = await run_apply_environment(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "environment-service":
        result = await run_apply_environment_service(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "code-scan":
        result = await run_apply_code_scan(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "test":
        result = await run_apply_test(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "service":
        result = await run_apply_service(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.mode == "delete" and args.workflow and not args.file and not args.dir:
        result = await zadig_workflow_delete(
            workflow_name=args.workflow,
            project_key=args.project,
            dry_run=not args.confirm,
            confirm=args.confirm,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if not args.file and not args.dir:
        args.dir = str(default_config_dir(args.project, "workflows"))

    target_path = Path(args.file or args.dir).expanduser().resolve()
    workflow_files = desired_workflow_files(target_path)
    if not workflow_files:
        raise ValueError(f"no workflow YAML files found under {target_path}")

    results = []
    for workflow_file in workflow_files:
        raw_document = load_data(workflow_file)
        workflow = workflow_payload_from_file(workflow_file)
        if isinstance(raw_document, dict) and raw_document.get("kind") == "Workflow":
            workflow_name = workflow_name_from_document(raw_document)
        else:
            workflow_name = workflow.get("workflow_name") or workflow.get("workflow_key") or workflow.get("name")
        workflow_name = args.workflow or workflow_name
        if not workflow_name:
            raise ValueError("--workflow is required when the file does not contain workflow_name/workflow_key/name")
        if args.workflow and workflow_name != args.workflow:
            continue
        if args.diff:
            result = await zadig_workflow_diff(
                workflow_name=str(workflow_name),
                workflow=workflow,
                project_key=args.project,
            )
            results.append(result)
            continue
        if args.mode == "delete":
            results.append(
                await zadig_workflow_delete(
                    workflow_name=str(workflow_name),
                    project_key=args.project,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
            continue
        results.append(
            await zadig_workflow_apply(
                workflow_name=str(workflow_name),
                workflow=workflow,
                project_key=args.project,
                mode=args.mode,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    output = {
        "project_key": args.project,
        "entity": "workflow",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "target_path": str(target_path),
        "desired_file_count": len(workflow_files),
        "results": results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))


async def run_apply_code_scan(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project
    if args.mode == "delete" and args.code_scan and not args.file and not args.dir:
        result = await zadig_code_scan_delete(
            scan_name=args.code_scan,
            project_key=project,
            dry_run=not args.confirm,
            confirm=args.confirm,
        )
        return {
            "project_key": project,
            "entity": "code-scan",
            "dry_run": not args.confirm,
            "confirm": args.confirm,
            "desired_file_count": 0,
            "results": [result],
        }
    if not args.file and not args.dir:
        raise ValueError("--file or --dir is required for code-scan apply")
    if args.mode == "delete" and not args.code_scan and not args.file:
        raise ValueError("--code-scan or --file is required for code-scan delete mode")

    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_code_scan_files(target_path)
    if not files and args.mode != "delete":
        raise ValueError(f"no code scan YAML files found under {target_path}")

    results = []
    for scan_file in files:
        document = code_scan_document_from_file(scan_file)
        scan_name = args.code_scan or code_scan_name_from_payload(document)
        if not scan_name:
            raise ValueError(f"code scan file {scan_file} must contain metadata.name or spec.name")
        if args.code_scan and scan_name != args.code_scan:
            continue
        if args.diff:
            results.append(
                await zadig_code_scan_diff(
                    scan=document,
                    scan_name=scan_name,
                    project_key=project,
                )
            )
        elif args.mode == "delete":
            results.append(
                await zadig_code_scan_delete(
                    scan_name=scan_name,
                    project_key=project,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
        else:
            results.append(
                await zadig_code_scan_apply(
                    scan=document,
                    scan_name=scan_name,
                    project_key=project,
                    mode=args.mode,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                    allow_redacted=args.allow_redacted,
                )
            )

    if args.code_scan and not results:
        raise ValueError(f"no matching code scan file found under {target_path}")
    return {
        "project_key": project,
        "entity": "code-scan",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "target_path": str(target_path),
        "desired_file_count": len(files),
        "results": results,
    }


async def run_apply_test(args: argparse.Namespace) -> dict[str, Any]:
    if not args.file and not args.dir:
        raise ValueError("--file or --dir is required for test apply")
    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_test_files(target_path)
    if not files and args.mode != "delete":
        raise ValueError(f"no test YAML files found under {target_path}")
    results = []
    for test_file in files:
        document = test_document_from_file(test_file)
        name = args.test or test_name_from_payload(document)
        if args.test and name != args.test:
            continue
        if args.diff:
            results.append(await zadig_test_diff(document, name, args.project))
        elif args.mode == "delete":
            results.append(await zadig_test_delete(name, args.project, not args.confirm, args.confirm))
        else:
            results.append(await zadig_test_apply(
                document,
                name,
                args.project,
                args.mode,
                not args.confirm,
                args.confirm,
                args.allow_redacted,
            ))
    if args.test and not results:
        raise ValueError(f"no matching test file found under {target_path}")
    return {
        "project_key": args.project,
        "entity": "test",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "target_path": str(target_path),
        "desired_file_count": len(files),
        "results": results,
    }


def resolve_project_file(args: argparse.Namespace) -> Path | None:
    if args.file:
        return Path(args.file).expanduser().resolve()
    if args.dir:
        return Path(args.dir).expanduser().resolve() / "project.yaml"
    return None


async def run_apply_project(args: argparse.Namespace) -> dict[str, Any]:
    project_file = resolve_project_file(args)
    project_document = None
    if args.mode != "delete":
        if project_file is None:
            raise ValueError("--file or --dir is required for project create/update plan")
        if not project_file.is_file():
            raise ValueError(f"project file not found: {project_file}")
        project_document = project_document_from_file(project_file)
    elif project_file is not None and project_file.is_file():
        project_document = project_document_from_file(project_file)

    result = await zadig_project_apply_plan(
        project_document=project_document,
        project_key=args.project,
        mode=args.mode,
    )
    result["file"] = str(project_file) if project_file else None
    result["confirm_ignored"] = bool(args.confirm)
    return result


async def run_apply_build(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project
    if args.mode == "delete" and args.build and not args.file and not args.dir:
        return {
            "project_key": project,
            "entity": "build",
            "dry_run": not args.confirm,
            "confirm": args.confirm,
            "desired_file_count": 0,
            "results": [
                await delete_build(
                    project,
                    args.build,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            ],
            "prune_results": [],
        }
    if not args.file and not args.dir:
        raise ValueError("--file or --dir is required for build apply")
    if args.prune and not args.dir:
        raise ValueError("--prune requires --dir so the desired build set is explicit")
    if args.mode == "delete" and not args.build and not args.file:
        raise ValueError("--build or --file is required for build delete mode")

    files: list[Path] = []
    if args.mode != "delete" or args.file or args.dir:
        target_path = Path(args.file or args.dir).expanduser().resolve()
        files = desired_build_files(target_path)
        if not files and args.mode != "delete":
            raise ValueError(f"no build YAML files found under {target_path}")

    results = []
    desired_names: set[str] = set()
    for build_file in files:
        document = build_document_from_file(build_file)
        build_name = build_name_from_document(document)
        desired_names.add(build_name)
        if args.build and build_name != args.build:
            continue
        if args.mode == "delete":
            results.append(
                await delete_build(
                    project,
                    build_name,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
            continue
        build_spec = expand_build_script_ref(document, build_file)
        results.append(
            await zadig_build_apply(
                build_name=build_name,
                build=build_spec,
                project_key=project,
                mode=args.mode,
                update_api=args.build_update_api,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    prune_results = []
    if args.prune:
        for live_name in sorted(await live_build_names(project)):
            if args.build and live_name != args.build:
                continue
            if live_name in desired_names:
                continue
            prune_results.append(
                await delete_build(
                    project,
                    live_name,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )

    return {
        "project_key": project,
        "entity": "build",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "desired_file_count": len(files),
        "results": results,
        "prune_results": prune_results,
    }


async def run_apply_template(args: argparse.Namespace) -> dict[str, Any]:
    if args.mode == "delete" and args.template and not args.file and not args.dir:
        return {
            "entity": "template",
            "dry_run": not args.confirm,
            "confirm": args.confirm,
            "desired_file_count": 0,
            "results": [
                await zadig_build_template_delete(
                    template_name=args.template,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            ],
        }
    if not args.file and not args.dir:
        raise ValueError("--file or --dir is required for template apply")
    if args.mode == "delete" and not args.template and not args.file:
        raise ValueError("--template or --file is required for template delete mode")
    if args.prune:
        raise ValueError("template prune is intentionally unsupported; delete templates explicitly")

    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_build_template_files(target_path)
    if not files:
        raise ValueError(f"no build template YAML files found under {target_path}")

    results = []
    for template_file in files:
        document = build_template_document_from_file(template_file)
        template_name = build_template_name_from_document(document)
        template_id = build_template_id_from_document(document)
        if args.template and template_name != args.template and template_id != args.template:
            continue
        template_spec = expand_template_script_refs(document, template_file)
        if args.diff:
            results.append(
                await zadig_build_template_diff(
                    template=template_spec,
                    template_id=template_id,
                    template_name=template_name,
                )
            )
            continue
        if args.mode == "delete":
            results.append(
                await zadig_build_template_delete(
                    template_id=template_id,
                    template_name=template_name,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
            continue
        results.append(
            await zadig_build_template_apply(
                template=template_spec,
                template_id=template_id,
                template_name=template_name,
                mode=args.mode,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    return {
        "entity": "template",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "desired_file_count": len(files),
        "results": results,
    }


async def run_apply_environment(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project
    production = bool(args.production) if args.production is not None else False
    if args.mode == "delete" and args.environment and not args.file and not args.dir:
        return {
            "project_key": project,
            "entity": "environment",
            "dry_run": not args.confirm,
            "confirm": args.confirm,
            "desired_file_count": 0,
            "results": [
                await zadig_environment_delete(
                    env_name=args.environment,
                    project_key=project,
                    production=production,
                    is_delete=args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            ],
            "prune_results": [],
        }
    inferred_dir = False
    if not args.file and not args.dir:
        args.dir = str(default_config_dir(project, "environments"))
        inferred_dir = True
    if args.prune and not args.dir:
        raise ValueError("--prune requires --dir so the desired environment set is explicit")

    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_environment_files(target_path)
    if not files:
        raise ValueError(f"no environment YAML files found under {target_path}")

    results = []
    desired_names: set[str] = set()
    productions_by_env: dict[str, bool] = {}
    for env_file in files:
        document = environment_document_from_file(env_file)
        env_name = environment_name_from_document(document)
        env_production = environment_production_from_document(document)
        desired_names.add(env_name)
        productions_by_env[env_name] = env_production
        if args.environment and env_name != args.environment:
            continue
        if args.mode == "delete":
            results.append(
                await zadig_environment_delete(
                    env_name=env_name,
                    project_key=project,
                    production=env_production,
                    is_delete=args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
            continue

        env_spec = environment_spec_from_document(document)
        if args.diff:
            results.append(
                await zadig_environment_diff(
                    environment=env_spec,
                    env_name=env_name,
                    project_key=project,
                    production=env_production,
                )
            )
            continue
        results.append(
            await zadig_environment_apply(
                environment=env_spec,
                env_name=env_name,
                project_key=project,
                production=env_production,
                mode=args.mode,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    prune_results = []
    if args.prune:
        for live_name in sorted(await live_environment_names(project, production)):
            if args.environment and live_name != args.environment:
                continue
            if live_name in desired_names and productions_by_env.get(live_name, production) == production:
                continue
            prune_results.append(
                await zadig_environment_delete(
                    env_name=live_name,
                    project_key=project,
                    production=production,
                    is_delete=args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )

    if args.environment and not results and args.mode != "delete":
        raise ValueError(f"environment {args.environment!r} not found in desired files under {target_path}")

    return {
        "project_key": project,
        "entity": "environment",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "inferred_dir": inferred_dir,
        "target_path": str(target_path),
        "desired_file_count": len(files),
        "results": results,
        "prune_results": prune_results,
    }


async def run_apply_environment_service(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project
    production = bool(args.production) if args.production is not None else False
    if args.mode == "delete" and args.environment and args.service and not args.file and not args.dir:
        return {
            "project_key": project,
            "entity": "environment-service",
            "dry_run": not args.confirm,
            "confirm": args.confirm,
            "desired_file_count": 0,
            "results": [
                await zadig_environment_service_delete(
                    env_name=args.environment,
                    service_name=args.service,
                    project_key=project,
                    production=production,
                    not_delete_resource=not args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            ],
            "prune_results": [],
        }
    inferred_dir = False
    if not args.file and not args.dir:
        if not args.environment:
            raise ValueError("--environment is required when --file/--dir is omitted for environment-service apply")
        args.dir = str(default_config_dir(project, "environments", "services", args.environment))
        inferred_dir = True
    if args.prune and (not args.dir or not args.environment):
        raise ValueError("--prune for environment-service requires --dir and --environment")

    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_environment_service_files(target_path, args.environment or "")
    if not files:
        raise ValueError(f"no environment service YAML files found under {target_path}")

    results = []
    desired_names: set[str] = set()
    for service_file in files:
        document = environment_service_document_from_file(service_file)
        env_name = environment_service_env_from_document(document)
        service_name = environment_service_name_from_document(document)
        env_production = environment_service_production_from_document(document)
        desired_names.add(service_name)
        if args.environment and env_name != args.environment:
            continue
        if args.service and service_name != args.service:
            continue
        if args.mode == "delete":
            results.append(
                await zadig_environment_service_delete(
                    env_name=env_name,
                    service_name=service_name,
                    project_key=project,
                    production=env_production,
                    not_delete_resource=not args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )
            continue
        service_spec = environment_service_spec_from_document(document)
        if args.diff:
            service_spec.setdefault("service_name", service_name)
            results.append(
                await zadig_environment_service_apply(
                    env_name=env_name,
                    service=service_spec,
                    project_key=project,
                    production=env_production,
                    mode=args.mode,
                    dry_run=True,
                    confirm=False,
                    allow_redacted=args.allow_redacted,
                )
            )
            continue
        results.append(
            await zadig_environment_service_apply(
                env_name=env_name,
                service=service_spec,
                project_key=project,
                production=env_production,
                mode=args.mode,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    prune_results = []
    if args.prune:
        live_payload = await client().request(
            "GET",
            f"{environment_prefix(production)}/{path_name(args.environment)}",
            project_key=project,
        )
        live_services = live_payload.get("services") if isinstance(live_payload, dict) else []
        for live_service in live_services if isinstance(live_services, list) else []:
            if not isinstance(live_service, dict):
                continue
            live_name = str(first_present(live_service, "service_name", "name") or "")
            if not live_name or live_name in desired_names:
                continue
            if args.service and live_name != args.service:
                continue
            prune_results.append(
                await zadig_environment_service_delete(
                    env_name=args.environment,
                    service_name=live_name,
                    project_key=project,
                    production=production,
                    not_delete_resource=not args.delete_resources,
                    dry_run=not args.confirm,
                    confirm=args.confirm,
                )
            )

    if (args.environment or args.service) and not results and args.mode != "delete":
        raise ValueError(f"no matching environment service desired files found under {target_path}")

    return {
        "project_key": project,
        "entity": "environment-service",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "inferred_dir": inferred_dir,
        "target_path": str(target_path),
        "desired_file_count": len(files),
        "results": results,
        "prune_results": prune_results,
    }


async def run_apply_service(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project
    if not args.file and not args.dir:
        raise ValueError("--file or --dir is required for service apply")
    if args.prune and not args.dir:
        raise ValueError("--prune requires --dir so the desired service set is explicit")
    target_path = Path(args.file or args.dir).expanduser().resolve()
    files = desired_service_files(target_path)
    if not files:
        raise ValueError(f"no service YAML files found under {target_path}")

    results = []
    desired_by_production: dict[bool, set[str]] = {}
    for service_file in files:
        document = service_document_from_file(service_file)
        service_name = service_name_from_document(document)
        production = service_production_from_document(document)
        desired_by_production.setdefault(production, set()).add(service_name)
        if args.service and service_name != args.service:
            continue
        results.append(
            await apply_service_document(
                project,
                service_file,
                dry_run=not args.confirm,
                confirm=args.confirm,
                allow_redacted=args.allow_redacted,
            )
        )

    prune_results = []
    if args.prune:
        productions = [args.production] if args.production is not None else sorted(desired_by_production)
        for production in productions:
            desired_names = desired_by_production.get(production, set())
            for live_name in sorted(await live_service_names(project, production)):
                if args.service and live_name != args.service:
                    continue
                if live_name in desired_names:
                    continue
                prune_results.append(
                    await delete_service(
                        project,
                        live_name,
                        production,
                        dry_run=not args.confirm,
                        confirm=args.confirm,
                    )
                )

    return {
        "project_key": project,
        "entity": "service",
        "dry_run": not args.confirm,
        "confirm": args.confirm,
        "desired_file_count": len(files),
        "results": results,
        "prune_results": prune_results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zadig-gitops", description="GitOps helpers for Zadig configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot", help="Export a redacted Zadig project snapshot to files.")
    snapshot.add_argument("--project", required=True, help="Zadig project key.")
    snapshot.add_argument("--output", default="zadig-config", help="Output directory.")
    snapshot.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output file format.")
    snapshot.add_argument(
        "--section",
        dest="sections",
        action="append",
        choices=["all", *DEFAULT_SNAPSHOT_SECTIONS],
        help="Snapshot section to export. Can be specified multiple times. Defaults to all.",
    )
    snapshot.add_argument("--workflow", action="append", help="Workflow name to include for detail/webhook export.")
    snapshot.add_argument("--max-workflows", type=int, default=0, help="Limit workflow detail/webhook exports.")
    snapshot.add_argument(
        "--include-workflow-raw-list",
        action="store_true",
        help="Include raw workflow list payload in workflows/index file.",
    )
    snapshot.set_defaults(func=run_snapshot)

    snapshot_template = subparsers.add_parser("snapshot-template", help="Export build template library snapshot to files.")
    snapshot_template.add_argument("--output", default="zadig-config", help="Output directory.")
    snapshot_template.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output file format.")
    snapshot_template.add_argument("--template", help="Build template name or id filter.")
    snapshot_template.add_argument("--query", default="", help="Filter templates by text search against list items.")
    snapshot_template.add_argument("--page-num", type=int, default=1, help="Template list page number.")
    snapshot_template.add_argument("--page-size", type=int, default=500, help="Template list page size.")
    snapshot_template.set_defaults(func=run_snapshot_template)

    apply = subparsers.add_parser("apply", help="Apply Zadig workflow/service/build/template configuration, or plan project changes.")
    apply.add_argument(
        "entity",
        nargs="?",
        choices=["workflow", "service", "project", "build", "template", "environment", "environment-service", "code-scan", "test"],
        default="workflow",
        help="Entity type to apply or plan.",
    )
    apply.add_argument("--project", required=True, help="Zadig project key.")
    apply.add_argument("--workflow", help="Workflow name. Defaults to workflow_name/workflow_key/name from file.")
    apply.add_argument("--service", help="Service name filter for service apply.")
    apply.add_argument("--build", help="Build name filter for build apply/delete.")
    apply.add_argument("--template", help="Build template name or id filter for template apply/delete.")
    apply.add_argument("--code-scan", help="Code scan name filter for code-scan apply/delete.")
    apply.add_argument("--test", help="Test name filter for test apply/delete.")
    apply.add_argument("--environment", help="Environment name/key filter for environment apply/delete.")
    apply.add_argument("--file", help="Workflow or service YAML/JSON file.")
    apply.add_argument("--dir", help="Directory containing item YAML files, for example projects/<project>/services or templates/build-templates.")
    apply.add_argument("--mode", choices=["auto", "create", "update", "delete"], default="auto", help="Apply mode.")
    apply.add_argument(
        "--build-update-api",
        choices=["auto", "openapi", "ui"],
        default="auto",
        help="For build update/apply, choose OpenAPI, UI-compatible API, or automatic fallback.",
    )
    apply.add_argument("--prune", action="store_true", help="For service apply, delete live services missing from desired files.")
    apply.add_argument(
        "--production",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="For service prune, choose production or test services. Defaults to productions present in desired files.",
    )
    apply.add_argument(
        "--delete-resources",
        action="store_true",
        help="For environment and environment-service delete, also delete underlying K8s resources where Zadig supports it.",
    )
    apply.add_argument("--confirm", action="store_true", help="Apply the change. Omit for dry-run.")
    apply.add_argument("--diff", action="store_true", help="Only print diff between Zadig and the file.")
    apply.add_argument(
        "--allow-redacted",
        action="store_true",
        help="Allow applying files that contain ***redacted*** placeholders. Dangerous; off by default.",
    )
    apply.set_defaults(func=run_apply)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
