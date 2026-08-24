import argparse
import asyncio
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

from .client import ZadigAPIError, path_name, service_prefix
from .server import (
    DEFAULT_SNAPSHOT_SECTIONS,
    assert_no_redacted_placeholders,
    client,
    zadig_project_snapshot,
    zadig_project_apply_plan,
    zadig_build_apply,
    zadig_workflow_apply,
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


def load_data(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def workflow_payload_from_file(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"workflow file {path} must contain a mapping")
    detail = data.get("detail")
    if isinstance(detail, dict):
        return detail
    return data


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


def normalize_script(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_root_for(path: Path) -> Path:
    for parent in [path if path.is_dir() else path.parent, *path.parents]:
        if (parent / "projects").is_dir():
            return parent
    return Path.cwd()


def build_script_ref_path(project: str, script_name: str) -> str:
    return f"projects/{safe_name(project)}/builds/scripts/{script_name}"


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


def split_snapshot(snapshot: dict[str, Any], output_dir: Path, output_format: str) -> None:
    project = snapshot.get("metadata", {}).get("project_key") or "unknown-project"
    project_dir = output_dir / "projects" / safe_name(str(project))
    shared_template_dir = output_dir / "templates" / "build-templates"
    shared_template_reference_dir = output_dir / "references" / "build-templates"
    snapshot_dir = project_dir / "_snapshot"
    write_data(snapshot_dir / data_filename("metadata", output_format), snapshot.get("metadata", {}), output_format)
    write_data(snapshot_dir / data_filename("errors", output_format), snapshot.get("errors", []), output_format)

    if "project" in snapshot:
        write_data(project_dir / data_filename("project", output_format), snapshot["project"], output_format)

    if "iterations" in snapshot:
        write_data(project_dir / "iterations" / data_filename("index", output_format), snapshot["iterations"], output_format)

    if "workflows" in snapshot:
        write_data(project_dir / "workflows" / data_filename("index", output_format), snapshot["workflows"], output_format)

    workflow_details = snapshot.get("workflow_details", {}).get("items", {})
    for workflow_name, detail in workflow_details.items():
        write_data(
            project_dir / "workflows" / "details" / data_filename(safe_name(str(workflow_name)), output_format),
            detail,
            output_format,
        )

    webhooks = snapshot.get("webhooks", {}).get("items", {})
    if webhooks:
        write_data(project_dir / "webhooks" / data_filename("index", output_format), snapshot["webhooks"], output_format)
    for workflow_name, detail in webhooks.items():
        write_data(project_dir / "webhooks" / data_filename(safe_name(str(workflow_name)), output_format), detail, output_format)

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
        write_data(project_dir / "tests" / data_filename("index", output_format), snapshot["tests"], output_format)

    if "code_scans" in snapshot:
        write_data(project_dir / "code-scans" / data_filename("index", output_format), snapshot["code_scans"], output_format)

    build_templates = snapshot.get("build_templates", {})
    if build_templates:
        write_data(
            shared_template_dir / data_filename("index", output_format),
            {
                "count": build_templates.get("count", 0),
                "scope": build_templates.get("scope"),
                "project_key": build_templates.get("project_key"),
                "summary": build_templates.get("summary", []),
            },
            output_format,
        )
    for template_id, item in build_templates.get("items", {}).items():
        template_name = item.get("name") or template_id
        write_data(
            shared_template_dir / data_filename(f"{safe_name(str(template_name))}.{safe_name(str(template_id))}", output_format),
            item,
            output_format,
        )

    template_refs = snapshot.get("build_template_references", {})
    if template_refs:
        write_data(
            shared_template_reference_dir / data_filename("index", output_format),
            template_refs,
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
        write_data(
            project_dir / "environments" / data_filename("index", output_format),
            snapshot["environments"],
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


async def run_apply(args: argparse.Namespace) -> None:
    if args.entity == "project":
        result = await run_apply_project(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "build":
        result = await run_apply_build(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.entity == "service":
        result = await run_apply_service(args)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return

    if not args.file:
        raise ValueError("--file is required for workflow apply")
    workflow_file = Path(args.file).expanduser().resolve()
    workflow = workflow_payload_from_file(workflow_file)
    workflow_name = args.workflow or workflow.get("workflow_name") or workflow.get("workflow_key") or workflow.get("name")
    if not workflow_name:
        raise ValueError("--workflow is required when the file does not contain workflow_name/workflow_key/name")

    if args.diff:
        result = await zadig_workflow_diff(
            workflow_name=str(workflow_name),
            workflow=workflow,
            project_key=args.project,
        )
        print(result.get("diff", ""))
        return

    result = await zadig_workflow_apply(
        workflow_name=str(workflow_name),
        workflow=workflow,
        project_key=args.project,
        mode=args.mode,
        dry_run=not args.confirm,
        confirm=args.confirm,
        allow_redacted=args.allow_redacted,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


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

    apply = subparsers.add_parser("apply", help="Apply Zadig workflow/service configuration, or plan project changes.")
    apply.add_argument(
        "entity",
        nargs="?",
        choices=["workflow", "service", "project", "build"],
        default="workflow",
        help="Entity type to apply or plan.",
    )
    apply.add_argument("--project", required=True, help="Zadig project key.")
    apply.add_argument("--workflow", help="Workflow name. Defaults to workflow_name/workflow_key/name from file.")
    apply.add_argument("--service", help="Service name filter for service apply.")
    apply.add_argument("--build", help="Build name filter for build apply/delete.")
    apply.add_argument("--file", help="Workflow or service YAML/JSON file.")
    apply.add_argument("--dir", help="Directory containing service item YAML files, usually projects/<project>/services.")
    apply.add_argument("--mode", choices=["auto", "create", "update", "delete"], default="auto", help="Apply mode.")
    apply.add_argument("--prune", action="store_true", help="For service apply, delete live services missing from desired files.")
    apply.add_argument(
        "--production",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="For service prune, choose production or test services. Defaults to productions present in desired files.",
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
