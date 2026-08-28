import copy
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP

from .client import ZadigAPIError, ZadigClient, default_project, environment_prefix, path_name, service_prefix
from .service_ops import iter_services, replace_container_image, summarize_services, unified_diff, upsert_variable

mcp = FastMCP("zadig")


def client() -> ZadigClient:
    return ZadigClient()


def summarize_workflows(payload: Any, query: str = "") -> list[dict[str, Any]]:
    workflows = payload
    if isinstance(payload, dict):
        for key in ("data", "workflows", "items", "list", "pipelines"):
            value = payload.get(key)
            if isinstance(value, list):
                workflows = value
                break
            if isinstance(value, dict):
                for nested_key in ("workflows", "items", "list", "pipelines"):
                    nested_value = value.get(nested_key)
                    if isinstance(nested_value, list):
                        workflows = nested_value
                        break
                if isinstance(workflows, list):
                    break

    if not isinstance(workflows, list):
        return []

    needle = query.lower().strip()
    items = []
    for workflow in workflows:
        if not isinstance(workflow, dict):
            text = str(workflow)
            if needle and needle not in text.lower():
                continue
            items.append({"name": text})
            continue

        name = (
            workflow.get("name")
            or workflow.get("workflow_key")
            or workflow.get("workflowKey")
            or workflow.get("display_name")
            or workflow.get("workflow_name")
            or workflow.get("workflowName")
            or workflow.get("id")
        )
        workflow_key = workflow.get("workflow_key") or workflow.get("workflowKey")
        workflow_name = workflow.get("workflow_name") or workflow.get("workflowName")
        summary = {
            "name": name,
            "workflow_key": workflow_key,
            "workflow_name": workflow_name,
            "display_name": workflow.get("display_name") or workflow.get("displayName") or workflow_name,
            "workflow_type": workflow.get("workflow_type") or workflow.get("workflowType") or workflow.get("type"),
            "enabled": workflow.get("enabled"),
            "created_by": workflow.get("created_by") or workflow.get("createdBy"),
            "updated_by": workflow.get("updated_by") or workflow.get("updatedBy"),
        }
        summary = {key: value for key, value in summary.items() if value is not None}
        haystack = " ".join(str(value) for value in summary.values()).lower()
        if needle and needle not in haystack:
            continue
        items.append(summary)

    return items


SENSITIVE_FIELD_NAMES = {
    "oauth_token",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "private_key",
    "database_url",
    "database_uri",
    "mongodb_url",
    "mongodb_uri",
    "redis_url",
    "redis_uri",
    "dsn",
    "connection_string",
}


DEFAULT_SNAPSHOT_SECTIONS = [
    "project",
    "iterations",
    "workflows",
    "workflow_details",
    "webhooks",
    "builds",
    "build_templates",
    "build_template_references",
    "services",
    "environments",
    "tests",
    "code_scans",
    "releases",
]

KNOWN_SNAPSHOT_SECTIONS = set(DEFAULT_SNAPSHOT_SECTIONS)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in {"is_credential", "iscredential"}:
        return False
    return lowered in SENSITIVE_FIELD_NAMES or any(
        marker in lowered
        for marker in ("token", "secret", "password", "credential", "private", "database_url", "dsn")
    )


def redact_url_userinfo(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc or "@" not in parsed.netloc:
        return value
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, f"***redacted***@{host}", parsed.path, parsed.query, parsed.fragment))


def redact_sensitive(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        credential_marker = value.get("is_credential")
        is_credential = credential_marker is True or str(credential_marker).lower() == "true"
        value_name = first_present(value, "key", "name", "variable_name", "variableName", "env_name", "envName")
        value_is_sensitive = isinstance(value_name, str) and is_sensitive_key(value_name)
        for key, item in value.items():
            if key in {"value", "default", "choice_option", "choiceOption"} and (is_credential or value_is_sensitive):
                redacted[key] = "***redacted***"
            elif is_sensitive_key(str(key)):
                redacted[key] = "***redacted***"
            else:
                redacted[key] = redact_sensitive(item, str(key))
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item, parent_key) for item in value]
    if is_sensitive_key(parent_key) and value not in (None, ""):
        return "***redacted***"
    if isinstance(value, str):
        return redact_url_userinfo(value)
    return value


def workflow_tasks_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("workflow_list", "workflow_tasks", "tasks", "items", "list"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def task_param_value(task: dict[str, Any], *names: str) -> Any:
    wanted = set(names)
    for param in task.get("params") or []:
        if isinstance(param, dict) and param.get("name") in wanted:
            return param.get("value")
    return None


def compact(value: Any) -> Any:
    return value if value not in (None, "", [], {}) else None


def value_as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def short_commit(value: Any) -> str:
    return value_as_text(value)[:12]


def collect_repo_like_values(value: Any) -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key in ("repos", "repositories", "repo_infos", "repoInfos"):
            repo_list = value.get(key)
            if isinstance(repo_list, list):
                repos.extend(item for item in repo_list if isinstance(item, dict))

        repo_markers = {
            "repo_name",
            "repoName",
            "repository_name",
            "repositoryName",
            "branch",
            "branch_name",
            "branchName",
            "commit_id",
            "commitId",
            "revision",
        }
        if any(key in value for key in repo_markers):
            repos.append(value)

        for item in value.values():
            repos.extend(collect_repo_like_values(item))
    elif isinstance(value, list):
        for item in value:
            repos.extend(collect_repo_like_values(item))
    return repos


def dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(redact_sensitive(item), ensure_ascii=False, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def repo_summary(repo: dict[str, Any]) -> dict[str, str]:
    repo_name = (
        first_present(repo, "repo_name", "repoName", "repository_name", "repositoryName", "name")
        or deep_first_present(repo, "repo_name", "repoName", "repository_name", "repositoryName")
    )
    branch = first_present(repo, "branch", "branch_name", "branchName", "ref")
    commit = first_present(repo, "commit_id", "commitId", "revision", "commit")
    return {
        "repo": value_as_text(repo_name),
        "branch": value_as_text(branch),
        "commit": short_commit(commit),
    }


def job_has_deployment_signal(job: dict[str, Any], spec: dict[str, Any], job_info: dict[str, Any]) -> bool:
    job_type = value_as_text(first_present(job, "type", "job_type", "jobType"))
    job_name = value_as_text(first_present(job, "name", "display_name", "displayName"))
    haystack = f"{job_type} {job_name}".lower()
    if any(marker in haystack for marker in ("deploy", "build", "zadig-build", "zadig-deploy", "部署", "构建")):
        return True

    return any(
        compact(deep_first_present(source, *keys))
        for source in (spec, job_info)
        for keys in (
            ("service_name", "serviceName", "service_module", "serviceModule"),
            ("image", "image_name", "imageName"),
            ("repo_name", "repoName", "branch", "commit_id", "commitId"),
        )
    )


def summarize_workflow_task_deployments(task: dict[str, Any]) -> list[dict[str, Any]]:
    deployments: list[dict[str, Any]] = []
    for stage in task.get("stages") or []:
        if not isinstance(stage, dict):
            continue
        stage_name = stage.get("name") or ""
        for job in stage.get("jobs") or []:
            if not isinstance(job, dict):
                continue
            spec = job.get("spec") if isinstance(job.get("spec"), dict) else {}
            job_info = job.get("job_info") if isinstance(job.get("job_info"), dict) else {}
            if not job_has_deployment_signal(job, spec, job_info):
                continue

            service_name = (
                deep_first_present(spec, "service_name", "serviceName")
                or deep_first_present(job_info, "service_name", "serviceName")
            )
            service_module = (
                deep_first_present(spec, "service_module", "serviceModule")
                or deep_first_present(job_info, "service_module", "serviceModule")
            )
            image = (
                deep_first_present(spec, "image")
                or deep_first_present(job_info, "image")
                or deep_first_present(spec, "image_name", "imageName")
                or deep_first_present(job_info, "image_name", "imageName")
            )
            job_name = first_present(job, "display_name", "displayName", "name")
            job_type = first_present(job, "type", "job_type", "jobType")
            repos = dedupe_dicts(collect_repo_like_values(spec) + collect_repo_like_values(job_info))
            if not repos:
                deployments.append(
                    {
                        "stage": stage_name,
                        "job": job_name,
                        "job_type": job_type,
                        "status": job.get("status"),
                        "service_name": service_name or service_module,
                        "service_module": service_module,
                        "repo": "",
                        "branch": "",
                        "commit": "",
                        "image": value_as_text(image),
                    }
                )
                continue

            for repo in repos:
                if not isinstance(repo, dict):
                    continue
                repo_fields = repo_summary(repo)
                deployments.append(
                    {
                        "stage": stage_name,
                        "job": job_name,
                        "job_type": job_type,
                        "status": job.get("status"),
                        "service_name": service_name or service_module or repo_fields["repo"],
                        "service_module": service_module,
                        "repo": repo_fields["repo"],
                        "branch": repo_fields["branch"],
                        "commit": repo_fields["commit"],
                        "image": value_as_text(image),
                    }
                )
    return dedupe_dicts(deployments)


def summarize_workflow_task(task: dict[str, Any], include_deployments: bool = True) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "task_id": task.get("task_id"),
        "workflow_name": task.get("workflow_name") or task.get("workflow_key"),
        "status": task.get("status"),
        "creator": task.get("task_creator"),
        "create_time": task.get("create_time"),
        "start_time": task.get("start_time"),
        "end_time": task.get("end_time"),
        "env": task_param_value(task, "cluster", "env", "ENV_NAME", "ENV"),
    }
    if include_deployments:
        summary["deployments"] = summarize_workflow_task_deployments(task)
    return {key: value for key, value in summary.items() if value is not None}


def text_from_log_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list):
        return "\n".join(text_from_log_payload(item) for item in payload)
    if isinstance(payload, dict):
        for key in ("log", "logs", "content", "data", "message"):
            value = payload.get(key)
            if value is not None:
                return text_from_log_payload(value)
        return json.dumps(redact_sensitive(payload), ensure_ascii=False, indent=2)
    if payload is None:
        return ""
    return str(payload)


def filter_log_text(log_text: str, keyword: str = "", tail_lines: int = 300) -> tuple[str, int, int]:
    lines = log_text.splitlines()
    total_lines = len(lines)
    if keyword:
        needle = keyword.lower()
        lines = [line for line in lines if needle in line.lower()]
    if tail_lines > 0:
        lines = lines[-tail_lines:]
    return "\n".join(lines), total_lines, len(lines)


def json_for_diff(value: Any) -> str:
    return json.dumps(redact_sensitive(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def webhook_items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    for key in ("webhooks", "hooks", "triggers", "items", "list"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        nested = webhook_items_from_payload(data)
        if nested:
            return nested

    return [payload]


def first_present(source: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source and source.get(key) is not None:
            return source.get(key)
    return None


def deep_first_present(value: Any, *keys: str) -> Any:
    if isinstance(value, dict):
        found = first_present(value, *keys)
        if found is not None:
            return found
        for item in value.values():
            found = deep_first_present(item, *keys)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = deep_first_present(item, *keys)
            if found is not None:
                return found
    return None


def summarize_workflow_args(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"type": type(value).__name__} if value is not None else {}

    params = value.get("params") if isinstance(value.get("params"), list) else []
    services = value.get("services") if isinstance(value.get("services"), list) else []
    repos = value.get("repos") if isinstance(value.get("repos"), list) else []
    return {
        "env": first_present(value, "env", "env_name", "environment", "ENV_NAME"),
        "param_count": len(params),
        "service_count": len(services),
        "repo_count": len(repos),
        "keys": sorted(value.keys()),
    }


def summarize_webhook(item: dict[str, Any]) -> dict[str, Any]:
    repo = deep_first_present(item, "repo", "repository")
    repo_name = repo.get("repo_name") or repo.get("name") if isinstance(repo, dict) else repo
    workflow_args = deep_first_present(item, "workflow_args", "workflowArgs", "workflow_arg", "workflowArg")
    summary = {
        "name": deep_first_present(item, "name", "hook_name", "webhook_name"),
        "enabled": deep_first_present(item, "enabled", "enable", "is_enabled", "isEnabled"),
        "repo": deep_first_present(item, "repo_name", "repoName", "repository_name") or repo_name,
        "branch": deep_first_present(item, "branch", "branch_name", "branchName"),
        "events": deep_first_present(item, "events", "event", "hook_events", "hookEvents"),
        "match_folders": deep_first_present(item, "match_folders", "matchFolders", "paths"),
        "workflow_args": summarize_workflow_args(workflow_args),
        "top_level_keys": sorted(item.keys()),
    }
    return {key: value for key, value in summary.items() if value not in (None, {}, [])}


def normalize_snapshot_sections(sections: list[str] | None) -> list[str]:
    if not sections:
        return list(DEFAULT_SNAPSHOT_SECTIONS)
    normalized = []
    for section in sections:
        value = str(section).strip()
        if not value:
            continue
        if value == "all":
            return list(DEFAULT_SNAPSHOT_SECTIONS)
        if value not in KNOWN_SNAPSHOT_SECTIONS:
            raise ValueError(f"unknown snapshot section {value!r}; known sections: {sorted(KNOWN_SNAPSHOT_SECTIONS)}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def error_summary(exc: Exception) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def payload_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "list", "data", "tests", "scans", "codescans", "releases"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = payload_items(value)
                if nested:
                    return nested
    return []


def project_items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("projects", "items", "list", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = project_items_from_payload(value)
                if nested:
                    return nested
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def project_key_from_item(item: dict[str, Any]) -> str:
    return str(
        first_present(
            item,
            "project_key",
            "projectKey",
            "name",
            "project_name",
            "projectName",
            "key",
        )
        or ""
    )


def summarize_project(item: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "project_key": project_key_from_item(item),
        "name": first_present(item, "name", "project_name", "projectName"),
        "display_name": first_present(item, "display_name", "displayName"),
        "type": first_present(item, "type", "project_type", "projectType"),
        "desc": first_present(item, "desc", "description"),
        "is_public": first_present(item, "is_public", "isPublic", "public"),
        "create_time": first_present(item, "create_time", "createTime", "created_at", "createdAt"),
        "update_time": first_present(item, "update_time", "updateTime", "updated_at", "updatedAt"),
        "created_by": first_present(item, "created_by", "createdBy", "creator"),
        "updated_by": first_present(item, "updated_by", "updatedBy", "update_by", "updateBy"),
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def project_gitops_document(project: str, live_item: dict[str, Any] | None = None) -> dict[str, Any]:
    live_item = live_item or {}
    summary = summarize_project(live_item) if live_item else {"project_key": project}
    name = summary.get("project_key") or project
    spec = {
        "name": summary.get("name") or name,
        "displayName": summary.get("display_name"),
        "type": summary.get("type"),
        "description": summary.get("desc"),
        "isPublic": summary.get("is_public"),
    }
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "Project",
        "metadata": {
            "name": name,
            "projectKey": project,
        },
        "spec": {key: value for key, value in spec.items() if value not in (None, "", [], {})},
        "live": {
            "summary": summary,
            "raw": redact_sensitive(live_item),
        },
    }


async def fetch_project_item(project: str) -> dict[str, Any] | None:
    payload = await client().request("GET", "/openapi/projects/project")
    for item in project_items_from_payload(payload):
        if project_key_from_item(item) == project:
            return item
    return None


async def fetch_project_document(project: str) -> dict[str, Any] | None:
    item = await fetch_project_item(project)
    if item is None:
        return None
    return project_gitops_document(project, item)


def project_name_from_document(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    name = metadata.get("projectKey") or metadata.get("name") or spec.get("name")
    if not name:
        raise ValueError("project document must contain metadata.projectKey or metadata.name")
    return str(name)


async def zadig_project_apply_plan(
    project_document: dict[str, Any] | None = None,
    project_key: str | None = None,
    mode: str = "auto",
) -> dict[str, Any]:
    """Plan project create/update/delete only. This function never mutates Zadig."""
    if mode not in {"auto", "create", "update", "delete"}:
        raise ValueError("mode must be one of: auto, create, update, delete")

    desired_project = project_key or ""
    if project_document:
        desired_project = project_name_from_document(project_document)
        if project_key and desired_project != project_key:
            raise ValueError(
                f"project document targets {desired_project!r}, but --project/project_key is {project_key!r}"
            )
    else:
        desired_project = default_project(project_key)

    live_document = await fetch_project_document(desired_project)
    exists = live_document is not None
    desired = {} if mode == "delete" else project_document or project_gitops_document(desired_project)

    if mode == "delete":
        action = "delete" if exists else "none"
        reason = "project exists and would be deleted" if exists else "project does not exist"
    elif not exists:
        action = "create" if mode in {"auto", "create"} else "blocked"
        reason = "project does not exist" if action == "create" else "project does not exist; update is not possible"
    elif mode == "create":
        action = "blocked"
        reason = "project already exists; create is not possible"
    else:
        current_spec = live_document.get("spec", {}) if isinstance(live_document, dict) else {}
        desired_spec = desired.get("spec", {}) if isinstance(desired.get("spec"), dict) else {}
        action = "update" if current_spec != desired_spec else "none"
        reason = "project spec differs" if action == "update" else "project exists and spec matches"

    return {
        "applied": False,
        "dry_run": True,
        "mutation_supported": False,
        "reason": "project apply is plan-only; create/update/delete API calls are intentionally not implemented yet",
        "project_key": desired_project,
        "entity": "project",
        "exists": exists,
        "mode": mode,
        "action": action,
        "action_reason": reason,
        "diff": unified_diff(
            json_for_diff(live_document or {}),
            json_for_diff(desired),
            f"{desired_project}:current",
            f"{desired_project}:desired",
        ),
        "desired": redact_sensitive(desired),
        "live": redact_sensitive(live_document),
    }


def unsupported_project_section(name: str, reason: str) -> dict[str, Any]:
    return {
        "count": 0,
        "items": [],
        "snapshot_status": "unsupported",
        "section": name,
        "reason": reason,
    }


def service_index_item(service: dict[str, Any], project: str) -> dict[str, Any]:
    service_name = service.get("service_name") or service.get("name") or ""
    containers = service.get("containers") if isinstance(service.get("containers"), list) else []
    return {
        "name": service_name,
        "project_key": project,
        "type": service.get("type"),
        "source": service.get("source"),
        "production": False,
        "file": f"items/{safe_file_name(str(service_name))}.yaml",
        "container_count": len(containers),
        "containers": [
            {
                "name": container.get("name", ""),
                "image_name": container.get("image_name", ""),
                "image": container.get("image", ""),
            }
            for container in containers
            if isinstance(container, dict)
        ],
    }


def safe_file_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in "._-" else "-" for char in value.strip())
    return safe.strip("-") or "unnamed"


def service_gitops_document(
    project: str,
    service_name: str,
    list_item: dict[str, Any],
    detail: dict[str, Any] | None,
    template_name: str = "",
) -> dict[str, Any]:
    detail = detail or {}
    containers = detail.get("containers") if isinstance(detail.get("containers"), list) else list_item.get("containers") or []
    variables = detail.get("service_variable_kvs") if isinstance(detail.get("service_variable_kvs"), list) else []
    resolved_template_name = detail.get("template_name") or template_name
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "Service",
        "metadata": {
            "project": project,
            "name": service_name,
            "production": False,
        },
        "spec": {
            "type": detail.get("type") or list_item.get("type"),
            "source": detail.get("source") or list_item.get("source"),
            "template": {
                "name": resolved_template_name,
                "autoSync": False,
                "valuesYaml": detail.get("values_yaml") or "",
                "variables": variables,
            },
            "containers": containers,
            "yaml": detail.get("yaml") or "",
        },
        "live": {
            "list": list_item,
            "detail": detail,
        },
    }


def environment_name(value: dict[str, Any]) -> str:
    return str(first_present(value, "env_key", "env_name", "name", "environment") or "")


def environment_index_item(env: dict[str, Any], project: str, production: bool = False) -> dict[str, Any]:
    name = environment_name(env)
    services = env.get("services") if isinstance(env.get("services"), list) else []
    variables = env.get("global_variables") if isinstance(env.get("global_variables"), list) else []
    return {
        "name": name,
        "project_key": project,
        "production": bool(first_present(env, "production") if first_present(env, "production") is not None else production),
        "cluster_id": env.get("cluster_id"),
        "namespace": env.get("namespace"),
        "registry_id": env.get("registry_id"),
        "status": env.get("status"),
        "update_by": env.get("update_by"),
        "update_time": env.get("update_time"),
        "service_count": len(services),
        "global_variable_count": len(variables),
        "file": f"items/{safe_file_name(name)}.yaml",
        "services_file": f"services/{safe_file_name(name)}/index.yaml",
    }


def environment_service_index_item(env_name: str, service: dict[str, Any]) -> dict[str, Any]:
    service_name = str(first_present(service, "service_name", "name") or "")
    containers = service.get("containers") if isinstance(service.get("containers"), list) else []
    variables = service.get("variable_kvs") if isinstance(service.get("variable_kvs"), list) else []
    return {
        "name": service_name,
        "env": env_name,
        "type": service.get("type"),
        "status": service.get("status"),
        "container_count": len(containers),
        "variable_count": len(variables),
        "file": f"{safe_file_name(service_name)}.yaml",
        "containers": [
            {
                "name": container.get("name", ""),
                "image_name": container.get("image_name", ""),
                "image": container.get("image", ""),
            }
            for container in containers
            if isinstance(container, dict)
        ],
    }


def environment_service_gitops_document(
    project: str,
    env_name: str,
    service: dict[str, Any],
    production: bool = False,
) -> dict[str, Any]:
    service_name = str(first_present(service, "service_name", "name") or "")
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "EnvironmentService",
        "metadata": {
            "project": project,
            "env": env_name,
            "service": service_name,
            "production": production,
        },
        "spec": {
            "service_name": service_name,
            "type": service.get("type"),
            "containers": service.get("containers") if isinstance(service.get("containers"), list) else [],
            "variable_kvs": service.get("variable_kvs") if isinstance(service.get("variable_kvs"), list) else [],
        },
        "live": {
            "summary": environment_service_index_item(env_name, service),
        },
    }


def environment_gitops_document(
    project: str,
    env: dict[str, Any],
    production: bool = False,
) -> dict[str, Any]:
    name = environment_name(env)
    global_variables = env.get("global_variables") if isinstance(env.get("global_variables"), list) else []
    spec = {
        "env_key": env.get("env_key") or name,
        "env_name": env.get("env_name") or name,
        "cluster_id": env.get("cluster_id"),
        "namespace": env.get("namespace"),
        "registry_id": env.get("registry_id"),
        "global_variables": global_variables,
        "sub_env": env.get("sub_env") or env.get("subEnv") or [],
        "services_ref": {
            "path": f"projects/{safe_file_name(project)}/environments/services/{safe_file_name(name)}/index.yaml",
        },
    }
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "Environment",
        "metadata": {
            "project": project,
            "name": name,
            "production": bool(first_present(env, "production") if first_present(env, "production") is not None else production),
        },
        "spec": spec,
        "live": {
            "summary": environment_index_item(env, project, production),
            "detail": env,
        },
    }


def environment_desired_payload(env_name: str, environment: dict[str, Any], production: bool = False) -> dict[str, Any]:
    payload = {
        "env_key": environment.get("env_key") or environment.get("env_name") or env_name,
        "env_name": environment.get("env_name") or environment.get("env_key") or env_name,
        "cluster_id": environment.get("cluster_id"),
        "namespace": environment.get("namespace"),
        "registry_id": environment.get("registry_id"),
        "global_variables": environment.get("global_variables") or [],
        "sub_env": environment.get("sub_env") or environment.get("subEnv") or [],
    }
    if not production:
        payload["env_configs"] = environment.get("env_configs") or environment.get("envConfigs") or []
    return {key: value for key, value in payload.items() if value is not None}


def environment_update_payload(environment: dict[str, Any], production: bool = False) -> dict[str, Any]:
    allowed = ["registry_id", "env_name"] if production else ["registry_id"]
    return {
        key: copy.deepcopy(environment[key])
        for key in allowed
        if key in environment and environment[key] is not None
    }


def environment_service_desired_payload(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": first_present(service, "service_name", "name") or "",
        "type": service.get("type"),
        "containers": service.get("containers") if isinstance(service.get("containers"), list) else [],
        "variable_kvs": service.get("variable_kvs") if isinstance(service.get("variable_kvs"), list) else [],
    }


async def environment_detail_or_none(project: str, env_name: str, production: bool = False) -> dict[str, Any] | None:
    try:
        payload = await client().request(
            "GET",
            f"{environment_prefix(production)}/{path_name(env_name)}",
            project_key=project,
        )
        return payload if isinstance(payload, dict) else {}
    except ZadigAPIError as exc:
        if "HTTP 404" in str(exc) or "no documents in result" in str(exc):
            return None
        raise


def environment_service_from_detail(detail: dict[str, Any], service_name: str) -> dict[str, Any] | None:
    for service in detail.get("services") or []:
        if not isinstance(service, dict):
            continue
        if first_present(service, "service_name", "name") == service_name:
            return service
    return None


def chart_template_items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        value = payload.get("chartTemplates") or payload.get("chart_templates") or payload.get("items") or payload.get("data")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def prepare_workflow_payload(
    workflow_name: str,
    project: str,
    workflow: dict[str, Any],
) -> dict[str, Any]:
    payload = dict(workflow)
    payload.setdefault("name", workflow_name)
    payload.setdefault("workflow_name", workflow_name)
    payload.setdefault("workflow_key", workflow_name)
    payload.setdefault("display_name", workflow_name)
    payload.setdefault("project", project)
    payload.setdefault("project_key", project)
    return payload


def comparable_workflow_payload(workflow_name: str, project: str, workflow: dict[str, Any]) -> dict[str, Any]:
    payload = prepare_workflow_payload(workflow_name, project, workflow)
    for key in ("create_time", "update_time", "created_by", "updated_by", "hash", "id"):
        payload.pop(key, None)
    return payload


def redacted_placeholder_paths(value: Any, path: str = "$") -> list[str]:
    if value == "***redacted***":
        return [path]
    if isinstance(value, dict):
        paths: list[str] = []
        for key, item in value.items():
            paths.extend(redacted_placeholder_paths(item, f"{path}.{key}"))
        return paths
    if isinstance(value, list):
        paths = []
        for index, item in enumerate(value):
            paths.extend(redacted_placeholder_paths(item, f"{path}[{index}]"))
        return paths
    return []


def assert_no_redacted_placeholders(value: Any, allow_redacted: bool = False) -> None:
    if allow_redacted:
        return
    paths = redacted_placeholder_paths(value)
    if paths:
        preview = ", ".join(paths[:10])
        suffix = "" if len(paths) <= 10 else f", ... ({len(paths)} total)"
        raise ValueError(
            "payload contains redacted placeholders and cannot be applied safely; "
            f"replace/remove them or set allow_redacted=true. paths: {preview}{suffix}"
        )


async def workflow_exists(project: str, workflow_name: str) -> bool:
    try:
        await client().request(
            "GET",
            f"/openapi/workflows/custom/{path_name(workflow_name)}/detail",
            project_key=project,
        )
        return True
    except ZadigAPIError as exc:
        if "HTTP 404" in str(exc):
            return False
        raise
        return False


@mcp.tool()
async def zadig_project_get(project_key: str | None = None) -> dict[str, Any]:
    """Get one Zadig project as a redacted GitOps Project document."""
    project = default_project(project_key)
    document = await fetch_project_document(project)
    if document is None:
        return {
            "project_key": project,
            "exists": False,
            "document": project_gitops_document(project),
        }
    return {
        "project_key": project,
        "exists": True,
        "document": document,
    }


@mcp.tool()
async def zadig_project_plan(
    project: dict[str, Any] | None = None,
    project_key: str | None = None,
    mode: str = "auto",
) -> dict[str, Any]:
    """Plan Zadig project create/update/delete. This is always dry-run and never mutates."""
    return await zadig_project_apply_plan(project_document=project, project_key=project_key, mode=mode)


@mcp.tool()
async def zadig_workflow_list(
    query: str = "",
    project_key: str | None = None,
) -> dict[str, Any]:
    """List Zadig workflows in a project."""
    project = default_project(project_key)
    payload = await client().request("GET", "/openapi/workflows", project_key=project)
    items = summarize_workflows(payload, query)
    return {
        "project_key": project,
        "count": len(items),
        "items": items,
        "raw": payload,
    }


@mcp.tool()
async def zadig_workflow_get(
    workflow_name: str,
    project_key: str | None = None,
    include_raw: bool = True,
) -> dict[str, Any]:
    """Get one custom workflow detail."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        f"/openapi/workflows/custom/{path_name(workflow_name)}/detail",
        project_key=project,
    )
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "detail": redact_sensitive(payload),
    }
    if not include_raw:
        result.pop("detail", None)
        result["summary"] = summarize_workflows([payload])[0] if isinstance(payload, dict) else {}
    return result


@mcp.tool()
async def zadig_workflow_update(
    workflow_name: str,
    workflow: dict[str, Any],
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Update a custom workflow. Defaults to dry_run=true and requires confirm=true to mutate."""
    project = default_project(project_key)
    payload = prepare_workflow_payload(workflow_name, project, workflow)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig workflow",
            "project_key": project,
            "workflow_name": workflow_name,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    result = await client().request(
        "PUT",
        f"/api/aslan/workflow/v4/{path_name(workflow_name)}",
        params={"projectName": project},
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "workflow_name": workflow_name, "result": result}


@mcp.tool()
async def zadig_workflow_create(
    workflow_name: str,
    workflow: dict[str, Any],
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create a custom workflow. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = prepare_workflow_payload(workflow_name, project, workflow)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to create Zadig workflow",
            "project_key": project,
            "workflow_name": workflow_name,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    result = await client().request(
        "POST",
        "/api/aslan/workflow/v4",
        params={"projectName": project},
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "workflow_name": workflow_name, "result": result}


@mcp.tool()
async def zadig_workflow_delete(
    workflow_name: str,
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete a custom workflow. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = {"workflowKey": workflow_name, "projectKey": project}

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to delete Zadig workflow",
            "project_key": project,
            "workflow_name": workflow_name,
            "payload": payload,
        }

    result = await client().request(
        "DELETE",
        "/openapi/workflows/custom",
        params={"workflowKey": workflow_name},
        project_key=project,
    )
    return {"applied": True, "project_key": project, "workflow_name": workflow_name, "result": result}


@mcp.tool()
async def zadig_workflow_diff(
    workflow_name: str,
    workflow: dict[str, Any],
    project_key: str | None = None,
) -> dict[str, Any]:
    """Diff current Zadig workflow detail against a desired workflow payload."""
    project = default_project(project_key)
    desired = comparable_workflow_payload(workflow_name, project, workflow)
    exists = await workflow_exists(project, workflow_name)
    if not exists:
        return {
            "project_key": project,
            "workflow_name": workflow_name,
            "exists": False,
            "diff": unified_diff("", json_for_diff(desired), f"{workflow_name}:current", f"{workflow_name}:desired"),
            "desired": redact_sensitive(desired),
        }

    current = await client().request(
        "GET",
        f"/openapi/workflows/custom/{path_name(workflow_name)}/detail",
        project_key=project,
    )
    current_comparable = comparable_workflow_payload(workflow_name, project, current if isinstance(current, dict) else {})
    diff = unified_diff(
        json_for_diff(current_comparable),
        json_for_diff(desired),
        f"{workflow_name}:current",
        f"{workflow_name}:desired",
    )
    return {
        "project_key": project,
        "workflow_name": workflow_name,
        "exists": True,
        "changed": bool(diff.strip()),
        "diff": diff,
    }


@mcp.tool()
async def zadig_workflow_apply(
    workflow_name: str,
    workflow: dict[str, Any],
    project_key: str | None = None,
    mode: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create or update a custom workflow. mode can be auto, create, or update. Defaults to dry_run=true."""
    project = default_project(project_key)
    if mode not in {"auto", "create", "update"}:
        raise ValueError("mode must be one of: auto, create, update")

    exists = await workflow_exists(project, workflow_name)
    action = mode
    if action == "auto":
        action = "update" if exists else "create"
    if action == "create" and exists:
        raise ValueError(f"workflow {workflow_name!r} already exists; use mode='update' or mode='auto'")
    if action == "update" and not exists:
        raise ValueError(f"workflow {workflow_name!r} does not exist; use mode='create' or mode='auto'")

    diff_result = await zadig_workflow_diff(workflow_name, workflow, project)
    payload = prepare_workflow_payload(workflow_name, project, workflow)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to apply Zadig workflow",
            "project_key": project,
            "workflow_name": workflow_name,
            "exists": exists,
            "action": action,
            "diff": diff_result.get("diff", ""),
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    if action == "create":
        result = await client().request(
            "POST",
            "/api/aslan/workflow/v4",
            params={"projectName": project},
            json_body=payload,
        )
    else:
        result = await client().request(
            "PUT",
            f"/api/aslan/workflow/v4/{path_name(workflow_name)}",
            params={"projectName": project},
            json_body=payload,
        )
    return {
        "applied": True,
        "project_key": project,
        "workflow_name": workflow_name,
        "exists_before_apply": exists,
        "action": action,
        "diff": diff_result.get("diff", ""),
        "result": result,
    }


@mcp.tool()
async def zadig_project_snapshot(
    project_key: str | None = None,
    sections: list[str] | None = None,
    workflow_names: list[str] | None = None,
    max_workflows: int = 0,
    include_workflow_raw_list: bool = False,
) -> dict[str, Any]:
    """Create a redacted project snapshot for audit/GitOps preparation."""
    project = default_project(project_key)
    selected_sections = normalize_snapshot_sections(sections)
    snapshot: dict[str, Any] = {
        "metadata": {
            "project_key": project,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": selected_sections,
            "redacted": True,
        },
        "errors": [],
    }

    workflow_items: list[dict[str, Any]] = []
    workflow_names_to_fetch: list[str] = []

    if "project" in selected_sections:
        try:
            project_item = await fetch_project_item(project)
            snapshot["project"] = project_gitops_document(project, project_item)
            if project_item is None:
                snapshot["errors"].append(
                    {
                        "section": "project",
                        "type": "NotFound",
                        "message": f"project {project!r} was not found in /openapi/projects/project",
                    }
                )
        except Exception as exc:
            snapshot["project"] = project_gitops_document(project)
            snapshot["errors"].append({"section": "project", **error_summary(exc)})

    if any(section in selected_sections for section in ("workflows", "workflow_details", "webhooks")):
        try:
            workflow_payload = await client().request("GET", "/openapi/workflows", project_key=project)
            workflow_items = summarize_workflows(workflow_payload)
            snapshot["workflows"] = {
                "count": len(workflow_items),
                "items": workflow_items,
            }
            if include_workflow_raw_list:
                snapshot["workflows"]["raw"] = redact_sensitive(workflow_payload)
        except Exception as exc:
            snapshot["errors"].append({"section": "workflows", **error_summary(exc)})

    if workflow_names:
        workflow_names_to_fetch = [name for name in workflow_names if name]
    else:
        workflow_names_to_fetch = [str(item["name"]) for item in workflow_items if item.get("name")]

    if max_workflows > 0:
        workflow_names_to_fetch = workflow_names_to_fetch[:max_workflows]

    if "workflow_details" in selected_sections:
        details: dict[str, Any] = {}
        for workflow_name in workflow_names_to_fetch:
            try:
                payload = await client().request(
                    "GET",
                    f"/openapi/workflows/custom/{path_name(workflow_name)}/detail",
                    project_key=project,
                )
                details[workflow_name] = redact_sensitive(payload)
            except Exception as exc:
                snapshot["errors"].append(
                    {"section": "workflow_details", "workflow_name": workflow_name, **error_summary(exc)}
                )
        snapshot["workflow_details"] = {
            "count": len(details),
            "items": details,
        }

    if "webhooks" in selected_sections:
        webhooks: dict[str, Any] = {}
        for workflow_name in workflow_names_to_fetch:
            try:
                webhook_payload = await client().request(
                    "GET",
                    "/api/aslan/workflow/v4/webhook",
                    params={"projectName": project, "workflowName": workflow_name},
                )
                preset_payload = await client().request(
                    "GET",
                    "/api/aslan/workflow/v4/webhook/preset",
                    params={"projectName": project, "workflowName": workflow_name},
                )
                webhook_items = webhook_items_from_payload(webhook_payload)
                preset_items = webhook_items_from_payload(preset_payload)
                webhooks[workflow_name] = {
                    "webhook_count": len(webhook_items),
                    "preset_count": len(preset_items),
                    "webhook_items": [summarize_webhook(item) for item in webhook_items],
                    "preset_items": [summarize_webhook(item) for item in preset_items],
                    "raw": {
                        "webhooks": redact_sensitive(webhook_payload),
                        "preset": redact_sensitive(preset_payload),
                    },
                }
            except Exception as exc:
                snapshot["errors"].append({"section": "webhooks", "workflow_name": workflow_name, **error_summary(exc)})
        snapshot["webhooks"] = {
            "count": len(webhooks),
            "items": webhooks,
        }

    if "builds" in selected_sections:
        try:
            build_payload = await client().request(
                "GET",
                "/openapi/build",
                project_key=project,
                params={"pageNum": 1, "pageSize": 200},
            )
            build_items = build_items_from_payload(build_payload)
            build_summaries = [summarize_build(item) for item in build_items]
            build_details: dict[str, Any] = {}
            build_items_by_name = {
                str(item["name"]): item for item in build_summaries if item.get("name")
            }
            for build_name, index_item in build_items_by_name.items():
                try:
                    detail_payload = await client().request(
                        "GET",
                        f"/openapi/build/{path_name(build_name)}/detail",
                        project_key=project,
                    )
                    detail = redact_sensitive(detail_payload)
                    build_details[build_name] = build_gitops_document(project, build_name, index_item, detail)
                except Exception as exc:
                    snapshot["errors"].append({"section": "build_details", "build_name": build_name, **error_summary(exc)})
                    build_details[build_name] = build_gitops_document(project, build_name, index_item, None)
            snapshot["builds"] = {
                "count": len(build_items),
                "items": build_summaries,
                "details": build_details,
                "raw": redact_sensitive(build_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "builds", **error_summary(exc)})

    if "tests" in selected_sections:
        try:
            test_payload = await client().request(
                "GET",
                "/api/aslan/testing/testdetail",
                params={"projectName": project},
            )
            test_items = payload_items(test_payload)
            snapshot["tests"] = {
                "count": len(test_items),
                "items": redact_sensitive(test_items),
                "raw": redact_sensitive(test_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "tests", **error_summary(exc)})

    if "code_scans" in selected_sections:
        try:
            scan_payload = await client().request(
                "GET",
                "/api/aslan/testing/scanning",
                params={"projectName": project},
            )
            scan_items = payload_items(scan_payload)
            snapshot["code_scans"] = {
                "count": len(scan_items),
                "items": redact_sensitive(scan_items),
                "raw": redact_sensitive(scan_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "code_scans", **error_summary(exc)})

    template_items: list[dict[str, Any]] = []
    if any(section in selected_sections for section in ("build_templates", "build_template_references")):
        try:
            template_payload = await client().request("GET", "/api/aslan/template/build")
            template_items = build_template_items_from_payload(template_payload)
        except Exception as exc:
            snapshot["errors"].append({"section": "build_templates", **error_summary(exc)})

    project_template_refs: dict[str, Any] = {}
    if any(section in selected_sections for section in ("build_templates", "build_template_references")) and template_items:
        for item in template_items:
            template_id = first_present(item, "id", "_id")
            template_name = first_present(item, "name", "template_name", "templateName")
            if not template_id:
                continue
            try:
                reference_payload = await client().request(
                    "GET",
                    f"/api/aslan/template/build/{path_name(str(template_id))}/reference",
                )
                project_references = filter_references_for_project(reference_payload, project)
                if not project_references:
                    continue
                project_template_refs[str(template_id)] = {
                    "name": template_name,
                    "references": redact_sensitive(project_references),
                }
            except Exception as exc:
                snapshot["errors"].append(
                    {
                        "section": "build_template_references",
                        "template_id": str(template_id),
                        "template_name": str(template_name or ""),
                        **error_summary(exc),
                    }
                )

    if "build_templates" in selected_sections and template_items:
        template_details: dict[str, Any] = {}
        template_items_by_id = {
            str(first_present(item, "id", "_id")): item for item in template_items if first_present(item, "id", "_id")
        }
        for template_id in project_template_refs:
            item = template_items_by_id.get(template_id, {})
            template_name = first_present(item, "name", "template_name", "templateName") or project_template_refs[
                template_id
            ].get("name")
            try:
                detail_payload = await client().request(
                    "GET",
                    f"/api/aslan/template/build/{path_name(str(template_id))}",
                )
                template_details[template_id] = {
                    "name": template_name,
                    "detail": redact_sensitive(detail_payload),
                }
            except Exception as exc:
                snapshot["errors"].append(
                    {
                        "section": "build_templates",
                        "template_id": str(template_id),
                        "template_name": str(template_name or ""),
                        **error_summary(exc),
                    }
                )
        snapshot["build_templates"] = {
            "count": len(template_details),
            "scope": "project_referenced",
            "project_key": project,
            "summary": [
                summarize_build_template(template_items_by_id[template_id])
                for template_id in project_template_refs
                if template_id in template_items_by_id
            ],
            "items": template_details,
        }

    if "build_template_references" in selected_sections and template_items:
        snapshot["build_template_references"] = {
            "count": len(project_template_refs),
            "scope": "project_referenced",
            "project_key": project,
            "items": project_template_refs,
        }

    if "services" in selected_sections:
        try:
            service_payload = await client().request("GET", f"{service_prefix(False)}/services", project_key=project)
            service_items = iter_services(service_payload)
            index_items = [service_index_item(item, project) for item in service_items]
            service_details: dict[str, Any] = {}
            service_items_by_name = {
                str(item["name"]): item for item in index_items if item.get("name")
            }
            service_chart_templates: dict[str, str] = {}
            try:
                chart_payload = await client().request("GET", "/api/aslan/template/charts")
                for chart_item in chart_template_items_from_payload(chart_payload):
                    chart_name = first_present(chart_item, "name")
                    if not chart_name:
                        continue
                    try:
                        reference_payload = await client().request(
                            "GET",
                            f"/api/aslan/template/charts/{path_name(str(chart_name))}/reference",
                        )
                        for reference in payload_items(reference_payload):
                            if not isinstance(reference, dict):
                                continue
                            if reference.get("project_name") != project:
                                continue
                            service_name = reference.get("service_name")
                            if service_name:
                                service_chart_templates[str(service_name)] = str(chart_name)
                    except Exception as exc:
                        snapshot["errors"].append(
                            {
                                "section": "service_chart_template_references",
                                "template_name": str(chart_name),
                                **error_summary(exc),
                            }
                        )
            except Exception as exc:
                snapshot["errors"].append({"section": "service_chart_templates", **error_summary(exc)})
            for service_name, index_item in service_items_by_name.items():
                try:
                    detail_payload = await client().request(
                        "GET",
                        f"{service_prefix(False)}/{path_name(service_name)}",
                        project_key=project,
                    )
                    detail = redact_sensitive(detail_payload)
                    service_details[service_name] = service_gitops_document(
                        project,
                        service_name,
                        index_item,
                        detail,
                        service_chart_templates.get(service_name, ""),
                    )
                except Exception as exc:
                    snapshot["errors"].append(
                        {"section": "service_details", "service_name": service_name, **error_summary(exc)}
                    )
                    service_details[service_name] = service_gitops_document(
                        project,
                        service_name,
                        index_item,
                        None,
                        service_chart_templates.get(service_name, ""),
                    )
            snapshot["services"] = {
                "count": len(index_items),
                "items": index_items,
                "details": service_details,
                "summary": summarize_services(service_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "services", **error_summary(exc)})

    if "environments" in selected_sections:
        try:
            env_payload = await client().request("GET", environment_prefix(False), project_key=project)
            env_details: dict[str, Any] = {}
            env_items = [item for item in payload_items(env_payload) if isinstance(item, dict)]
            index_items = [environment_index_item(item, project, False) for item in env_items]
            for env_name, index_item in {
                str(item["name"]): item for item in index_items if item.get("name")
            }.items():
                try:
                    detail_payload = await client().request(
                        "GET",
                        f"{environment_prefix(False)}/{path_name(env_name)}",
                        project_key=project,
                    )
                    detail = redact_sensitive(detail_payload)
                    env_details[env_name] = environment_gitops_document(project, detail, False)
                except Exception as exc:
                    snapshot["errors"].append(
                        {"section": "environment_details", "env_name": env_name, **error_summary(exc)}
                    )
                    env_details[env_name] = environment_gitops_document(project, index_item, False)
            detailed_index_items: list[dict[str, Any]] = []
            for name, fallback in {str(item["name"]): item for item in index_items if item.get("name")}.items():
                document = env_details.get(name) if isinstance(env_details.get(name), dict) else {}
                live = document.get("live") if isinstance(document.get("live"), dict) else {}
                summary = live.get("summary") if isinstance(live.get("summary"), dict) else {}
                detailed_index_items.append(summary or fallback)
            snapshot["environments"] = {
                "count": len(detailed_index_items),
                "items": detailed_index_items,
                "details": env_details,
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "environments", **error_summary(exc)})

    if "iterations" in selected_sections:
        snapshot["iterations"] = unsupported_project_section(
            "iterations",
            "Zadig iteration-management API is not mapped yet; keep this section visible for project layout completeness.",
        )

    if "releases" in selected_sections:
        snapshot["releases"] = unsupported_project_section(
            "releases",
            "Zadig release/version-management API is not mapped yet; keep this section visible for project layout completeness.",
        )

    snapshot["metadata"]["error_count"] = len(snapshot["errors"])
    return snapshot


@mcp.tool()
async def zadig_workflow_task_list(
    workflow_name: str,
    project_key: str | None = None,
    page_num: int = 1,
    page_size: int = 20,
    query_type: str = "",
    filters: str = "",
    job_name: str = "",
    include_deployments: bool = True,
    include_raw: bool = False,
) -> dict[str, Any]:
    """List Zadig workflow tasks with optional deployment summaries."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        "/api/aslan/workflow/v4/workflowtask",
        params={
            "workflow_name": workflow_name,
            "page_num": page_num,
            "page_size": page_size,
            "projectName": project,
            "queryType": query_type,
            "filters": filters,
            "jobName": job_name,
        },
    )
    tasks = workflow_tasks_from_payload(payload)
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "page_num": page_num,
        "page_size": page_size,
        "count": len(tasks),
        "items": [summarize_workflow_task(task, include_deployments) for task in tasks],
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_workflow_task_detail(
    workflow_name: str,
    task_id: int,
    project_key: str | None = None,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Get a Zadig workflow task detail with deployment summaries."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        f"/api/aslan/workflow/v4/workflowtask/workflow/{path_name(workflow_name)}/task/{task_id}",
        params={"projectName": project},
    )
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "task_id": task_id,
        "task": summarize_workflow_task(payload, include_deployments=True) if isinstance(payload, dict) else {},
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_workflow_task_job_log(
    workflow_name: str,
    task_id: int,
    job_name: str,
    project_key: str | None = None,
    tail_lines: int = 300,
    keyword: str = "",
    include_raw: bool = False,
) -> dict[str, Any]:
    """Get one Zadig workflow task job log. Supports tail_lines and keyword filtering."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        (
            f"/api/aslan/logs/log/v4/workflow/{path_name(workflow_name)}"
            f"/tasks/{task_id}/jobs/{path_name(job_name)}"
        ),
        params={"projectName": project},
    )
    log_text = text_from_log_payload(payload)
    filtered_log, total_lines, returned_lines = filter_log_text(log_text, keyword, tail_lines)
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "task_id": task_id,
        "job_name": job_name,
        "tail_lines": tail_lines,
        "keyword": keyword,
        "total_lines": total_lines,
        "returned_lines": returned_lines,
        "log": filtered_log,
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_workflow_webhook_list(
    workflow_name: str,
    project_key: str | None = None,
    include_raw: bool = False,
) -> dict[str, Any]:
    """List webhook/git trigger settings for one Zadig workflow."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        "/api/aslan/workflow/v4/webhook",
        params={"projectName": project, "workflowName": workflow_name},
    )
    items = webhook_items_from_payload(payload)
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "count": len(items),
        "items": [summarize_webhook(item) for item in items],
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_workflow_webhook_preset(
    workflow_name: str,
    project_key: str | None = None,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Get the current webhook/git trigger preset for one Zadig workflow."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        "/api/aslan/workflow/v4/webhook/preset",
        params={"projectName": project, "workflowName": workflow_name},
    )
    items = webhook_items_from_payload(payload)
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "count": len(items),
        "items": [summarize_webhook(item) for item in items],
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_workflow_webhook_compare_to_preset(
    workflow_name: str,
    project_key: str | None = None,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Compare saved webhook/git trigger settings with the current workflow webhook preset."""
    project = default_project(project_key)
    webhook_payload = await client().request(
        "GET",
        "/api/aslan/workflow/v4/webhook",
        params={"projectName": project, "workflowName": workflow_name},
    )
    preset_payload = await client().request(
        "GET",
        "/api/aslan/workflow/v4/webhook/preset",
        params={"projectName": project, "workflowName": workflow_name},
    )
    webhook_items = webhook_items_from_payload(webhook_payload)
    preset_items = webhook_items_from_payload(preset_payload)
    webhook_summary = [summarize_webhook(item) for item in webhook_items]
    preset_summary = [summarize_webhook(item) for item in preset_items]
    summary_diff = unified_diff(
        json_for_diff(webhook_summary),
        json_for_diff(preset_summary),
        f"{workflow_name}:webhook",
        f"{workflow_name}:preset",
    )
    result: dict[str, Any] = {
        "project_key": project,
        "workflow_name": workflow_name,
        "webhook_count": len(webhook_items),
        "preset_count": len(preset_items),
        "matches_preset": webhook_summary == preset_summary,
        "summary_diff": summary_diff,
        "webhook_items": webhook_summary,
        "preset_items": preset_summary,
    }
    if include_raw:
        result["raw_diff"] = unified_diff(
            json_for_diff(webhook_payload),
            json_for_diff(preset_payload),
            f"{workflow_name}:webhook:raw",
            f"{workflow_name}:preset:raw",
        )
        result["webhook_raw"] = redact_sensitive(webhook_payload)
        result["preset_raw"] = redact_sensitive(preset_payload)
    return result


def build_items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("builds", "items", "list", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = build_items_from_payload(value)
                if nested:
                    return nested
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def summarize_build(item: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "name": first_present(item, "name", "build_name", "buildName"),
        "project_key": first_present(item, "project_key", "projectKey"),
        "source": item.get("source"),
        "template_name": first_present(item, "template_name", "templateName"),
        "update_by": first_present(item, "update_by", "updateBy"),
        "update_time": first_present(item, "update_time", "updateTime"),
        "target_services": item.get("target_services") or item.get("services"),
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def build_gitops_document(
    project: str,
    build_name: str,
    list_item: dict[str, Any] | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    list_item = list_item or {}
    detail = detail or {}
    spec = build_desired_payload(build_name, project, detail)
    spec.setdefault("name", build_name)
    spec.setdefault("project_key", project)
    return {
        "apiVersion": "zadig.storehub.io/v1alpha1",
        "kind": "Build",
        "metadata": {
            "project": project,
            "name": build_name,
        },
        "spec": spec,
        "live": {
            "list": list_item,
            "detail": detail,
        },
    }


def prepare_build_payload(build_name: str, project: str, build: dict[str, Any]) -> dict[str, Any]:
    payload = build_desired_payload(build_name, project, build)
    payload.setdefault("name", build_name)
    payload.setdefault("project_key", project)
    return payload


def build_desired_payload(build_name: str, project: str, build: dict[str, Any]) -> dict[str, Any]:
    payload = {
        key: copy.deepcopy(value)
        for key, value in build.items()
        if key not in {"update_by", "updateBy", "update_time", "updateTime"}
    }
    payload.pop("build_script_ref", None)
    payload.setdefault("name", build_name)
    payload.setdefault("project_key", project)
    return payload


async def build_exists(project: str, build_name: str) -> bool:
    try:
        await client().request(
            "GET",
            f"/openapi/build/{path_name(build_name)}/detail",
            project_key=project,
        )
        return True
    except ZadigAPIError as exc:
        if "HTTP 404" in str(exc) or "no documents in result" in str(exc):
            return False
        raise


def prepare_ui_build_update_payload(live: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(live)
    field_map = {
        "build_script": "scripts",
        "scripts": "scripts",
        "post_build": "post_build",
        "outputs": "outputs",
    }
    for source_key, target_key in field_map.items():
        if source_key in desired:
            payload[target_key] = copy.deepcopy(desired[source_key])

    advanced_settings = desired.get("advanced_settings")
    if isinstance(advanced_settings, dict) and "timeout" in advanced_settings:
        payload["timeout"] = copy.deepcopy(advanced_settings["timeout"])
    if "timeout" in desired:
        payload["timeout"] = copy.deepcopy(desired["timeout"])

    payload.setdefault("name", desired.get("name") or live.get("name"))
    payload.setdefault("product_name", desired.get("project_key") or live.get("product_name"))
    return payload


async def update_build_via_ui(project: str, build_name: str, desired: dict[str, Any]) -> dict[str, Any]:
    live = await client().request(
        "GET",
        f"/api/aslan/build/build/{path_name(build_name)}",
        params={"projectName": project},
    )
    if not isinstance(live, dict):
        raise ZadigAPIError(f"GET UI build detail for {build_name!r} returned non-object payload")
    payload = prepare_ui_build_update_payload(live, desired)
    result = await client().request(
        "PUT",
        "/api/aslan/build/build",
        params={"projectName": project},
        json_body=payload,
    )
    return {
        "api": "ui",
        "preserved_live_fields": True,
        "mapped_fields": [
            key
            for key in ("build_script", "scripts", "post_build", "outputs", "timeout", "advanced_settings")
            if key in desired
        ],
        "result": result,
    }


async def update_build_with_api(
    project: str,
    build_name: str,
    payload: dict[str, Any],
    update_api: str,
) -> dict[str, Any]:
    if update_api not in {"auto", "openapi", "ui"}:
        raise ValueError("update_api must be one of: auto, openapi, ui")
    if update_api == "ui":
        return await update_build_via_ui(project, build_name, payload)

    try:
        result = await client().request("PUT", "/openapi/build", project_key=project, json_body=payload)
        return {"api": "openapi", "result": result}
    except ZadigAPIError as exc:
        if update_api == "openapi":
            raise
        error_text = str(exc)
        fallback_markers = (
            "codehost",
            "code host",
            "codehost_name",
            "failed to find codehost",
            "http 400",
        )
        if any(marker in error_text.lower() for marker in fallback_markers):
            fallback = await update_build_via_ui(project, build_name, payload)
            fallback["fallback_from"] = "openapi"
            fallback["openapi_error"] = error_text
            return fallback
        raise


def build_template_items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("build_templates", "buildTemplates", "templates", "items", "list", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = build_template_items_from_payload(value)
                if nested:
                    return nested
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def reference_mentions_project(value: Any, project: str) -> bool:
    if isinstance(value, dict):
        for key in ("project_name", "projectName", "project_key", "projectKey"):
            if value.get(key) == project:
                return True
        return any(reference_mentions_project(item, project) for item in value.values())
    if isinstance(value, list):
        return any(reference_mentions_project(item, project) for item in value)
    return False


def filter_references_for_project(value: Any, project: str) -> Any:
    if isinstance(value, list):
        return [item for item in value if reference_mentions_project(item, project)]
    if isinstance(value, dict):
        if reference_mentions_project(value, project):
            return value
        return {}
    return [] if not reference_mentions_project(value, project) else value


def summarize_build_template(item: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "id": first_present(item, "id", "_id"),
        "name": first_present(item, "name", "template_name", "templateName"),
        "timeout": item.get("timeout"),
        "script_type": first_present(item, "script_type", "scriptType"),
        "update_by": first_present(item, "update_by", "updateBy"),
        "update_time": first_present(item, "update_time", "updateTime"),
    }
    pre_build = item.get("pre_build") if isinstance(item.get("pre_build"), dict) else {}
    if pre_build:
        summary["build_os"] = first_present(pre_build, "build_os", "buildOS")
        summary["image_from"] = first_present(pre_build, "image_from", "imageFrom")
        summary["res_req"] = first_present(pre_build, "res_req", "resReq")
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


async def resolve_build_template_id(
    template_id: str = "",
    template_name: str = "",
) -> str:
    if template_id:
        return template_id
    if not template_name:
        raise ValueError("template_id or template_name is required")

    payload = await client().request("GET", "/api/aslan/template/build")
    matches = [
        item
        for item in build_template_items_from_payload(payload)
        if first_present(item, "name", "template_name", "templateName") == template_name
    ]
    if not matches:
        raise ValueError(f"build template {template_name!r} not found")
    if len(matches) > 1:
        ids = [first_present(item, "id", "_id") for item in matches]
        raise ValueError(f"build template name {template_name!r} is ambiguous; use template_id. matched ids: {ids}")
    template_id_value = first_present(matches[0], "id", "_id")
    if not template_id_value:
        raise ValueError(f"build template {template_name!r} did not include id")
    return str(template_id_value)


@mcp.tool()
async def zadig_build_list(
    query: str = "",
    project_key: str | None = None,
    page_num: int = 1,
    page_size: int = 50,
    include_raw: bool = False,
) -> dict[str, Any]:
    """List/search Zadig build configurations."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        "/openapi/build",
        project_key=project,
        params={"pageNum": page_num, "pageSize": page_size},
    )
    needle = query.lower().strip()
    items = [summarize_build(item) for item in build_items_from_payload(payload)]
    if needle:
        items = [item for item in items if needle in json.dumps(item, ensure_ascii=False).lower()]
    result: dict[str, Any] = {
        "project_key": project,
        "page_num": page_num,
        "page_size": page_size,
        "count": len(items),
        "items": items,
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_build_template_list(
    query: str = "",
    include_raw: bool = False,
) -> dict[str, Any]:
    """List/search build template store templates."""
    payload = await client().request("GET", "/api/aslan/template/build")
    needle = query.lower().strip()
    items = [summarize_build_template(item) for item in build_template_items_from_payload(payload)]
    if needle:
        items = [item for item in items if needle in json.dumps(item, ensure_ascii=False).lower()]
    result: dict[str, Any] = {
        "count": len(items),
        "items": items,
    }
    if include_raw:
        result["raw"] = redact_sensitive(payload)
    return result


@mcp.tool()
async def zadig_build_template_get(
    template_id: str = "",
    template_name: str = "",
) -> dict[str, Any]:
    """Get one build template store template by id or exact name."""
    resolved_id = await resolve_build_template_id(template_id, template_name)
    payload = await client().request("GET", f"/api/aslan/template/build/{path_name(resolved_id)}")
    return {
        "template_id": resolved_id,
        "template_name": template_name or first_present(payload, "name", "template_name", "templateName")
        if isinstance(payload, dict)
        else template_name,
        "detail": redact_sensitive(payload),
    }


@mcp.tool()
async def zadig_build_template_reference(
    template_id: str = "",
    template_name: str = "",
) -> dict[str, Any]:
    """List build configurations that reference one build template."""
    resolved_id = await resolve_build_template_id(template_id, template_name)
    payload = await client().request("GET", f"/api/aslan/template/build/{path_name(resolved_id)}/reference")
    return {
        "template_id": resolved_id,
        "template_name": template_name,
        "references": redact_sensitive(payload),
    }


@mcp.tool()
async def zadig_build_template_update(
    template: dict[str, Any],
    template_id: str = "",
    template_name: str = "",
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Update one build template store template. Defaults to dry_run=true and requires confirm=true."""
    resolved_id = await resolve_build_template_id(template_id, template_name)
    payload = dict(template)
    payload.setdefault("id", resolved_id)
    if template_name:
        payload.setdefault("name", template_name)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig build template",
            "template_id": resolved_id,
            "template_name": template_name,
            "payload": redact_sensitive(payload),
        }

    result = await client().request(
        "PUT",
        f"/api/aslan/template/build/{path_name(resolved_id)}",
        json_body=payload,
    )
    return {"applied": True, "template_id": resolved_id, "template_name": template_name, "result": result}


def build_template_desired_payload(template: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in template.items()
        if key not in {"id", "_id", "update_by", "updateBy", "update_time", "updateTime"}
    }


async def build_template_exists(template_id: str = "", template_name: str = "") -> tuple[bool, str]:
    try:
        resolved_id = await resolve_build_template_id(template_id, template_name)
        return True, resolved_id
    except ValueError as exc:
        if "not found" in str(exc):
            return False, ""
        raise
    except ZadigAPIError as exc:
        if "HTTP 404" in str(exc) or "no documents in result" in str(exc):
            return False, ""
        raise


@mcp.tool()
async def zadig_build_template_create(
    template: dict[str, Any],
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create one build template store template. Defaults to dry_run=true and requires confirm=true."""
    payload = build_template_desired_payload(dict(template))
    template_name = first_present(payload, "name", "template_name", "templateName") or ""

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to create Zadig build template",
            "template_name": template_name,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    result = await client().request("POST", "/api/aslan/template/build", json_body=payload)
    return {"applied": True, "template_name": template_name, "result": result}


@mcp.tool()
async def zadig_build_template_delete(
    template_id: str = "",
    template_name: str = "",
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete one build template store template. Defaults to dry_run=true and requires confirm=true."""
    resolved_id = await resolve_build_template_id(template_id, template_name)
    references = await client().request("GET", f"/api/aslan/template/build/{path_name(resolved_id)}/reference")
    result: dict[str, Any] = {
        "applied": False,
        "dry_run": dry_run,
        "template_id": resolved_id,
        "template_name": template_name,
        "references": redact_sensitive(references),
    }
    if dry_run or not confirm:
        result["reason"] = "set dry_run=false and confirm=true to delete Zadig build template"
        return result

    delete_result = await client().request("DELETE", f"/api/aslan/template/build/{path_name(resolved_id)}")
    result["applied"] = True
    result["result"] = delete_result
    return result


@mcp.tool()
async def zadig_build_template_diff(
    template: dict[str, Any],
    template_id: str = "",
    template_name: str = "",
) -> dict[str, Any]:
    """Diff current Zadig build template detail against desired template payload."""
    desired = build_template_desired_payload(dict(template))
    desired_name = template_name or str(first_present(desired, "name", "template_name", "templateName") or "")
    exists, resolved_id = await build_template_exists(template_id, desired_name)
    if not exists:
        return {
            "template_id": resolved_id,
            "template_name": desired_name,
            "exists": False,
            "changed": True,
            "diff": unified_diff("", json_for_diff(desired), f"{desired_name}:current", f"{desired_name}:desired"),
            "desired": redact_sensitive(desired),
        }

    current = await client().request("GET", f"/api/aslan/template/build/{path_name(resolved_id)}")
    current_desired = build_template_desired_payload(current if isinstance(current, dict) else {})
    diff = unified_diff(
        json_for_diff(current_desired),
        json_for_diff(desired),
        f"{desired_name or resolved_id}:current",
        f"{desired_name or resolved_id}:desired",
    )
    return {
        "template_id": resolved_id,
        "template_name": desired_name,
        "exists": True,
        "changed": bool(diff.strip()),
        "diff": diff,
    }


@mcp.tool()
async def zadig_build_template_apply(
    template: dict[str, Any],
    template_id: str = "",
    template_name: str = "",
    mode: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create or update one build template. mode can be auto, create, or update. Defaults to dry_run=true."""
    if mode not in {"auto", "create", "update"}:
        raise ValueError("mode must be one of: auto, create, update")

    payload = build_template_desired_payload(dict(template))
    desired_name = template_name or str(first_present(payload, "name", "template_name", "templateName") or "")
    exists, resolved_id = await build_template_exists(template_id, desired_name)
    action = mode
    if action == "auto":
        action = "update" if exists else "create"
    if action == "create" and exists:
        raise ValueError(f"build template {desired_name!r} already exists; use mode='update' or mode='auto'")
    if action == "update" and not exists:
        raise ValueError(f"build template {desired_name!r} does not exist; use mode='create' or mode='auto'")

    diff_result = await zadig_build_template_diff(payload, resolved_id, desired_name) if exists else {
        "diff": unified_diff("", json_for_diff(payload), f"{desired_name}:current", f"{desired_name}:desired")
    }
    diff_text = diff_result.get("diff", "")
    if action == "update" and not diff_text.strip():
        action = "none"

    if dry_run or not confirm or action == "none":
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "build template exists and desired spec matches live state"
            if action == "none"
            else "set dry_run=false and confirm=true to apply Zadig build template",
            "template_id": resolved_id,
            "template_name": desired_name,
            "exists": exists,
            "action": action,
            "diff": diff_text,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    if action == "create":
        result = await client().request("POST", "/api/aslan/template/build", json_body=payload)
    else:
        result = await client().request(
            "PUT",
            f"/api/aslan/template/build/{path_name(resolved_id)}",
            json_body=payload,
        )
    return {
        "applied": True,
        "template_id": resolved_id,
        "template_name": desired_name,
        "exists_before_apply": exists,
        "action": action,
        "diff": diff_text,
        "result": result,
    }


@mcp.tool()
async def zadig_build_get(
    build_name: str,
    project_key: str | None = None,
    service_name: str = "",
    service_module: str = "",
) -> dict[str, Any]:
    """Get one Zadig build configuration detail."""
    project = default_project(project_key)
    params: dict[str, Any] = {}
    if service_name:
        params["serviceName"] = service_name
    if service_module:
        params["serviceModule"] = service_module
    payload = await client().request(
        "GET",
        f"/openapi/build/{path_name(build_name)}/detail",
        project_key=project,
        params=params,
    )
    return {
        "project_key": project,
        "build_name": build_name,
        "detail": redact_sensitive(payload),
    }


@mcp.tool()
async def zadig_build_create(
    build_name: str,
    build: dict[str, Any],
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create one Zadig build. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = prepare_build_payload(build_name, project, build)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to create Zadig build",
            "project_key": project,
            "build_name": build_name,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    params = {"source": "template"} if payload.get("source") == "template" else None
    result = await client().request("POST", "/openapi/build", project_key=project, params=params, json_body=payload)
    return {"applied": True, "project_key": project, "build_name": build_name, "result": result}


@mcp.tool()
async def zadig_build_update(
    build_name: str,
    build: dict[str, Any],
    project_key: str | None = None,
    update_api: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Update one Zadig build configuration. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = prepare_build_payload(build_name, project, build)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig build",
            "project_key": project,
            "build_name": build_name,
            "update_api": update_api,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    result = await update_build_with_api(project, build_name, payload, update_api)
    return {"applied": True, "project_key": project, "build_name": build_name, "update_api": update_api, "result": result}


@mcp.tool()
async def zadig_build_delete(
    build_name: str,
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete one Zadig build. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = {"name": build_name, "projectKey": project}

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to delete Zadig build",
            "project_key": project,
            "build_name": build_name,
            "payload": payload,
        }

    result = await client().request("DELETE", "/openapi/build", params={"name": build_name}, project_key=project)
    return {"applied": True, "project_key": project, "build_name": build_name, "result": result}


@mcp.tool()
async def zadig_build_diff(
    build_name: str,
    build: dict[str, Any],
    project_key: str | None = None,
) -> dict[str, Any]:
    """Diff current Zadig build detail against desired build payload."""
    project = default_project(project_key)
    desired = prepare_build_payload(build_name, project, build)
    exists = await build_exists(project, build_name)
    if not exists:
        return {
            "project_key": project,
            "build_name": build_name,
            "exists": False,
            "diff": unified_diff("", json_for_diff(desired), f"{build_name}:current", f"{build_name}:desired"),
            "desired": redact_sensitive(desired),
        }

    current = await client().request(
        "GET",
        f"/openapi/build/{path_name(build_name)}/detail",
        project_key=project,
    )
    current_desired = build_desired_payload(build_name, project, current if isinstance(current, dict) else {})
    diff = unified_diff(
        json_for_diff(current_desired),
        json_for_diff(desired),
        f"{build_name}:current",
        f"{build_name}:desired",
    )
    return {
        "project_key": project,
        "build_name": build_name,
        "exists": True,
        "changed": bool(diff.strip()),
        "diff": diff,
    }


@mcp.tool()
async def zadig_build_apply(
    build_name: str,
    build: dict[str, Any],
    project_key: str | None = None,
    mode: str = "auto",
    update_api: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create or update one Zadig build. mode can be auto, create, or update. Defaults to dry_run=true."""
    project = default_project(project_key)
    if mode not in {"auto", "create", "update"}:
        raise ValueError("mode must be one of: auto, create, update")

    exists = await build_exists(project, build_name)
    action = mode
    if action == "auto":
        action = "update" if exists else "create"
    if action == "create" and exists:
        raise ValueError(f"build {build_name!r} already exists; use mode='update' or mode='auto'")
    if action == "update" and not exists:
        raise ValueError(f"build {build_name!r} does not exist; use mode='create' or mode='auto'")

    diff_result = await zadig_build_diff(build_name, build, project)
    payload = prepare_build_payload(build_name, project, build)
    diff_text = diff_result.get("diff", "")
    if action == "update" and not diff_text.strip():
        action = "none"

    if dry_run or not confirm or action == "none":
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "build exists and desired spec matches live state"
            if action == "none"
            else "set dry_run=false and confirm=true to apply Zadig build",
            "project_key": project,
            "build_name": build_name,
            "exists": exists,
            "action": action,
            "update_api": update_api,
            "diff": diff_text,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    if action == "create":
        params = {"source": "template"} if payload.get("source") == "template" else None
        result = await client().request("POST", "/openapi/build", project_key=project, params=params, json_body=payload)
    else:
        result = await update_build_with_api(project, build_name, payload, update_api)
    return {
        "applied": True,
        "project_key": project,
        "build_name": build_name,
        "exists_before_apply": exists,
        "action": action,
        "update_api": update_api,
        "diff": diff_text,
        "result": result,
    }


@mcp.tool()
async def zadig_build_update_from_template(
    build_name: str,
    template_name: str,
    target_services: list[dict[str, Any]],
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Update a build created from a build template. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = {
        "name": build_name,
        "project_key": project,
        "template_name": template_name,
        "target_services": target_services,
    }

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig build from template",
            "project_key": project,
            "build_name": build_name,
            "payload": redact_sensitive(payload),
        }

    result = await client().request(
        "PUT",
        f"/openapi/build/{path_name(build_name)}/template",
        project_key=project,
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "build_name": build_name, "result": result}


@mcp.tool()
async def zadig_service_search(
    query: str = "",
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """Search Zadig K8s YAML services by service, container, image name or image."""
    project = default_project(project_key)
    payload = await client().request("GET", f"{service_prefix(production)}/services", project_key=project)
    return {
        "project_key": project,
        "production": production,
        "items": summarize_services(payload, query),
        "raw": payload,
    }


@mcp.tool()
async def zadig_service_get(
    service_name: str,
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """Get a Zadig K8s YAML service detail."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
    )
    return {
        "project_key": project,
        "production": production,
        "service_name": service_name,
        "detail": payload,
    }


@mcp.tool()
async def zadig_service_update_yaml(
    service_name: str,
    yaml: str,
    service_type: str = "k8s",
    project_key: str | None = None,
    production: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Replace service YAML. This is mutating and requires confirm=true."""
    if not confirm:
        return {
            "applied": False,
            "reason": "confirm must be true before updating Zadig service YAML",
            "service_name": service_name,
        }

    project = default_project(project_key)
    payload = await client().request(
        "PUT",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
        json_body={"type": service_type, "yaml": yaml},
    )
    return {"applied": True, "project_key": project, "production": production, "result": payload}


@mcp.tool()
async def zadig_service_update_variables(
    service_name: str,
    service_variable_kvs: list[dict[str, Any]],
    project_key: str | None = None,
    production: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Replace all service variables. This is mutating and requires confirm=true."""
    if not confirm:
        return {
            "applied": False,
            "reason": "confirm must be true before updating Zadig service variables",
            "service_name": service_name,
            "payload": {"service_variable_kvs": service_variable_kvs},
        }

    project = default_project(project_key)
    payload = await client().request(
        "PUT",
        f"{service_prefix(production)}/{path_name(service_name)}/variable",
        project_key=project,
        json_body={"service_variable_kvs": service_variable_kvs},
    )
    return {"applied": True, "project_key": project, "production": production, "result": payload}


@mcp.tool()
async def zadig_service_set_variable(
    service_name: str,
    key: str,
    value: Any,
    value_type: str = "string",
    desc: str = "",
    options: list[Any] | None = None,
    project_key: str | None = None,
    production: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Upsert a single service variable. Defaults to dry_run=true."""
    project = default_project(project_key)
    detail = await client().request(
        "GET",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
    )
    existing = []
    if isinstance(detail, dict):
        existing = detail.get("service_variable_kvs") or []
    new_variables = upsert_variable(existing, key, value, value_type, desc, options)
    payload = {"service_variable_kvs": new_variables}

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to apply",
            "project_key": project,
            "production": production,
            "service_name": service_name,
            "payload": payload,
        }

    result = await client().request(
        "PUT",
        f"{service_prefix(production)}/{path_name(service_name)}/variable",
        project_key=project,
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "production": production, "result": result}


@mcp.tool()
async def zadig_service_set_image(
    service_name: str,
    container_name: str,
    image: str,
    project_key: str | None = None,
    production: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Update one container image in service YAML. Defaults to dry_run=true and returns a diff."""
    project = default_project(project_key)
    detail = await client().request(
        "GET",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
    )
    if not isinstance(detail, dict) or not detail.get("yaml"):
        raise ValueError("service detail did not include yaml")

    before = detail["yaml"]
    after = replace_container_image(before, container_name, image)
    diff = unified_diff(before, after, f"{service_name}:before", f"{service_name}:after")

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to apply",
            "project_key": project,
            "production": production,
            "service_name": service_name,
            "diff": diff,
        }

    result = await client().request(
        "PUT",
        f"{service_prefix(production)}/{path_name(service_name)}",
        project_key=project,
        json_body={"type": detail.get("type", "k8s"), "yaml": after},
    )
    return {"applied": True, "project_key": project, "production": production, "diff": diff, "result": result}


@mcp.tool()
async def zadig_environment_list(
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """List Zadig environments."""
    project = default_project(project_key)
    payload = await client().request("GET", environment_prefix(production), project_key=project)
    return {"project_key": project, "production": production, "items": payload}


@mcp.tool()
async def zadig_environment_get(
    env_name: str,
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """Get a Zadig environment detail."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        f"{environment_prefix(production)}/{path_name(env_name)}",
        project_key=project,
    )
    return {
        "project_key": project,
        "production": production,
        "env_name": env_name,
        "detail": redact_sensitive(payload),
    }


@mcp.tool()
async def zadig_environment_create(
    environment: dict[str, Any],
    env_name: str = "",
    project_key: str | None = None,
    production: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create a Zadig environment. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    desired_name = env_name or str(first_present(environment, "env_key", "env_name", "name") or "")
    payload = environment_desired_payload(desired_name, dict(environment), production)
    if production:
        payload = {
            key: value
            for key, value in payload.items()
            if key in {"env_key", "env_name", "cluster_id", "namespace", "registry_id", "sub_env"}
        }

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to create Zadig environment",
            "project_key": project,
            "production": production,
            "env_name": desired_name,
            "redacted_placeholder_paths": redacted_placeholder_paths(payload),
            "payload": redact_sensitive(payload),
        }

    assert_no_redacted_placeholders(payload, allow_redacted)
    result = await client().request("POST", environment_prefix(production), project_key=project, json_body=payload)
    return {"applied": True, "project_key": project, "production": production, "env_name": desired_name, "result": result}


@mcp.tool()
async def zadig_environment_update(
    env_name: str,
    environment: dict[str, Any],
    project_key: str | None = None,
    production: bool = False,
    update_global_variables: bool = True,
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Update a Zadig environment. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = environment_update_payload(dict(environment), production)
    global_variables = environment.get("global_variables") if isinstance(environment.get("global_variables"), list) else None
    steps: list[dict[str, Any]] = []
    if payload:
        steps.append(
            {
                "action": "update_environment",
                "method": "PUT",
                "path": f"{environment_prefix(production)}/{path_name(env_name)}",
                "payload": payload,
            }
        )
    if update_global_variables and global_variables is not None:
        steps.append(
            {
                "action": "update_global_variables",
                "method": "PUT",
                "path": f"{environment_prefix(production)}/{path_name(env_name)}/variable",
                "payload": {"global_variables": global_variables},
            }
        )

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig environment",
            "project_key": project,
            "production": production,
            "env_name": env_name,
            "steps": redact_sensitive(steps),
        }

    assert_no_redacted_placeholders(steps, allow_redacted)
    results = []
    for step in steps:
        results.append(
            {
                "action": step["action"],
                "result": await client().request(
                    step["method"],
                    step["path"],
                    project_key=project,
                    json_body=step["payload"],
                ),
            }
        )
    return {"applied": True, "project_key": project, "production": production, "env_name": env_name, "results": results}


@mcp.tool()
async def zadig_environment_delete(
    env_name: str,
    project_key: str | None = None,
    production: bool = False,
    is_delete: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete a Zadig environment. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    params = {"isDelete": str(is_delete).lower()} if not production else {}
    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to delete Zadig environment",
            "project_key": project,
            "production": production,
            "env_name": env_name,
            "is_delete": is_delete,
        }
    result = await client().request(
        "DELETE",
        f"{environment_prefix(production)}/{path_name(env_name)}",
        project_key=project,
        params=params,
    )
    return {"applied": True, "project_key": project, "production": production, "env_name": env_name, "result": result}


@mcp.tool()
async def zadig_environment_diff(
    environment: dict[str, Any],
    env_name: str = "",
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """Diff current Zadig environment against desired Environment spec."""
    project = default_project(project_key)
    desired_name = env_name or str(first_present(environment, "env_key", "env_name", "name") or "")
    live = await environment_detail_or_none(project, desired_name, production)
    desired = environment_desired_payload(desired_name, dict(environment), production)
    if live is None:
        return {
            "project_key": project,
            "production": production,
            "env_name": desired_name,
            "exists": False,
            "changed": True,
            "diff": unified_diff("", json_for_diff(desired), f"{desired_name}:current", f"{desired_name}:desired"),
            "desired": redact_sensitive(desired),
        }

    current = environment_desired_payload(desired_name, live, production)
    diff = unified_diff(
        json_for_diff(current),
        json_for_diff(desired),
        f"{desired_name}:current",
        f"{desired_name}:desired",
    )
    return {
        "project_key": project,
        "production": production,
        "env_name": desired_name,
        "exists": True,
        "changed": bool(diff.strip()),
        "diff": diff,
    }


@mcp.tool()
async def zadig_environment_apply(
    environment: dict[str, Any],
    env_name: str = "",
    project_key: str | None = None,
    production: bool = False,
    mode: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Create or update a Zadig environment. mode can be auto, create, or update. Defaults to dry_run=true."""
    if mode not in {"auto", "create", "update"}:
        raise ValueError("mode must be one of: auto, create, update")
    project = default_project(project_key)
    desired_name = env_name or str(first_present(environment, "env_key", "env_name", "name") or "")
    exists = await environment_detail_or_none(project, desired_name, production) is not None
    action = "update" if mode == "auto" and exists else "create" if mode == "auto" else mode
    if action == "create" and exists:
        raise ValueError(f"environment {desired_name!r} already exists; use mode='update' or mode='auto'")
    if action == "update" and not exists:
        raise ValueError(f"environment {desired_name!r} does not exist; use mode='create' or mode='auto'")

    diff = await zadig_environment_diff(environment, desired_name, project, production)
    if action == "update" and not diff.get("changed"):
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "environment exists and desired spec matches live state",
            "project_key": project,
            "production": production,
            "env_name": desired_name,
            "action": "none",
            "diff": "",
        }
    if action == "create":
        result = await zadig_environment_create(
            environment,
            desired_name,
            project,
            production,
            dry_run,
            confirm,
            allow_redacted,
        )
    else:
        result = await zadig_environment_update(
            desired_name,
            environment,
            project,
            production,
            True,
            dry_run,
            confirm,
            allow_redacted,
        )
    result["action"] = action
    result["diff"] = diff.get("diff", "")
    return result


@mcp.tool()
async def zadig_environment_service_list(
    env_name: str,
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """List services deployed in a Zadig environment."""
    project = default_project(project_key)
    detail = await client().request(
        "GET",
        f"{environment_prefix(production)}/{path_name(env_name)}",
        project_key=project,
    )
    services = detail.get("services") if isinstance(detail, dict) and isinstance(detail.get("services"), list) else []
    return {
        "project_key": project,
        "production": production,
        "env_name": env_name,
        "count": len(services),
        "items": [environment_service_index_item(env_name, item) for item in services if isinstance(item, dict)],
    }


@mcp.tool()
async def zadig_environment_service_get(
    env_name: str,
    service_name: str,
    project_key: str | None = None,
    production: bool = False,
    workload_type: str = "",
) -> dict[str, Any]:
    """Get service detail in a Zadig environment."""
    project = default_project(project_key)
    params = {"workLoadtype": workload_type} if workload_type else None
    payload = await client().request(
        "GET",
        f"{environment_prefix(production)}/{path_name(env_name)}/services/{path_name(service_name)}",
        project_key=project,
        params=params,
    )
    return {
        "project_key": project,
        "production": production,
        "env_name": env_name,
        "service_name": service_name,
        "detail": redact_sensitive(payload),
    }


@mcp.tool()
async def zadig_environment_service_apply(
    env_name: str,
    service: dict[str, Any],
    project_key: str | None = None,
    production: bool = False,
    mode: str = "auto",
    dry_run: bool = True,
    confirm: bool = False,
    allow_redacted: bool = False,
) -> dict[str, Any]:
    """Add or update one service in a Zadig environment. Defaults to dry_run=true and requires confirm=true."""
    if mode not in {"auto", "create", "update"}:
        raise ValueError("mode must be one of: auto, create, update")
    project = default_project(project_key)
    payload_service = environment_service_desired_payload(dict(service))
    service_name = str(payload_service.get("service_name") or "")
    if not service_name:
        raise ValueError("service must include service_name")

    env_detail = await environment_detail_or_none(project, env_name, production)
    if env_detail is None:
        raise ValueError(f"environment {env_name!r} does not exist")
    live_service = environment_service_from_detail(env_detail, service_name)
    exists = live_service is not None
    action = "update" if mode == "auto" and exists else "create" if mode == "auto" else mode
    if action == "create" and exists:
        raise ValueError(f"environment service {service_name!r} already exists; use mode='update' or mode='auto'")
    if action == "update" and not exists:
        raise ValueError(f"environment service {service_name!r} does not exist; use mode='create' or mode='auto'")

    live_payload = environment_service_desired_payload(live_service or {})
    diff = unified_diff(
        json_for_diff(live_payload),
        json_for_diff(payload_service),
        f"{env_name}/{service_name}:current",
        f"{env_name}/{service_name}:desired",
    )
    result: dict[str, Any] = {
        "applied": False,
        "dry_run": dry_run,
        "project_key": project,
        "production": production,
        "env_name": env_name,
        "service_name": service_name,
        "action": action if diff.strip() or action == "create" else "none",
        "diff": diff,
    }
    if action == "update" and not diff.strip():
        result["reason"] = "environment service exists and desired spec matches live state"
        return result

    endpoint = (
        f"{environment_prefix(production)}/{path_name(env_name)}/services"
        if action == "update"
        else f"{environment_prefix(production)}/service/yaml"
    )
    payload = {"service_list": [payload_service]}
    if action == "create":
        payload["env_key"] = env_name

    if dry_run or not confirm:
        result["reason"] = "set dry_run=false and confirm=true to apply Zadig environment service"
        result["payload"] = redact_sensitive(payload)
        return result

    assert_no_redacted_placeholders(payload, allow_redacted)
    result["result"] = await client().request(
        "PUT" if action == "update" else "POST",
        endpoint,
        project_key=project,
        json_body=payload,
    )
    result["applied"] = True
    return result


@mcp.tool()
async def zadig_environment_service_delete(
    env_name: str,
    service_name: str,
    project_key: str | None = None,
    production: bool = False,
    not_delete_resource: bool = True,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete one service from a Zadig environment. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = {
        "env_key": env_name,
        "service_names": [service_name],
        "not_delete_resource": not_delete_resource,
    }
    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to delete Zadig environment service",
            "project_key": project,
            "production": production,
            "env_name": env_name,
            "service_name": service_name,
            "payload": payload,
        }
    result = await client().request(
        "DELETE",
        f"{environment_prefix(production)}/service/yaml",
        project_key=project,
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "production": production, "env_name": env_name, "result": result}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
