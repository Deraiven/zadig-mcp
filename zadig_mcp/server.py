import json
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import ZadigClient, default_project, environment_prefix, path_name, service_prefix
from .service_ops import replace_container_image, summarize_services, unified_diff, upsert_variable

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
            or workflow.get("display_name")
            or workflow.get("workflow_name")
            or workflow.get("workflowName")
            or workflow.get("id")
        )
        summary = {
            "name": name,
            "display_name": workflow.get("display_name") or workflow.get("displayName"),
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
}


DEFAULT_SNAPSHOT_SECTIONS = [
    "workflows",
    "workflow_details",
    "webhooks",
    "builds",
    "build_templates",
    "build_template_references",
    "services",
    "environments",
]

KNOWN_SNAPSHOT_SECTIONS = set(DEFAULT_SNAPSHOT_SECTIONS)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_FIELD_NAMES or any(
        marker in lowered for marker in ("token", "secret", "password", "credential", "private")
    )


def redact_sensitive(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        credential_marker = value.get("is_credential")
        is_credential = credential_marker is True or str(credential_marker).lower() == "true"
        value_name = first_present(value, "key", "name", "variable_name", "variableName", "env_name", "envName")
        value_is_sensitive = isinstance(value_name, str) and is_sensitive_key(value_name)
        for key, item in value.items():
            if key == "value" and (is_credential or value_is_sensitive):
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
    return json.dumps(redact_sensitive(value), ensure_ascii=False, indent=2, sort_keys=True)


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
) -> dict[str, Any]:
    """Update a custom workflow. Defaults to dry_run=true and requires confirm=true to mutate."""
    project = default_project(project_key)
    payload = dict(workflow)
    payload.setdefault("project", project)
    payload.setdefault("name", workflow_name)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig workflow",
            "project_key": project,
            "workflow_name": workflow_name,
            "payload": redact_sensitive(payload),
        }

    result = await client().request(
        "PUT",
        f"/api/aslan/workflow/v4/{path_name(workflow_name)}",
        params={"projectName": project},
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "workflow_name": workflow_name, "result": result}


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
            snapshot["builds"] = {
                "count": len(build_items),
                "items": [summarize_build(item) for item in build_items],
                "raw": redact_sensitive(build_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "builds", **error_summary(exc)})

    template_items: list[dict[str, Any]] = []
    if any(section in selected_sections for section in ("build_templates", "build_template_references")):
        try:
            template_payload = await client().request("GET", "/api/aslan/template/build")
            template_items = build_template_items_from_payload(template_payload)
            if "build_templates" in selected_sections:
                template_details: dict[str, Any] = {}
                for item in template_items:
                    template_id = first_present(item, "id", "_id")
                    template_name = first_present(item, "name", "template_name", "templateName")
                    if not template_id:
                        continue
                    try:
                        detail_payload = await client().request(
                            "GET",
                            f"/api/aslan/template/build/{path_name(str(template_id))}",
                        )
                        template_details[str(template_id)] = {
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
                    "summary": [summarize_build_template(item) for item in template_items],
                    "items": template_details,
                }
        except Exception as exc:
            snapshot["errors"].append({"section": "build_templates", **error_summary(exc)})

    if "build_template_references" in selected_sections and template_items:
        references: dict[str, Any] = {}
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
                references[str(template_id)] = {
                    "name": template_name,
                    "references": redact_sensitive(reference_payload),
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
        snapshot["build_template_references"] = {
            "count": len(references),
            "items": references,
        }

    if "services" in selected_sections:
        try:
            service_payload = await client().request("GET", f"{service_prefix(False)}/services", project_key=project)
            snapshot["services"] = {
                "count": len(summarize_services(service_payload)),
                "summary": summarize_services(service_payload),
                "raw": redact_sensitive(service_payload),
            }
        except Exception as exc:
            snapshot["errors"].append({"section": "services", **error_summary(exc)})

    if "environments" in selected_sections:
        try:
            env_payload = await client().request("GET", environment_prefix(False), project_key=project)
            snapshot["environments"] = redact_sensitive(env_payload)
        except Exception as exc:
            snapshot["errors"].append({"section": "environments", **error_summary(exc)})

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
async def zadig_build_update(
    build_name: str,
    build: dict[str, Any],
    project_key: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Update one Zadig build configuration. Defaults to dry_run=true and requires confirm=true."""
    project = default_project(project_key)
    payload = dict(build)
    payload.setdefault("name", build_name)
    payload.setdefault("project_key", project)

    if dry_run or not confirm:
        return {
            "applied": False,
            "dry_run": dry_run,
            "reason": "set dry_run=false and confirm=true to update Zadig build",
            "project_key": project,
            "build_name": build_name,
            "payload": redact_sensitive(payload),
        }

    result = await client().request(
        "PUT",
        "/openapi/build",
        project_key=project,
        json_body=payload,
    )
    return {"applied": True, "project_key": project, "build_name": build_name, "result": result}


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
async def zadig_environment_service_get(
    env_name: str,
    service_name: str,
    project_key: str | None = None,
    production: bool = False,
) -> dict[str, Any]:
    """Get service detail in a Zadig environment."""
    project = default_project(project_key)
    payload = await client().request(
        "GET",
        f"{environment_prefix(production)}/{path_name(env_name)}/services/{path_name(service_name)}",
        project_key=project,
    )
    return {
        "project_key": project,
        "production": production,
        "env_name": env_name,
        "service_name": service_name,
        "detail": payload,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
