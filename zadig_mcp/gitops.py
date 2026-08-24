import argparse
import asyncio
import json
import re
from pathlib import Path
from typing import Any

import yaml

from .server import DEFAULT_SNAPSHOT_SECTIONS, zadig_project_snapshot, zadig_workflow_apply, zadig_workflow_diff


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


def split_snapshot(snapshot: dict[str, Any], output_dir: Path, output_format: str) -> None:
    project = snapshot.get("metadata", {}).get("project_key") or "unknown-project"
    project_dir = output_dir / "projects" / safe_name(str(project))
    shared_template_dir = output_dir / "templates" / "build-templates"
    shared_template_reference_dir = output_dir / "references" / "build-templates"
    snapshot_dir = project_dir / "_snapshot"
    write_data(snapshot_dir / data_filename("metadata", output_format), snapshot.get("metadata", {}), output_format)
    write_data(snapshot_dir / data_filename("errors", output_format), snapshot.get("errors", []), output_format)

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
        write_data(project_dir / "builds" / data_filename("index", output_format), snapshot["builds"], output_format)

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
        write_data(project_dir / "services" / data_filename("index", output_format), snapshot["services"], output_format)

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

    apply = subparsers.add_parser("apply", help="Create or update a Zadig workflow from YAML/JSON.")
    apply.add_argument("--project", required=True, help="Zadig project key.")
    apply.add_argument("--workflow", help="Workflow name. Defaults to workflow_name/workflow_key/name from file.")
    apply.add_argument("--file", required=True, help="Workflow YAML/JSON file.")
    apply.add_argument("--mode", choices=["auto", "create", "update"], default="auto", help="Apply mode.")
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
