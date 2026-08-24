import argparse
import asyncio
import json
import re
from pathlib import Path
from typing import Any

from .server import DEFAULT_SNAPSHOT_SECTIONS, zadig_project_snapshot


def safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return safe.strip("-") or "unnamed"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def split_snapshot(snapshot: dict[str, Any], output_dir: Path) -> None:
    project = snapshot.get("metadata", {}).get("project_key") or "unknown-project"
    project_dir = output_dir / "projects" / safe_name(str(project))
    write_json(project_dir / "metadata.json", snapshot.get("metadata", {}))
    write_json(project_dir / "errors.json", snapshot.get("errors", []))

    if "workflows" in snapshot:
        write_json(project_dir / "workflows" / "index.json", snapshot["workflows"])

    workflow_details = snapshot.get("workflow_details", {}).get("items", {})
    for workflow_name, detail in workflow_details.items():
        write_json(project_dir / "workflows" / "details" / f"{safe_name(str(workflow_name))}.json", detail)

    webhooks = snapshot.get("webhooks", {}).get("items", {})
    if webhooks:
        write_json(project_dir / "webhooks" / "index.json", snapshot["webhooks"])
    for workflow_name, detail in webhooks.items():
        write_json(project_dir / "webhooks" / f"{safe_name(str(workflow_name))}.json", detail)

    if "builds" in snapshot:
        write_json(project_dir / "builds" / "index.json", snapshot["builds"])

    build_templates = snapshot.get("build_templates", {})
    if build_templates:
        write_json(
            project_dir / "build-templates" / "index.json",
            {
                "count": build_templates.get("count", 0),
                "summary": build_templates.get("summary", []),
            },
        )
    for template_id, item in build_templates.get("items", {}).items():
        template_name = item.get("name") or template_id
        write_json(
            project_dir / "build-templates" / f"{safe_name(str(template_name))}.{safe_name(str(template_id))}.json",
            item,
        )

    template_refs = snapshot.get("build_template_references", {})
    if template_refs:
        write_json(project_dir / "build-template-references" / "index.json", template_refs)

    if "services" in snapshot:
        write_json(project_dir / "services" / "index.json", snapshot["services"])

    if "environments" in snapshot:
        write_json(project_dir / "environments" / "index.json", snapshot["environments"])


async def run_snapshot(args: argparse.Namespace) -> None:
    snapshot = await zadig_project_snapshot(
        project_key=args.project,
        sections=args.sections,
        workflow_names=args.workflow,
        max_workflows=args.max_workflows,
        include_workflow_raw_list=args.include_workflow_raw_list,
    )
    output_dir = Path(args.output).expanduser().resolve()
    split_snapshot(snapshot, output_dir)
    project = snapshot.get("metadata", {}).get("project_key")
    error_count = snapshot.get("metadata", {}).get("error_count", 0)
    print(f"wrote snapshot for project={project} to {output_dir}")
    print(f"sections={','.join(snapshot.get('metadata', {}).get('sections', []))}")
    print(f"error_count={error_count}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zadig-gitops", description="GitOps helpers for Zadig configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot", help="Export a redacted Zadig project snapshot to files.")
    snapshot.add_argument("--project", required=True, help="Zadig project key.")
    snapshot.add_argument("--output", default="zadig-config", help="Output directory.")
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
        help="Include raw workflow list payload in workflows/index.json.",
    )
    snapshot.set_defaults(func=run_snapshot)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
