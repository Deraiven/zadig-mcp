import difflib
from typing import Any


def iter_services(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        services = payload.get("service") or payload.get("services") or []
    elif isinstance(payload, list):
        services = payload
    else:
        services = []
    return [item for item in services if isinstance(item, dict)]


def summarize_services(payload: Any, query: str = "") -> list[dict[str, Any]]:
    needle = query.lower().strip()
    rows: list[dict[str, Any]] = []
    for service in iter_services(payload):
        service_name = service.get("service_name") or service.get("name") or ""
        service_type = service.get("type") or ""
        containers = service.get("containers") or []
        if not containers:
            haystack = f"{service_name} {service_type}".lower()
            if needle and needle not in haystack:
                continue
            rows.append(
                {
                    "service": service_name,
                    "type": service_type,
                    "container": "",
                    "image_name": "",
                    "image": "",
                }
            )
            continue

        for container in containers:
            if not isinstance(container, dict):
                continue
            container_name = container.get("name") or ""
            image = container.get("image") or ""
            image_name = container.get("image_name") or ""
            haystack = f"{service_name} {service_type} {container_name} {image_name} {image}".lower()
            if needle and needle not in haystack:
                continue
            rows.append(
                {
                    "service": service_name,
                    "type": service_type,
                    "container": container_name,
                    "image_name": image_name,
                    "image": image,
                }
            )
    return rows


def replace_container_image(yaml_text: str, container_name: str, new_image: str) -> str:
    lines = yaml_text.splitlines(keepends=True)
    in_containers = False
    target_indent = None
    item_indent = None
    found_container = False

    for idx, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if stripped == "containers:":
            in_containers = True
            target_indent = indent
            item_indent = None
            found_container = False
            continue

        if in_containers and stripped and target_indent is not None and indent <= target_indent and not stripped.startswith("- "):
            in_containers = False
            found_container = False

        if not in_containers:
            continue

        if stripped.startswith("- name:"):
            item_indent = indent
            name = stripped.split(":", 1)[1].strip().strip("'\"")
            found_container = name == container_name
            continue

        if found_container and stripped.startswith("image:"):
            newline = "\n" if line.endswith("\n") else ""
            lines[idx] = f"{' ' * indent}image: {new_image}{newline}"
            return "".join(lines)

        if found_container and item_indent is not None and stripped.startswith("- ") and indent <= item_indent:
            found_container = False

    raise ValueError(f"container {container_name!r} image field not found in service YAML")


def unified_diff(before: str, after: str, before_name: str, after_name: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=before_name,
            tofile=after_name,
        )
    )


def upsert_variable(
    variables: list[dict[str, Any]],
    key: str,
    value: Any,
    value_type: str = "string",
    desc: str = "",
    options: list[Any] | None = None,
) -> list[dict[str, Any]]:
    updated = {
        "key": key,
        "value": value,
        "type": value_type,
        "options": options or [],
        "desc": desc,
    }

    result = [dict(item) for item in variables if isinstance(item, dict)]
    for idx, item in enumerate(result):
        if item.get("key") == key:
            merged = dict(item)
            merged.update(updated)
            result[idx] = merged
            break
    else:
        result.append(updated)

    return result
