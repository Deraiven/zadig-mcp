import json
import os
from typing import Any
from urllib.parse import quote

import httpx


class ZadigConfigError(RuntimeError):
    pass


class ZadigAPIError(RuntimeError):
    pass


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


class ZadigClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 30.0):
        self.base_url = (base_url or _env("ZADIG_BASE_URL") or "").rstrip("/")
        self.token = token or _env("ZADIG_TOKEN") or ""
        self.timeout = timeout
        if not self.base_url:
            raise ZadigConfigError("missing ZADIG_BASE_URL")
        if not self.token:
            raise ZadigConfigError("missing ZADIG_TOKEN")

    async def request(
        self,
        method: str,
        path: str,
        *,
        project_key: str | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
    ) -> Any:
        query = dict(params or {})
        if project_key:
            query["projectKey"] = project_key

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.request(
                    method,
                    url,
                    params=query or None,
                    headers=headers,
                    json=json_body,
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                body = exc.response.text
                raise ZadigAPIError(f"{method} {url} failed: HTTP {exc.response.status_code}: {body}") from exc
            except httpx.HTTPError as exc:
                raise ZadigAPIError(f"{method} {url} failed: {exc}") from exc

        if not response.content:
            return None

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()

        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text


def default_project(project_key: str | None = None) -> str:
    project = project_key or _env("ZADIG_PROJECT")
    if not project:
        raise ZadigConfigError("missing project_key or ZADIG_PROJECT")
    return project


def service_prefix(production: bool = False) -> str:
    return "/openapi/service/yaml/production" if production else "/openapi/service/yaml"


def environment_prefix(production: bool = False) -> str:
    return "/openapi/environments/production" if production else "/openapi/environments"


def path_name(name: str) -> str:
    return quote(name, safe="")
