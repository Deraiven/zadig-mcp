# zadig-mcp

Basic MCP server for Zadig OpenAPI.

## Tools

- `zadig_workflow_list`: list/search project workflows.
- `zadig_workflow_get`: get one custom workflow detail.
- `zadig_workflow_update`: update one custom workflow. Defaults to dry run and requires `confirm=true`.
- `zadig_project_snapshot`: create a redacted project snapshot for audit/GitOps preparation.
- `zadig_workflow_task_list`: list workflow tasks with deployment summaries.
- `zadig_workflow_task_detail`: get one workflow task detail with deployment summaries.
- `zadig_workflow_task_job_log`: get one workflow task job log, with tail and keyword filtering.
- `zadig_workflow_webhook_list`: list saved webhook/git trigger settings for a workflow.
- `zadig_workflow_webhook_preset`: get current webhook/git trigger preset for a workflow.
- `zadig_workflow_webhook_compare_to_preset`: compare saved webhook/git trigger settings with the current preset.
- `zadig_build_list`: list/search build configurations.
- `zadig_build_template_list`: list/search build template store templates.
- `zadig_build_template_get`: get one build template store template by id or exact name.
- `zadig_build_template_reference`: list build configurations that reference one build template.
- `zadig_build_template_update`: update one build template store template. Defaults to dry run and requires `confirm=true`.
- `zadig_build_get`: get one build configuration detail.
- `zadig_build_update`: update one build configuration. Defaults to dry run and requires `confirm=true`.
- `zadig_build_update_from_template`: update a build created from a build template. Defaults to dry run and requires `confirm=true`.
- `zadig_service_search`: list/search K8s YAML services.
- `zadig_service_get`: get service detail, including YAML and variables.
- `zadig_service_update_variables`: replace service variables. Requires `confirm=true`.
- `zadig_service_set_variable`: upsert a single service variable. Defaults to dry run.
- `zadig_service_set_image`: update a container image in service YAML. Defaults to dry run.
- `zadig_environment_list`: list test or production environments.
- `zadig_environment_service_get`: get service detail in an environment.

## Config

```toml
[mcp_servers.zadig]
command = "uv"
args = ["--directory", "/Users/storehub/Desktop/devops-tools-auto/zadig-mcp", "run", "zadig-mcp"]

[mcp_servers.zadig.env]
ZADIG_BASE_URL = "https://zadigx.shub.us"
ZADIG_TOKEN = "replace-me"
ZADIG_PROJECT = "devops-tools"
UV_CACHE_DIR = "/tmp/uv-cache"
```

`ZADIG_PROJECT` is optional. Every tool also accepts `project_key`.

Workflow task tools use Zadig v4 workflow task read APIs and return compact
summaries by default. Set `include_raw=true` only when the caller needs the raw
task payload; credential-like fields are recursively redacted before returning.

## Development

```bash
uv run python -m py_compile zadig_mcp/*.py
uv run zadig-mcp
```

## GitOps preparation

`zadig-gitops snapshot` exports a redacted project snapshot into a stable file
tree that is suitable for Git review and later PR-based change loops.

```bash
ZADIG_BASE_URL="https://zadigx.shub.us" \
ZADIG_TOKEN="..." \
uv run zadig-gitops snapshot \
  --project fat \
  --output ./zadig-config
```

The output layout is:

```text
zadig-config/
  projects/<project>/
    metadata.json
    errors.json
    workflows/index.json
    workflows/details/<workflow>.json
    webhooks/<workflow>.json
    builds/index.json
    build-templates/index.json
    build-templates/<template>.<id>.json
    build-template-references/index.json
    services/index.json
    environments/index.json
```

For a smaller export:

```bash
uv run zadig-gitops snapshot \
  --project fat \
  --section workflows \
  --section workflow_details \
  --section webhooks \
  --workflow fat-pipelines \
  --output ./zadig-config
```

Snapshot output is redacted by default. Credential-like fields and variables
marked with `is_credential=true` are written as `***redacted***`.
