# zadig-mcp

Basic MCP server for Zadig OpenAPI.

## Version target

This tool targets StoreHub's Zadig 4.3 deployment. API behavior should be
checked against the live `zadigx.shub.us` instance and Zadig
`release-4.3.0` source when public documentation is incomplete.

## Tools

- `zadig_workflow_list`: list/search project workflows.
- `zadig_workflow_get`: get one custom workflow detail.
- `zadig_workflow_create`: create one custom workflow. Defaults to dry run and requires `confirm=true`.
- `zadig_workflow_update`: update one custom workflow. Defaults to dry run and requires `confirm=true`.
- `zadig_workflow_delete`: delete one custom workflow. Defaults to dry run and requires `confirm=true`.
- `zadig_workflow_diff`: diff current workflow detail against a desired workflow payload.
- `zadig_workflow_apply`: create or update one workflow. Defaults to dry run and requires `confirm=true`.
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
- `zadig_build_template_create`: create one build template store template. Defaults to dry run and requires `confirm=true`.
- `zadig_build_template_update`: update one build template store template. Defaults to dry run and requires `confirm=true`.
- `zadig_build_template_delete`: delete one build template store template. Defaults to dry run and requires `confirm=true`.
- `zadig_build_template_diff`: diff current build template detail against a desired payload.
- `zadig_build_template_apply`: create or update one build template. Defaults to dry run and requires `confirm=true`.
- `zadig_build_get`: get one build configuration detail.
- `zadig_build_update`: update one build configuration. Defaults to dry run and requires `confirm=true`.
- `zadig_build_update_from_template`: update a build created from a build template. Defaults to dry run and requires `confirm=true`.
- `zadig_service_search`: list/search K8s YAML services.
- `zadig_service_get`: get service detail, including YAML and variables.
- `zadig_service_update_variables`: replace service variables. Requires `confirm=true`.
- `zadig_service_set_variable`: upsert a single service variable. Defaults to dry run.
- `zadig_service_set_image`: update a container image in service YAML. Defaults to dry run.
- `zadig_environment_list`: list test or production environments.
- `zadig_environment_get`: get one environment detail.
- `zadig_environment_create`: create one environment. Defaults to dry run and requires `confirm=true`.
- `zadig_environment_update`: update one environment registry/global variables. Defaults to dry run and requires `confirm=true`.
- `zadig_environment_delete`: delete one environment. Defaults to dry run and requires `confirm=true`.
- `zadig_environment_diff`: diff current environment against desired `Environment` spec.
- `zadig_environment_apply`: create or update one environment. Defaults to dry run and requires `confirm=true`.
- `zadig_environment_service_list`: list services in an environment.
- `zadig_environment_service_get`: get service detail in an environment.
- `zadig_environment_service_apply`: add or update one environment service. Defaults to dry run and requires `confirm=true`.
- `zadig_environment_service_delete`: delete one environment service. Defaults to dry run and requires `confirm=true`.

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

`zadig-gitops snapshot` exports a redacted project snapshot into a stable YAML
file tree that is suitable for Git review and later PR-based change loops.

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
    project.yaml
    _snapshot/
      metadata.yaml
      errors.yaml
    iterations/index.yaml
    workflows/index.yaml
    workflows/details/<workflow>.yaml
    webhooks/<workflow>.yaml
    builds/index.yaml
    workflows/index.yaml
    workflows/items/<workflow>.yaml
    workflows/scripts/<workflow>/<stage>.<job>.script.sh
    workflows/scripts/index.yaml
    workflows/triggers/<workflow>.yaml
    workflows/notifications/<workflow>.yaml
    builds/items/<build>.yaml
    builds/scripts/<script>.sh
    builds/scripts/<script>.meta.yaml
    tests/index.yaml
    code-scans/index.yaml
    services/index.yaml
    services/items/<service>.yaml
    environments/index.yaml
    releases/index.yaml
  templates/
    build-templates/
      index.yaml
      <template>.<id>.yaml
    helm-charts/
      <chart>/
        Chart.yaml
        values.yaml
        templates/
```

Project snapshots only include build templates that are actually referenced by
that project, and those templates are written under `templates/` because Zadig
template-library resources are shared resources rather than project-owned
resources.

Per-template files under `templates/build-templates/` are exported as
`kind: BuildTemplate` documents. Their `spec` is the desired Zadig template
payload; `metadata.id` keeps the live template ID when known, and `metadata.name`
is used to resolve the template when the ID is absent.

When a build template contains non-empty script fields such as `scripts`,
`pre_build.scripts`, or `post_build.scripts`, `snapshot-template` writes those
scripts under `templates/build-templates/scripts/<template>/` and replaces the
inline value with a `*_ref` object containing the path and SHA-256 checksum.
Template apply expands those refs back into the Zadig template payload after
verifying the checksum. This keeps template metadata reviewable while preserving
exact scripts as separate files.

`_snapshot/errors.yaml` is not Zadig configuration. It records snapshot-time API
failures or unsupported sections so GitOps reviewers can tell whether an export
is complete.

`services/index.yaml` is an inventory only. Per-service files under
`services/items/` hold the live service detail and a GitOps-oriented `spec`
section that later service CRUD apply commands can use.

`builds/index.yaml` is also an inventory only. Per-build files under
`builds/items/` hold the live build detail and a GitOps-oriented `spec`.
When a build has a `build_script`, snapshot writes the script under
`projects/<project>/builds/scripts/` and replaces the inline script with
`spec.build_script_ref`. Multiple builds with identical scripts share one
script file and the matching `.meta.yaml` lists the `used_by` impact set. Build
apply expands the script ref back into the Zadig `build_script` payload after
checking the optional SHA-256 checksum.

`project.yaml` is the top-level project document exported from live Zadig
project metadata. It is currently read-only snapshot data plus a small
GitOps-oriented `spec`.

Workflow snapshots are split for reviewability:

- `workflows/items/<workflow>.yaml` stores the main `kind: Workflow` desired
  state.
- `workflows/scripts/<workflow>/*.sh` stores long job scripts referenced by
  `script_ref` with a SHA-256 checksum.
- `workflows/triggers/<workflow>.yaml` stores `kind: WorkflowTriggers` under the
  workflow namespace.
- `workflows/notifications/<workflow>.yaml` stores `kind: WorkflowNotifications`.

Workflow apply expands `script_ref` and `notifications_ref` back into the Zadig
workflow payload. Trigger apply is intentionally separate so webhook drift can
be reviewed without mixing it into stage/job changes.

Environment snapshots are split for future CRUD support:

```text
projects/<project>/environments/
  index.yaml
  items/
    <env>.yaml
  services/
    <env>/
      index.yaml
      <service>.yaml
```

`items/<env>.yaml` is a `kind: Environment` document for cluster, namespace,
registry, global variables, and a `services_ref`. Environment service placement
is exported separately as `kind: EnvironmentService` files under
`services/<env>/`, so changing the environment and changing service deployment
state remain reviewable as separate diffs.

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

Export the shared build-template library independently from project snapshots:

```bash
uv run zadig-gitops snapshot-template \
  --output ./zadig-config
```

Export one template by name or id:

```bash
uv run zadig-gitops snapshot-template \
  --template fat-build \
  --output ./zadig-config
```

Snapshot output is redacted by default. Credential-like fields and variables
marked with `is_credential=true` are written as `***redacted***`.

Apply a workflow from YAML. This is a dry-run unless `--confirm` is set.

```bash
uv run zadig-gitops apply \
  --project fat \
  --workflow my-new-workflow \
  --file ./zadig-config/projects/fat/workflows/items/my-new-workflow.yaml
```

Print only the diff:

```bash
uv run zadig-gitops apply \
  --project fat \
  --workflow my-new-workflow \
  --file ./zadig-config/projects/fat/workflows/items/my-new-workflow.yaml \
  --diff
```

You can omit `--file/--dir` when using the default config layout:

```bash
uv run zadig-gitops apply workflow \
  --project fat \
  --workflow my-new-workflow \
  --diff
```

Actually create or update the workflow:

```bash
uv run zadig-gitops apply \
  --project fat \
  --workflow my-new-workflow \
  --file ./zadig-config/projects/fat/workflows/items/my-new-workflow.yaml \
  --confirm
```

Real apply rejects files that still contain `***redacted***` placeholders by
default. Replace the placeholder values before applying, or pass
`--allow-redacted` only when the target fields are intentionally redacted-safe.

Apply service desired state from per-service YAML files. This is also dry-run
unless `--confirm` is set.

```bash
uv run zadig-gitops apply service \
  --project bi \
  --file ./zadig-config/projects/bi/services/items/product-insights.yaml
```

Apply all service files in a project:

```bash
uv run zadig-gitops apply service \
  --project bi \
  --dir ./zadig-config/projects/bi/services
```

Delete live services that are missing from the desired service directory:

```bash
uv run zadig-gitops apply service \
  --project bi \
  --dir ./zadig-config/projects/bi/services \
  --prune \
  --confirm
```

Service apply currently supports creating Helm `chartTemplate` services,
deleting missing services with `--prune`, and updating supported mutable fields
(`spec.yaml` and `spec.template.variables`) when Zadig exposes them.

Apply build desired state from per-build YAML files. This is dry-run unless
`--confirm` is set.

```bash
uv run zadig-gitops apply build \
  --project bi \
  --file ./zadig-config/projects/bi/builds/items/bi-build.yaml
```

Build update defaults to `--build-update-api auto`: it first tries Zadig's
OpenAPI and falls back to the UI-compatible build API when the live instance
requires UI-only fields such as `codehost_id`. The fallback loads the live build
detail, preserves repository/codehost/target fields, and maps only supported
desired fields such as `build_script`, `post_build`, `outputs`, and `timeout`.
Use `--build-update-api ui` to force that path for known script-only updates.

Apply all build files in a project:

```bash
uv run zadig-gitops apply build \
  --project bi \
  --dir ./zadig-config/projects/bi/builds
```

Delete live builds that are missing from the desired build directory:

```bash
uv run zadig-gitops apply build \
  --project bi \
  --dir ./zadig-config/projects/bi/builds \
  --prune \
  --confirm
```

Apply build template desired state from `templates/build-templates`. This is
dry-run unless `--confirm` is set.

```bash
uv run zadig-gitops apply template \
  --project fat \
  --file ./zadig-config/templates/build-templates/fat-build.<id>.yaml
```

Print only the template diff:

```bash
uv run zadig-gitops apply template \
  --project fat \
  --file ./zadig-config/templates/build-templates/fat-build.<id>.yaml \
  --diff
```

Delete a build template explicitly by name or id:

```bash
uv run zadig-gitops apply template \
  --project fat \
  --template fat-build \
  --mode delete
```

Template prune is intentionally unsupported because build templates are shared
library resources and the blast radius can cross projects. Delete templates one
at a time after checking references.

Apply environment desired state from `projects/<project>/environments`. This is
dry-run unless `--confirm` is set. Environment apply manages the environment
object itself, including registry and global variables; deployed services are
handled by `environment-service`.

```bash
uv run zadig-gitops apply environment \
  --project bi \
  --file ./zadig-config/projects/bi/environments/items/fat.yaml
```

Print only the environment diff:

```bash
uv run zadig-gitops apply environment \
  --project bi \
  --file ./zadig-config/projects/bi/environments/items/fat.yaml \
  --diff
```

Delete an environment explicitly. By default this only deletes the Zadig
environment record where supported; add `--delete-resources` only when the
underlying Kubernetes namespace/resources should also be removed.

```bash
uv run zadig-gitops apply environment \
  --project bi \
  --environment fat \
  --mode delete
```

Apply services deployed inside an environment:

```bash
uv run zadig-gitops apply environment-service \
  --project bi \
  --environment fat \
  --dir ./zadig-config/projects/bi/environments/services/fat
```

Delete one service from an environment. By default `not_delete_resource=true`;
add `--delete-resources` to ask Zadig to delete underlying Kubernetes resources.

```bash
uv run zadig-gitops apply environment-service \
  --project bi \
  --environment fat \
  --service csp-v1-web-fe \
  --mode delete
```

Plan project changes from `project.yaml`. Project apply is intentionally
plan-only for now: create/update/delete modes only compare desired config with
live Zadig state and never call mutating project APIs, even when `--confirm` is
passed.

```bash
uv run zadig-gitops apply project \
  --project bi \
  --dir ./zadig-config/projects/bi
```

```bash
uv run zadig-gitops apply project \
  --project bi \
  --mode delete
```
