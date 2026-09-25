# devplatform-quality-check
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The DevPlatform Quality Check repository holds a suite of custom policies designed to enforce security and compliance standards for application teams deploying through DevPlatform's Secure Pipelines.

The policies are written as [Checkov](https://www.checkov.io/) custom checks and are published as a reusable GitHub composite action so that any application repository can scan its own CloudFormation/SAM templates against them.

## What the action does

`.github/actions/quality-check` runs a Checkov scan of your templates using both the standard Checkov rule set and the custom DevPlatform checks in [`src/checks`](src/checks). In a single job step it:

1. Checks out this repository into `.devplatform-quality-check` so the custom checks are available locally.
2. Works out which `*.yaml` files changed on the branch (`git diff --name-only origin/main...HEAD`) so only modified templates are scanned.
3. Installs Checkov on Python 3.12.
4. Runs Checkov against the changed files with `--external-checks-dir .devplatform-quality-check/src/checks/`, writing results to the console and to `results.sarif`.
5. Uploads `results.sarif` to GitHub code scanning under the category `devplatform-quality-check`. This runs on success or failure, so findings are always published.

A policy failure **fails the step and the pull request check**. Findings are printed in the job log and also appear in the repository's **Security → Code scanning** tab, annotated against the offending lines. To ship a template that a check flags, either fix the template or add a Checkov [inline suppression](https://www.checkov.io/2.Basics/Suppressing%20and%20Skipping%20Policies.html) with a justification:

## Usage

Add the action as a step in an existing job that has already checked out your repository:

```yaml
jobs:
  pre-merge-checks:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # required to upload the SARIF results
    steps:
      - name: Checkout
        uses: actions/checkout@v7
        with:
          fetch-depth: 0 # required so the action can diff against origin/main

      - name: Quality check
        uses: govuk-one-login/devplatform-quality-check/.github/actions/quality-check@v1
        with:
          framework: cloudformation
          ref: v1
```

### Inputs

| Input       | Required | Default          | Description                                                                                                            |
|-------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------|
| `framework` | No       | `cloudformation` | Checkov framework to scan with. Use `cloudformation` for SAM and CloudFormation templates.                             |
| `ref`       | No       | `v1`             | Tag or branch of this repository to load the custom checks from. Keep it aligned with the `@ref` you pin the action to. |

### Prerequisites

* `fetch-depth: 0` (or a fetch of `main`) is needed, otherwise the changed-files diff against `origin/main` cannot be resolved.
* `security-events: write` is needed for the SARIF upload. Without it the upload step fails even though the scan itself succeeded.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest test/ -v
```

Each check lives in `src/checks` with shared template-parsing logic in `src/checks/helpers.py`. Tests live in `test/<check>/` with pass/fail CloudFormation fixtures under `fixtures/`; add a fixture per scenario and assert the expected `CheckResult`. To reproduce what the action runs, scan a template locally with:

```bash
checkov -f path/to/template.yaml \
  --framework cloudformation \
  --external-checks-dir src/checks/
```

## Licence
[MIT License](LICENSE)
