# omarchy-plugin-guard

Review Omarchy shell plugin updates **before** they merge into `~/.config/omarchy/plugins`.

Plugins run unsandboxed inside the long-lived `omarchy-shell` process. `omarchy plugin validate` only checks the manifest schema. This tool:

1. `git fetch`es without touching the live tree
2. Snapshots `FETCH_HEAD` and runs mechanical gates on the incoming tree
3. Compares capabilities against the previous commit (and a stored baseline)
4. Sends the diff to a **read-only** local Cursor agent
5. Fast-forwards **only the reviewed SHA** (no second fetch)

## Install

```bash
cd ~/Projects/omarchy-plugin-guard
python3 -m venv .venv
.venv/bin/pip install -e .
ln -sf "$PWD/.venv/bin/omarchy-plugin-guard" ~/.local/bin/omarchy-plugin-guard
```

Export a Cursor user API key (Dashboard → Integrations):

```bash
export CURSOR_API_KEY=cursor_...
```

Optional: `CURSOR_MODEL` (default `composer-2.5`).

## First run

Trust the currently installed trees as the capability baseline:

```bash
omarchy-plugin-guard baseline --write
omarchy-plugin-guard status
```

Then update through the guard instead of `omarchy plugin update`:

```bash
omarchy-plugin-guard update --dry-run
omarchy-plugin-guard update
omarchy-plugin-guard add https://github.com/acme/omarchy-weather.git
```

## Verdicts

| Combined verdict | `--yes` | `--force` |
| --- | --- | --- |
| `allow` (clean delta, agent allow, no new capabilities) | applies | applies |
| `needs-human` (new Process/network/binary, origin change, no baseline, agent unsure) | skipped | applies |
| `deny` (pipe-to-shell, credential paths, agent deny, agent failure) | refused | refused |

`--skip-agent` never auto-applies; it still ends `needs-human`.

On `needs-human`, the CLI prints **NEEDS HUMAN REVIEW** and the reasons (plus the agent summary) **before** the accept/deny prompt. Denies print **DENIED — will not apply** and never ask.

State lives in `~/.config/omarchy/plugin-guard/` (`baselines/`, `reviews/`).

## Commands

```text
omarchy-plugin-guard status
omarchy-plugin-guard baseline --write
omarchy-plugin-guard review [--json]
omarchy-plugin-guard update [id] [--dry-run] [--yes] [--force] [--skip-agent] [--json]
omarchy-plugin-guard add <git-url> [--enable] [--dry-run] [--force]
```

Exit codes: `0` ok / up to date / applied, `1` hard error, `2` denied or skipped.
