# Tool Configuration Hardening Recipes

Disable AI attribution at the source before relying on Git hooks as a safety net. Always preview changes first with `harden-configs` (dry-run default) before passing `--apply`.

## 1. Claude Code (`~/.claude/settings.json` or `.claude/settings.json`)

Modern Claude Code uses the `attribution` object (superseding the deprecated `includeCoAuthoredBy` boolean):

```json
{
  "attribution": {
    "commit": "",
    "pr": ""
  }
}
```

### Optional: Claude Code `SessionStart` + `PreToolUse` Hooks
- **`SessionStart`** (`session-start`): Automatically evaluates `git remote` scope at startup/resume/compact and injects clean-contribution guidance via official `hookSpecificOutput.additionalContext` whenever working in external/public repos.
- **`PreToolUse`** (`pre-tool-guard`): Blocks `git commit`, `git add`, `gh pr create/edit`, and `gh issue` commands containing AI watermarks, confidential blocked terms, or agent trace files *before* Bash executes:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/undercover.py session-start"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/undercover.py pre-tool-guard"
          }
        ]
      }
    ]
  }
}
```

Automate attribution disabling + both hooks with automatic backup:
```bash
python3 ./scripts/undercover.py harden-configs --claude --with-claude-hook --apply
```

## 2. Google Antigravity (`~/.gemini/config/hooks.json` or `.agents/hooks.json`)

Both `session-start` and `pre-tool-guard` auto-detect Antigravity's camelCase hook payloads (`SessionStart` uses a flat handler array returning `injectSteps`; `PreToolUse` returns `{"decision": "deny", "reason": "..."}`):

```json
{
  "undercover-guard": {
    "enabled": true,
    "SessionStart": [
      {
        "type": "command",
        "command": "python3 /path/to/undercover.py session-start",
        "timeout": 10
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/undercover.py pre-tool-guard",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Automate with:
```bash
python3 ./scripts/undercover.py harden-configs --antigravity-hook --apply
```

## 2b. Fail-Closed Remote Allowlist Policy (`~/.config/undercover/config.json`)

Configure private/internal remote patterns so hooks stand down on internal repos while staying automatically active (fail-closed) on every external, public, or unconnected repository:

```json
{
  "mode": "auto",
  "internal_remotes": [
    "github.com/my-private-org/*",
    "git.corp.local/*"
  ],
  "blocked_terms": [
    "ConfidentialCodename",
    "internal-wiki.local"
  ]
}
```

Manage safely with dry-run & backup:
```bash
python3 ./scripts/undercover.py init-policy --mode auto --internal-remotes "github.com/my-private-org/*" --blocked-terms "ConfidentialCodename" --apply
python3 ./scripts/undercover.py repo-status /path/to/repo
```
Set `UNDERCOVER_FORCE=1` to force enforcement on even inside allowlisted internal repositories.

## 3. Aider (`~/.aider.conf.yml` or `<repo>/.aider.conf.yml`)

```yaml
attribute-author: false
attribute-committer: false
attribute-co-authored-by: false
```

Equivalent environment variables:
```bash
export AIDER_ATTRIBUTE_AUTHOR=false
export AIDER_ATTRIBUTE_COMMITTER=false
export AIDER_ATTRIBUTE_CO_AUTHORED_BY=false
```

Automate with:
```bash
python3 ./scripts/undercover.py harden-configs --aider --apply
```

## 4. VS Code & Cursor (`settings.json`)

Disable automatic AI co-author trailer injection in editor Git integration:
```json
{
  "git.addAICoAuthor": false
}
```
Automate with:
```bash
python3 ./scripts/undercover.py harden-configs --editors --apply
```

## 5. Private Local Ignore (`.git/info/exclude` instead of `.gitignore`)

Adding `.claude/` or `.cursorrules` to a repository's tracked `.gitignore` itself signals AI tooling usage to anyone inspecting `.gitignore`. Put private ignores in `.git/info/exclude` (never committed) or global `~/.config/git/ignore`:

```bash
python3 ./scripts/undercover.py harden-configs --project /path/to/repo --apply
```

## 6. Codex CLI / Gemini CLI / OpenCode

These CLI agents follow `SKILL.md` / `AGENTS.md` / global skill instructions. Installing `undercover` via `./install.sh --all` plus global Git hooks (`install-hooks --global --mode scrub --apply`) guarantees zero watermark leaks regardless of which agent invokes `git commit` or `git push`.
