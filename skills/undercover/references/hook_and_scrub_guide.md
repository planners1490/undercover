# Git Hooks & Safe History Scrubbing Guide

## 1. Layered Git Hook Defense

Install all three hooks in a single repository or globally across every repository on your machine:

| Hook | What It Checks | Default Behavior |
| :--- | :--- | :--- |
| **`commit-msg`** | AI `Co-Authored-By` / `Assisted-by` / `Made-with` trailers, `🤖 Generated with ...` footers, user `blocked_terms`, invisible Unicode in commit messages, AI bot author/committer env vars | Auto-scrubs commit message in place (`--mode scrub`) or rejects commit (`--mode block`); respects `internal_remotes` policy |
| **`pre-commit`** | Staged AI trace files (`.claude/`, `.cursor*`, `.aider*`, etc.), staged AI attribution comments, user `blocked_terms`, staged invisible Unicode watermarks | Blocks commit with exact file/line diagnostics; respects `internal_remotes` policy |
| **`pre-push`** | All outgoing commits not yet on the remote for AI trailers, user `blocked_terms`, bot author/committer identities, and invisible Unicode | Blocks push and prints the exact `scrub` command; respects `internal_remotes` policy |

### Preserving Existing Hooks (Husky / Lefthook / Custom)
- **Repo-local install (`--chain`)**: Moves any existing non-Undercover hook to `<hook>.pre-undercover` and invokes it after Undercover completes. Running `uninstall-hooks --apply` automatically restores the original hook.
- **Global install (`--global`)**: Installs hooks into `~/.config/undercover/hooks` and sets `git config --global core.hooksPath ~/.config/undercover/hooks`. Each global hook automatically detects and chains the current repo's `.git/hooks/<hook>` if executable.

### Intentional Allowlists & One-Time Bypass
- To allow specific tracked instruction files (e.g., `AGENTS.md` or `CLAUDE.md`) in a repository, list repo-relative paths in `.undercoverignore` (one per line) or set `UNDERCOVER_ALLOW_FILES="AGENTS.md,CLAUDE.md"`.
- For an explicit one-time manual bypass:
  ```bash
  UNDERCOVER_SKIP=1 git commit -m "..."
  ```

## 2. Safe Commit History Scrubbing (`scrub`)

`undercover.py scrub` rewrites commit metadata using pure `git commit-tree` + atomic `git update-ref` (zero external dependencies, no deprecated `git filter-branch`). It preserves exact file trees, merge parent DAG topology, and original author/committer timestamps.

### Built-In Safety Rails
1. **Clean working tree required** when running `--apply`.
2. **Dry-run by default** — inspects every commit and reports exact removals without altering any ref.
3. **Unpushed-only by default** (`@{u}..HEAD`) — refuses to rewrite commits already reachable from `refs/remotes/*` unless `--allow-pushed` is explicitly passed.
4. **Automatic backup ref** — before touching the branch ref, saves the original HEAD at `refs/undercover-backup/<branch>-<UTC_TIMESTAMP>` and prints the exact rollback command:
   ```bash
   git reset --hard refs/undercover-backup/<branch>-<timestamp>
   ```
5. **Signed commit warning** — detects `gpgsig` headers and flags `signed_commits_warning: true` because rewritten commits have new SHA-1/SHA-256 hashes and drop old signatures.

### Common Scrub Workflows

Scrub unpushed commits on a tracked branch:
```bash
python3 ./scripts/undercover.py scrub /path/to/repo
python3 ./scripts/undercover.py scrub /path/to/repo --apply
```

Scrub a fresh local branch with no upstream yet:
```bash
python3 ./scripts/undercover.py scrub /path/to/repo --all-local --apply
```

Scrub from a specific base commit (and replace any bot email with your human identity):
```bash
python3 ./scripts/undercover.py scrub /path/to/repo \
  --base HEAD~5 \
  --author-name "Your Name" \
  --author-email "you@example.com" \
  --apply
```

Verify zero leaks remain:
```bash
python3 ./scripts/undercover.py audit /path/to/repo --unpushed --output /tmp/post_scrub.json
```
