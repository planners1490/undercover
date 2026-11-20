#!/usr/bin/env python3
"""Comprehensive end-to-end tests for UNDERCOVER AI watermark neutralization CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "skills" / "undercover" / "scripts" / "undercover.py"


def run_cli(
    args: list[str],
    *,
    cwd: Path | None = None,
    stdin_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(cwd) if cwd else None,
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
        check=False,
    )


def git(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    # Prevent any user global core.hooksPath from interfering with isolated test repos
    merged_env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    if env:
        merged_env.update(env)
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
        check=False,
    )


def init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    git(["init", "-b", "main"], path)
    git(["config", "user.name", "Alice Engineer"], path)
    git(["config", "user.email", "alice@example.com"], path)
    # Explicitly point hooksPath to local .git/hooks so tests are hermetic
    git(["config", "core.hooksPath", str(path / ".git" / "hooks")], path)


class TestSanitizeText(unittest.TestCase):
    def test_strips_ai_trailers_and_preserves_humans(self) -> None:
        raw = (
            "feat: implement parser\n\n"
            "Detailed explanation.\n\n"
            "Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>\n"
            "Co-authored-by: cursoragent <cursoragent@cursor.com>\n"
            "Made-with: Cursor\n"
            "Assisted-by: codex:gpt-5.3\n"
            "Co-Authored-By: Claude Dupont <claude.dupont@company.com>\n"
            "Signed-off-by: Alice Engineer <alice@example.com>\n"
            "🤖 Generated with [Claude Code](https://claude.com/claude-code)\n"
        )
        proc = run_cli(["sanitize-text", "--kind", "commit"], stdin_text=raw)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertNotIn("noreply@anthropic.com", out)
        self.assertNotIn("cursoragent", out)
        self.assertNotIn("Made-with: Cursor", out)
        self.assertNotIn("Assisted-by: codex", out)
        self.assertNotIn("Generated with", out)
        # Human co-author named Claude Dupont AND Signed-off-by MUST survive
        self.assertIn("Co-Authored-By: Claude Dupont <claude.dupont@company.com>", out)
        self.assertIn("Signed-off-by: Alice Engineer <alice@example.com>", out)

    def test_pr_footer_and_dangling_divider_cleanup(self) -> None:
        raw = (
            "## Summary\n"
            "- Fix retry backoff logic\n\n"
            "---\n"
            "🤖 Generated with [Claude Code](https://claude.com/claude-code)\n"
        )
        proc = run_cli(["sanitize-text", "--kind", "pr"], stdin_text=raw)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "## Summary\n- Fix retry backoff logic\n")

    def test_check_mode_exits_nonzero_on_watermark(self) -> None:
        raw = "fix: edge case\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"
        proc = run_cli(["sanitize-text", "--kind", "commit", "--mode", "check"], stdin_text=raw)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Blocked AI watermark", proc.stderr)


class TestPreToolGuard(unittest.TestCase):
    def test_claude_code_protocol_blocks_watermarked_commit(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": 'git commit -m "feat: ok\\n\\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"'
            },
        }
        proc = run_cli(["pre-tool-guard"], stdin_text=json.dumps(payload))
        self.assertEqual(proc.returncode, 0)
        resp = json.loads(proc.stdout)
        self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("UNDERCOVER GUARD", resp["hookSpecificOutput"]["permissionDecisionReason"])

    def test_claude_code_protocol_blocks_pr_footer_and_agent_add(self) -> None:
        for cmd in (
            'gh pr create --title "Fix" --body "Done\n🤖 Generated with [Claude Code](https://claude.com/claude-code)"',
            "git add .claude/settings.local.json src/app.py",
        ):
            payload = {"tool_name": "Bash", "tool_input": {"command": cmd}}
            proc = run_cli(["pre-tool-guard"], stdin_text=json.dumps(payload))
            self.assertEqual(proc.returncode, 0)
            resp = json.loads(proc.stdout)
            self.assertEqual(resp["hookSpecificOutput"]["permissionDecision"], "deny", cmd)

    def test_claude_code_protocol_allows_clean_commands(self) -> None:
        for cmd in (
            'git commit -m "feat: add unit tests"',
            "ls -la",
            "pytest tests/",
        ):
            payload = {"tool_name": "Bash", "tool_input": {"command": cmd}}
            proc = run_cli(["pre-tool-guard"], stdin_text=json.dumps(payload))
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout.strip(), "", cmd)

    def test_antigravity_protocol_denies_and_allows(self) -> None:
        bad = {
            "hookEventName": "PreToolUse",
            "toolCall": {
                "id": "t1",
                "name": "run_command",
                "args": {"CommandLine": 'git commit -m "fix\\n\\nMade-with: Cursor"'},
            },
        }
        proc = run_cli(["pre-tool-guard"], stdin_text=json.dumps(bad))
        self.assertEqual(proc.returncode, 0)
        resp = json.loads(proc.stdout)
        self.assertEqual(resp["decision"], "deny")

        good = {
            "hookEventName": "PreToolUse",
            "toolCall": {
                "id": "t2",
                "name": "run_command",
                "args": {"CommandLine": 'git commit -m "fix: handle empty list"'},
            },
        }
        proc2 = run_cli(["pre-tool-guard"], stdin_text=json.dumps(good))
        self.assertEqual(proc2.returncode, 0)
        resp2 = json.loads(proc2.stdout)
        self.assertEqual(resp2["decision"], "allow")


class TestUnicodeAndComments(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="undercover_unicode_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unicode_cleans_watermarks_preserves_korean_and_emoji(self) -> None:
        f = self.tmp / "sample.py"
        # Include: Korean text, emoji ZWJ (👨‍💻), Unicode Tag U+E0041, ZWSP U+200B, NNBSP U+202F
        original = (
            "# 한국어 주석 테스트 👨‍💻\n"
            "msg = 'hello\u200bworld\U000E0041\U000E0042'\n"
            "time_str = '10:30\u202fAM'\n"
        )
        f.write_text(original, encoding="utf-8")

        # Dry run first
        dry = run_cli(["clean-unicode", str(f)])
        self.assertEqual(dry.returncode, 0, dry.stderr)
        data = json.loads(dry.stdout)
        self.assertEqual(data["mode"], "dry_run")
        self.assertEqual(data["total_chars"], 4)  # ZWSP + 2 tag chars + NNBSP; emoji ZWJ preserved!
        self.assertEqual(f.read_text(encoding="utf-8"), original)

        # Apply
        app = run_cli(["clean-unicode", str(f), "--apply"])
        self.assertEqual(app.returncode, 0, app.stderr)
        cleaned = f.read_text(encoding="utf-8")
        self.assertIn("한국어 주석 테스트 👨‍💻", cleaned)
        self.assertIn("msg = 'helloworld'", cleaned)
        self.assertIn("time_str = '10:30 AM'", cleaned)

    def test_clean_comments_removes_only_ai_attribution_comments(self) -> None:
        f = self.tmp / "app.ts"
        original = (
            "// Generated by Claude Code\n"
            "// Normal architectural comment about Claude API client\n"
            "export const x = 1;\n"
            "/* Auto-generated with Cursor AI */\n"
            "// TODO(copilot): refactor this\n"
        )
        f.write_text(original, encoding="utf-8")

        proc = run_cli(["clean-comments", str(f), "--apply"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cleaned = f.read_text(encoding="utf-8")
        self.assertNotIn("Generated by Claude Code", cleaned)
        self.assertNotIn("Auto-generated with Cursor AI", cleaned)
        self.assertNotIn("TODO(copilot)", cleaned)
        self.assertIn("// Normal architectural comment about Claude API client", cleaned)
        self.assertIn("export const x = 1;", cleaned)


class TestGitHooksAuditAndScrub(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="undercover_git_"))
        self.repo = self.tmp / "repo"
        self.remote = self.tmp / "remote.git"
        init_repo(self.repo)
        git(["init", "--bare", str(self.remote)], self.tmp)
        git(["remote", "add", "origin", str(self.remote)], self.repo)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_hooks_scrubs_commits_and_blocks_artifacts_and_chains_existing(self) -> None:
        # Place a custom pre-existing commit-msg hook to test --chain
        existing_hook = self.repo / ".git" / "hooks" / "commit-msg"
        marker_file = self.tmp / "chained_ran.txt"
        existing_hook.write_text(f"#!/usr/bin/env bash\necho chained > {marker_file}\n", encoding="utf-8")
        existing_hook.chmod(0o755)

        # Without --chain, install-hooks should report conflict (exit 1)
        conflict = run_cli(["install-hooks", "--repo", str(self.repo), "--apply"])
        self.assertEqual(conflict.returncode, 1)

        # With --chain, install succeeds and preserves original hook
        inst = run_cli(["install-hooks", "--repo", str(self.repo), "--mode", "scrub", "--chain", "--apply"])
        self.assertEqual(inst.returncode, 0, inst.stderr)
        self.assertTrue((self.repo / ".git" / "hooks" / "commit-msg.pre-undercover").exists())

        # Commit with Claude Code watermark -> commit-msg hook scrubs it automatically!
        (self.repo / "hello.py").write_text("print('hi')\n", encoding="utf-8")
        git(["add", "hello.py"], self.repo)
        c = git(
            [
                "commit",
                "-m",
                "feat: initial\n\nCo-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>\n🤖 Generated with [Claude Code](https://claude.com/claude-code)",
            ],
            self.repo,
        )
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertTrue(marker_file.exists(), "Chained pre-existing hook did not execute")
        msg = git(["log", "-1", "--format=%B"], self.repo).stdout
        self.assertNotIn("Co-Authored-By", msg)
        self.assertNotIn("Generated with", msg)
        self.assertIn("feat: initial", msg)

        # Staging .claude/settings.local.json -> pre-commit hook MUST block
        (self.repo / ".claude").mkdir()
        (self.repo / ".claude" / "settings.local.json").write_text("{}", encoding="utf-8")
        git(["add", "-f", ".claude/settings.local.json"], self.repo)
        blocked = git(["commit", "-m", "chore: leak"], self.repo)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("Blocked commit due to AI watermark leaks", blocked.stderr)
        git(["reset", "HEAD", ".claude/settings.local.json"], self.repo)
        shutil.rmtree(self.repo / ".claude")

        # Uninstall hooks -> restores original pre-existing commit-msg hook
        uninst = run_cli(["uninstall-hooks", "--repo", str(self.repo), "--apply"])
        self.assertEqual(uninst.returncode, 0, uninst.stderr)
        self.assertIn("chained_ran.txt", existing_hook.read_text(encoding="utf-8"))
        self.assertFalse((self.repo / ".git" / "hooks" / "commit-msg.pre-undercover").exists())

    def test_audit_and_scrub_unpushed_with_pushed_protection_and_rollback(self) -> None:
        # Commit 1 (clean, pushed to origin/main)
        (self.repo / "a.py").write_text("a = 1\n", encoding="utf-8")
        git(["add", "a.py"], self.repo)
        git(["commit", "-m", "feat: clean base"], self.repo)
        p = git(["push", "-u", "origin", "main"], self.repo)
        self.assertEqual(p.returncode, 0, p.stderr)

        # Commit 2 (unpushed, dirty with Claude trailer + Aider author suffix)
        (self.repo / "b.py").write_text("b = 2\n", encoding="utf-8")
        git(["add", "b.py"], self.repo)
        git(
            [
                "commit",
                "-m",
                "feat: add b\n\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>\nGenerated with [Claude Code](https://claude.com/claude-code)",
            ],
            self.repo,
            env={"GIT_AUTHOR_NAME": "Alice Engineer (aider)", "GIT_COMMITTER_NAME": "Alice Engineer (aider)"},
        )

        # Commit 3 (unpushed, clean child commit that must be replayed on top of scrubbed parent)
        (self.repo / "c.py").write_text("c = 3\n", encoding="utf-8")
        git(["add", "c.py"], self.repo)
        git(["commit", "-m", "feat: add c"], self.repo)

        # Audit should catch CRITICAL findings
        audit_before = run_cli(["audit", str(self.repo), "--skip-configs"])
        self.assertEqual(audit_before.returncode, 0, audit_before.stderr)
        rep_before = json.loads(audit_before.stdout)
        self.assertGreater(rep_before["severity_counts"]["CRITICAL"], 0)
        self.assertIn(rep_before["stealth_grade"], ("D", "F"))

        # Scrub dry-run should detect 1 dirty commit without changing HEAD
        old_head = git(["rev-parse", "HEAD"], self.repo).stdout.strip()
        dry = run_cli(["scrub", str(self.repo)])
        self.assertEqual(dry.returncode, 0, dry.stderr)
        dry_data = json.loads(dry.stdout)
        self.assertEqual(dry_data["commits_with_watermarks"], 1)
        self.assertEqual(dry_data["commits_rewritten"], 0)
        self.assertEqual(git(["rev-parse", "HEAD"], self.repo).stdout.strip(), old_head)

        # Scrub --apply rewrites commit 2 & replays commit 3, creates backup ref, preserves all file trees
        applied = run_cli(["scrub", str(self.repo), "--apply"])
        self.assertEqual(applied.returncode, 0, applied.stderr)
        app_data = json.loads(applied.stdout)
        self.assertEqual(app_data["commits_rewritten"], 2)
        self.assertIsNotNone(app_data["backup_ref"])
        self.assertNotEqual(app_data["new_head"], old_head)

        # Verify backup ref points to original HEAD
        bak_oid = git(["rev-parse", app_data["backup_ref"]], self.repo).stdout.strip()
        self.assertEqual(bak_oid, old_head)

        # Verify author & messages are clean while files are untouched
        log_out = git(["log", "--format=%an|%B---"], self.repo).stdout
        self.assertNotIn("noreply@anthropic.com", log_out)
        self.assertNotIn("(aider)", log_out)
        self.assertIn("Alice Engineer|feat: add b", log_out)
        self.assertEqual((self.repo / "c.py").read_text(encoding="utf-8"), "c = 3\n")

        # Post-scrub audit must be grade A!
        audit_after = run_cli(["audit", str(self.repo), "--skip-configs"])
        rep_after = json.loads(audit_after.stdout)
        self.assertEqual(rep_after["stealth_grade"], "A")
        self.assertEqual(rep_after["severity_counts"]["CRITICAL"], 0)

        # Safety check: refusing to scrub already-pushed commit without --allow-pushed
        pushed_refuse = run_cli(["scrub", str(self.repo), "--all-local"])
        self.assertEqual(pushed_refuse.returncode, 1)
        self.assertIn("Refusing to rewrite", pushed_refuse.stderr)

    def test_pre_push_blocks_dirty_commit_and_commit_msg_blocks_ai_env_identity(self) -> None:
        # Initial clean push
        (self.repo / "base.txt").write_text("ok\n", encoding="utf-8")
        git(["add", "base.txt"], self.repo)
        git(["commit", "-m", "chore: init"], self.repo)
        self.assertEqual(git(["push", "-u", "origin", "main"], self.repo).returncode, 0)

        # Install all 3 hooks
        inst = run_cli(["install-hooks", "--repo", str(self.repo), "--mode", "scrub", "--apply"])
        self.assertEqual(inst.returncode, 0, inst.stderr)

        # commit-msg hook MUST block AI bot email in GIT_AUTHOR_EMAIL
        (self.repo / "bad_id.txt").write_text("x\n", encoding="utf-8")
        git(["add", "bad_id.txt"], self.repo)
        blocked_id = git(
            ["commit", "-m", "feat: bad id"],
            self.repo,
            env={"GIT_AUTHOR_EMAIL": "noreply@anthropic.com"},
        )
        self.assertNotEqual(blocked_id.returncode, 0)
        self.assertIn("Blocked AI identity", blocked_id.stderr)
        git(["reset", "HEAD", "bad_id.txt"], self.repo)
        (self.repo / "bad_id.txt").unlink()

        # Bypass commit-msg once with UNDERCOVER_SKIP=1 to create a dirty unpushed commit
        (self.repo / "dirty.txt").write_text("d\n", encoding="utf-8")
        git(["add", "dirty.txt"], self.repo)
        bypassed = git(
            ["commit", "-m", "feat: sneaky\n\nCo-Authored-By: Claude <noreply@anthropic.com>"],
            self.repo,
            env={"UNDERCOVER_SKIP": "1"},
        )
        self.assertEqual(bypassed.returncode, 0, bypassed.stderr)

        # pre-push hook MUST block pushing the dirty commit!
        push_blocked = git(["push", "origin", "main"], self.repo)
        self.assertNotEqual(push_blocked.returncode, 0)
        self.assertIn("UNDERCOVER pre-push", push_blocked.stderr)

        # Scrub unpushed commit -> push now succeeds cleanly!
        scrub = run_cli(["scrub", str(self.repo), "--apply"])
        self.assertEqual(scrub.returncode, 0, scrub.stderr)
        push_ok = git(["push", "origin", "main"], self.repo)
        self.assertEqual(push_ok.returncode, 0, push_ok.stderr)

    def test_scrub_preserves_merge_commit_topology(self) -> None:
        # Base commit pushed
        (self.repo / "main.txt").write_text("v1\n", encoding="utf-8")
        git(["add", "main.txt"], self.repo)
        git(["commit", "-m", "chore: base"], self.repo)
        git(["push", "-u", "origin", "main"], self.repo)

        # Side branch with dirty commit
        git(["checkout", "-b", "feature"], self.repo)
        (self.repo / "feat.txt").write_text("f1\n", encoding="utf-8")
        git(["add", "feat.txt"], self.repo)
        git(["commit", "-m", "feat: side\n\nCo-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"], self.repo)

        # Main commit + true merge commit
        git(["checkout", "main"], self.repo)
        (self.repo / "main2.txt").write_text("v2\n", encoding="utf-8")
        git(["add", "main2.txt"], self.repo)
        git(["commit", "-m", "chore: main advance"], self.repo)
        m = git(["merge", "--no-ff", "feature", "-m", "merge: feature\n\nGenerated with [Claude Code](https://claude.com/claude-code)"], self.repo)
        self.assertEqual(m.returncode, 0, m.stderr)

        # Scrub unpushed commits (includes both branch commits & merge commit)
        scrub = run_cli(["scrub", str(self.repo), "--apply"])
        self.assertEqual(scrub.returncode, 0, scrub.stderr)

        # Verify HEAD is still a 2-parent merge commit and all watermarks are gone
        parents = git(["rev-list", "--parents", "-n", "1", "HEAD"], self.repo).stdout.strip().split()
        self.assertEqual(len(parents), 3, f"Expected merge commit with 2 parents, got: {parents}")
        all_logs = git(["log", "--format=%B"], self.repo).stdout
        self.assertNotIn("Co-Authored-By", all_logs)
        self.assertNotIn("Generated with", all_logs)
        self.assertTrue((self.repo / "feat.txt").exists())
        self.assertTrue((self.repo / "main2.txt").exists())

    def test_undercoverignore_allows_dotfile_paths(self) -> None:
        (self.repo / ".claude" / "skills" / "demo").mkdir(parents=True)
        (self.repo / ".claude" / "skills" / "demo" / "SKILL.md").write_text("# demo\n", encoding="utf-8")
        (self.repo / ".undercoverignore").write_text(".claude/skills/demo\n", encoding="utf-8")
        git(["add", "-f", ".claude/skills/demo/SKILL.md", ".undercoverignore"], self.repo)
        git(["commit", "-m", "chore: add intentional skill"], self.repo)

        audit = run_cli(["audit", str(self.repo), "--skip-configs"])
        self.assertEqual(audit.returncode, 0, audit.stderr)
        rep = json.loads(audit.stdout)
        self.assertEqual(rep["pillars"]["artifacts"]["leaked_files"], 0)
        self.assertEqual(rep["stealth_grade"], "A")


class TestHardenConfigs(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="undercover_cfg_"))
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir()
        self.repo = self.tmp / "proj"
        init_repo(self.repo)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_harden_configs_dry_run_and_apply_with_backups(self) -> None:
        claude_dir = self.fake_home / ".claude"
        claude_dir.mkdir(parents=True)
        claude_settings = claude_dir / "settings.json"
        claude_settings.write_text(json.dumps({"theme": "dark", "includeCoAuthoredBy": True}), encoding="utf-8")

        env = {"HOME": str(self.fake_home)}

        # Dry run must not modify file
        dry = run_cli(
            ["harden-configs", "--claude", "--with-claude-hook", "--aider", "--antigravity-hook", "--project", str(self.repo)],
            env=env,
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(json.loads(claude_settings.read_text(encoding="utf-8"))["includeCoAuthoredBy"], True)

        # Apply writes all configs cleanly and preserves existing keys + creates backup
        app = run_cli(
            [
                "harden-configs",
                "--claude",
                "--with-claude-hook",
                "--aider",
                "--antigravity-hook",
                "--project",
                str(self.repo),
                "--apply",
            ],
            env=env,
        )
        self.assertEqual(app.returncode, 0, app.stderr)
        res = json.loads(app.stdout)
        self.assertEqual(res["mode"], "apply")

        updated = json.loads(claude_settings.read_text(encoding="utf-8"))
        self.assertEqual(updated["theme"], "dark")
        self.assertEqual(updated["attribution"], {"commit": "", "pr": ""})
        self.assertEqual(updated["includeCoAuthoredBy"], False)
        self.assertIn("PreToolUse", updated["hooks"])
        self.assertIn("SessionStart", updated["hooks"])

        # Idempotent second run produces zero changes
        second = run_cli(
            [
                "harden-configs",
                "--claude",
                "--with-claude-hook",
                "--aider",
                "--antigravity-hook",
                "--project",
                str(self.repo),
                "--apply",
            ],
            env=env,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        second_res = json.loads(second.stdout)
        self.assertTrue(all(len(a["changes"]) == 0 for a in second_res["actions"]))

        # Backup created
        backups = list(claude_dir.glob("settings.json.undercover.bak.*"))
        self.assertEqual(len(backups), 1)

        # Aider config hardened
        aider_txt = (self.fake_home / ".aider.conf.yml").read_text(encoding="utf-8")
        self.assertIn("attribute-author: false", aider_txt)
        self.assertIn("attribute-committer: false", aider_txt)
        self.assertIn("attribute-co-authored-by: false", aider_txt)

        # Antigravity hooks.json hardened with BOTH SessionStart (flat list) & PreToolUse
        agy_hooks = json.loads((self.fake_home / ".gemini" / "config" / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("undercover-guard", agy_hooks)
        self.assertIn("SessionStart", agy_hooks["undercover-guard"])
        self.assertIn("PreToolUse", agy_hooks["undercover-guard"])
        self.assertEqual(agy_hooks["undercover-guard"]["SessionStart"][0]["type"], "command")

        # Private .git/info/exclude hardened (without touching tracked .gitignore)
        exclude_txt = (self.repo / ".git" / "info" / "exclude").read_text(encoding="utf-8")
        self.assertIn(".claude/", exclude_txt)
        self.assertIn(".cursorrules", exclude_txt)
        self.assertFalse((self.repo / ".gitignore").exists())


class TestPolicyScopeAndSessionStart(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="undercover_policy_"))
        self.cfg_path = self.tmp / "config.json"
        self.internal_repo = self.tmp / "internal_repo"
        self.external_repo = self.tmp / "external_repo"
        self.dual_repo = self.tmp / "dual_repo"
        self.unconnected_repo = self.tmp / "unconnected_repo"

        for r in (self.internal_repo, self.external_repo, self.dual_repo, self.unconnected_repo):
            init_repo(r)

        git(["remote", "add", "origin", "git@github.com:my-corp/private-service.git"], self.internal_repo)
        git(["remote", "add", "origin", "https://github.com/public-oss/awesome-lib.git"], self.external_repo)
        git(["remote", "add", "origin", "git@github.com:my-corp/forked-lib.git"], self.dual_repo)
        git(["remote", "add", "upstream", "https://github.com/public-oss/awesome-lib.git"], self.dual_repo)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_init_policy_and_fail_closed_remote_classification(self) -> None:
        # Dry run first
        dry = run_cli(
            [
                "init-policy",
                "--mode",
                "auto",
                "--internal-remotes",
                "github.com/my-corp/*",
                "--blocked-terms",
                "SecretProjectOrion,wiki.internal.example",
                "--config",
                str(self.cfg_path),
            ]
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertFalse(self.cfg_path.exists())

        # Apply policy
        app = run_cli(
            [
                "init-policy",
                "--mode",
                "auto",
                "--internal-remotes",
                "github.com/my-corp/*",
                "--blocked-terms",
                "SecretProjectOrion,wiki.internal.example",
                "--config",
                str(self.cfg_path),
                "--apply",
            ]
        )
        self.assertEqual(app.returncode, 0, app.stderr)
        self.assertTrue(self.cfg_path.is_file())

        # 1. Internal-only repo -> stands down (active=False)
        st_int = json.loads(run_cli(["repo-status", str(self.internal_repo), "--config", str(self.cfg_path)]).stdout)
        self.assertFalse(st_int["active"])
        self.assertEqual(st_int["reason"], "internal_allowlisted_repo")

        # 2. External repo -> active=True
        st_ext = json.loads(run_cli(["repo-status", str(self.external_repo), "--config", str(self.cfg_path)]).stdout)
        self.assertTrue(st_ext["active"])
        self.assertEqual(st_ext["reason"], "external_remote_detected")

        # 3. Dual repo (internal origin + public upstream) -> fail-closed active=True
        st_dual = json.loads(run_cli(["repo-status", str(self.dual_repo), "--config", str(self.cfg_path)]).stdout)
        self.assertTrue(st_dual["active"])
        self.assertEqual(st_dual["reason"], "external_remote_detected")

        # 4. Unconnected local repo (no remotes) -> fail-closed active=True
        st_none = json.loads(run_cli(["repo-status", str(self.unconnected_repo), "--config", str(self.cfg_path)]).stdout)
        self.assertTrue(st_none["active"])
        self.assertEqual(st_none["reason"], "no_remotes_fail_closed")

        # 5. UNDERCOVER_FORCE=1 forces active even in internal repo
        st_force = json.loads(
            run_cli(
                ["repo-status", str(self.internal_repo), "--config", str(self.cfg_path)],
                env={"UNDERCOVER_FORCE": "1"},
            ).stdout
        )
        self.assertTrue(st_force["active"])
        self.assertEqual(st_force["reason"], "forced_always_on")

    def test_session_start_dual_protocol_and_blocked_terms_guard(self) -> None:
        run_cli(
            [
                "init-policy",
                "--mode",
                "auto",
                "--internal-remotes",
                "github.com/my-corp/*",
                "--blocked-terms",
                "SecretProjectOrion",
                "--config",
                str(self.cfg_path),
                "--apply",
            ]
        )
        env = {"UNDERCOVER_CONFIG": str(self.cfg_path)}

        # Claude Code SessionStart in external repo -> injects additionalContext
        cc_ext = run_cli(
            ["session-start"],
            stdin_text=json.dumps({"session_id": "s1", "cwd": str(self.external_repo)}),
            env=env,
        )
        self.assertEqual(cc_ext.returncode, 0, cc_ext.stderr)
        cc_data = json.loads(cc_ext.stdout)
        self.assertEqual(cc_data["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertIn("CLEAN-CONTRIBUTION POLICY", cc_data["hookSpecificOutput"]["additionalContext"])

        # Claude Code SessionStart in allowlisted internal repo -> silent (empty stdout)
        cc_int = run_cli(
            ["session-start"],
            stdin_text=json.dumps({"session_id": "s2", "cwd": str(self.internal_repo)}),
            env=env,
        )
        self.assertEqual(cc_int.returncode, 0)
        self.assertEqual(cc_int.stdout.strip(), "")

        # Antigravity SessionStart in external repo -> injects systemMessage
        agy_ext = run_cli(
            ["session-start"],
            stdin_text=json.dumps({"conversationId": "c1", "workspacePaths": [str(self.external_repo)], "cwd": str(self.external_repo)}),
            env=env,
        )
        self.assertEqual(agy_ext.returncode, 0, agy_ext.stderr)
        agy_data = json.loads(agy_ext.stdout)
        self.assertIn("injectSteps", agy_data)
        self.assertIn("CLEAN-CONTRIBUTION POLICY", agy_data["injectSteps"][0]["systemMessage"]["systemMessage"])

        # Antigravity SessionStart in allowlisted internal repo -> returns {}
        agy_int = run_cli(
            ["session-start"],
            stdin_text=json.dumps({"conversationId": "c2", "workspacePaths": [str(self.internal_repo)], "cwd": str(self.internal_repo)}),
            env=env,
        )
        self.assertEqual(agy_int.returncode, 0)
        self.assertEqual(json.loads(agy_int.stdout), {})

        # PreToolUse blocks user-configured blocked term in external repo
        ptg_ext = run_cli(
            ["pre-tool-guard"],
            stdin_text=json.dumps(
                {
                    "tool_name": "Bash",
                    "cwd": str(self.external_repo),
                    "tool_input": {"command": 'git commit -m "feat: sync with SecretProjectOrion"'},
                }
            ),
            env=env,
        )
        self.assertEqual(json.loads(ptg_ext.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

        # PreToolUse stands down in allowlisted internal repo
        ptg_int = run_cli(
            ["pre-tool-guard"],
            stdin_text=json.dumps(
                {
                    "tool_name": "Bash",
                    "cwd": str(self.internal_repo),
                    "tool_input": {"command": 'git commit -m "feat: sync with SecretProjectOrion"'},
                }
            ),
            env=env,
        )
        self.assertEqual(ptg_int.stdout.strip(), "")

    def test_git_hooks_respect_remote_allowlist_and_blocked_terms(self) -> None:
        run_cli(
            [
                "init-policy",
                "--mode",
                "auto",
                "--internal-remotes",
                "github.com/my-corp/*",
                "--blocked-terms",
                "SecretProjectOrion",
                "--config",
                str(self.cfg_path),
                "--apply",
            ]
        )
        env = {"UNDERCOVER_CONFIG": str(self.cfg_path)}

        # Install hooks on both repos
        self.assertEqual(run_cli(["install-hooks", "--repo", str(self.external_repo), "--mode", "scrub", "--apply"]).returncode, 0)
        self.assertEqual(run_cli(["install-hooks", "--repo", str(self.internal_repo), "--mode", "scrub", "--apply"]).returncode, 0)

        # External repo: pre-commit MUST block staged diff containing SecretProjectOrion
        (self.external_repo / "app.py").write_text("x = 'SecretProjectOrion'\n", encoding="utf-8")
        git(["add", "app.py"], self.external_repo)
        blocked = git(["commit", "-m", "feat: add app"], self.external_repo, env=env)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("blocked confidential term", blocked.stderr)

        # Clean file in external repo + commit msg containing SecretProjectOrion & Co-Authored-By -> commit-msg scrubs both!
        (self.external_repo / "app.py").write_text("x = 'public'\n", encoding="utf-8")
        git(["add", "app.py"], self.external_repo)
        ok_ext = git(
            ["commit", "-m", "feat: public\n\nRef: SecretProjectOrion\nCo-Authored-By: Claude <noreply@anthropic.com>"],
            self.external_repo,
            env=env,
        )
        self.assertEqual(ok_ext.returncode, 0, ok_ext.stderr)
        msg_ext = git(["log", "-1", "--format=%B"], self.external_repo).stdout
        self.assertNotIn("SecretProjectOrion", msg_ext)
        self.assertNotIn("Co-Authored-By", msg_ext)

        # Allowlisted internal repo: hooks stand down cleanly
        (self.internal_repo / "internal.py").write_text("x = 'SecretProjectOrion'\n", encoding="utf-8")
        git(["add", "internal.py"], self.internal_repo)
        ok_int = git(
            ["commit", "-m", "feat: internal sync\n\nRef: SecretProjectOrion"],
            self.internal_repo,
            env=env,
        )
        self.assertEqual(ok_int.returncode, 0, ok_int.stderr)
        msg_int = git(["log", "-1", "--format=%B"], self.internal_repo).stdout
        self.assertIn("SecretProjectOrion", msg_int)

    def test_session_prompt_is_vendor_neutral_clean_room(self) -> None:
        proc = run_cli(["session-start", "--preview", str(self.external_repo)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        prompt = data["injected_prompt"]
        self.assertIsInstance(prompt, str)
        self.assertIn("CLEAN-CONTRIBUTION POLICY", prompt)
        # Injected system prompt must remain strictly vendor-neutral
        for vendor_word in ("anthropic", "openai", "google"):
            self.assertNotIn(vendor_word, prompt.lower())


class TestInstallerDefaults(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="undercover_installer_"))
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_sh_enables_agent_and_global_git_hooks_by_default(self) -> None:
        env = os.environ.copy()
        env["HOME"] = str(self.fake_home)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        installer = REPO_ROOT / "install.sh"

        proc = subprocess.run(
            ["bash", str(installer)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

        # 1. Skill files installed
        installed_script = self.fake_home / ".gemini" / "config" / "skills" / "undercover" / "scripts" / "undercover.py"
        self.assertTrue(installed_script.is_file())
        self.assertTrue((self.fake_home / ".claude" / "skills" / "undercover" / "SKILL.md").is_file())
        self.assertTrue((self.fake_home / ".agents" / "skills" / "undercover" / "SKILL.md").is_file())

        # 2. Agent hooks enabled by default pointing to permanent installed script path
        claude_cfg = json.loads((self.fake_home / ".claude" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(claude_cfg["attribution"], {"commit": "", "pr": ""})
        self.assertIn("SessionStart", claude_cfg["hooks"])
        self.assertIn("PreToolUse", claude_cfg["hooks"])
        self.assertIn(str(installed_script), claude_cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"])

        agy_cfg = json.loads((self.fake_home / ".gemini" / "config" / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("SessionStart", agy_cfg["undercover-guard"])
        self.assertIn("PreToolUse", agy_cfg["undercover-guard"])

        # 3. Global Git 3-layer hooks enabled by default
        hooks_dir = self.fake_home / ".config" / "undercover" / "hooks"
        for h in ("commit-msg", "pre-commit", "pre-push"):
            self.assertTrue((hooks_dir / h).is_file())
        hp = subprocess.run(
            ["git", "config", "--global", "--get", "core.hooksPath"],
            stdout=subprocess.PIPE,
            text=True,
            env=env,
            check=True,
        ).stdout.strip()
        self.assertEqual(Path(hp).resolve(), hooks_dir.resolve())

    def test_install_sh_skills_only_and_existing_global_hooks_protection(self) -> None:
        env = os.environ.copy()
        env["HOME"] = str(self.fake_home)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        installer = REPO_ROOT / "install.sh"

        # --skills-only must NOT create settings.json, hooks.json, or global Git hooks
        proc = subprocess.run(
            ["bash", str(installer), "--skills-only"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((self.fake_home / ".claude" / "skills" / "undercover" / "SKILL.md").is_file())
        self.assertFalse((self.fake_home / ".claude" / "settings.json").exists())
        self.assertFalse((self.fake_home / ".gemini" / "config" / "hooks.json").exists())
        self.assertFalse((self.fake_home / ".config" / "undercover" / "hooks").exists())

        # Pre-existing custom global core.hooksPath must not be clobbered without --force
        custom_hooks = self.tmp / "custom_hooks"
        custom_hooks.mkdir()
        subprocess.run(
            ["git", "config", "--global", "core.hooksPath", str(custom_hooks)],
            env=env,
            check=True,
        )
        conflict = run_cli(["install-hooks", "--global", "--apply"], env=env)
        self.assertEqual(conflict.returncode, 1)
        still = subprocess.run(
            ["git", "config", "--global", "--get", "core.hooksPath"],
            stdout=subprocess.PIPE,
            text=True,
            env=env,
            check=True,
        ).stdout.strip()
        self.assertEqual(Path(still).resolve(), custom_hooks.resolve())


if __name__ == "__main__":
    unittest.main()
