#!/usr/bin/env python3
"""
UNDERCOVER — Universal AI Contribution Watermark Neutralization & Stealth Audit CLI.

Zero-dependency Python 3.9+ tool for auditing, blocking, hardening, and scrubbing
AI coding-agent attribution watermarks across Git commits, PR/issue text, source
files, agent artifact files, invisible Unicode markers, and local tool configs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "1.1.0"
HOOK_MARKER = "# UNDERCOVER-MANAGED-HOOK v1"

# ---------------------------------------------------------------------------
# Watermark Detection Catalog
# ---------------------------------------------------------------------------

# Trailer keys that are unconditionally AI attribution regardless of value
AI_ONLY_TRAILER_KEYS = {
    "ai-assisted-by",
    "ai-contributor",
    "ai-co-authored-by",
    "ai-generated-by",
    "x-ai-attribution",
    "agent-by",
    "generated-by-ai",
}

# Standard or semi-standard trailer keys that must be paired with an AI value
CONDITIONAL_TRAILER_KEYS = {
    "co-authored-by",
    "assisted-by",
    "generated-by",
    "made-with",
    "created-by",
    "authored-with",
    "signed-off-by",
}

# Known AI coding-agent emails / bot identities (matched case-insensitively)
AI_EMAIL_PATTERNS: Tuple[str, ...] = (
    r"noreply@anthropic\.com",
    r"claude(?:-[a-z0-9._-]+)?@anthropic\.com",
    r"cursoragent@cursor\.com",
    r"noreply@cursor\.com",
    r"aider@aider\.chat",
    r"copilot@github\.com",
    r"175728472\+copilot@users\.noreply\.github\.com",
    r"copilot-swe-agent\[bot\]",
    r"codex@openai\.com",
    r"noreply@openai\.com",
    r"chatgpt@openai\.com",
    r"amp@ampcode\.com",
    r"agent@warp\.dev",
    r"devin@cognition\.ai",
    r"devin-ai-integration\[bot\]",
    r"droid@factory\.ai",
    r"factory-droid\[bot\]",
    r"gemini-code-assist(?:\[bot\])?",
    r"google-labs-jules\[bot\]",
    r"jules\[bot\]",
    r"sweep\[bot\]",
    r"coderabbitai\[bot\]",
    r"qodo-merge-pro\[bot\]",
    r"amazon-q-developer(?:\[bot\])?",
    r"junie@jetbrains\.com",
    r"kiro@(?:aws|amazon)\.com",
    r"windsurf@codeium\.com",
    r"opencode@",
    r"antigravity@",
)

AI_EMAIL_RE = re.compile("|".join(AI_EMAIL_PATTERNS), re.IGNORECASE)

# AI identity patterns inside conditional trailer values (e.g. Co-Authored-By: <value>)
# Carefully written so human names like "Claude Dupont <claude@company.com>" do NOT false-positive.
AI_TRAILER_VALUE_PATTERNS: Tuple[str, ...] = (
    r"\bclaude[\s:/-]+(?:code|opus|sonnet|haiku|instant|ai|bot|\d+(?:\.\d+)*)\b",
    r"^\s*claude\s*(?:<[^>]*>)?\s*$",
    r"\banthropic(?:'s)?\s+claude\b",
    r"\bgithub\s+copilot\b",
    r"^\s*copilot\s*(?:<[^>]*>)?\s*$",
    r"\bcursor\s*(?:agent|ai|ide)?\s*(?:<[^>]*>)?\s*$",
    r"\bcursoragent\b",
    r"\baider\b",
    r"\b(?:openai[\s:/-]+)?codex\b",
    r"\bchatgpt\b",
    r"\bgpt-[\d.]+(?:-[a-z0-9]+)?\b",
    r"\bgemini[\s:/-]+(?:cli|code\s*assist|pro|flash|ultra|ai|\d+(?:\.\d+)*)\b",
    r"^\s*gemini\s*(?:<[^>]*>)?\s*$",
    r"\bgoogle\s+jules\b",
    r"\bantigravity\b",
    r"\bopencode\b",
    r"\bwindsurf\b",
    r"\bcodeium\b",
    r"\bdevin(?:\s+ai)?\b",
    r"\bcline\b",
    r"\broo(?:\s*code|\s*cline)\b",
    r"\bsourcegraph\s+amp\b",
    r"^\s*amp\s*<[^>]*ampcode\.com[^>]*>\s*$",
    r"\bfactory[\s-]?droid\b",
    r"\bwarp\s+agent\b",
    r"\bamazon\s+q(?:\s+developer)?\b",
    r"\btabnine\b",
    r"\bjetbrains\s+junie\b",
    r"\bkiro(?:\s+ai)?\b",
    r"\baugment\s+(?:code|agent)\b",
    r"\bcoderabbit\b",
)

AI_TRAILER_VALUE_RE = re.compile("|".join(AI_TRAILER_VALUE_PATTERNS), re.IGNORECASE)

TRAILER_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+?)\s*$")

# Generator footer / badge lines in commit messages, PR bodies, and issue comments
AI_TOOL_NAME_ALT = (
    r"(?:"
    r"Claude(?:\s+(?:Code|Opus|Sonnet|Haiku)(?:\s+[\d.]+)*)?|"
    r"Anthropic\s+Claude(?:\s+[\d.]+)*|"
    r"Cursor(?:\s+AI|\s+Agent)?|"
    r"(?:GitHub\s+)?Copilot|"
    r"(?:OpenAI\s+)?Codex(?:\s+CLI)?|"
    r"ChatGPT|GPT-[\d.]+(?:-[a-z0-9]+)?|"
    r"Aider|"
    r"Gemini(?:\s+(?:CLI|Code\s+Assist|Pro|Flash|[\d.]+))*|"
    r"Antigravity|"
    r"Windsurf|"
    r"Devin(?:\s+AI)?|"
    r"Cline|"
    r"Roo\s*Code|"
    r"OpenCode|"
    r"Amp|"
    r"Factory\s+Droid|"
    r"Warp\s+Agent|"
    r"Amazon\s+Q(?:\s+Developer)?|"
    r"Kiro|"
    r"Junie|"
    r"Augment\s+Code"
    r")"
)

GENERATOR_FOOTER_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"^\s*(?:[-*>]?\s*)?[*_~]*\s*(?:[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]+\s*)?"
        rf"(?:Generated|Created|Written|Authored|Drafted|Built|Committed|Assisted)\s+"
        rf"(?:with|by|using)\s+\[?{AI_TOOL_NAME_ALT}\]?(?:\([^)]*\))?[\s.!*_~]*$",
        re.IGNORECASE,
    ),
    re.compile(
        rf"^\s*(?:[-*>]?\s*)?[*_~]*\s*(?:[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]+\s*)?"
        rf"Powered\s+by\s+\[?{AI_TOOL_NAME_ALT}\]?(?:\([^)]*\))?[\s.!*_~]*$",
        re.IGNORECASE,
    ),
    re.compile(
        rf"^\s*<!--\s*(?:Generated|Created|Written|Edited|Authored)\s+"
        rf"(?:by|with|using)\s+{AI_TOOL_NAME_ALT}[^>]*-->\s*$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*[*_~]*\s*(?:[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]+\s*)?"
        r"Generated\s+(?:with|by)\s+\[?(?:AI|an?\s+AI(?:\s+assistant|\s+agent)?|LLM)\]?[\s.!*_~]*$",
        re.IGNORECASE,
    ),
)

# Inline AI self-disclosure phrases in commit messages or PR text (vendor-neutral clean-room rules)
SELF_DISCLOSURE_PATTERNS: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    (
        "inline_ai_generator_phrase",
        re.compile(rf"\bgenerated\s+(?:with|by)\s+\[?{AI_TOOL_NAME_ALT}\]?", re.IGNORECASE),
        "HIGH",
    ),
    (
        "ai_self_disclosure",
        re.compile(r"\b(?:as an ai(?: language model)?|written by an ai(?: assistant| agent)?)\b", re.IGNORECASE),
        "HIGH",
    ),
)

# Author/committer identity leak patterns
AIDER_NAME_SUFFIX_RE = re.compile(r"\s*\(aider\)\s*$", re.IGNORECASE)
AI_AUTHOR_NAME_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\(aider\)\s*$", re.IGNORECASE),
    re.compile(r"^claude(?:\s+(?:code|opus|sonnet|haiku))?$", re.IGNORECASE),
    re.compile(r"^cursoragent$", re.IGNORECASE),
    re.compile(r"^(?:github\s+)?copilot(?:-swe-agent\[bot\])?$", re.IGNORECASE),
    re.compile(r"^devin-ai-integration\[bot\]$", re.IGNORECASE),
    re.compile(r"^factory-droid\[bot\]$", re.IGNORECASE),
    re.compile(r"^google-labs-jules\[bot\]$", re.IGNORECASE),
)

# Explicit AI-attribution comment headers in source code
CODE_AI_COMMENT_RE = re.compile(
    rf"^\s*(?://+|#+|--+|;+|%+|/\*+|<!--)\s*"
    rf"(?:"
    rf"(?:auto[- ]?)?(?:generated|created|written|authored|added|modified)\s+(?:with|by|using)\s+"
    rf"(?:{AI_TOOL_NAME_ALT}|an?\s+AI(?:\s+assistant|\s+agent)?|AI\b|LLM\b)|"
    rf"AI[- ]generated(?:\s+code|\s+by\b|\s+with\b|\s*$)|"
    rf"(?:TODO|NOTE|FIXME|HACK)\s*\(\s*(?:claude|cursor|copilot|codex|aider|gemini|ai|llm|antigravity|opencode)\s*\)\s*:"
    rf")"
    rf".*$",
    re.IGNORECASE,
)

# Agent trace files & directories that can leak AI tooling usage into repositories
AGENT_ARTIFACT_RULES: Tuple[Tuple[str, str, str], ...] = (
    # (glob/prefix pattern description, regex on repo-relative POSIX path, severity)
    ("claude_local_settings", r"(?:^|/)\.claude/settings\.local\.json$", "CRITICAL"),
    ("claude_local_md", r"(?:^|/)CLAUDE\.local\.md$", "CRITICAL"),
    ("claude_session_state", r"(?:^|/)\.claude/(?:projects|todos|plans|statsig|debug)(?:/|$)", "CRITICAL"),
    ("aider_history", r"(?:^|/)\.aider\.(?:chat\.history\.md|input\.history|tags\.cache[^/]*)$", "CRITICAL"),
    ("cursor_mcp_local", r"(?:^|/)\.cursor/mcp\.json$", "CRITICAL"),
    ("claude_dir", r"(?:^|/)\.claude/", "HIGH"),
    ("claude_ignore", r"(?:^|/)\.claudeignore$", "HIGH"),
    ("cursor_dir", r"(?:^|/)\.cursor/", "HIGH"),
    ("cursor_rules", r"(?:^|/)\.cursor(?:rules|ignore)$", "HIGH"),
    ("windsurf_files", r"(?:^|/)\.windsurf(?:/|rules$)", "HIGH"),
    ("aider_config", r"(?:^|/)\.aider(?:\.conf\.yml|ignore)$", "HIGH"),
    ("cline_roo_rules", r"(?:^|/)\.(?:clinerules|roorules|roo/)$|(?:^|/)\.roo/", "HIGH"),
    ("codex_dir", r"(?:^|/)\.codex/", "HIGH"),
    ("opencode_dir", r"(?:^|/)\.opencode/", "HIGH"),
    ("gemini_dir", r"(?:^|/)\.gemini/", "HIGH"),
    ("claude_md", r"(?:^|/)CLAUDE\.md$", "MEDIUM"),
    ("agents_md", r"(?:^|/)AGENTS\.md$", "MEDIUM"),
    ("gemini_md", r"(?:^|/)GEMINI\.md$", "MEDIUM"),
    ("agents_dir", r"(?:^|/)(?:\.agents|\.agent|_agents|_agent)/", "MEDIUM"),
    ("copilot_instructions", r"^\.github/copilot-instructions\.md$", "MEDIUM"),
)

AGENT_ARTIFACT_COMPILED = tuple(
    (name, re.compile(pattern, re.IGNORECASE), severity)
    for name, pattern, severity in AGENT_ARTIFACT_RULES
)

# Standard private local exclude lines for .git/info/exclude
LOCAL_EXCLUDE_ENTRIES: Tuple[str, ...] = (
    ".claude/",
    "CLAUDE.local.md",
    ".claudeignore",
    ".cursor/",
    ".cursorrules",
    ".cursorignore",
    ".windsurf/",
    ".windsurfrules",
    ".aider*",
    ".clinerules",
    ".roorules",
    ".roo/",
    ".codex/",
    ".opencode/",
)

# Invisible Unicode watermark classification
ZERO_WIDTH_CHARS: Dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
}

BIDI_CONTROL_CHARS: Dict[int, str] = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x061C: "ARABIC LETTER MARK",
}

EXOTIC_SPACE_CHARS: Dict[int, str] = {
    0x202F: "NARROW NO-BREAK SPACE",
    0x2000: "EN QUAD",
    0x2001: "EM QUAD",
    0x2002: "EN SPACE",
    0x2003: "EM SPACE",
    0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE",
    0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE",
    0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE",
    0x200A: "HAIR SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE",
}

SKIP_DIR_NAMES: Set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
}

CODE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm",
    ".swift", ".kt", ".kts", ".java", ".cs", ".rb", ".php", ".sh",
    ".bash", ".zsh", ".fish", ".lua", ".pl", ".r", ".sql", ".zig",
    ".dart", ".scala", ".ex", ".exs", ".erl", ".hs", ".ml", ".mli",
    ".html", ".htm", ".css", ".scss", ".less", ".vue", ".svelte",
    ".xml", ".yaml", ".yml", ".toml", ".tf", ".hcl", ".dockerfile",
}

TEXT_EXTENSIONS: Set[str] = CODE_EXTENSIONS | {
    ".md", ".markdown", ".txt", ".rst", ".adoc", ".json", ".ini",
    ".cfg", ".conf", ".env", ".gitignore", ".gitattributes", ".editorconfig",
    ".csv", ".tsv", ".tex",
}

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

# ---------------------------------------------------------------------------
# General Helpers
# ---------------------------------------------------------------------------


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run_git(
    args: Sequence[str],
    cwd: Path,
    *,
    input_bytes: Optional[bytes] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged_env,
        check=False,
    )
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {err}")
    return proc


def find_git_root(path: Path) -> Optional[Path]:
    target = path if path.is_dir() else path.parent
    if not target.exists():
        return None
    proc = run_git(["rev-parse", "--show-toplevel"], target)
    if proc.returncode != 0:
        return None
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    return Path(out) if out else None


def find_git_dir(repo_root: Path) -> Path:
    proc = run_git(["rev-parse", "--git-dir"], repo_root, check=True)
    raw = proc.stdout.decode("utf-8", errors="replace").strip()
    p = Path(raw)
    return p if p.is_absolute() else (repo_root / p).resolve()


def is_binary_bytes(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    return False


def is_text_file(path: Path, max_bytes: int = 2_000_000) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
        return False
    try:
        with path.open("rb") as f:
            sample = f.read(8192)
    except OSError:
        return False
    return not is_binary_bytes(sample)


def backup_file(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    bak = path.with_name(f"{path.name}.undercover.bak.{utc_timestamp()}")
    shutil.copy2(path, bak)
    return bak


def write_json_report(report: Dict[str, Any], output_path: Optional[str], summary_line: str) -> None:
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{summary_line} -> {out}")
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))


def compile_extra_patterns(raw: Optional[str]) -> List[re.Pattern[str]]:
    if not raw:
        return []
    out: List[re.Pattern[str]] = []
    for token in raw.split(","):
        pat = token.strip()
        if pat:
            out.append(re.compile(re.escape(pat), re.IGNORECASE))
    return out


# ---------------------------------------------------------------------------
# Clean-Room Repository Scope & Policy Engine (Fail-Closed Auto-Activation)
# ---------------------------------------------------------------------------


def default_policy_config_path() -> Path:
    override = os.environ.get("UNDERCOVER_CONFIG", "").strip()
    if override:
        return Path(os.path.expanduser(override)).resolve()
    return Path.home() / ".config" / "undercover" / "config.json"


def load_policy_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    path = Path(os.path.expanduser(config_path)).resolve() if config_path else default_policy_config_path()
    mode = "auto"
    internal_remotes: List[str] = []
    blocked_terms: List[str] = []
    exists = path.is_file()

    if exists:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                if raw.get("mode") in ("auto", "always"):
                    mode = str(raw["mode"])
                if isinstance(raw.get("internal_remotes"), list):
                    internal_remotes.extend(str(x).strip() for x in raw["internal_remotes"] if str(x).strip())
                if isinstance(raw.get("blocked_terms"), list):
                    blocked_terms.extend(str(x).strip() for x in raw["blocked_terms"] if str(x).strip())
        except Exception:
            # Fail-closed: malformed config never silently disables stealth enforcement
            mode = "always"

    env_mode = os.environ.get("UNDERCOVER_MODE", "").strip().lower()
    if env_mode in ("auto", "always"):
        mode = env_mode

    # Fail-closed force-on flag (intentionally no force-off flag for policy evaluation)
    forced = os.environ.get("UNDERCOVER_FORCE", "").strip() in ("1", "true", "yes", "on") or mode == "always"

    env_remotes = os.environ.get("UNDERCOVER_INTERNAL_REMOTES", "").strip()
    if env_remotes:
        internal_remotes.extend(x.strip() for x in env_remotes.split(",") if x.strip())

    env_terms = os.environ.get("UNDERCOVER_BLOCKED_TERMS", "").strip()
    if env_terms:
        blocked_terms.extend(x.strip() for x in env_terms.split(",") if x.strip())

    # Deduplicate while preserving order
    dedup_remotes = list(dict.fromkeys(internal_remotes))
    dedup_terms = list(dict.fromkeys(blocked_terms))

    return {
        "config_path": str(path),
        "config_exists": exists,
        "mode": mode,
        "forced": forced,
        "internal_remotes": dedup_remotes,
        "blocked_terms": dedup_terms,
    }


def normalize_remote_url(url: str) -> str:
    """Normalize SSH/HTTPS/SCP-style Git remote URLs to '<host>/<path>' for glob matching."""
    u = url.strip()
    if not u:
        return ""

    # Strip scheme://[user[:pass]@]
    scheme_m = re.match(r"^(?:https?|ssh|git|file)://(?:[^@/]+@)?(.+)$", u, re.IGNORECASE)
    if scheme_m:
        rest = scheme_m.group(1)
        if u.lower().startswith("file://"):
            return rest.rstrip("/").removesuffix(".git") if hasattr(str, "removesuffix") else re.sub(r"\.git$", "", rest.rstrip("/"))
        # Split host[:port]/path
        slash = rest.find("/")
        if slash != -1:
            host_port = rest[:slash]
            path_part = rest[slash + 1 :]
            host = host_port.split(":", 1)[0].lower()
            path_clean = re.sub(r"\.git$", "", path_part.rstrip("/"), flags=re.IGNORECASE)
            return f"{host}/{path_clean}"
        return rest.lower()

    # SCP-style SSH: [user@]host:org/repo.git
    scp_m = re.match(r"^(?:[^@/]+@)?([A-Za-z0-9._-]+):(.+)$", u)
    if scp_m:
        host = scp_m.group(1).lower()
        path_clean = re.sub(r"\.git$", "", scp_m.group(2).lstrip("/").rstrip("/"), flags=re.IGNORECASE)
        return f"{host}/{path_clean}"

    # Local filesystem path
    return re.sub(r"\.git$", "", u.rstrip("/"), flags=re.IGNORECASE)


def get_repo_remotes(repo_root: Path) -> List[Dict[str, str]]:
    proc = run_git(["remote", "-v"], repo_root)
    if proc.returncode != 0:
        return []
    seen: Set[Tuple[str, str]] = set()
    remotes: List[Dict[str, str]] = []
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, raw_url = parts[0], parts[1]
        norm = normalize_remote_url(raw_url)
        key = (name, norm)
        if key in seen:
            continue
        seen.add(key)
        remotes.append({"name": name, "normalized": norm})
    return remotes


def _remote_matches_allowlist(normalized_remote: str, patterns: Sequence[str]) -> bool:
    norm_lower = normalized_remote.lower()
    for pat in patterns:
        p = normalize_remote_url(pat) if ("://" in pat or ":" in pat) else pat.strip()
        p_lower = p.lower().rstrip("/")
        if not p_lower:
            continue
        if fnmatch.fnmatch(norm_lower, p_lower) or fnmatch.fnmatch(norm_lower, f"{p_lower}/*"):
            return True
    return False


def evaluate_stealth_policy(cwd: Path, config_path: Optional[str] = None) -> Dict[str, Any]:
    """Fail-closed repository scope classifier: active on external/unrecognized repos, quiet only on allowlisted internals."""
    cfg = load_policy_config(config_path)
    repo_root = find_git_root(cwd)
    base: Dict[str, Any] = {
        "config_path": cfg["config_path"],
        "config_exists": cfg["config_exists"],
        "mode": cfg["mode"],
        "forced": cfg["forced"],
        "repo_root": str(repo_root) if repo_root else None,
        "remotes": [],
        "external_remotes": [],
        "internal_remotes_configured": cfg["internal_remotes"],
        "blocked_terms_count": len(cfg["blocked_terms"]),
    }

    if cfg["forced"]:
        base["active"] = True
        base["reason"] = "forced_always_on"
        if repo_root:
            base["remotes"] = get_repo_remotes(repo_root)
        return base

    if not repo_root:
        base["active"] = True
        base["reason"] = "non_git_workspace_fail_closed"
        return base

    remotes = get_repo_remotes(repo_root)
    base["remotes"] = remotes

    if not cfg["internal_remotes"]:
        base["active"] = True
        base["reason"] = "default_active_all_repos"
        return base

    if not remotes:
        base["active"] = True
        base["reason"] = "no_remotes_fail_closed"
        return base

    external = [
        r["normalized"]
        for r in remotes
        if not _remote_matches_allowlist(r["normalized"], cfg["internal_remotes"])
    ]
    base["external_remotes"] = external

    if external:
        base["active"] = True
        base["reason"] = "external_remote_detected"
    else:
        base["active"] = False
        base["reason"] = "internal_allowlisted_repo"
    return base


def get_effective_extra_patterns(
    cli_extra: Optional[str],
    config_path: Optional[str] = None,
) -> List[re.Pattern[str]]:
    cfg = load_policy_config(config_path)
    patterns = [re.compile(re.escape(t), re.IGNORECASE) for t in cfg["blocked_terms"]]
    patterns.extend(compile_extra_patterns(cli_extra))
    return patterns


def build_session_policy_prompt(policy: Dict[str, Any]) -> str:
    """Original clean-room session contribution hygiene prompt (vendor-neutral, zero proprietary text)."""
    ext = policy.get("external_remotes") or []
    scope_note = f"External remote(s): {', '.join(ext[:3])}." if ext else f"Policy state: {policy.get('reason', 'active')}."
    terms_note = (
        f"\n5. Never emit any confidential terms configured in local policy ({policy['blocked_terms_count']} active rule(s))."
        if policy.get("blocked_terms_count", 0) > 0
        else ""
    )
    return (
        "[UNDERCOVER CLEAN-CONTRIBUTION POLICY — ACTIVE]\n"
        f"{scope_note}\n"
        "Apply strict attribution-free hygiene to every Git commit, pull request title/body, "
        "issue/review comment, and code edit in this session:\n"
        "1. Omit all AI attribution trailers (Co-Authored-By, Assisted-by, Made-with, Generated-by) "
        "and tool/model generator footers or badges.\n"
        "2. Do not mention AI assistants, model names/versions, or automated authorship in commits, PRs, issues, or code comments.\n"
        "3. Keep commit messages, PR descriptions, and comments concise and natural, matching the repository's existing human conventions.\n"
        "4. Never stage local agent config/history files (.claude/, CLAUDE.local.md, .cursor*, .aider*, .windsurf*, .roorules, .clinerules) "
        "or emit invisible Unicode characters."
        f"{terms_note}"
    )


# ---------------------------------------------------------------------------
# Unicode Watermark Engine (Emoji / CJK / RTL-Script Aware)
# ---------------------------------------------------------------------------


def _is_emoji_like(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x2300 <= cp <= 0x23FF
        or cp in (0xFE0F, 0x20E3)
        or 0x1F1E6 <= cp <= 0x1F1FF
    )


def _is_cjk_ideograph(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x4E00 <= cp <= 0x9FFF
        or 0x3400 <= cp <= 0x4DBF
        or 0x20000 <= cp <= 0x2FA1F
    )


def _is_complex_joiner_script(ch: str) -> bool:
    """Arabic, Persian, Syriac, Indic scripts where ZWNJ/ZWJ are grammatically legitimate."""
    cp = ord(ch)
    return (
        0x0600 <= cp <= 0x06FF  # Arabic / Persian
        or 0x0750 <= cp <= 0x077F
        or 0x08A0 <= cp <= 0x08FF
        or 0x0900 <= cp <= 0x0DFF  # Indic scripts (Devanagari, Bengali, Malayalam, Sinhala, etc.)
        or 0x0590 <= cp <= 0x05FF  # Hebrew (for bidi check)
    )


def scan_unicode_watermarks(
    text: str,
    *,
    is_code_file: bool = False,
    include_nbsp: bool = False,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    line_no = 1
    col_no = 0
    n = len(text)

    for idx, ch in enumerate(text):
        if ch == "\n":
            line_no += 1
            col_no = 0
            continue
        col_no += 1
        cp = ord(ch)
        prev_ch = text[idx - 1] if idx > 0 else ""
        next_ch = text[idx + 1] if idx + 1 < n else ""

        # 1. Unicode Tags block (U+E0000 - U+E007F) — classic invisible steganography
        if 0xE0000 <= cp <= 0xE007F:
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": f"U+{cp:04X}",
                    "name": unicodedata.name(ch, "TAG CHARACTER"),
                    "category": "unicode_tag",
                    "severity": "CRITICAL",
                    "action": "remove",
                }
            )
            continue

        # 2. Variation Selectors Supplement (U+E0100 - U+E01EF) — skip real CJK IVS
        if 0xE0100 <= cp <= 0xE01EF:
            if prev_ch and _is_cjk_ideograph(prev_ch):
                continue
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": f"U+{cp:04X}",
                    "name": unicodedata.name(ch, "VARIATION SELECTOR SUPPLEMENT"),
                    "category": "variation_selector_supp",
                    "severity": "HIGH",
                    "action": "remove",
                }
            )
            continue

        # 3. Zero-width & invisible format chars
        if cp in ZERO_WIDTH_CHARS:
            if cp == 0xFEFF and idx == 0:
                findings.append(
                    {
                        "index": idx,
                        "line": line_no,
                        "col": col_no,
                        "codepoint": "U+FEFF",
                        "name": "UTF-8 BOM (start of file)",
                        "category": "utf8_bom",
                        "severity": "INFO",
                        "action": "keep_unless_strip_bom",
                    }
                )
                continue
            if cp == 0x200D:
                # Preserve legitimate emoji ZWJ sequences and Indic/Arabic joiners
                if (prev_ch and _is_emoji_like(prev_ch)) or (next_ch and _is_emoji_like(next_ch)):
                    continue
                if (prev_ch and _is_complex_joiner_script(prev_ch)) or (
                    next_ch and _is_complex_joiner_script(next_ch)
                ):
                    continue
            if cp == 0x200C:
                if (prev_ch and _is_complex_joiner_script(prev_ch)) or (
                    next_ch and _is_complex_joiner_script(next_ch)
                ):
                    continue
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": f"U+{cp:04X}",
                    "name": ZERO_WIDTH_CHARS[cp],
                    "category": "zero_width",
                    "severity": "HIGH",
                    "action": "remove",
                }
            )
            continue

        # 4. Bidi control / Trojan Source characters
        if cp in BIDI_CONTROL_CHARS:
            if cp in (0x200E, 0x200F, 0x061C) and (
                (prev_ch and _is_complex_joiner_script(prev_ch))
                or (next_ch and _is_complex_joiner_script(next_ch))
            ):
                continue
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": f"U+{cp:04X}",
                    "name": BIDI_CONTROL_CHARS[cp],
                    "category": "bidi_control",
                    "severity": "HIGH",
                    "action": "remove",
                }
            )
            continue

        # 5. Exotic typographic spaces (e.g. U+202F Narrow No-Break Space LLM tell)
        if cp in EXOTIC_SPACE_CHARS:
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": f"U+{cp:04X}",
                    "name": EXOTIC_SPACE_CHARS[cp],
                    "category": "exotic_space",
                    "severity": "MEDIUM",
                    "action": "space",
                }
            )
            continue

        # 6. Non-breaking space (U+00A0) in source code or when explicitly requested
        if cp == 0x00A0 and (is_code_file or include_nbsp):
            findings.append(
                {
                    "index": idx,
                    "line": line_no,
                    "col": col_no,
                    "codepoint": "U+00A0",
                    "name": "NO-BREAK SPACE",
                    "category": "nbsp_in_code",
                    "severity": "MEDIUM",
                    "action": "space",
                }
            )

    return findings


def strip_unicode_watermarks(
    text: str,
    *,
    is_code_file: bool = False,
    normalize_nbsp: bool = False,
    strip_bom: bool = False,
) -> Tuple[str, List[Dict[str, Any]]]:
    hits = scan_unicode_watermarks(
        text, is_code_file=is_code_file, include_nbsp=normalize_nbsp
    )
    if not hits:
        return text, []

    actions_by_idx: Dict[int, str] = {}
    applied_hits: List[Dict[str, Any]] = []
    for h in hits:
        act = h["action"]
        if act == "keep_unless_strip_bom":
            if strip_bom:
                actions_by_idx[h["index"]] = "remove"
                applied_hits.append(h)
        else:
            actions_by_idx[h["index"]] = act
            applied_hits.append(h)

    if not actions_by_idx:
        return text, []

    out_chars: List[str] = []
    for idx, ch in enumerate(text):
        act = actions_by_idx.get(idx)
        if act == "remove":
            continue
        elif act == "space":
            out_chars.append(" ")
        else:
            out_chars.append(ch)
    return "".join(out_chars), applied_hits


# ---------------------------------------------------------------------------
# Commit Message / PR Body / Comment Sanitizer
# ---------------------------------------------------------------------------


def is_ai_trailer_line(line: str) -> Tuple[bool, Optional[str]]:
    m = TRAILER_LINE_RE.match(line)
    if not m:
        return False, None
    key = m.group(1).lower()
    val = m.group(2).strip()

    if key in AI_ONLY_TRAILER_KEYS:
        return True, f"ai_trailer:{key}"

    if key in CONDITIONAL_TRAILER_KEYS:
        if AI_EMAIL_RE.search(val):
            return True, f"ai_trailer_email:{key}"
        if AI_TRAILER_VALUE_RE.search(val):
            return True, f"ai_trailer_name:{key}"

    return False, None


def is_generator_footer_line(line: str) -> bool:
    return any(pat.match(line) for pat in GENERATOR_FOOTER_PATTERNS)


def is_ai_author_identity(name: str, email: str) -> Tuple[bool, Optional[str]]:
    if email and AI_EMAIL_RE.search(email):
        return True, f"ai_email:{email}"
    if name:
        for pat in AI_AUTHOR_NAME_PATTERNS:
            if pat.search(name.strip()):
                return True, f"ai_author_name:{name}"
    return False, None


def detect_text_watermarks(
    text: str,
    *,
    extra_patterns: Sequence[re.Pattern[str]] = (),
) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        matched_trailer, reason = is_ai_trailer_line(line)
        if matched_trailer:
            issues.append(
                {
                    "type": "ai_trailer",
                    "rule": reason,
                    "severity": "CRITICAL",
                    "line": lineno,
                    "excerpt": line.strip()[:160],
                }
            )
            continue

        if is_generator_footer_line(line):
            issues.append(
                {
                    "type": "generator_footer",
                    "rule": "ai_generator_footer",
                    "severity": "CRITICAL",
                    "line": lineno,
                    "excerpt": line.strip()[:160],
                }
            )
            continue

        for rule_name, pat, sev in SELF_DISCLOSURE_PATTERNS:
            if pat.search(line):
                issues.append(
                    {
                        "type": "self_disclosure",
                        "rule": rule_name,
                        "severity": sev,
                        "line": lineno,
                        "excerpt": line.strip()[:160],
                    }
                )

        for pat in extra_patterns:
            if pat.search(line):
                issues.append(
                    {
                        "type": "extra_pattern",
                        "rule": pat.pattern,
                        "severity": "HIGH",
                        "line": lineno,
                        "excerpt": line.strip()[:160],
                    }
                )

    unicode_hits = scan_unicode_watermarks(text, is_code_file=False, include_nbsp=False)
    for uh in unicode_hits:
        if uh["severity"] == "INFO":
            continue
        issues.append(
            {
                "type": "invisible_unicode",
                "rule": f"{uh['category']}:{uh['codepoint']}",
                "severity": uh["severity"],
                "line": uh["line"],
                "excerpt": f"{uh['codepoint']} ({uh['name']}) at col {uh['col']}",
            }
        )

    return issues


def sanitize_text_payload(
    text: str,
    *,
    kind: str = "commit",
    extra_patterns: Sequence[re.Pattern[str]] = (),
) -> Tuple[str, List[Dict[str, Any]]]:
    """Strip AI trailers, generator footers, and invisible Unicode watermarks cleanly."""
    removed: List[Dict[str, Any]] = []
    had_trailing_nl = text.endswith("\n")

    # Step 1: Remove invisible Unicode watermarks first so obfuscated trailers still match
    cleaned_text, unicode_hits = strip_unicode_watermarks(text, is_code_file=False)
    for uh in unicode_hits:
        removed.append(
            {
                "type": "invisible_unicode",
                "rule": f"{uh['category']}:{uh['codepoint']}",
                "line": uh["line"],
                "excerpt": f"{uh['codepoint']} ({uh['name']})",
            }
        )

    # Step 2: Strip matching attribution lines
    raw_lines = cleaned_text.splitlines()
    kept_lines: List[str] = []
    stripped_footer_indices: Set[int] = set()

    for idx, line in enumerate(raw_lines):
        # Preserve git comment lines (e.g., interactive commit template) untouched
        if kind == "commit" and line.startswith("#"):
            kept_lines.append(line)
            continue

        matched_trailer, reason = is_ai_trailer_line(line)
        if matched_trailer:
            removed.append(
                {
                    "type": "ai_trailer",
                    "rule": reason,
                    "line": idx + 1,
                    "excerpt": line.strip()[:160],
                }
            )
            stripped_footer_indices.add(idx)
            continue

        if is_generator_footer_line(line):
            removed.append(
                {
                    "type": "generator_footer",
                    "rule": "ai_generator_footer",
                    "line": idx + 1,
                    "excerpt": line.strip()[:160],
                }
            )
            stripped_footer_indices.add(idx)
            continue

        if extra_patterns and any(pat.search(line) for pat in extra_patterns):
            removed.append(
                {
                    "type": "extra_pattern",
                    "rule": "extra_pattern",
                    "line": idx + 1,
                    "excerpt": line.strip()[:160],
                }
            )
            stripped_footer_indices.add(idx)
            continue

        kept_lines.append(line)

    # Step 3: If we stripped trailing PR/commit footers, clean dangling trailing '---' or blank lines
    if stripped_footer_indices:
        # Separate trailing git comment block if commit message
        trailing_comments: List[str] = []
        if kind == "commit":
            while kept_lines and kept_lines[-1].startswith("#"):
                trailing_comments.append(kept_lines.pop())
            trailing_comments.reverse()

        while kept_lines and not kept_lines[-1].strip():
            kept_lines.pop()

        # Remove dangling horizontal rule only if it sat right before a stripped PR footer
        if kind == "pr" and kept_lines and re.match(r"^\s*(?:---+|___+|\*\*\*+)\s*$", kept_lines[-1]):
            kept_lines.pop()
            while kept_lines and not kept_lines[-1].strip():
                kept_lines.pop()

        if trailing_comments:
            if kept_lines:
                kept_lines.append("")
            kept_lines.extend(trailing_comments)

    result = "\n".join(kept_lines)
    if had_trailing_nl and result and not result.endswith("\n"):
        result += "\n"
    elif had_trailing_nl and not result:
        result = "\n"

    return result, removed


# ---------------------------------------------------------------------------
# Artifact & File Scanning
# ---------------------------------------------------------------------------


def match_agent_artifact(rel_posix_path: str, allow_patterns: Sequence[str] = ()) -> Optional[Tuple[str, str]]:
    for allow in allow_patterns:
        allow_clean = allow.strip()
        while allow_clean.startswith("./"):
            allow_clean = allow_clean[2:]
        allow_clean = allow_clean.lstrip("/")
        if not allow_clean:
            continue
        if rel_posix_path == allow_clean or rel_posix_path.startswith(allow_clean.rstrip("/") + "/"):
            return None
    for rule_name, pat, severity in AGENT_ARTIFACT_COMPILED:
        if pat.search(rel_posix_path):
            return rule_name, severity
    return None


def load_undercover_allowlist(repo_root: Optional[Path], cli_allow: Optional[str]) -> List[str]:
    entries: List[str] = []
    if cli_allow:
        entries.extend(x.strip() for x in cli_allow.split(",") if x.strip())
    env_allow = os.environ.get("UNDERCOVER_ALLOW_FILES", "")
    if env_allow:
        entries.extend(x.strip() for x in env_allow.split(",") if x.strip())
    if repo_root:
        ignore_file = repo_root / ".undercoverignore"
        if ignore_file.is_file():
            for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    entries.append(stripped)
    return entries


def collect_target_files(
    root: Path,
    *,
    exclude_substrings: Sequence[str] = (),
) -> List[Path]:
    git_root = find_git_root(root)
    files: List[Path] = []
    if root.is_file():
        return [root]

    if git_root and root.resolve() == git_root.resolve():
        proc = run_git(["ls-files", "-z"], git_root)
        if proc.returncode == 0:
            for rel_bytes in proc.stdout.split(b"\x00"):
                if not rel_bytes:
                    continue
                rel_str = rel_bytes.decode("utf-8", errors="replace")
                if any(ex in rel_str for ex in exclude_substrings):
                    continue
                p = git_root / rel_str
                if p.is_file():
                    files.append(p)
            return files

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for fname in filenames:
            p = Path(dirpath) / fname
            rel_str = p.relative_to(root).as_posix()
            if any(ex in rel_str for ex in exclude_substrings):
                continue
            files.append(p)
    return files


def scan_file_comments_and_unicode(
    path: Path,
    rel_display: str,
    *,
    include_nbsp: bool = False,
) -> Dict[str, Any]:
    if not is_text_file(path):
        return {"comments": [], "unicode": []}
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return {"comments": [], "unicode": []}

    ext = path.suffix.lower()
    is_code = ext in CODE_EXTENSIONS or path.name in ("Makefile", "Dockerfile")

    comment_hits: List[Dict[str, Any]] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        if CODE_AI_COMMENT_RE.match(line):
            comment_hits.append(
                {
                    "file": rel_display,
                    "line": lineno,
                    "severity": "HIGH",
                    "excerpt": line.strip()[:160],
                }
            )

    unicode_hits = scan_unicode_watermarks(
        content, is_code_file=is_code, include_nbsp=include_nbsp
    )
    filtered_unicode = [
        {
            "file": rel_display,
            "line": h["line"],
            "col": h["col"],
            "codepoint": h["codepoint"],
            "name": h["name"],
            "category": h["category"],
            "severity": h["severity"],
        }
        for h in unicode_hits
        if h["severity"] != "INFO"
    ]

    return {"comments": comment_hits, "unicode": filtered_unicode}


# ---------------------------------------------------------------------------
# Tool Configuration Auditor & Hardener
# ---------------------------------------------------------------------------


def _load_json_safe(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not path.exists():
        return None, None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None, "JSON root is not an object"
        return data, None
    except Exception as exc:
        return None, str(exc)


def _claude_hook_present(settings: Dict[str, Any], event_name: str = "PreToolUse", needle: str = "pre-tool-guard") -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        subhooks = entry.get("hooks")
        if not isinstance(subhooks, list):
            continue
        for h in subhooks:
            if isinstance(h, dict) and needle in str(h.get("command", "")):
                return True
    return False


def audit_tool_configs(repo_root: Optional[Path]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    checks: Dict[str, Any] = {}
    home = Path.home()

    # 1. Claude Code settings (global + project)
    claude_paths = [home / ".claude" / "settings.json"]
    if repo_root:
        proj_claude = repo_root / ".claude" / "settings.json"
        if proj_claude.exists():
            claude_paths.append(proj_claude)

    claude_status: List[Dict[str, Any]] = []
    for cpath in claude_paths:
        exists = cpath.exists()
        data, err = _load_json_safe(cpath)
        entry: Dict[str, Any] = {"path": str(cpath), "exists": exists}
        if err:
            entry["error"] = err
            findings.append(
                {
                    "pillar": "configs",
                    "severity": "MEDIUM",
                    "code": "claude_settings_parse_error",
                    "message": f"Could not parse {cpath}: {err}",
                    "target": str(cpath),
                }
            )
        elif not exists:
            if (home / ".claude").exists() and cpath == home / ".claude" / "settings.json":
                entry["attribution_disabled"] = False
                findings.append(
                    {
                        "pillar": "configs",
                        "severity": "HIGH",
                        "code": "claude_settings_missing_attribution",
                        "message": (
                            f"{cpath} does not exist while ~/.claude is present; "
                            "Claude Code defaults to injecting Co-Authored-By and PR attribution."
                        ),
                        "target": str(cpath),
                    }
                )
        else:
            assert data is not None
            attr = data.get("attribution")
            legacy = data.get("includeCoAuthoredBy")
            commit_off = False
            pr_off = False
            if attr is False:
                commit_off = True
                pr_off = True
            elif isinstance(attr, dict):
                commit_off = attr.get("commit") == ""
                pr_off = attr.get("pr") == ""
            entry["attribution"] = attr
            entry["legacy_includeCoAuthoredBy"] = legacy
            entry["attribution_disabled"] = commit_off and pr_off
            entry["pretool_guard_installed"] = _claude_hook_present(data, "PreToolUse", "pre-tool-guard")
            entry["session_start_hook_installed"] = _claude_hook_present(data, "SessionStart", "session-start")

            if not (commit_off and pr_off):
                detail = (
                    "legacy includeCoAuthoredBy=false alone is deprecated and does not silence PR attribution"
                    if legacy is False and attr is None
                    else 'missing "attribution": {"commit": "", "pr": ""}'
                )
                findings.append(
                    {
                        "pillar": "configs",
                        "severity": "HIGH",
                        "code": "claude_attribution_enabled",
                        "message": f"Claude Code attribution not fully disabled in {cpath} ({detail}).",
                        "target": str(cpath),
                    }
                )
            if not entry["pretool_guard_installed"]:
                findings.append(
                    {
                        "pillar": "configs",
                        "severity": "INFO",
                        "code": "claude_pretool_guard_absent",
                        "message": (
                            f"Optional Claude Code PreToolUse guard hook is not registered in {cpath}."
                        ),
                        "target": str(cpath),
                    }
                )
            if not entry["session_start_hook_installed"]:
                findings.append(
                    {
                        "pillar": "configs",
                        "severity": "INFO",
                        "code": "claude_session_start_absent",
                        "message": (
                            f"Optional Claude Code SessionStart auto-policy hook is not registered in {cpath}."
                        ),
                        "target": str(cpath),
                    }
                )
        claude_status.append(entry)
    checks["claude_code"] = claude_status

    # 2. Aider config
    aider_paths = [home / ".aider.conf.yml"]
    if repo_root and (repo_root / ".aider.conf.yml").exists():
        aider_paths.append(repo_root / ".aider.conf.yml")
    aider_status: List[Dict[str, Any]] = []
    for apath in aider_paths:
        if not apath.exists():
            continue
        raw = apath.read_text(encoding="utf-8", errors="replace")
        missing_flags: List[str] = []
        for flag in ("attribute-author", "attribute-committer", "attribute-co-authored-by"):
            if not re.search(rf"^\s*{re.escape(flag)}\s*:\s*false\b", raw, re.IGNORECASE | re.MULTILINE):
                missing_flags.append(flag)
        aider_status.append({"path": str(apath), "missing_false_flags": missing_flags})
        if missing_flags:
            findings.append(
                {
                    "pillar": "configs",
                    "severity": "HIGH",
                    "code": "aider_attribution_enabled",
                    "message": f"Aider config {apath} missing false flags: {', '.join(missing_flags)}",
                    "target": str(apath),
                }
            )
    checks["aider"] = aider_status

    # 3. VS Code / Cursor settings (read-only inspection)
    editor_candidates = [
        ("vscode", home / "Library" / "Application Support" / "Code" / "User" / "settings.json"),
        ("vscode_linux", home / ".config" / "Code" / "User" / "settings.json"),
        ("cursor", home / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"),
        ("cursor_linux", home / ".config" / "Cursor" / "User" / "settings.json"),
    ]
    editor_status: List[Dict[str, Any]] = []
    for label, epath in editor_candidates:
        if not epath.exists():
            continue
        raw = epath.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'"git\.addAICoAuthor"\s*:\s*(true|false)', raw)
        val = m.group(1) if m else None
        editor_status.append({"editor": label, "path": str(epath), "git.addAICoAuthor": val})
        if val == "true":
            findings.append(
                {
                    "pillar": "configs",
                    "severity": "HIGH",
                    "code": "editor_ai_coauthor_enabled",
                    "message": f'{label} has "git.addAICoAuthor": true in {epath}.',
                    "target": str(epath),
                }
            )
    checks["editors"] = editor_status

    # 4. Git hooks status (global core.hooksPath & repo hooks)
    global_hooks_proc = run_git(["config", "--global", "--get", "core.hooksPath"], home)
    global_hooks_path = (
        global_hooks_proc.stdout.decode("utf-8", errors="replace").strip()
        if global_hooks_proc.returncode == 0
        else ""
    )
    hooks_info: Dict[str, Any] = {"global_hooks_path": global_hooks_path or None, "repo_hooks": {}}
    any_commit_msg_managed = False

    if global_hooks_path:
        gp = Path(os.path.expanduser(global_hooks_path))
        g_cm = gp / "commit-msg"
        if g_cm.is_file() and HOOK_MARKER in g_cm.read_text(encoding="utf-8", errors="replace"):
            any_commit_msg_managed = True
            hooks_info["global_undercover_active"] = True

    if repo_root:
        git_dir = find_git_dir(repo_root)
        local_hp_proc = run_git(["config", "--local", "--get", "core.hooksPath"], repo_root)
        local_hp = (
            local_hp_proc.stdout.decode("utf-8", errors="replace").strip()
            if local_hp_proc.returncode == 0
            else ""
        )
        hook_dir = (
            (Path(local_hp) if Path(local_hp).is_absolute() else (repo_root / local_hp))
            if local_hp
            else (git_dir / "hooks")
        )
        for hname in ("commit-msg", "pre-commit", "pre-push"):
            hp = hook_dir / hname
            if hp.is_file():
                txt = hp.read_text(encoding="utf-8", errors="replace")
                managed = HOOK_MARKER in txt
                hooks_info["repo_hooks"][hname] = {"exists": True, "undercover_managed": managed}
                if hname == "commit-msg" and managed:
                    any_commit_msg_managed = True
            else:
                hooks_info["repo_hooks"][hname] = {"exists": False, "undercover_managed": False}

        # Check .git/info/exclude coverage
        exclude_file = git_dir / "info" / "exclude"
        exclude_txt = exclude_file.read_text(encoding="utf-8", errors="replace") if exclude_file.is_file() else ""
        missing_excludes = [e for e in (".claude/", "CLAUDE.local.md", ".cursor/", ".aider*") if e not in exclude_txt]
        checks["git_local_exclude"] = {
            "path": str(exclude_file),
            "missing_core_patterns": missing_excludes,
        }
        if missing_excludes:
            findings.append(
                {
                    "pillar": "configs",
                    "severity": "INFO",
                    "code": "git_exclude_incomplete",
                    "message": (
                        f"Private local ignore {exclude_file} is missing agent patterns: "
                        f"{', '.join(missing_excludes)}"
                    ),
                    "target": str(exclude_file),
                }
            )

    if not any_commit_msg_managed:
        findings.append(
            {
                "pillar": "configs",
                "severity": "MEDIUM",
                "code": "undercover_git_hooks_not_installed",
                "message": "Undercover Git commit-msg hook is not active (neither repo-local nor global).",
                "target": str(repo_root or home),
            }
        )
    checks["git_hooks"] = hooks_info

    # 5. Relevant non-secret environment variables
    env_vars = {
        k: os.environ.get(k)
        for k in (
            "UNDERCOVER_MODE",
            "UNDERCOVER_FORCE",
            "UNDERCOVER_INTERNAL_REMOTES",
            "UNDERCOVER_CONFIG",
            "AIDER_ATTRIBUTE_AUTHOR",
            "AIDER_ATTRIBUTE_COMMITTER",
            "AIDER_ATTRIBUTE_CO_AUTHORED_BY",
        )
        if k in os.environ
    }
    checks["environment"] = env_vars
    checks["policy"] = evaluate_stealth_policy(repo_root or Path.cwd())

    return {"checks": checks, "findings": findings}


# ---------------------------------------------------------------------------
# Subcommand 1: audit
# ---------------------------------------------------------------------------


def audit_commits(
    repo_root: Path,
    *,
    commit_range: Optional[str],
    unpushed: bool,
    max_commits: int,
    extra_patterns: Sequence[re.Pattern[str]],
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    resolved_range = commit_range
    if unpushed and not resolved_range:
        up = run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], repo_root)
        if up.returncode == 0:
            upstream = up.stdout.decode("utf-8", errors="replace").strip()
            resolved_range = f"{upstream}..HEAD"
        else:
            resolved_range = "HEAD"

    log_args = [
        "log",
        f"-n{max_commits}",
        "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e",
    ]
    if resolved_range:
        log_args.append(resolved_range)

    proc = run_git(log_args, repo_root)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        # Handle empty repository with no commits yet gracefully
        if "does not have any commits yet" in err or "unknown revision" in err:
            return {
                "commits_scanned": 0,
                "dirty_commits": 0,
                "range": resolved_range or "HEAD",
                "note": err,
                "findings": [],
            }
        raise RuntimeError(f"git log failed: {err}")

    raw_records = proc.stdout.decode("utf-8", errors="replace").split("\x1e")
    scanned = 0
    dirty_shas: Set[str] = set()

    for rec in raw_records:
        rec = rec.strip("\n")
        if not rec.strip():
            continue
        parts = rec.split("\x1f", 5)
        if len(parts) < 6:
            continue
        sha, an, ae, cn, ce, body = parts
        scanned += 1
        short_sha = sha[:10]

        # Check author / committer identities
        for role, name, email in (("author", an, ae), ("committer", cn, ce)):
            is_ai, reason = is_ai_author_identity(name, email)
            if is_ai:
                dirty_shas.add(sha)
                findings.append(
                    {
                        "pillar": "commits",
                        "severity": "CRITICAL",
                        "code": f"commit_{role}_identity_leak",
                        "commit": short_sha,
                        "full_sha": sha,
                        "message": f"Commit {short_sha} {role} exposes AI identity ({reason}): {name} <{email}>",
                    }
                )

        # Check message text
        msg_issues = detect_text_watermarks(body, extra_patterns=extra_patterns)
        for iss in msg_issues:
            dirty_shas.add(sha)
            findings.append(
                {
                    "pillar": "commits",
                    "severity": iss["severity"],
                    "code": f"commit_{iss['type']}",
                    "commit": short_sha,
                    "full_sha": sha,
                    "rule": iss["rule"],
                    "message": f"Commit {short_sha} line {iss['line']}: {iss['excerpt']}",
                }
            )

    return {
        "commits_scanned": scanned,
        "dirty_commits": len(dirty_shas),
        "range": resolved_range or f"HEAD (last {max_commits})",
        "findings": findings,
    }


def compute_stealth_grade(severity_counts: Dict[str, int]) -> str:
    if severity_counts["CRITICAL"] > 0:
        return "F" if severity_counts["CRITICAL"] >= 3 else "D"
    if severity_counts["HIGH"] > 0:
        return "C" if severity_counts["HIGH"] >= 3 else "B-"
    if severity_counts["MEDIUM"] > 0:
        return "B" if severity_counts["MEDIUM"] >= 3 else "A-"
    return "A"


def cmd_audit(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    repo_root = find_git_root(target)
    extra_patterns = get_effective_extra_patterns(args.extra_patterns, getattr(args, "config", None))
    allow_files = load_undercover_allowlist(repo_root, args.allow_files)
    exclude_substrings = [x.strip() for x in (args.exclude or "").split(",") if x.strip()]
    policy = evaluate_stealth_policy(target, getattr(args, "config", None))

    all_findings: List[Dict[str, Any]] = []
    report: Dict[str, Any] = {
        "tool": "undercover",
        "version": VERSION,
        "timestamp_utc": utc_timestamp(),
        "target": str(target),
        "git_root": str(repo_root) if repo_root else None,
        "policy": {
            "active": policy["active"],
            "reason": policy["reason"],
            "mode": policy["mode"],
            "blocked_terms_count": policy["blocked_terms_count"],
        },
        "pillars": {},
    }

    # Pillar 1: Commits
    if repo_root and not args.skip_commits:
        c_res = audit_commits(
            repo_root,
            commit_range=args.range,
            unpushed=args.unpushed,
            max_commits=args.max_commits,
            extra_patterns=extra_patterns,
        )
        report["pillars"]["commits"] = {k: v for k, v in c_res.items() if k != "findings"}
        all_findings.extend(c_res["findings"])
    else:
        report["pillars"]["commits"] = {"skipped": True}

    # Pillar 2: Tracked & staged agent artifact files
    artifact_hits: List[Dict[str, Any]] = []
    if repo_root:
        tracked_proc = run_git(["ls-files", "-z"], repo_root)
        staged_proc = run_git(["diff", "--cached", "--name-only", "-z"], repo_root)
        seen_paths: Set[str] = set()
        for source_label, proc in (("staged", staged_proc), ("tracked", tracked_proc)):
            if proc.returncode != 0:
                continue
            for raw_p in proc.stdout.split(b"\x00"):
                if not raw_p:
                    continue
                rel_p = raw_p.decode("utf-8", errors="replace")
                if rel_p in seen_paths or any(ex in rel_p for ex in exclude_substrings):
                    continue
                matched = match_agent_artifact(rel_p, allow_files)
                if matched:
                    seen_paths.add(rel_p)
                    rule_name, sev = matched
                    finding = {
                        "pillar": "artifacts",
                        "severity": sev,
                        "code": f"agent_artifact_{rule_name}",
                        "file": rel_p,
                        "state": source_label,
                        "message": f"Agent trace file ({source_label}): {rel_p} [{rule_name}]",
                    }
                    artifact_hits.append(finding)
                    all_findings.append(finding)
        report["pillars"]["artifacts"] = {"leaked_files": len(artifact_hits)}
    else:
        report["pillars"]["artifacts"] = {"skipped": True}

    # Pillar 3: Working tree source comments & invisible Unicode watermarks
    files_scanned = 0
    comment_count = 0
    unicode_count = 0
    for fpath in collect_target_files(target, exclude_substrings=exclude_substrings):
        rel = fpath.relative_to(repo_root).as_posix() if repo_root and str(fpath).startswith(str(repo_root)) else str(fpath)
        res = scan_file_comments_and_unicode(fpath, rel, include_nbsp=args.include_nbsp)
        files_scanned += 1
        for ch in res["comments"]:
            comment_count += 1
            all_findings.append(
                {
                    "pillar": "files",
                    "severity": ch["severity"],
                    "code": "ai_code_comment",
                    "file": ch["file"],
                    "line": ch["line"],
                    "message": f"{ch['file']}:{ch['line']} AI attribution comment: {ch['excerpt']}",
                }
            )
        for uh in res["unicode"]:
            unicode_count += 1
            all_findings.append(
                {
                    "pillar": "files",
                    "severity": uh["severity"],
                    "code": f"invisible_unicode_{uh['category']}",
                    "file": uh["file"],
                    "line": uh["line"],
                    "col": uh["col"],
                    "codepoint": uh["codepoint"],
                    "message": (
                        f"{uh['file']}:{uh['line']}:{uh['col']} "
                        f"{uh['codepoint']} ({uh['name']})"
                    ),
                }
            )
    report["pillars"]["files"] = {
        "files_scanned": files_scanned,
        "ai_comment_hits": comment_count,
        "unicode_watermark_hits": unicode_count,
    }

    # Pillar 4: Local tool configurations
    if not args.skip_configs:
        cfg_res = audit_tool_configs(repo_root)
        report["pillars"]["configs"] = cfg_res["checks"]
        all_findings.extend(cfg_res["findings"])
    else:
        report["pillars"]["configs"] = {"skipped": True}

    # Sort findings by severity & compute grade
    all_findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f.get("pillar", "")))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1

    grade = compute_stealth_grade(counts)
    report["stealth_grade"] = grade
    report["severity_counts"] = counts
    report["all_findings"] = all_findings

    summary = (
        f"[UNDERCOVER audit] grade={grade} "
        f"CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
        f"MEDIUM={counts['MEDIUM']} INFO={counts['INFO']}"
    )
    write_json_report(report, args.output, summary)
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(f["severity"], 99) <= threshold for f in all_findings):
            return 1
    return 0


# ---------------------------------------------------------------------------
# Subcommand 2: sanitize-text (also powers commit-msg hook & PR filtering)
# ---------------------------------------------------------------------------


def cmd_sanitize_text(args: argparse.Namespace) -> int:
    if getattr(args, "respect_policy", False):
        policy = evaluate_stealth_policy(Path.cwd(), getattr(args, "config", None))
        if not policy["active"]:
            if not args.in_place and not args.output:
                if args.file:
                    sys.stdout.write(Path(args.file).read_text(encoding="utf-8", errors="replace"))
                else:
                    sys.stdout.write(sys.stdin.read())
            return 0

    if getattr(args, "check_identity", False):
        for role, name_var, email_var in (
            ("author", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL"),
            ("committer", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"),
        ):
            name_v = os.environ.get(name_var, "")
            email_v = os.environ.get(email_var, "")
            is_ai, reason = is_ai_author_identity(name_v, email_v)
            if is_ai:
                print(
                    f"[UNDERCOVER] Blocked AI identity in {role} env ({reason}): {name_v} <{email_v}>",
                    file=sys.stderr,
                )
                return 1

    extra_patterns = get_effective_extra_patterns(args.extra_patterns, getattr(args, "config", None))
    if args.file:
        fpath = Path(args.file)
        if not fpath.is_file():
            print(f"Error: file not found: {fpath}", file=sys.stderr)
            return 2
        raw = fpath.read_text(encoding="utf-8", errors="replace")
    else:
        raw = sys.stdin.read()

    if args.mode == "check":
        issues = detect_text_watermarks(raw, extra_patterns=extra_patterns)
        report = {
            "mode": "check",
            "kind": args.kind,
            "clean": len(issues) == 0,
            "issue_count": len(issues),
            "issues": issues,
        }
        if args.output:
            write_json_report(
                report,
                args.output,
                f"[UNDERCOVER sanitize-text] clean={report['clean']} issues={len(issues)}",
            )
        elif issues:
            for iss in issues:
                print(
                    f"[UNDERCOVER] Blocked AI watermark ({iss['type']}/{iss['rule']}) "
                    f"at line {iss['line']}: {iss['excerpt']}",
                    file=sys.stderr,
                )
        return 0 if not issues else 1

    cleaned, removed = sanitize_text_payload(raw, kind=args.kind, extra_patterns=extra_patterns)
    if args.in_place:
        if not args.file:
            print("Error: --in-place requires --file", file=sys.stderr)
            return 2
        if removed:
            Path(args.file).write_text(cleaned, encoding="utf-8")
            if not args.quiet:
                print(
                    f"[UNDERCOVER] Scrubbed {len(removed)} AI watermark(s) from {args.file}",
                    file=sys.stderr,
                )
    elif args.output:
        report = {
            "mode": "scrub",
            "kind": args.kind,
            "removed_count": len(removed),
            "removed": removed,
            "cleaned_text": cleaned,
        }
        write_json_report(
            report,
            args.output,
            f"[UNDERCOVER sanitize-text] removed={len(removed)}",
        )
    else:
        sys.stdout.write(cleaned)
    return 0


# ---------------------------------------------------------------------------
# Subcommand 3: pre-tool-guard (Claude Code & Antigravity PreToolUse Hook)
# ---------------------------------------------------------------------------

OUTBOUND_CMD_RE = re.compile(
    r"\b(?:git\s+(?:commit|tag|notes|add|am|merge|cherry-pick|revert|push)|"
    r"gh\s+(?:pr|issue)\s+(?:create|edit|comment|review)|"
    r"glab\s+(?:mr|issue)\s+(?:create|update|note))\b",
    re.IGNORECASE,
)

GIT_ADD_AGENT_FILE_RE = re.compile(
    r"\bgit\s+add\b[^\n;|&]*(?:\.claude(?:/|\b)|CLAUDE\.local\.md|\.cursorrules|\.cursor/|\.aider|\.(?:clinerules|roorules|windsurfrules))",
    re.IGNORECASE,
)


def inspect_shell_command(command: str, extra_patterns: Sequence[re.Pattern[str]] = ()) -> List[str]:
    if not command or not OUTBOUND_CMD_RE.search(command):
        return []

    reasons: List[str] = []

    # 1. Check staging of high-risk agent trace files via git add
    if GIT_ADD_AGENT_FILE_RE.search(command):
        reasons.append(
            "Command stages AI agent configuration/history files (.claude/, CLAUDE.local.md, .cursor*, .aider*, etc.)."
        )

    # 2. Check trailers, generator footers, self-disclosure text, and invisible Unicode in command payload
    # Normalize escaped \n inside inline -m "..." strings so line-based detectors see each line
    normalized = command.replace("\\n", "\n")
    issues = detect_text_watermarks(normalized, extra_patterns=extra_patterns)
    for iss in issues:
        reasons.append(f"{iss['type']} ({iss['rule']}): {iss['excerpt']}")

    # 3. Direct inline check for common AI attribution snippets that may sit mid-line in quoted CLI flags
    inline_checks = (
        (r"Co-Authored-By:\s*[^\n\"']*(?:Claude|noreply@anthropic\.com|cursoragent|Copilot|Aider|Codex)", "Inline AI Co-Authored-By trailer"),
        (r"Generated\s+(?:with|by)\s+\[?(?:Claude\s+Code|Cursor|Copilot|Codex|Aider|Gemini\s+CLI|Antigravity)\]?", "Inline AI generator footer"),
        (r"noreply@anthropic\.com|cursoragent@cursor\.com|aider@aider\.chat", "AI bot attribution email"),
        (r"Made-with:\s*(?:Cursor|Claude|Copilot|Codex|Aider)", "Inline Made-with AI trailer"),
    )
    for pat_str, desc in inline_checks:
        if re.search(pat_str, normalized, re.IGNORECASE):
            if not any(desc in r for r in reasons):
                reasons.append(desc)

    return reasons


def _extract_hook_cwd(payload: Dict[str, Any]) -> Path:
    raw_cwd = payload.get("cwd")
    if isinstance(raw_cwd, str) and raw_cwd.strip():
        p = Path(os.path.expanduser(raw_cwd.strip()))
        if p.exists():
            return p.resolve()
    ws = payload.get("workspacePaths")
    if isinstance(ws, list) and ws and isinstance(ws[0], str) and ws[0].strip():
        p = Path(os.path.expanduser(ws[0].strip()))
        if p.exists():
            return p.resolve()
    return Path.cwd().resolve()


def cmd_pre_tool_guard(args: argparse.Namespace) -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return 0

    if not isinstance(payload, dict):
        return 0

    # Detect host protocol: Antigravity vs Claude Code
    is_antigravity = "toolCall" in payload and isinstance(payload.get("toolCall"), dict)
    command = ""

    if is_antigravity:
        tc = payload["toolCall"]
        tool_name = str(tc.get("name", ""))
        tc_args = tc.get("args") or {}
        if tool_name == "run_command" and isinstance(tc_args, dict):
            command = str(tc_args.get("CommandLine", ""))
    else:
        tool_name = str(payload.get("tool_name", ""))
        tool_input = payload.get("tool_input") or {}
        if tool_name == "Bash" and isinstance(tool_input, dict):
            command = str(tool_input.get("command", ""))

    if not command:
        if is_antigravity:
            print(json.dumps({"decision": "allow"}))
        return 0

    # Honor repository scope policy (stands down ONLY when repo matches user's internal_remotes allowlist)
    cwd = _extract_hook_cwd(payload)
    policy = evaluate_stealth_policy(cwd, getattr(args, "config", None))
    if not policy["active"]:
        if is_antigravity:
            print(json.dumps({"decision": "allow"}))
        return 0

    extra_patterns = get_effective_extra_patterns(args.extra_patterns, getattr(args, "config", None))
    reasons = inspect_shell_command(command, extra_patterns=extra_patterns)
    if not reasons:
        if is_antigravity:
            print(json.dumps({"decision": "allow"}))
        return 0

    reason_text = (
        "UNDERCOVER GUARD: Blocked AI contribution watermark or confidential term in command. "
        "Remove all AI attribution trailers, generator footers, blocked terms, agent trace files, "
        "or invisible Unicode watermarks and retry cleanly. Findings: "
        + "; ".join(reasons[:5])
    )

    if is_antigravity:
        print(json.dumps({"decision": "deny", "reason": reason_text}, ensure_ascii=False))
        return 0

    # Claude Code PreToolUse JSON deny contract
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason_text,
        }
    }
    print(json.dumps(response, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# Subcommand 3b/3c/3d: session-start, repo-status, init-policy (Clean-Room Auto-Activation)
# ---------------------------------------------------------------------------


def cmd_session_start(args: argparse.Namespace) -> int:
    """Dual-protocol SessionStart hook for Claude Code and Antigravity."""
    if args.preview:
        target = Path(args.preview).resolve()
        policy = evaluate_stealth_policy(target, getattr(args, "config", None))
        out = {
            "policy": policy,
            "injected_prompt": build_session_policy_prompt(policy) if policy["active"] else None,
        }
        write_json_report(
            out,
            args.output,
            f"[UNDERCOVER session-start] active={policy['active']} reason={policy['reason']}",
        )
        return 0

    raw = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    payload: Dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                payload = parsed
        except json.JSONDecodeError:
            payload = {}

    is_antigravity = any(
        k in payload for k in ("workspacePaths", "conversationId", "artifactDirectoryPath", "transcriptPath")
    )
    cwd = _extract_hook_cwd(payload)
    policy = evaluate_stealth_policy(cwd, getattr(args, "config", None))

    if not policy["active"]:
        if is_antigravity:
            print("{}")
        return 0

    prompt = build_session_policy_prompt(policy)
    if is_antigravity:
        print(
            json.dumps(
                {
                    "injectSteps": [
                        {
                            "systemMessage": {
                                "systemMessage": prompt,
                            }
                        }
                    ]
                },
                ensure_ascii=False,
            )
        )
        return 0

    # Claude Code official SessionStart hook contract
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": prompt,
                }
            },
            ensure_ascii=False,
        )
    )
    return 0


def cmd_repo_status(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2
    policy = evaluate_stealth_policy(target, getattr(args, "config", None))
    summary = (
        f"[UNDERCOVER repo-status] active={policy['active']} "
        f"reason={policy['reason']} mode={policy['mode']}"
    )
    write_json_report(policy, args.output, summary)
    return 0


def cmd_init_policy(args: argparse.Namespace) -> int:
    cfg_path = (
        Path(os.path.expanduser(args.config)).resolve()
        if args.config
        else default_policy_config_path()
    )
    existing, err = _load_json_safe(cfg_path)
    if err:
        print(f"Error: could not parse {cfg_path}: {err}", file=sys.stderr)
        return 2

    data: Dict[str, Any] = dict(existing) if existing is not None else {}
    cur_mode = str(data.get("mode", "auto"))
    cur_remotes = [str(x).strip() for x in data.get("internal_remotes", []) if str(x).strip()] if isinstance(data.get("internal_remotes"), list) else []
    cur_terms = [str(x).strip() for x in data.get("blocked_terms", []) if str(x).strip()] if isinstance(data.get("blocked_terms"), list) else []

    new_mode = args.mode or cur_mode
    if args.internal_remotes is not None:
        parsed_remotes = [x.strip() for x in args.internal_remotes.split(",") if x.strip()]
        new_remotes = list(dict.fromkeys(cur_remotes + parsed_remotes)) if args.append else list(dict.fromkeys(parsed_remotes))
    else:
        new_remotes = cur_remotes

    if args.blocked_terms is not None:
        parsed_terms = [x.strip() for x in args.blocked_terms.split(",") if x.strip()]
        new_terms = list(dict.fromkeys(cur_terms + parsed_terms)) if args.append else list(dict.fromkeys(parsed_terms))
    else:
        new_terms = cur_terms

    updated = {
        "mode": new_mode,
        "internal_remotes": new_remotes,
        "blocked_terms": new_terms,
    }
    backup: Optional[Path] = None
    if args.apply:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        backup = backup_file(cfg_path)
        cfg_path.write_text(json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "config_path": str(cfg_path),
        "backup": str(backup) if backup else None,
        "policy": updated,
    }
    summary = (
        f"[UNDERCOVER init-policy] mode={report['mode']} "
        f"policy_mode={new_mode} internal_remotes={len(new_remotes)} blocked_terms={len(new_terms)}"
    )
    write_json_report(report, args.output, summary)
    return 0


# ---------------------------------------------------------------------------
# Subcommand 4: harden-configs
# ---------------------------------------------------------------------------


def _ensure_claude_settings(
    path: Path,
    *,
    with_hook: bool,
    script_path: Path,
    apply: bool,
) -> Dict[str, Any]:
    existing, err = _load_json_safe(path)
    if err:
        return {"target": str(path), "status": "error", "error": err}

    data: Dict[str, Any] = dict(existing) if existing is not None else {}
    changes: List[str] = []

    attr = data.get("attribution")
    if not (isinstance(attr, dict) and attr.get("commit") == "" and attr.get("pr") == ""):
        data["attribution"] = {"commit": "", "pr": ""}
        changes.append('set attribution={"commit": "", "pr": ""}')

    # Remove deprecated key only if present as True; otherwise leave or remove cleanly
    if data.get("includeCoAuthoredBy") is True:
        data["includeCoAuthoredBy"] = False
        changes.append("set legacy includeCoAuthoredBy=false")

    if with_hook:
        hooks = data.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = {}
            data["hooks"] = hooks

        if not _claude_hook_present(data, "PreToolUse", "pre-tool-guard"):
            pre = hooks.setdefault("PreToolUse", [])
            if not isinstance(pre, list):
                pre = []
                hooks["PreToolUse"] = pre
            hook_cmd = f"python3 {shlex.quote(str(script_path.resolve()))} pre-tool-guard"
            pre.append(
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_cmd,
                        }
                    ],
                }
            )
            changes.append("registered Claude Code PreToolUse Bash guard hook")

        if not _claude_hook_present(data, "SessionStart", "session-start"):
            ss = hooks.setdefault("SessionStart", [])
            if not isinstance(ss, list):
                ss = []
                hooks["SessionStart"] = ss
            ss_cmd = f"python3 {shlex.quote(str(script_path.resolve()))} session-start"
            ss.append(
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": ss_cmd,
                        }
                    ],
                }
            )
            changes.append("registered Claude Code SessionStart auto-policy hook")

    result: Dict[str, Any] = {
        "target": str(path),
        "tool": "claude_code",
        "changes": changes,
        "applied": False,
        "backup": None,
    }

    if changes and apply:
        path.parent.mkdir(parents=True, exist_ok=True)
        bak = backup_file(path)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        result["applied"] = True
        result["backup"] = str(bak) if bak else None
    elif not changes:
        result["status"] = "already_hardened"
    else:
        result["status"] = "dry_run"

    return result


def _ensure_aider_config(path: Path, *, apply: bool) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    lines = raw.splitlines()
    changes: List[str] = []
    desired = ("attribute-author", "attribute-committer", "attribute-co-authored-by")

    for flag in desired:
        pattern = re.compile(rf"^(\s*{re.escape(flag)}\s*:\s*)(.+?)\s*$", re.IGNORECASE)
        found = False
        for i, line in enumerate(lines):
            m = pattern.match(line)
            if m:
                found = True
                if m.group(2).lower() != "false":
                    lines[i] = f"{m.group(1)}false"
                    changes.append(f"updated {flag}: false")
                break
        if not found:
            lines.append(f"{flag}: false")
            changes.append(f"added {flag}: false")

    result: Dict[str, Any] = {
        "target": str(path),
        "tool": "aider",
        "changes": changes,
        "applied": False,
        "backup": None,
    }
    if changes and apply:
        path.parent.mkdir(parents=True, exist_ok=True)
        bak = backup_file(path)
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        result["applied"] = True
        result["backup"] = str(bak) if bak else None
    elif not changes:
        result["status"] = "already_hardened"
    else:
        result["status"] = "dry_run"
    return result


def _ensure_git_local_exclude(repo_root: Path, *, apply: bool) -> Dict[str, Any]:
    git_dir = find_git_dir(repo_root)
    exclude_path = git_dir / "info" / "exclude"
    existing = exclude_path.read_text(encoding="utf-8", errors="replace") if exclude_path.exists() else ""
    existing_lines = {ln.strip() for ln in existing.splitlines()}
    missing = [e for e in LOCAL_EXCLUDE_ENTRIES if e not in existing_lines]

    result: Dict[str, Any] = {
        "target": str(exclude_path),
        "tool": "git_local_exclude",
        "changes": [f"add {e}" for e in missing],
        "applied": False,
        "backup": None,
    }
    if missing and apply:
        exclude_path.parent.mkdir(parents=True, exist_ok=True)
        bak = backup_file(exclude_path)
        addition = "\n# Undercover private AI-agent excludes (never committed)\n" + "\n".join(missing) + "\n"
        base = existing.rstrip("\n")
        new_content = (base + "\n" + addition) if base else addition.lstrip("\n")
        exclude_path.write_text(new_content, encoding="utf-8")
        result["applied"] = True
        result["backup"] = str(bak) if bak else None
    elif not missing:
        result["status"] = "already_hardened"
    else:
        result["status"] = "dry_run"
    return result


def _ensure_antigravity_hook(
    hooks_json_path: Path,
    *,
    script_path: Path,
    apply: bool,
) -> Dict[str, Any]:
    existing, err = _load_json_safe(hooks_json_path)
    if err:
        return {"target": str(hooks_json_path), "tool": "antigravity_hooks", "status": "error", "error": err}

    data: Dict[str, Any] = dict(existing) if existing is not None else {}
    changes: List[str] = []
    pre_cmd = f"python3 {shlex.quote(str(script_path.resolve()))} pre-tool-guard"
    ss_cmd = f"python3 {shlex.quote(str(script_path.resolve()))} session-start"

    entry = data.get("undercover-guard")
    if not isinstance(entry, dict):
        data["undercover-guard"] = {
            "enabled": True,
            "SessionStart": [
                {
                    "type": "command",
                    "command": ss_cmd,
                    "timeout": 10,
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "run_command",
                    "hooks": [
                        {
                            "type": "command",
                            "command": pre_cmd,
                            "timeout": 10,
                        }
                    ],
                }
            ],
        }
        changes.append("registered Antigravity SessionStart & PreToolUse guards in hooks.json")
    else:
        if "SessionStart" not in entry:
            entry["SessionStart"] = [
                {
                    "type": "command",
                    "command": ss_cmd,
                    "timeout": 10,
                }
            ]
            changes.append("added Antigravity SessionStart auto-policy hook to undercover-guard")
        if "PreToolUse" not in entry:
            entry["PreToolUse"] = [
                {
                    "matcher": "run_command",
                    "hooks": [
                        {
                            "type": "command",
                            "command": pre_cmd,
                            "timeout": 10,
                        }
                    ],
                }
            ]
            changes.append("added Antigravity PreToolUse run_command guard to undercover-guard")

    result: Dict[str, Any] = {
        "target": str(hooks_json_path),
        "tool": "antigravity_hooks",
        "changes": changes,
        "applied": False,
        "backup": None,
    }
    if changes and apply:
        hooks_json_path.parent.mkdir(parents=True, exist_ok=True)
        bak = backup_file(hooks_json_path)
        hooks_json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        result["applied"] = True
        result["backup"] = str(bak) if bak else None
    elif not changes:
        result["status"] = "already_hardened"
    else:
        result["status"] = "dry_run"
    return result


def _ensure_editor_settings(
    path: Path,
    *,
    editor_label: str,
    apply: bool,
) -> Dict[str, Any]:
    if not path.exists():
        return {"target": str(path), "tool": editor_label, "status": "not_found", "changes": [], "applied": False}
    raw = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r'("git\.addAICoAuthor"\s*:\s*)(true|false)', raw)
    result: Dict[str, Any] = {
        "target": str(path),
        "tool": editor_label,
        "changes": [],
        "applied": False,
        "backup": None,
    }
    if m:
        if m.group(2) == "false":
            result["status"] = "already_hardened"
            return result
        new_raw = raw[: m.start(2)] + "false" + raw[m.end(2) :]
        result["changes"] = ['updated "git.addAICoAuthor": false']
        if apply:
            bak = backup_file(path)
            path.write_text(new_raw, encoding="utf-8")
            result["applied"] = True
            result["backup"] = str(bak) if bak else None
        else:
            result["status"] = "dry_run"
        return result

    # Key not present: only modify cleanly if strict JSON (no JSONC comments)
    data, err = _load_json_safe(path)
    if err or data is None:
        result["status"] = "manual_required_jsonc"
        result["message"] = 'Settings file uses JSONC comments; manually add "git.addAICoAuthor": false.'
        return result
    data["git.addAICoAuthor"] = False
    result["changes"] = ['added "git.addAICoAuthor": false']
    if apply:
        bak = backup_file(path)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        result["applied"] = True
        result["backup"] = str(bak) if bak else None
    else:
        result["status"] = "dry_run"
    return result


def cmd_harden_configs(args: argparse.Namespace) -> int:
    home = Path.home()
    script_path = Path(__file__).resolve()
    actions: List[Dict[str, Any]] = []

    # Default targets if user passes none: claude + project local exclude (if --project)
    do_claude = args.claude or args.all or (
        not args.aider and not args.antigravity_hook and not args.editors and not args.project
    )
    do_aider = args.aider or args.all
    do_agy = args.antigravity_hook or args.all
    do_editors = args.editors or args.all

    if do_claude:
        c_target = (
            Path(args.project).resolve() / ".claude" / "settings.json"
            if args.project and args.project_only
            else home / ".claude" / "settings.json"
        )
        actions.append(
            _ensure_claude_settings(
                c_target,
                with_hook=args.with_claude_hook or args.all,
                script_path=script_path,
                apply=args.apply,
            )
        )

    if do_aider:
        a_target = (
            Path(args.project).resolve() / ".aider.conf.yml"
            if args.project and args.project_only
            else home / ".aider.conf.yml"
        )
        actions.append(_ensure_aider_config(a_target, apply=args.apply))

    if do_agy:
        agy_target = (
            Path(args.project).resolve() / ".agents" / "hooks.json"
            if args.project and args.project_only
            else home / ".gemini" / "config" / "hooks.json"
        )
        actions.append(
            _ensure_antigravity_hook(agy_target, script_path=script_path, apply=args.apply)
        )

    if do_editors:
        for label, epath in (
            ("vscode", home / "Library" / "Application Support" / "Code" / "User" / "settings.json"),
            ("vscode_linux", home / ".config" / "Code" / "User" / "settings.json"),
            ("cursor", home / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"),
            ("cursor_linux", home / ".config" / "Cursor" / "User" / "settings.json"),
        ):
            if epath.exists():
                actions.append(_ensure_editor_settings(epath, editor_label=label, apply=args.apply))

    if args.project:
        repo_root = find_git_root(Path(args.project).resolve())
        if repo_root:
            actions.append(_ensure_git_local_exclude(repo_root, apply=args.apply))

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "actions": actions,
    }
    total_changes = sum(len(a.get("changes", [])) for a in actions)
    summary = f"[UNDERCOVER harden-configs] mode={report['mode']} targets={len(actions)} changes={total_changes}"
    write_json_report(report, args.output, summary)
    return 0


# ---------------------------------------------------------------------------
# Subcommand 5: install-hooks & uninstall-hooks
# ---------------------------------------------------------------------------


def _render_commit_msg_hook(script_path: Path, mode: str, global_chain: bool) -> str:
    py = "python3"
    sp = shlex.quote(str(script_path.resolve()))
    chain_block = ""
    if global_chain:
        chain_block = r"""
# Chain repo-local commit-msg hook if present
LOCAL_GIT_DIR="$(git rev-parse --git-dir 2>/dev/null || true)"
if [ -n "${LOCAL_GIT_DIR}" ] && [ -x "${LOCAL_GIT_DIR}/hooks/commit-msg" ]; then
  SELF_REAL="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  LOCAL_REAL="$(cd "$(dirname "${LOCAL_GIT_DIR}/hooks/commit-msg")" && pwd)/commit-msg"
  if [ "${SELF_REAL}" != "${LOCAL_REAL}" ]; then
    "${LOCAL_GIT_DIR}/hooks/commit-msg" "$@"
  fi
fi
"""
    else:
        chain_block = r"""
# Chain preserved pre-existing hook if present
if [ -x "$0.pre-undercover" ]; then
  "$0.pre-undercover" "$@"
fi
"""
    if mode == "block":
        action_cmd = f'{py} {sp} sanitize-text --kind commit --mode check --respect-policy --check-identity --file "$1"'
    else:
        action_cmd = f'{py} {sp} sanitize-text --kind commit --mode scrub --in-place --respect-policy --check-identity --file "$1"'

    return f"""#!/usr/bin/env bash
{HOOK_MARKER}
set -euo pipefail

if [ "${{UNDERCOVER_SKIP:-0}}" = "1" ]; then
  exit 0
fi

{action_cmd}
{chain_block}
"""


def _render_pre_commit_hook(script_path: Path, global_chain: bool) -> str:
    py = "python3"
    sp = shlex.quote(str(script_path.resolve()))
    chain_block = ""
    if global_chain:
        chain_block = r"""
LOCAL_GIT_DIR="$(git rev-parse --git-dir 2>/dev/null || true)"
if [ -n "${LOCAL_GIT_DIR}" ] && [ -x "${LOCAL_GIT_DIR}/hooks/pre-commit" ]; then
  SELF_REAL="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  LOCAL_REAL="$(cd "$(dirname "${LOCAL_GIT_DIR}/hooks/pre-commit")" && pwd)/pre-commit"
  if [ "${SELF_REAL}" != "${LOCAL_REAL}" ]; then
    "${LOCAL_GIT_DIR}/hooks/pre-commit" "$@"
  fi
fi
"""
    else:
        chain_block = r"""
if [ -x "$0.pre-undercover" ]; then
  "$0.pre-undercover" "$@"
fi
"""
    return f"""#!/usr/bin/env bash
{HOOK_MARKER}
set -euo pipefail

if [ "${{UNDERCOVER_SKIP:-0}}" = "1" ]; then
  exit 0
fi

{py} {sp} check-staged
{chain_block}
"""


def _render_pre_push_hook(script_path: Path, global_chain: bool) -> str:
    py = "python3"
    sp = shlex.quote(str(script_path.resolve()))
    chain_block = ""
    if global_chain:
        chain_block = r"""
LOCAL_GIT_DIR="$(git rev-parse --git-dir 2>/dev/null || true)"
if [ -n "${LOCAL_GIT_DIR}" ] && [ -x "${LOCAL_GIT_DIR}/hooks/pre-push" ]; then
  SELF_REAL="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  LOCAL_REAL="$(cd "$(dirname "${LOCAL_GIT_DIR}/hooks/pre-push")" && pwd)/pre-push"
  if [ "${SELF_REAL}" != "${LOCAL_REAL}" ]; then
    "${LOCAL_GIT_DIR}/hooks/pre-push" "$@"
  fi
fi
"""
    else:
        chain_block = r"""
if [ -x "$0.pre-undercover" ]; then
  "$0.pre-undercover" "$@"
fi
"""
    return f"""#!/usr/bin/env bash
{HOOK_MARKER}
set -euo pipefail

if [ "${{UNDERCOVER_SKIP:-0}}" = "1" ]; then
  exit 0
fi

{py} {sp} check-push "$@"
{chain_block}
"""


def cmd_check_staged(args: argparse.Namespace) -> int:
    repo_root = find_git_root(Path(args.repo).resolve())
    if not repo_root:
        return 0
    policy = evaluate_stealth_policy(repo_root, getattr(args, "config", None))
    if not policy["active"]:
        return 0

    allow_files = load_undercover_allowlist(repo_root, args.allow_files)
    extra_patterns = get_effective_extra_patterns(None, getattr(args, "config", None))
    errors: List[str] = []

    # 1. Check staged file names for agent trace files
    staged_proc = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], repo_root)
    if staged_proc.returncode == 0:
        for raw_p in staged_proc.stdout.split(b"\x00"):
            if not raw_p:
                continue
            rel_p = raw_p.decode("utf-8", errors="replace")
            matched = match_agent_artifact(rel_p, allow_files)
            if matched:
                rule_name, sev = matched
                if sev in ("CRITICAL", "HIGH") or args.strict_artifacts:
                    errors.append(f"Staged AI agent artifact ({sev}/{rule_name}): {rel_p}")

    # 2. Check staged added lines for AI attribution comments, blocked terms & invisible Unicode watermarks
    diff_proc = run_git(["diff", "--cached", "-U0", "--no-color"], repo_root)
    if diff_proc.returncode == 0:
        cur_file = "<staged>"
        for raw_line in diff_proc.stdout.decode("utf-8", errors="replace").splitlines():
            if raw_line.startswith("+++ b/"):
                cur_file = raw_line[6:]
                continue
            if not raw_line.startswith("+") or raw_line.startswith("+++"):
                continue
            added = raw_line[1:]
            if CODE_AI_COMMENT_RE.match(added):
                errors.append(f"Staged AI comment in {cur_file}: {added.strip()[:120]}")
            for pat in extra_patterns:
                if pat.search(added):
                    errors.append(f"Staged blocked confidential term in {cur_file}: {added.strip()[:120]}")
            u_hits = scan_unicode_watermarks(added, is_code_file=False)
            for uh in u_hits:
                if uh["severity"] in ("CRITICAL", "HIGH"):
                    errors.append(
                        f"Staged invisible Unicode {uh['codepoint']} ({uh['name']}) in {cur_file}"
                    )

    if errors:
        print("[UNDERCOVER pre-commit] Blocked commit due to AI watermark leaks:", file=sys.stderr)
        for e in errors[:15]:
            print(f"  - {e}", file=sys.stderr)
        if len(errors) > 15:
            print(f"  ... and {len(errors) - 15} more.", file=sys.stderr)
        print("  (Allowlist intentional files in .undercoverignore or bypass once with UNDERCOVER_SKIP=1)", file=sys.stderr)
        return 1
    return 0


def cmd_check_push(args: argparse.Namespace) -> int:
    repo_root = find_git_root(Path(args.repo).resolve())
    if not repo_root:
        return 0
    policy = evaluate_stealth_policy(repo_root, getattr(args, "config", None))
    if not policy["active"]:
        return 0

    extra_patterns = get_effective_extra_patterns(None, getattr(args, "config", None))
    zero_oid = "0" * 40
    ranges: List[str] = []

    if not sys.stdin.isatty():
        for line in sys.stdin.read().splitlines():
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            _local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
            if local_sha == zero_oid:
                continue
            if remote_sha == zero_oid:
                ranges.append(f"{local_sha} --not --remotes")
            else:
                ranges.append(f"{remote_sha}..{local_sha}")

    if not ranges:
        # Fallback: inspect unpushed commits on HEAD
        up = run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], repo_root)
        if up.returncode == 0:
            upstream = up.stdout.decode("utf-8", errors="replace").strip()
            ranges.append(f"{upstream}..HEAD")
        else:
            ranges.append("HEAD --not --remotes")

    findings: List[Dict[str, Any]] = []
    for rng in ranges:
        parts = rng.split()
        proc = run_git(["log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", *parts], repo_root)
        if proc.returncode != 0:
            continue
        for rec in proc.stdout.decode("utf-8", errors="replace").split("\x1e"):
            rec = rec.strip("\n")
            if not rec.strip():
                continue
            fields = rec.split("\x1f", 5)
            if len(fields) < 6:
                continue
            sha, an, ae, cn, ce, body = fields
            short_sha = sha[:10]
            for role, name, email in (("author", an, ae), ("committer", cn, ce)):
                is_ai, reason = is_ai_author_identity(name, email)
                if is_ai:
                    findings.append({"commit": short_sha, "detail": f"{role} leak ({reason})"})
            for iss in detect_text_watermarks(body, extra_patterns=extra_patterns):
                if iss["severity"] in ("CRITICAL", "HIGH"):
                    findings.append({"commit": short_sha, "detail": f"{iss['type']}: {iss['excerpt']}"})

    if findings:
        print("[UNDERCOVER pre-push] Blocked push: outgoing commits contain AI watermarks:", file=sys.stderr)
        for f in findings[:15]:
            print(f"  - {f['commit']}: {f['detail']}", file=sys.stderr)
        print(
            f"  Run: python3 {Path(__file__).resolve()} scrub {repo_root} --apply",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_install_hooks(args: argparse.Namespace) -> int:
    script_path = Path(__file__).resolve()
    is_global = bool(args.global_hooks)

    if is_global:
        hooks_dir = Path(args.hooks_dir).expanduser().resolve() if args.hooks_dir else (Path.home() / ".config" / "undercover" / "hooks")
    else:
        repo_root = find_git_root(Path(args.repo).resolve())
        if not repo_root:
            print(f"Error: not a git repository: {args.repo}", file=sys.stderr)
            return 2
        hooks_dir = find_git_dir(repo_root) / "hooks"

    rendered = {
        "commit-msg": _render_commit_msg_hook(script_path, args.mode, global_chain=is_global),
        "pre-commit": _render_pre_commit_hook(script_path, global_chain=is_global),
        "pre-push": _render_pre_push_hook(script_path, global_chain=is_global),
    }

    selected = [h.strip() for h in args.hooks.split(",") if h.strip()]
    for h in selected:
        if h not in rendered:
            print(f"Error: unsupported hook '{h}'. Choose from: commit-msg, pre-commit, pre-push", file=sys.stderr)
            return 2

    actions: List[Dict[str, Any]] = []
    for hname in selected:
        dest = hooks_dir / hname
        existed = dest.exists()
        is_managed = existed and HOOK_MARKER in dest.read_text(encoding="utf-8", errors="replace")
        action = "install"
        if existed and is_managed:
            action = "update"
        elif existed and not is_managed:
            if args.chain:
                action = "chain_existing"
            elif args.force:
                action = "overwrite_backup"
            else:
                actions.append(
                    {
                        "hook": hname,
                        "path": str(dest),
                        "status": "conflict_existing_hook",
                        "message": "Existing custom hook found. Pass --chain (recommended) or --force.",
                    }
                )
                continue

        entry: Dict[str, Any] = {
            "hook": hname,
            "path": str(dest),
            "action": action,
            "applied": False,
        }
        if args.apply:
            hooks_dir.mkdir(parents=True, exist_ok=True)
            if action == "chain_existing":
                chained = dest.with_name(f"{hname}.pre-undercover")
                if not chained.exists():
                    shutil.move(str(dest), str(chained))
                entry["chained_original"] = str(chained)
            elif action == "overwrite_backup":
                bak = backup_file(dest)
                entry["backup"] = str(bak) if bak else None
            dest.write_text(rendered[hname], encoding="utf-8")
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            entry["applied"] = True
        actions.append(entry)

    git_config_action: Optional[Dict[str, Any]] = None
    global_hooks_conflict = False
    if is_global:
        cur_proc = run_git(["config", "--global", "--get", "core.hooksPath"], Path.home())
        cur_val = cur_proc.stdout.decode("utf-8", errors="replace").strip() if cur_proc.returncode == 0 else ""
        cur_resolved = Path(os.path.expanduser(cur_val)).resolve() if cur_val else None
        if cur_resolved and cur_resolved != hooks_dir and not args.force:
            global_hooks_conflict = True
            git_config_action = {
                "setting": "git config --global core.hooksPath",
                "existing_value": cur_val,
                "desired_value": str(hooks_dir),
                "status": "conflict_existing_global_hooks_path",
                "message": (
                    f"Existing global core.hooksPath is set to '{cur_val}'. "
                    "Pass --force to replace it, or install hooks per-repo with --repo <dir> --chain."
                ),
                "applied": False,
            }
        else:
            git_config_action = {
                "setting": "git config --global core.hooksPath",
                "value": str(hooks_dir),
                "previous_value": cur_val or None,
                "applied": False,
            }
            if args.apply:
                run_git(["config", "--global", "core.hooksPath", str(hooks_dir)], Path.home(), check=True)
                git_config_action["applied"] = True

    has_conflicts = global_hooks_conflict or any(a.get("status") == "conflict_existing_hook" for a in actions)
    report = {
        "mode": "apply" if args.apply else "dry_run",
        "scope": "global" if is_global else "repo",
        "hook_mode": args.mode,
        "hooks_dir": str(hooks_dir),
        "actions": actions,
        "git_config": git_config_action,
    }
    summary = (
        f"[UNDERCOVER install-hooks] mode={report['mode']} scope={report['scope']} "
        f"hooks={len(actions)} conflicts={int(has_conflicts)}"
    )
    write_json_report(report, args.output, summary)
    return 1 if has_conflicts else 0


def cmd_uninstall_hooks(args: argparse.Namespace) -> int:
    is_global = bool(args.global_hooks)
    if is_global:
        hooks_dir = Path(args.hooks_dir).expanduser().resolve() if args.hooks_dir else (Path.home() / ".config" / "undercover" / "hooks")
    else:
        repo_root = find_git_root(Path(args.repo).resolve())
        if not repo_root:
            print(f"Error: not a git repository: {args.repo}", file=sys.stderr)
            return 2
        hooks_dir = find_git_dir(repo_root) / "hooks"

    actions: List[Dict[str, Any]] = []
    for hname in ("commit-msg", "pre-commit", "pre-push"):
        dest = hooks_dir / hname
        if not dest.is_file():
            continue
        if HOOK_MARKER not in dest.read_text(encoding="utf-8", errors="replace"):
            actions.append({"hook": hname, "path": str(dest), "status": "skipped_unmanaged"})
            continue
        chained = dest.with_name(f"{hname}.pre-undercover")
        entry: Dict[str, Any] = {
            "hook": hname,
            "path": str(dest),
            "action": "restore_chained" if chained.exists() else "remove",
            "applied": False,
        }
        if args.apply:
            dest.unlink()
            if chained.exists():
                shutil.move(str(chained), str(dest))
            entry["applied"] = True
        actions.append(entry)

    if is_global and args.apply:
        cur = run_git(["config", "--global", "--get", "core.hooksPath"], Path.home())
        if cur.returncode == 0 and Path(os.path.expanduser(cur.stdout.decode().strip())).resolve() == hooks_dir:
            run_git(["config", "--global", "--unset", "core.hooksPath"], Path.home())

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "scope": "global" if is_global else "repo",
        "hooks_dir": str(hooks_dir),
        "actions": actions,
    }
    write_json_report(
        report,
        args.output,
        f"[UNDERCOVER uninstall-hooks] mode={report['mode']} affected={len(actions)}",
    )
    return 0


# ---------------------------------------------------------------------------
# Subcommand 6 & 7: clean-unicode & clean-comments
# ---------------------------------------------------------------------------


def cmd_clean_unicode(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2
    exclude = [x.strip() for x in (args.exclude or "").split(",") if x.strip()]
    files = collect_target_files(target, exclude_substrings=exclude)

    modified_files: List[Dict[str, Any]] = []
    total_chars = 0

    for fpath in files:
        if not is_text_file(fpath):
            continue
        try:
            raw = fpath.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        is_code = fpath.suffix.lower() in CODE_EXTENSIONS or fpath.name in ("Makefile", "Dockerfile")
        cleaned, hits = strip_unicode_watermarks(
            raw,
            is_code_file=is_code,
            normalize_nbsp=args.normalize_nbsp,
            strip_bom=args.strip_bom,
        )
        if not hits:
            continue
        total_chars += len(hits)
        if args.apply:
            fpath.write_text(cleaned, encoding="utf-8")
        modified_files.append(
            {
                "file": str(fpath),
                "chars_cleaned": len(hits),
                "applied": bool(args.apply),
                "samples": hits[:10],
            }
        )

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "target": str(target),
        "files_scanned": len(files),
        "files_with_watermarks": len(modified_files),
        "total_chars": total_chars,
        "files": modified_files,
    }
    summary = (
        f"[UNDERCOVER clean-unicode] mode={report['mode']} "
        f"files={len(modified_files)} chars={total_chars}"
    )
    write_json_report(report, args.output, summary)
    return 0


def cmd_clean_comments(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2
    exclude = [x.strip() for x in (args.exclude or "").split(",") if x.strip()]
    files = collect_target_files(target, exclude_substrings=exclude)

    modified_files: List[Dict[str, Any]] = []
    total_lines = 0

    for fpath in files:
        if not is_text_file(fpath):
            continue
        try:
            raw = fpath.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        had_nl = raw.endswith("\n")
        raw_lines = raw.splitlines()
        kept: List[str] = []
        removed_hits: List[Dict[str, Any]] = []
        for idx, line in enumerate(raw_lines, start=1):
            if CODE_AI_COMMENT_RE.match(line):
                removed_hits.append({"line": idx, "excerpt": line.strip()[:160]})
            else:
                kept.append(line)
        if not removed_hits:
            continue
        total_lines += len(removed_hits)
        if args.apply:
            new_text = "\n".join(kept) + ("\n" if had_nl and kept else "")
            fpath.write_text(new_text, encoding="utf-8")
        modified_files.append(
            {
                "file": str(fpath),
                "lines_removed": len(removed_hits),
                "applied": bool(args.apply),
                "removed": removed_hits,
            }
        )

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "target": str(target),
        "files_scanned": len(files),
        "files_with_ai_comments": len(modified_files),
        "total_lines": total_lines,
        "files": modified_files,
    }
    summary = (
        f"[UNDERCOVER clean-comments] mode={report['mode']} "
        f"files={len(modified_files)} lines={total_lines}"
    )
    write_json_report(report, args.output, summary)
    return 0


# ---------------------------------------------------------------------------
# Subcommand 8: scrub — Pure-Python Safe Git History Scrubber
# ---------------------------------------------------------------------------

IDENTITY_RE = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^>]*)>\s+(?P<date>\d+\s+[+-]\d{4})$")


def _parse_raw_commit(raw_bytes: bytes) -> Dict[str, Any]:
    sep = raw_bytes.find(b"\n\n")
    if sep == -1:
        header_bytes, msg_bytes = raw_bytes, b""
    else:
        header_bytes, msg_bytes = raw_bytes[:sep], raw_bytes[sep + 2 :]

    tree = ""
    parents: List[str] = []
    author = ""
    committer = ""
    was_signed = False
    encoding: Optional[str] = None

    in_multiline_sig = False
    for line in header_bytes.decode("utf-8", errors="replace").splitlines():
        if in_multiline_sig:
            if line.startswith(" "):
                continue
            in_multiline_sig = False
        if line.startswith("tree "):
            tree = line[5:].strip()
        elif line.startswith("parent "):
            parents.append(line[7:].strip())
        elif line.startswith("author "):
            author = line[7:].strip()
        elif line.startswith("committer "):
            committer = line[10:].strip()
        elif line.startswith("encoding "):
            encoding = line[9:].strip()
        elif line.startswith("gpgsig "):
            was_signed = True
            in_multiline_sig = True

    return {
        "tree": tree,
        "parents": parents,
        "author": author,
        "committer": committer,
        "encoding": encoding,
        "was_signed": was_signed,
        "message": msg_bytes.decode(encoding or "utf-8", errors="replace"),
    }


def _clean_identity_line(
    raw_ident: str,
    replace_name: Optional[str],
    replace_email: Optional[str],
) -> Tuple[str, str, str, bool]:
    m = IDENTITY_RE.match(raw_ident)
    if not m:
        return "", "", "", False
    name = m.group("name").strip()
    email = m.group("email").strip()
    date = m.group("date").strip()
    changed = False

    if AIDER_NAME_SUFFIX_RE.search(name):
        name = AIDER_NAME_SUFFIX_RE.sub("", name).strip()
        changed = True

    is_ai, _ = is_ai_author_identity(name, email)
    if is_ai:
        if replace_name:
            name = replace_name
            changed = True
        if replace_email:
            email = replace_email
            changed = True

    return name, email, date, changed


def cmd_scrub(args: argparse.Namespace) -> int:
    repo_root = find_git_root(Path(args.repo).resolve())
    if not repo_root:
        print(f"Error: not a git repository: {args.repo}", file=sys.stderr)
        return 2

    # Safety 1: Require clean working tree when applying
    status_proc = run_git(["status", "--porcelain"], repo_root, check=True)
    dirty_tree = bool(status_proc.stdout.strip())
    if dirty_tree and args.apply:
        print(
            "Error: Working tree has uncommitted changes. Commit or stash them before running scrub --apply.",
            file=sys.stderr,
        )
        return 1

    # Resolve current branch / HEAD
    head_sha = run_git(["rev-parse", "HEAD"], repo_root, check=True).stdout.decode().strip()
    sym_proc = run_git(["symbolic-ref", "-q", "HEAD"], repo_root)
    branch_ref = sym_proc.stdout.decode().strip() if sym_proc.returncode == 0 else None

    # Determine commit range
    if args.base:
        rev_range = [f"{args.base}..HEAD"]
        range_label = f"{args.base}..HEAD"
    elif args.all_local:
        rev_range = ["HEAD"]
        range_label = "HEAD (all commits on branch)"
    else:
        up_proc = run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], repo_root)
        if up_proc.returncode != 0:
            print(
                "Error: Current branch has no upstream tracking branch. "
                "Specify --base <commit_or_ref> or --all-local to scrub local commits.",
                file=sys.stderr,
            )
            return 2
        upstream = up_proc.stdout.decode().strip()
        rev_range = [f"{upstream}..HEAD"]
        range_label = f"{upstream}..HEAD"

    rev_proc = run_git(["rev-list", "--reverse", "--topo-order", *rev_range], repo_root, check=True)
    commits = [c.strip() for c in rev_proc.stdout.decode().splitlines() if c.strip()]

    if not commits:
        report = {
            "mode": "apply" if args.apply else "dry_run",
            "repo": str(repo_root),
            "range": range_label,
            "commits_inspected": 0,
            "commits_to_clean": 0,
            "message": "No commits in target range.",
        }
        write_json_report(report, args.output, "[UNDERCOVER scrub] commits=0 (nothing to scrub)")
        return 0

    # Safety 2: Check if any commit in range is already on a remote-tracking branch
    pushed_commits: List[str] = []
    for sha in commits:
        rb = run_git(["branch", "-r", "--contains", sha], repo_root)
        if rb.returncode == 0 and rb.stdout.strip():
            pushed_commits.append(sha[:10])

    if pushed_commits and not args.allow_pushed:
        print(
            f"Error: Refusing to rewrite {len(pushed_commits)} commit(s) already pushed to remote "
            f"({', '.join(pushed_commits[:5])}). Pass --allow-pushed ONLY if you intend to force-push.",
            file=sys.stderr,
        )
        return 1

    # Fallback replacement identity from local git config if needed
    fallback_name = args.author_name or run_git(["config", "user.name"], repo_root).stdout.decode("utf-8", errors="replace").strip() or None
    fallback_email = args.author_email or run_git(["config", "user.email"], repo_root).stdout.decode("utf-8", errors="replace").strip() or None
    extra_patterns = get_effective_extra_patterns(args.extra_patterns, getattr(args, "config", None))

    # Inspect every commit in range
    plan: List[Dict[str, Any]] = []
    parsed_cache: Dict[str, Dict[str, Any]] = {}
    first_dirty_idx: Optional[int] = None
    signed_count = 0

    for idx, sha in enumerate(commits):
        raw_obj = run_git(["cat-file", "commit", sha], repo_root, check=True).stdout
        parsed = _parse_raw_commit(raw_obj)
        parsed_cache[sha] = parsed

        cleaned_msg, removed_items = sanitize_text_payload(
            parsed["message"], kind="commit", extra_patterns=extra_patterns
        )
        an, ae, ad, a_changed = _clean_identity_line(parsed["author"], fallback_name, fallback_email)
        cn, ce, cd, c_changed = _clean_identity_line(parsed["committer"], fallback_name, fallback_email)

        needs_clean = bool(removed_items or a_changed or c_changed)
        if needs_clean and first_dirty_idx is None:
            first_dirty_idx = idx
        if parsed["was_signed"]:
            signed_count += 1

        plan.append(
            {
                "sha": sha,
                "short_sha": sha[:10],
                "subject": parsed["message"].splitlines()[0][:100] if parsed["message"].splitlines() else "",
                "needs_clean": needs_clean,
                "removed_items": removed_items,
                "author_changed": a_changed,
                "committer_changed": c_changed,
                "was_signed": parsed["was_signed"],
                "cleaned_message": cleaned_msg,
                "author_tuple": (an, ae, ad),
                "committer_tuple": (cn, ce, cd),
            }
        )

    dirty_entries = [p for p in plan if p["needs_clean"]]
    if not dirty_entries:
        report = {
            "mode": "apply" if args.apply else "dry_run",
            "repo": str(repo_root),
            "range": range_label,
            "commits_inspected": len(commits),
            "commits_to_clean": 0,
            "message": "All commits in range are already clean.",
        }
        write_json_report(
            report,
            args.output,
            f"[UNDERCOVER scrub] inspected={len(commits)} dirty=0 (already clean)",
        )
        return 0

    assert first_dirty_idx is not None
    commits_to_rewrite = len(commits) - first_dirty_idx
    backup_ref: Optional[str] = None
    new_head: Optional[str] = None

    if args.apply:
        safe_branch = (branch_ref.split("/")[-1] if branch_ref else "detached").replace(" ", "_")
        backup_ref = f"refs/undercover-backup/{safe_branch}-{utc_timestamp()}"
        run_git(["update-ref", backup_ref, head_sha], repo_root, check=True)

        oid_map: Dict[str, str] = {}
        for idx, item in enumerate(plan):
            sha = item["sha"]
            if idx < first_dirty_idx:
                oid_map[sha] = sha
                continue

            parsed = parsed_cache[sha]
            tree = parsed["tree"]
            new_parents = [oid_map.get(p, p) for p in parsed["parents"]]
            an, ae, ad = item["author_tuple"]
            cn, ce, cd = item["committer_tuple"]

            ct_args = ["commit-tree", tree]
            for p in new_parents:
                ct_args.extend(["-p", p])

            ct_env = {
                "GIT_AUTHOR_NAME": an,
                "GIT_AUTHOR_EMAIL": ae,
                "GIT_AUTHOR_DATE": ad,
                "GIT_COMMITTER_NAME": cn,
                "GIT_COMMITTER_EMAIL": ce,
                "GIT_COMMITTER_DATE": cd,
            }
            ct_proc = run_git(
                ct_args,
                repo_root,
                input_bytes=item["cleaned_message"].encode("utf-8"),
                env=ct_env,
                check=True,
            )
            new_sha = ct_proc.stdout.decode().strip()
            oid_map[sha] = new_sha

        new_head = oid_map[head_sha]
        target_ref = branch_ref or "HEAD"
        run_git(["update-ref", target_ref, new_head, head_sha], repo_root, check=True)

    preview = [
        {
            "commit": p["short_sha"],
            "subject": p["subject"],
            "removed": p["removed_items"],
            "author_changed": p["author_changed"],
            "committer_changed": p["committer_changed"],
            "was_signed": p["was_signed"],
        }
        for p in dirty_entries
    ]

    report = {
        "mode": "apply" if args.apply else "dry_run",
        "repo": str(repo_root),
        "range": range_label,
        "working_tree_dirty": dirty_tree,
        "pushed_commits_in_range": pushed_commits,
        "commits_inspected": len(commits),
        "commits_with_watermarks": len(dirty_entries),
        "commits_rewritten": commits_to_rewrite if args.apply else 0,
        "signed_commits_warning": signed_count > 0,
        "old_head": head_sha,
        "new_head": new_head,
        "backup_ref": backup_ref,
        "rollback_command": f"git reset --hard {backup_ref}" if backup_ref else None,
        "cleaned_commits": preview,
    }
    summary = (
        f"[UNDERCOVER scrub] mode={report['mode']} inspected={len(commits)} "
        f"dirty={len(dirty_entries)} rewritten={report['commits_rewritten']}"
    )
    write_json_report(report, args.output, summary)
    return 0


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover.py",
        description="UNDERCOVER — AI Contribution Watermark Neutralization & Stealth Audit CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. audit
    p_audit = sub.add_parser("audit", help="Full 4-surface watermark audit (commits, artifacts, files, configs)")
    p_audit.add_argument("path", nargs="?", default=".", help="Repository or directory path (default: .)")
    p_audit.add_argument("--range", help="Git commit range (e.g. origin/main..HEAD)")
    p_audit.add_argument("--unpushed", action="store_true", help="Inspect only unpushed commits (@{u}..HEAD)")
    p_audit.add_argument("--max-commits", type=int, default=200, help="Max commits to scan (default: 200)")
    p_audit.add_argument("--extra-patterns", help="Comma-separated extra confidential keywords to detect")
    p_audit.add_argument("--config", help="Path to undercover policy config JSON (default: ~/.config/undercover/config.json)")
    p_audit.add_argument("--allow-files", help="Comma-separated repo-relative paths allowed as intentional agent docs")
    p_audit.add_argument("--exclude", help="Comma-separated path substrings to exclude from scanning")
    p_audit.add_argument("--include-nbsp", action="store_true", help="Flag U+00A0 NBSP in non-code text files too")
    p_audit.add_argument("--skip-commits", action="store_true", help="Skip Git commit history scan")
    p_audit.add_argument("--skip-configs", action="store_true", help="Skip local AI tool config inspection")
    p_audit.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "INFO"], help="Exit 1 if findings >= level")
    p_audit.add_argument("--output", "-o", help="Write full JSON report to file and print 1-line summary")
    p_audit.set_defaults(func=cmd_audit)

    # 2. sanitize-text
    p_san = sub.add_parser("sanitize-text", help="Sanitize or check commit messages, PR bodies, or comments")
    p_san.add_argument("--file", "-f", help="Input file path (omit to read stdin)")
    p_san.add_argument("--in-place", action="store_true", help="Rewrite --file in place (used by commit-msg hook)")
    p_san.add_argument("--mode", choices=["scrub", "check"], default="scrub", help="scrub (strip) or check (exit 1 on match)")
    p_san.add_argument("--kind", choices=["commit", "pr", "text"], default="commit", help="Text type (default: commit)")
    p_san.add_argument("--respect-policy", action="store_true", help="Stand down if repo matches internal_remotes allowlist")
    p_san.add_argument("--check-identity", action="store_true", help="Also block AI bot author/committer Git env vars")
    p_san.add_argument("--config", help="Path to undercover policy config JSON")
    p_san.add_argument("--extra-patterns", help="Comma-separated extra confidential terms to strip/block")
    p_san.add_argument("--quiet", action="store_true", help="Suppress stderr status notes")
    p_san.add_argument("--output", "-o", help="Write JSON report to file")
    p_san.set_defaults(func=cmd_sanitize_text)

    # 3a. pre-tool-guard
    p_ptg = sub.add_parser("pre-tool-guard", help="PreToolUse hook guard for Claude Code (Bash) & Antigravity (run_command)")
    p_ptg.add_argument("--config", help="Path to undercover policy config JSON")
    p_ptg.add_argument("--extra-patterns", help="Comma-separated extra confidential keywords to block")
    p_ptg.set_defaults(func=cmd_pre_tool_guard)

    # 3b. session-start
    p_ss = sub.add_parser("session-start", help="SessionStart auto-policy hook for Claude Code & Antigravity")
    p_ss.add_argument("--preview", help="Preview evaluated policy and injected prompt for a directory path")
    p_ss.add_argument("--config", help="Path to undercover policy config JSON")
    p_ss.add_argument("--output", "-o", help="Write preview JSON report to file")
    p_ss.set_defaults(func=cmd_session_start)

    # 3c. repo-status
    p_rs = sub.add_parser("repo-status", help="Inspect fail-closed repository scope classification (external vs internal)")
    p_rs.add_argument("path", nargs="?", default=".", help="Repository or directory path (default: .)")
    p_rs.add_argument("--config", help="Path to undercover policy config JSON")
    p_rs.add_argument("--output", "-o", help="Write JSON report to file")
    p_rs.set_defaults(func=cmd_repo_status)

    # 3d. init-policy
    p_ip = sub.add_parser("init-policy", help="Create or update ~/.config/undercover/config.json (internal remotes & blocked terms)")
    p_ip.add_argument("--mode", choices=["auto", "always"], help="Policy mode: auto (remote allowlist) or always")
    p_ip.add_argument("--internal-remotes", help="Comma-separated glob patterns for internal repos (e.g. github.com/my-org/*)")
    p_ip.add_argument("--blocked-terms", help="Comma-separated confidential project terms/links to block")
    p_ip.add_argument("--append", action="store_true", help="Append to existing lists instead of replacing")
    p_ip.add_argument("--config", help="Target policy JSON path (default: ~/.config/undercover/config.json)")
    p_ip.add_argument("--apply", action="store_true", help="Write policy file with backup (default is dry-run)")
    p_ip.add_argument("--output", "-o", help="Write JSON report to file")
    p_ip.set_defaults(func=cmd_init_policy)

    # 4. harden-configs
    p_hc = sub.add_parser("harden-configs", help="Disable AI attribution and register SessionStart + PreToolUse hooks")
    p_hc.add_argument("--claude", action="store_true", help="Harden Claude Code settings.json")
    p_hc.add_argument("--with-claude-hook", action="store_true", help="Register Claude Code SessionStart & PreToolUse hooks")
    p_hc.add_argument("--aider", action="store_true", help="Harden Aider .aider.conf.yml")
    p_hc.add_argument("--editors", action="store_true", help="Harden VS Code / Cursor git.addAICoAuthor=false")
    p_hc.add_argument("--antigravity-hook", action="store_true", help="Register Antigravity SessionStart & PreToolUse hooks in hooks.json")
    p_hc.add_argument("--all", action="store_true", help="Harden all supported tools + hooks")
    p_hc.add_argument("--project", help="Also harden repo-local .git/info/exclude (and project config if --project-only)")
    p_hc.add_argument("--project-only", action="store_true", help="Write tool configs inside --project instead of $HOME")
    p_hc.add_argument("--apply", action="store_true", help="Write changes (default is safe dry-run)")
    p_hc.add_argument("--output", "-o", help="Write JSON report to file")
    p_hc.set_defaults(func=cmd_harden_configs)

    # 5a. install-hooks
    p_ih = sub.add_parser("install-hooks", help="Install Git hooks (commit-msg, pre-commit, pre-push)")
    p_ih.add_argument("--repo", default=".", help="Target repository path (ignored when --global is set)")
    p_ih.add_argument("--global", dest="global_hooks", action="store_true", help="Install globally via core.hooksPath")
    p_ih.add_argument("--hooks-dir", help="Custom global hooks dir (default: ~/.config/undercover/hooks)")
    p_ih.add_argument("--hooks", default="commit-msg,pre-commit,pre-push", help="Comma-separated hook list")
    p_ih.add_argument("--mode", choices=["scrub", "block"], default="scrub", help="commit-msg mode: scrub (default) or block")
    p_ih.add_argument("--chain", action="store_true", help="Preserve and chain existing custom repo hooks")
    p_ih.add_argument("--force", action="store_true", help="Backup and replace existing custom hooks")
    p_ih.add_argument("--apply", action="store_true", help="Write hooks (default is safe dry-run)")
    p_ih.add_argument("--output", "-o", help="Write JSON report to file")
    p_ih.set_defaults(func=cmd_install_hooks)

    # 5b. uninstall-hooks
    p_uh = sub.add_parser("uninstall-hooks", help="Remove Undercover-managed Git hooks and restore chained hooks")
    p_uh.add_argument("--repo", default=".", help="Target repository path")
    p_uh.add_argument("--global", dest="global_hooks", action="store_true", help="Uninstall global hooks")
    p_uh.add_argument("--hooks-dir", help="Custom global hooks dir")
    p_uh.add_argument("--apply", action="store_true", help="Perform removal (default is safe dry-run)")
    p_uh.add_argument("--output", "-o", help="Write JSON report to file")
    p_uh.set_defaults(func=cmd_uninstall_hooks)

    # Internal hook helpers
    p_cs = sub.add_parser("check-staged", help="Internal pre-commit helper: inspect staged files and diff")
    p_cs.add_argument("--repo", default=".", help="Repository path")
    p_cs.add_argument("--allow-files", help="Comma-separated allowed files")
    p_cs.add_argument("--config", help="Path to undercover policy config JSON")
    p_cs.add_argument("--strict-artifacts", action="store_true", help="Also block MEDIUM-severity docs (CLAUDE.md, AGENTS.md)")
    p_cs.set_defaults(func=cmd_check_staged)

    p_cp = sub.add_parser("check-push", help="Internal pre-push helper: inspect outgoing commits")
    p_cp.add_argument("--repo", default=".", help="Repository path")
    p_cp.add_argument("--config", help="Path to undercover policy config JSON")
    p_cp.add_argument("remote_args", nargs="*", help="Arguments passed by git pre-push hook")
    p_cp.set_defaults(func=cmd_check_push)

    # 6. clean-unicode
    p_cu = sub.add_parser("clean-unicode", help="Detect and remove invisible Unicode watermarks from files")
    p_cu.add_argument("path", nargs="?", default=".", help="File or directory path")
    p_cu.add_argument("--exclude", help="Comma-separated path substrings to exclude")
    p_cu.add_argument("--normalize-nbsp", action="store_true", help="Also convert U+00A0 NBSP to ASCII space in non-code files")
    p_cu.add_argument("--strip-bom", action="store_true", help="Also strip leading UTF-8 BOM (U+FEFF at byte 0)")
    p_cu.add_argument("--apply", action="store_true", help="Modify files in place (default is safe dry-run)")
    p_cu.add_argument("--output", "-o", help="Write JSON report to file")
    p_cu.set_defaults(func=cmd_clean_unicode)

    # 7. clean-comments
    p_cc = sub.add_parser("clean-comments", help="Detect and remove explicit AI-attribution code comment lines")
    p_cc.add_argument("path", nargs="?", default=".", help="File or directory path")
    p_cc.add_argument("--exclude", help="Comma-separated path substrings to exclude")
    p_cc.add_argument("--apply", action="store_true", help="Modify files in place (default is safe dry-run)")
    p_cc.add_argument("--output", "-o", help="Write JSON report to file")
    p_cc.set_defaults(func=cmd_clean_comments)

    # 8. scrub
    p_sc = sub.add_parser("scrub", help="Safely scrub AI watermarks from local Git commit history")
    p_sc.add_argument("repo", nargs="?", default=".", help="Target repository path")
    p_sc.add_argument("--base", help="Base commit/ref (rewrites <base>..HEAD)")
    p_sc.add_argument("--all-local", action="store_true", help="Rewrite from root when branch has no upstream")
    p_sc.add_argument("--allow-pushed", action="store_true", help="Allow rewriting commits already on remote (requires force-push)")
    p_sc.add_argument("--author-name", help="Replacement name if commit author is an AI bot")
    p_sc.add_argument("--author-email", help="Replacement email if commit email is an AI bot")
    p_sc.add_argument("--config", help="Path to undercover policy config JSON")
    p_sc.add_argument("--extra-patterns", help="Comma-separated extra confidential terms to strip")
    p_sc.add_argument("--apply", action="store_true", help="Rewrite history with automatic backup ref (default is dry-run)")
    p_sc.add_argument("--output", "-o", help="Write JSON report to file")
    p_sc.set_defaults(func=cmd_scrub)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
