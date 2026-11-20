#!/usr/bin/env bash
set -euo pipefail

# UNDERCOVER — Cross-Agent AI Contribution Watermark Neutralization Skill Installer
# By default, installs:
#   1) Skill files (Codex, Antigravity, Claude Code; or selected targets)
#   2) Agent SessionStart + PreToolUse guard hooks & attribution disabling (with automatic backup)
#   3) Global Git 3-layer hooks (commit-msg scrub, pre-commit guard, pre-push gate)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="${SCRIPT_DIR}/skills/undercover"

if [ ! -f "${SKILL_SRC}/SKILL.md" ]; then
  echo "Error: Could not find ${SKILL_SRC}/SKILL.md" >&2
  exit 1
fi

TARGETS=()
LOCAL_DIR=""
ENABLE_AGENT_HOOKS=1
ENABLE_GIT_HOOKS=1
FORCE_GIT_HOOKS=0
DO_UNINSTALL_HOOKS=0
PRIMARY_SCRIPT=""

install_to() {
  local dest="$1"
  local label="$2"
  mkdir -p "$(dirname "${dest}")"
  rm -rf "${dest}"
  cp -R "${SKILL_SRC}" "${dest}"
  chmod +x "${dest}/scripts/undercover.py"
  echo "  [OK] Installed UNDERCOVER skill for ${label} -> ${dest}"
  if [ -z "${PRIMARY_SCRIPT}" ]; then
    PRIMARY_SCRIPT="${dest}/scripts/undercover.py"
  fi
}

usage() {
  cat <<'EOF'
UNDERCOVER — AI Contribution Watermark Neutralization Skill Installer

Default behavior (./install.sh):
  1. Installs the UNDERCOVER skill globally for Codex, Antigravity, and Claude Code.
  2. Hardens Claude Code (~/.claude/settings.json attribution + SessionStart & PreToolUse hooks)
     and Antigravity (~/.gemini/config/hooks.json SessionStart & PreToolUse hooks) with backups.
  3. Installs global Git 3-layer hooks (commit-msg auto-scrub, pre-commit, pre-push)
     in ~/.config/undercover/hooks via core.hooksPath (auto-chaining repo-local hooks).

Usage:
  ./install.sh                  Full default install (skills + agent hooks + global Git hooks)
  ./install.sh --all            Install for all agents (Codex, Antigravity, Claude Code, Cursor, Gemini CLI, OpenCode) + hooks
  ./install.sh --codex          Install for Codex (~/.agents/skills & ~/.codex/skills)
  ./install.sh --antigravity    Install for Antigravity (~/.gemini/config/skills)
  ./install.sh --claude         Install for Claude Code (~/.claude/skills)
  ./install.sh --cursor         Install for Cursor (~/.cursor/skills)
  ./install.sh --gemini         Install for Gemini CLI (~/.gemini/skills)
  ./install.sh --opencode       Install for OpenCode (~/.config/opencode/skills)
  ./install.sh --local <dir>    Workspace-only install into <dir> (project skills, project hooks & repo Git hooks)

Hook options:
  --skills-only                 Install skill files only (skip agent hooks and Git hooks)
  --no-agent-hooks              Skip Claude Code / Antigravity SessionStart & PreToolUse hook registration
  --no-git-hooks                Skip global (or repo-local) Git hook installation
  --force-git-hooks             Replace an existing custom global core.hooksPath if present
  --uninstall-hooks             Remove global Undercover Git hooks and unset core.hooksPath
  -h, --help                    Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --all)
      TARGETS+=("all")
      ;;
    --codex)
      TARGETS+=("codex")
      ;;
    --antigravity)
      TARGETS+=("antigravity")
      ;;
    --claude)
      TARGETS+=("claude")
      ;;
    --cursor)
      TARGETS+=("cursor")
      ;;
    --gemini)
      TARGETS+=("gemini")
      ;;
    --opencode)
      TARGETS+=("opencode")
      ;;
    --local)
      shift
      if [ $# -eq 0 ]; then
        echo "Error: --local requires a project directory path." >&2
        exit 1
      fi
      LOCAL_DIR="$1"
      ;;
    --skills-only)
      ENABLE_AGENT_HOOKS=0
      ENABLE_GIT_HOOKS=0
      ;;
    --no-agent-hooks)
      ENABLE_AGENT_HOOKS=0
      ;;
    --no-git-hooks)
      ENABLE_GIT_HOOKS=0
      ;;
    --force-git-hooks)
      FORCE_GIT_HOOKS=1
      ;;
    --uninstall-hooks)
      DO_UNINSTALL_HOOKS=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "${DO_UNINSTALL_HOOKS}" -eq 1 ]; then
  echo "Removing global UNDERCOVER Git hooks..."
  python3 "${SKILL_SRC}/scripts/undercover.py" uninstall-hooks --global --apply
  exit 0
fi

# Workspace-local install mode (--local <dir>)
if [ -n "${LOCAL_DIR}" ]; then
  echo "Installing UNDERCOVER into workspace: ${LOCAL_DIR}"
  install_to "${LOCAL_DIR}/.agents/skills/undercover" "Workspace (.agents/skills)"
  install_to "${LOCAL_DIR}/.claude/skills/undercover" "Workspace (.claude/skills)"
  LOCAL_SCRIPT="${LOCAL_DIR}/.agents/skills/undercover/scripts/undercover.py"

  if [ "${ENABLE_AGENT_HOOKS}" -eq 1 ]; then
    echo "Configuring workspace agent hooks & private .git/info/exclude..."
    python3 "${LOCAL_SCRIPT}" harden-configs \
      --claude --with-claude-hook --antigravity-hook \
      --project "${LOCAL_DIR}" --project-only --apply >/dev/null
    echo "  [OK] Configured workspace Claude Code & Antigravity hooks (+ .git/info/exclude)"
  fi

  if [ "${ENABLE_GIT_HOOKS}" -eq 1 ] && git -C "${LOCAL_DIR}" rev-parse --git-dir >/dev/null 2>&1; then
    echo "Installing repository Git hooks (commit-msg, pre-commit, pre-push)..."
    python3 "${LOCAL_SCRIPT}" install-hooks --repo "${LOCAL_DIR}" --mode scrub --chain --apply >/dev/null
    echo "  [OK] Installed repo Git hooks with safe chaining -> ${LOCAL_DIR}/.git/hooks"
  fi
  echo ""
  echo "Done! UNDERCOVER is active in ${LOCAL_DIR}."
  exit 0
fi

# Global install mode (default targets if none specified)
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=("default")
fi

INSTALL_CLAUDE_HOOKS=0
INSTALL_AGY_HOOKS=0

echo "Installing UNDERCOVER skill globally..."
for t in "${TARGETS[@]}"; do
  case "${t}" in
    default)
      install_to "${HOME}/.gemini/config/skills/undercover" "Antigravity"
      install_to "${HOME}/.claude/skills/undercover" "Claude Code"
      install_to "${HOME}/.agents/skills/undercover" "Codex (~/.agents/skills)"
      INSTALL_CLAUDE_HOOKS=1
      INSTALL_AGY_HOOKS=1
      ;;
    all)
      install_to "${HOME}/.gemini/config/skills/undercover" "Antigravity"
      install_to "${HOME}/.claude/skills/undercover" "Claude Code"
      install_to "${HOME}/.agents/skills/undercover" "Agent Skills (~/.agents/skills)"
      install_to "${HOME}/.codex/skills/undercover" "Codex (~/.codex/skills)"
      install_to "${HOME}/.cursor/skills/undercover" "Cursor"
      install_to "${HOME}/.gemini/skills/undercover" "Gemini CLI"
      install_to "${HOME}/.config/opencode/skills/undercover" "OpenCode"
      INSTALL_CLAUDE_HOOKS=1
      INSTALL_AGY_HOOKS=1
      ;;
    codex)
      install_to "${HOME}/.agents/skills/undercover" "Agent Skills (~/.agents/skills)"
      install_to "${HOME}/.codex/skills/undercover" "Codex (~/.codex/skills)"
      ;;
    antigravity)
      install_to "${HOME}/.gemini/config/skills/undercover" "Antigravity"
      INSTALL_AGY_HOOKS=1
      ;;
    claude)
      install_to "${HOME}/.claude/skills/undercover" "Claude Code"
      INSTALL_CLAUDE_HOOKS=1
      ;;
    cursor)
      install_to "${HOME}/.cursor/skills/undercover" "Cursor"
      ;;
    gemini)
      install_to "${HOME}/.gemini/skills/undercover" "Gemini CLI"
      ;;
    opencode)
      install_to "${HOME}/.config/opencode/skills/undercover" "OpenCode"
      ;;
  esac
done

# Step 1 (Default ON): Agent SessionStart + PreToolUse hooks & attribution hardening
if [ "${ENABLE_AGENT_HOOKS}" -eq 1 ]; then
  HARDEN_FLAGS=()
  if [ "${INSTALL_CLAUDE_HOOKS}" -eq 1 ]; then
    HARDEN_FLAGS+=(--claude --with-claude-hook)
  fi
  if [ "${INSTALL_AGY_HOOKS}" -eq 1 ]; then
    HARDEN_FLAGS+=(--antigravity-hook)
  fi
  if [ ${#HARDEN_FLAGS[@]} -gt 0 ]; then
    echo "Activating automatic SessionStart + PreToolUse guard hooks (backups created automatically)..."
    python3 "${PRIMARY_SCRIPT}" harden-configs "${HARDEN_FLAGS[@]}" --apply >/dev/null
    if [ "${INSTALL_CLAUDE_HOOKS}" -eq 1 ]; then
      echo "  [OK] Hardened Claude Code (~/.claude/settings.json: attribution off + SessionStart & PreToolUse)"
    fi
    if [ "${INSTALL_AGY_HOOKS}" -eq 1 ]; then
      echo "  [OK] Hardened Antigravity (~/.gemini/config/hooks.json: SessionStart & PreToolUse)"
    fi
  fi
fi

# Step 2 (Default ON): Global Git 3-layer hooks (commit-msg scrub, pre-commit, pre-push)
if [ "${ENABLE_GIT_HOOKS}" -eq 1 ]; then
  echo "Activating global Git 3-layer hooks (commit-msg scrub, pre-commit, pre-push)..."
  GIT_HOOK_FLAGS=(install-hooks --global --mode scrub --apply)
  if [ "${FORCE_GIT_HOOKS}" -eq 1 ]; then
    GIT_HOOK_FLAGS+=(--force)
  fi
  if python3 "${PRIMARY_SCRIPT}" "${GIT_HOOK_FLAGS[@]}" >/dev/null; then
    echo "  [OK] Installed global Git hooks -> ~/.config/undercover/hooks (core.hooksPath)"
  else
    echo "  [WARN] Skipped global core.hooksPath because an existing custom hooksPath is configured." >&2
    echo "         Re-run with --force-git-hooks to replace it, or use install-hooks --repo <dir> --chain." >&2
  fi
fi

echo ""
echo "Done! UNDERCOVER is active globally (automatic hooks + Git scrub enabled by default)."
echo "Tip: Pass --skills-only to install skill files without hooks, or --uninstall-hooks to remove global Git hooks."
