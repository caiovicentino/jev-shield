#!/usr/bin/env bash
# Installs the jev-shield agent skill for Claude Code and opencode.
# Injects this repo's absolute path into the installed SKILL.md so the
# agent can locate verify-cli.mjs without any config.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="$REPO/skills/jev-shield/SKILL.md"

install_to() {
  local dir="$1"
  mkdir -p "$dir/jev-shield"
  sed "s|{{JEV_SHIELD_PATH}}|$REPO|g" "$SKILL_SRC" > "$dir/jev-shield/SKILL.md"
  echo "installed: $dir/jev-shield/SKILL.md"
}

install_to "$HOME/.claude/skills"
install_to "$HOME/.config/opencode/skills"

cat <<EOF

Done. The skill will be picked up the next time your agent starts.
Requires AI_GATEWAY_API_KEY in your environment (see .env.example).
EOF
