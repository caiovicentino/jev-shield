#!/usr/bin/env node
// Installs jev-shield enforcement for supported agents:
//   Claude Code — PreToolUse/PostToolUse hook (~/.claude/hooks + settings.json merge)
//   opencode    — tool.execute.before/after plugin (~/.config/opencode/plugins)
//   Codex       — no hook API; prints MCP firewall wrap instructions (enforcement at the MCP layer)
import { copyFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, 'src');
const HOME = process.env.HOME ?? '~';

function inject(path) {
  let s = readFileSync(path, 'utf8');
  s = s.replace("const LOCAL_SRC = '';", `const LOCAL_SRC = ${JSON.stringify(SRC)};`);
  return s;
}

// ---- Claude Code hook ----
const ccHooksDir = join(HOME, '.claude/hooks');
try {
  mkdirSync(ccHooksDir, { recursive: true });
  writeFileSync(join(ccHooksDir, 'jev-shield.mjs'), inject(join(HERE, 'hooks/claude-code/jev-shield.mjs')));
  console.log(`hook installed:   ${join(ccHooksDir, 'jev-shield.mjs')}`);
} catch (e) {
  console.error(`hook install failed: ${e?.message ?? e}`);
}

// ---- Claude Code settings.json merge ----
const settingsPath = join(HOME, '.claude/settings.json');
const CMD = 'node "$HOME/.claude/hooks/jev-shield.mjs"';
const WANT = [
  { event: 'PreToolUse', matcher: 'Bash|Edit|Write|NotebookEdit|MultiEdit|WebFetch|WebSearch|mcp__.*' },
  { event: 'PostToolUse', matcher: 'Bash|WebFetch|WebSearch|Grep|mcp__.*' },
];
try {
  let settings = {};
  if (existsSync(settingsPath)) {
    settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
  }
  settings.hooks ??= {};
  for (const { event, matcher } of WANT) {
    settings.hooks[event] ??= [];
    const exists = settings.hooks[event].some(
      (h) => h?.matcher === matcher && Array.isArray(h.hooks) && h.hooks.some((k) => k?.command === CMD)
    );
    if (!exists) {
      settings.hooks[event].push({ matcher, hooks: [{ type: 'command', command: CMD }] });
      console.log(`settings merged:  ${event} matcher "${matcher}"`);
    } else {
      console.log(`settings present: ${event} matcher "${matcher}"`);
    }
  }
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
  console.log(`settings saved:   ${settingsPath}`);
} catch (e) {
  console.error(`settings merge failed: ${e?.message ?? e}`);
}

// ---- opencode plugin ----
const ocDir = join(HOME, '.config/opencode/plugins');
try {
  mkdirSync(ocDir, { recursive: true });
  writeFileSync(join(ocDir, 'jev-shield.js'), inject(join(HERE, 'plugins/opencode/jev-shield.js')));
  console.log(`plugin installed: ${join(ocDir, 'jev-shield.js')}`);
} catch (e) {
  console.error(`plugin install failed: ${e?.message ?? e}`);
}

// ---- Codex (no hook API — MCP wrap) ----
console.log(`
Codex has no hook API. Enforcement there is at the MCP layer — wrap upstream servers:
  jev-shield wrap -- <upstream-cmd> [args…]
and point Codex's ~/.codex/config.toml at the wrapper:
  [mcp_servers.my-server]
  command = "jev-shield"
  args = ["wrap", "--", "npx", "-y", "some-mcp-server"]
The skill (installed separately) covers the behavioral layer for Codex agents.`);

console.log('\nDone. Requires AI_GATEWAY_API_KEY in the environment. Kill switch: JEV_HOOK_OFF=1.');
