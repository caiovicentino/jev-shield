#!/usr/bin/env node
// Removes jev-shield enforcement from this machine (hook + plugin). The skill and /verify stay.
import { rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const HOME = process.env.HOME ?? '~';
const targets = [
  join(HOME, '.claude/hooks/jev-shield.mjs'),
  join(HOME, '.config/opencode/plugins/jev-shield.js'),
];
for (const t of targets) {
  if (existsSync(t)) {
    rmSync(t);
    console.log(`removed: ${t}`);
  }
}

const settingsPath = join(HOME, '.claude/settings.json');
if (existsSync(settingsPath)) {
  const s = JSON.parse(readFileSync(settingsPath, 'utf8'));
  for (const ev of Object.keys(s.hooks ?? {})) {
    s.hooks[ev] = (s.hooks[ev] ?? []).filter((h) => !JSON.stringify(h).includes('jev-shield'));
    if (s.hooks[ev].length === 0) delete s.hooks[ev];
  }
  if (Object.keys(s.hooks ?? {}).length === 0) delete s.hooks;
  writeFileSync(settingsPath, JSON.stringify(s, null, 2) + '\n');
  console.log(`cleaned:  ${settingsPath}`);
}
console.log('\nEnforcement removed. The cooperative skill (/verify, verify-cli) is still installed.');
