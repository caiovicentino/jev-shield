#!/usr/bin/env node
// Installs the jev-shield agent skill for Claude Code and opencode,
// injecting this package's location into the installed SKILL.md.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, '../skills/jev-shield/SKILL.md');
const body = readFileSync(SRC, 'utf8').replaceAll('{{JEV_SHIELD_PATH}}', join(HERE, '../src'));

for (const dir of [join(process.env.HOME ?? '~', '.claude/skills'), join(process.env.HOME ?? '~', '.config/opencode/skills')]) {
  try {
    mkdirSync(join(dir, 'jev-shield'), { recursive: true });
    writeFileSync(join(dir, 'jev-shield/SKILL.md'), body);
    console.log(`installed: ${join(dir, 'jev-shield/SKILL.md')}`);
  } catch (e) {
    console.error(`skip ${dir}: ${e?.message ?? e}`);
  }
}
console.log('\nDone. The skill will be picked up the next time your agent starts.');
console.log('Requires AI_GATEWAY_API_KEY in the environment (see .env.example).');
