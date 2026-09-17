#!/usr/bin/env node
// jev-shield CLI dispatcher.
//   jev-shield verify            — read JSON payload from stdin, print typed verdict
//   jev-shield wrap -- <cmd> …   — run as a stdio MCP firewall proxy (default)
// Also used by the agent skill: npx github:caiovicentino/jev-shield verify

const [, , sub, ...rest] = process.argv;

if (sub === 'verify') {
  await import('../src/verify-cli.mjs');
} else if (sub === 'wrap' && rest[0] === '--') {
  process.argv = [process.argv[0], process.argv[1], '--', ...rest.slice(1)];
  await import('../src/firewall.mjs');
} else if (sub === '--' || sub == null) {
  // legacy: jev-shield -- <cmd> <args>
  await import('../src/firewall.mjs');
} else if (sub === 'install-skill') {
  await import('../install-skill.mjs');
} else {
  console.error(`usage:
  jev-shield verify                 # verify action/content from JSON on stdin
  jev-shield wrap -- <cmd> [args…]  # run as stdio MCP firewall proxy
  jev-shield -- <cmd> [args…]       # same as wrap
  jev-shield install-skill          # install the agent skill locally`);
  process.exit(sub ? 2 : 0);
}
