#!/usr/bin/env node
// jev-verify — CLI for agents to verify a risky action or untrusted content
// before acting. Reads a JSON payload from stdin, prints a typed verdict.
//
// Payload (call):   { "kind":"call", "tool":{"name":"shell_exec","description":"..."}, "args":{"command":"rm -rf /"} }
// Payload (result): { "kind":"result", "tool":"web_search", "text":"...tool output..." }
// Output: { decision: "block"|"annotate"|"pass", hazards: {...}, severity, ms, usd }

import { loadConfig, verifyCall, verifyResult } from './verify.mjs';

const cfg = loadConfig(process.env.JEV_SHIELD_CONFIG);
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', async () => {
  let req;
  try {
    req = JSON.parse(input);
  } catch {
    console.log(JSON.stringify({ decision: 'block', reason: 'invalid payload JSON' }));
    return;
  }
  try {
    const out =
      req.kind === 'result'
        ? await verifyResult(req.tool ?? 'unknown', { content: [{ type: 'text', text: req.text ?? '' }] }, cfg)
        : await verifyCall(req.tool?.name ?? 'unknown', req.args ?? {}, req.tool ?? {}, cfg);
    console.log(
      JSON.stringify(
        { decision: out.action, triggered: out.triggered, hazards: out.hazards, severity: out.severity, ms: out.ms, usd: out.usd, error: out.error ?? undefined },
        null,
        2,
      ),
    );
  } catch (e) {
    console.log(JSON.stringify({ decision: 'annotate', error: String(e?.message ?? e) }));
  }
});
