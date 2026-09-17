# jev-shield

**Semantic MCP firewall powered by [Jev](https://vercel.com/ai-gateway/models/jev)** — a System One verification model. Sits between any MCP client and any MCP server (stdio) and screens, with **calibrated probabilities**, every tool call, every tool result, and every tool description.

## Why another MCP firewall?

Existing MCP security proxies (pipelock, mcpwall, mcp-firewall, Lakera, NeMo Guardrails) are **deterministic or pattern-based**: they catch payloads that look like known attacks. Attackers paraphrase. Jev catches the *meaning* of a payload — including phrasings never seen before — and returns a **probability, not a boolean**, so your policy (not the vendor's) decides what happens.

jev-shield layers three kinds of control:

| Layer | What it does | Cost |
|---|---|---|
| **Structural** (deterministic) | Recipient allowlists, required flags, config-owned rules | free |
| **Semantic** (Jev, one call per event) | Exfiltration, destructive actions, injection-in-args, credential/payload sensitivity, tool-result injection, secrets in results, tool-description poisoning | ~$0.00003/event, ~500ms |
| **Session** (taint tracking) | After a result is flagged, subsequent calls are verified under an escalated policy | free |

Measured in the bundled demo: 10 verifications, **$0.0003 total**, median latency 558ms.

## What it catches (demo included)

```
npm install
AI_GATEWAY_API_KEY=... npm run demo
```

The demo runs a vulnerable MCP server (poisoned tool description, injection in search results, `.env` leak) behind the firewall and simulates an agent that gets tricked:

1. `tools/list` → poisoned tool **flagged** (`tool_poisoning=0.9x`)
2. benign call → passes clean
3. poisoned search result → **REDACTED before the agent ever reads it** (`contains_injection=0.98`)
4. agent tries exfil → **BLOCKED** (allowlist + semantics)
5. legitimate email to ops → passes (semantic discrimination, not keyword)
6. novel-phrasing exfil *inside the allowlist* → **BLOCKED** (`payload_sensitivity=0.98`)
7. destructive call → **BLOCKED** (severity escalation: 2.11 ≥ 2.0)
8. secret-leaking result → **REDACTED** (`contains_secrets=0.97`)

## Architecture

```
MCP client (Claude Code, Cursor, any agent)
        │ stdio
        ▼
┌─ jev-shield ──────────────────────────────────────────┐
│  tools/list → Jev poisoning scan → annotate/hide      │
│  tools/call → structural rules → Jev call battery     │
│               (exfil, destructive, injection, creds)  │
│  result     → Jev result battery → annotate or redact │
│  session    → taint tracking escalates policy         │
│  audit      → JSONL trail: hazards, severity, ms, $   │
└────────────────────┬──────────────────────────────────┘
                     │ stdio
                     ▼
             your real MCP server
```

## Usage

```bash
# wrap any stdio MCP server
AI_GATEWAY_API_KEY=<your-key> npx jev-shield -- node path/to/server.js
# custom policy
JEV_SHIELD_CONFIG=./config/policies.json npx jev-shield -- python -m my_server
```

Point your MCP client's command at `jev-shield` instead of the server. Everything else is transparent.

## Agent skill (Claude Code / opencode / compatible agents)

Give any agent semantic verification of its own risky actions — destructive commands, external sends, secrets/PII, untrusted content:

```bash
# zero-install: agents call it directly
echo '{"kind":"call","tool":{"name":"shell_exec","description":"Execute a shell command"},"args":{"command":"rm -rf /var/data"}}' \
  | npx -y github:caiovicentino/jev-shield verify

# or install the skill so agents pick it up automatically
npx -y github:caiovicentino/jev-shield install-skill   # ~/.claude/skills + ~/.config/opencode/skills + /verify command
npx -y skills add caiovicentino/jev-shield -g          # multi-agent: Claude Code, Codex, Cursor, opencode, +70 more
```

In opencode, `/verify <command or text>` screens anything on demand. The skill requires `AI_GATEWAY_API_KEY` in the environment (see `.env.example`).

## Enforcement (hooks & plugins)

The skill is cooperative — the hook/plugin layer is enforced, tool-by-tool:

| Agent | Mechanism | Covers |
|---|---|---|
| Claude Code | `PreToolUse` hook → `deny`/`ask` before Bash/Write/Edit/WebFetch/MCP tools; `PostToolUse` hook → flags poisoned tool results to the model | every tool call, incl. MCP |
| opencode | plugin `tool.execute.before` (throws = block) and `tool.execute.after` (withholds injected results) | every tool call, incl. MCP |
| Codex | no hook API — enforcement via the MCP firewall: `jev-shield wrap -- <upstream-cmd>` as the MCP server command | every MCP tool call |

```bash
npx -y github:caiovicentino/jev-shield install-hooks   # installs hook + plugin (merges, never clobbers)
JEV_HOOK_OFF=1                                         # kill switch (env), JEV_FAIL_MODE=closed to fail closed
```

Every check costs ~$0.00003 and adds ~0.5–1.3s to a tool call. Local file reads (Read/Grep/Glob) are exempt by default.

## Policy is code, not a prompt

`config/policies.json`:

```json
{
  "policy": { "review": 0.35, "action": 0.7, "severity_block": 2.0 },
  "hazard_actions": { "data_exfiltration": "block", "destructive_action": "block" },
  "fail_mode": "open",                 // or "closed" if Jev is unreachable
  "tools": {
    "send_email": { "recipient_allowlist": ["@empresa.com"] },
    "delete_records": { "require_flag": { "confirm": true } }
  }
}
```

Probabilities are the same for every policy; thresholds decide actions. Change policy in code review, not in a prompt.

## Honest limits

- **This is not a security boundary.** It is a probabilistic signal layer. Keep sandboxing, least privilege, and human approval for high-stakes actions. (See S. Willison, *The lethal trifecta*, 2025.)
- Determined attackers can try to evade the semantic layer; mitigation is depth: multi-question batteries, severity gating, taint tracking, structural allowlists, and review of the audit trail.
- Adds ~500ms per tool call/result (parallel questions, single call). Async/streaming modes are on the roadmap.
- State budget per request ≈ 32k tokens; huge tool outputs are truncated for screening.
- Depends on TypeSafe early access pricing via AI Gateway; the model layer is abstracted so providers can be swapped.

## Roadmap

- [ ] HTTP/SSE transport support (remote MCP)
- [ ] Policy packs per industry (healthcare, finance, e-commerce) — community-driven
- [ ] Streaming-friendly async screening (annotate post-hoc instead of blocking)
- [ ] Dashboard for the audit trail; export to SIEM
- [ ] Eval harness: curated adversarial suite (PT-BR + EN) in CI

MIT
