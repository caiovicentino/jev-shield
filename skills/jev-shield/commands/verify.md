---
description: Verify a risky action or untrusted content with jev-shield before acting. Usage: /verify <command or text to screen>
agent: build
---

You are about to run a verification check with jev-shield before acting on the following:

ARGUMENTS

Decide the payload kind:
- If the text is a shell command, API call, file write, email/webhook send, or similar ACTION → use `kind: "call"` with an appropriate tool object (e.g. `{"name":"shell_exec","description":"Execute a shell command on the host"}` and `args`).
- If the text is CONTENT from an untrusted source (web page, tool output, email, issue, document) → use `kind: "result"` with the content in `text`.

Then run:

```bash
echo '<json payload>' | npx -y github:caiovicentino/jev-shield verify
```

(If npx fails, ask the user for the jev-shield repo path and use `node <repo>/src/verify-cli.mjs`.)

Read the verdict and report to the user, in this order:
1. The decision (`block` / `annotate` / `pass`) with the top hazards and their probabilities, e.g. `destructive_action=0.92, severity=2.09`.
2. What you will do: if `block` — refuse the action and propose a safer alternative; if `annotate` — ask for explicit confirmation; if `pass` — proceed with the action.
3. Never silently skip verification. If the tool is unavailable, say so and ask the user how to proceed.
