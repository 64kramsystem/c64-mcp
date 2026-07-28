# Development — agent rules

**Simplicity is paramount: never overengineer; start with the simplest possible implementation.**

## Workflow

- Decide autonomously whether to work inline or use subagents.
- Claude must never run `/claude`; Codex must never run `/codex`.
- Review every non-`AGENTS.md` change with the other agent: Claude Code uses `/codex review`; Codex uses `$claude review`.

## MCP servers

- An MCP server is a launch-time client child. Killing it permanently removes its tools for the session; only the user can reconnect it with `/mcp`. Never kill it to load code changes.
- Disk changes are live with editable installs, but new or changed tools require reconnecting the running server. Before reconnecting, verify a tool by importing and calling it directly from the project venv.

## Debugging

- Never guess causes or fixes. If an essential fact is inaccessible, ask the user to run specific diagnostics, then stop for the output.
- Never SSH into or run commands on remote servers.

## Code, prose, and plans

- Scope by usefulness and correctness, never release cost.
- Prefer better public contracts to compatibility. Change names, arguments, groups, or results directly; add no legacy response, shim, flag, or versioned duplicate.
- Add no handling for impossible cases, speculative options, or configuration for always-on or hypothetical behavior.
- Write only the minimum factual prose or commands. Omit obvious restatement, “what I did,” and speculative risks, caveats, open items, or future-work sections.
- Remove obsolete code, comments, and tests when behavior is removed unless told to retain them.
- Comment only non-obvious code; wrap source comments at 100 characters.
- Put docs only in the shared doc directories; create none for simple changes.
- Runbooks must not re-verify state directly established by the preceding command.

## Tests

- Keep tests only for shipped runtime behavior exercised through production runtime code with observable assertions.
- Keep no tests, fixtures, snapshots, mutation checks, or CI assertions for repository content, docs, metadata, generated artifacts, build/CI, install/setup, configuration patching, deployment, packaging, release, migrations, or maintenance scripts.
- Check infrastructure manually with temporary artifacts, then remove them.

## Output

- Put CLI/chat tables in aligned Markdown fences.
- Never hard-wrap Markdown docs or script help, especially specs.
- Make multiline commands copyable: end each continued line with `\` and prefix interleaved instructions with `#`.
