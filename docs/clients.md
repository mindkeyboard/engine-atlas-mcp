# Connecting a client

Install the server first, as the [README](../README.md) describes, and check it:

```sh
engine-atlas-mcp doctor
```

If your client cannot find `engine-atlas-mcp`, give it the full path. Find it with
`where engine-atlas-mcp` on Windows or `which engine-atlas-mcp` elsewhere. Use forward
slashes in paths inside JSON and TOML.

## Claude Code

```sh
claude mcp add --transport stdio --scope user engine-atlas -- engine-atlas-mcp mcp
```

`--scope user` makes it available in all projects. Without it, the server is added to
the current project only. Everything after `--` goes to the server unchanged.

Check it with `claude mcp list`, or with `/mcp` inside Claude Code. The server should
show as connected. Remove it with `claude mcp remove engine-atlas`.

Documentation: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp).

## Codex

```sh
codex mcp add engine-atlas -- engine-atlas-mcp mcp
```

Or add this to `~/.codex/config.toml`. The CLI, IDE extension and desktop app share it:

```toml
[mcp_servers.engine-atlas]
command = "engine-atlas-mcp"
args = ["mcp"]
startup_timeout_sec = 60
```

`startup_timeout_sec` gives slower machines more than the default 10 seconds. Check it with `codex mcp list`, or with
`/mcp` inside Codex.

Documentation: [Model Context Protocol in Codex](https://developers.openai.com/codex/mcp),
[configuration reference](https://developers.openai.com/codex/config-reference).

## Antigravity

Open the configuration file:

- **Antigravity IDE:** click **…** at the top of the agent side panel, choose
  **MCP Servers**, then **Manage MCP Servers** and **View raw config**.
- **Antigravity CLI or by hand:** edit `~/.gemini/config/mcp_config.json`. To use the
  server in one workspace only, edit `<workspace>/.agents/mcp_config.json`.

Add the server:

```json
{
  "mcpServers": {
    "engine-atlas": {
      "command": "engine-atlas-mcp",
      "args": ["mcp"]
    }
  }
}
```

Keep any other servers already in the file. Check it with `/mcp` in the Antigravity CLI,
or with **Refresh** under **Installed MCP Servers** in the app.

Documentation: [Antigravity MCP](https://antigravity.google/docs/mcp).

## Other clients

Any MCP client can start the server over stdio with this command:

```sh
engine-atlas-mcp mcp
```

## When something does not work

| Symptom | What to do |
|---|---|
| The server does not start | Run `engine-atlas-mcp doctor`, then `engine-atlas-mcp mcp` in a terminal and read the error |
| `command not found` | Use the full path to `engine-atlas-mcp` |
| Connection timeout on start | Raise the client's startup timeout |
| Decompilation fails | Start Ghidra, open `libasphalt8.so`, enable Ghidra MCP, pass `--ghidra` if the address differs from `http://127.0.0.1:8089` |
| The site does not see the MCP | Start a client session, open the edits link from `engine-atlas-mcp doctor`, allow local network access; Safari will not work |
| The site is unreachable or its data is old | Open the site in a browser; `engine-atlas-mcp doctor` shows the reason |
| Tools are not found | Restart the client session after adding the server |
