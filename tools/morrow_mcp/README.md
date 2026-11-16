# morrow-mcp

Ask your own AI assistant about your self-hosted Morrow ("what's our quantum risk?", "what needs
fixing first?") without opening the console. `morrow-mcp` is a small
[MCP](https://modelcontextprotocol.io) server that runs on your machine; your assistant starts it
and talks to it over stdio. It opens no network port.

It can only read. Every tool is a `GET` to your Morrow server with your organization's read-only API
key, and the server journals each call in its hash-chained audit log.

```
pip install ./tools/morrow_mcp
MORROW_URL=https://morrow.example.internal MORROW_API_KEY=pq_... morrow-mcp --check
```

The server needs `MORROW_MCP_ENABLED=1` (off unless set, and off on the hosted morrow.soqlab.com).

Environment variables:

- `MORROW_URL`: your Morrow address (default `http://localhost:8000`)
- `MORROW_API_KEY`: an organization API key with only the `read` scope
- `MORROW_MCP_ALLOW_HTTP=1`: allow plain http to another machine on a trusted private network

Tools: `risk_sentence`, `inventory_summary`, `findings_needing_action`, `make_safe_status`,
`watch_changes`, `harvest_clock`.

Setup for Claude Desktop, Claude Code and other MCP clients, what is logged and the limits:
[docs/ASK_YOUR_ASSISTANT.md](https://github.com/soqlab/Morrow/blob/main/docs/ASK_YOUR_ASSISTANT.md).

Requires Python 3.10+ and the MCP SDK version 2.
