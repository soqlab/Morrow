# Ask your assistant

Ask your own AI assistant about your Morrow ("what's our quantum risk?", "what needs fixing first?",
"is example.com safe yet?") without opening the console. `morrow-mcp` (`tools/morrow_mcp`) is a small
[MCP](https://modelcontextprotocol.io) server that runs on your machine. Your assistant starts it and
talks to it over stdio; it opens no network port.

It can only read. Every tool is a `GET` to your Morrow server's API with your organization's
read-only API key, so it sees what a viewer of your organization sees in the console, and nothing
else.

**Self-hosted Morrow only, for now.** The hosted service at morrow.soqlab.com refuses assistant
requests. On your own server, the operator turns it on with `MORROW_MCP_ENABLED=1`; without it every
request marked as coming from an assistant is refused with a sentence saying so.

## 1. Turn it on (server operator)

Set `MORROW_MCP_ENABLED=1` in the server's environment and restart. Nothing else changes: the
read-only API key scope, the audit journal and the routes are the same as before.

## 2. Make a read-only key

In the operator console (`/vendor-admin`), open the organization, then **API keys**, and create a key
with only the **read** scope (`POST /platform/customers/{organization_id}/api-keys` with
`"scopes": ["read"]`). Copy the secret: it is shown once.

Morrow refuses an assistant that uses any other credential: a key with write, admin or sign scope, a
session token, a support token, header identities, or nothing. The refusal says to create a key with
only the read scope.

## 3. Install

```bash
pip install ./tools/morrow_mcp          # from a checkout of this repository
MORROW_URL=https://morrow.example.internal MORROW_API_KEY=pq_... morrow-mcp --check
```

`--check` tries the address and key once and says whether an assistant can use them. Plain `http` to
another machine is refused unless you set `MORROW_MCP_ALLOW_HTTP=1`, because the key would travel
unencrypted.

## 4. Add it to your assistant

Most MCP clients (Claude Desktop, Claude Code and others) take a JSON entry like this:

```json
{
  "mcpServers": {
    "morrow": {
      "command": "morrow-mcp",
      "env": {
        "MORROW_URL": "https://morrow.example.internal",
        "MORROW_API_KEY": "pq_your_read_only_key"
      }
    }
  }
}
```

If `morrow-mcp` isn't on the assistant's PATH, give its full path, or use `"command": "python",
"args": ["-m", "morrow_mcp"]` with the Python you installed it into. The key goes in `env`, never in
`args`, so it doesn't show up in process lists.

## Tools

| Tool | What it reads |
|---|---|
| `risk_sentence` | a domain's stored grade and its quantum risk in one sentence (`GET /api/public/grade/{domain}?stored=1`) |
| `inventory_summary` | your assets by criticality and environment, assets without an owner, the last five scans (`GET /assets`, `GET /scans`) |
| `findings_needing_action` | open remediation and migration work, highest priority first (`GET /work/remediation-feed`) |
| `make_safe_status` | Make it safe for a domain: the fix for its stack, the re-check status, the signed proof (`GET /api/public/make-safe/{domain}`, `.../watch`, `GET /r/{domain}/proof.json`) |
| `watch_changes` | a domain's stored grade history, or the public "what changed" feed (`GET /api/public/history/{domain}`, `GET /api/public/changes`) |
| `harvest_clock` | from which year today's traffic could be read, and whether the chosen kind of data stays private long enough (`GET /api/public/risk-sentence`) |

No tool starts a check. `risk_sentence` and `harvest_clock` read the newest stored grade
(`?stored=1`); a domain Morrow has never graded gets "no grade stored yet". Watch lists belong to
people, not keys, so `watch_changes` reads a domain's grade history rather than someone's watch list.

## What is logged

Every assistant request that presents an API key is appended to the organization's hash-chained
audit journal (`GET /audit/logs`, verifiable with `services/audit_chain.py`) as `mcp.tool_call`:

- actor `apikey:<key id>`, decision `allow` or `deny`, and for a denial the reason;
- details: the tool name, the key id, the method, the route path (no query string) and the status.

The key and the answers are never logged. The usual request journal (security logging) records the
request as well, as for any API key.

## Limits

- **Read-only, enforced by the server.** A read-only key can only `GET`/`HEAD`; an assistant-marked
  request (`X-Client: mcp/<tool>`) that is anything else is refused before it reaches an endpoint and
  journaled as a denial.
- **Bounded answers.** Each answer is cut to about 12,000 characters (long text, long lists and deep
  nesting are shortened and marked), control characters are removed, and the answer is wrapped as
  JSON naming the request it came from. Answers over 2 MB, redirects and non-JSON replies are refused.
- **Your assistant decides what to do with the data.** Asset names, finding titles and owners' replies
  are text people wrote; `morrow-mcp` passes them on as data and does not interpret them.
- To stop access, revoke the key in the operator console, or unset `MORROW_MCP_ENABLED`.
