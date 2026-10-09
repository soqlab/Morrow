# Security Truth API

The Security Truth API is the external guardrail contract for coding agents, IDE assistants, CI systems, and security tools that want to propose or apply infrastructure changes.

It answers one question:

> Is this proposed change allowed by the organization's PQC/security policy?

## Endpoint

`POST /v1/guardrails/evaluate-change`

The endpoint is read/evaluate only. It does not merge, approve, apply, or revert changes.

## External Tool Authentication

For external tools, configure:

```text
PQC_TOOL_API_KEYS=wiz:REDACTED_KEY:guardrails:evaluate|findings:write|findings:read|write_path:request
```

Then call APIs with:

```text
x-tool-api-key: REDACTED_KEY
```

Supported scopes:

- `guardrails:evaluate`
- `findings:write`
- `findings:read`
- `write_path:request`
- `*`

## Request

```json
{
  "repo": "acme/infra",
  "ref": "feature/change-s3-policy",
  "provider": "github",
  "actor_type": "ai_agent",
  "actor_id": "cipherlens-session-123",
  "tool_source": "cipherlens",
  "intent": "propose_change",
  "changed_files": [
    {
      "file_path": "s3.tf",
      "content": "resource \"aws_s3_bucket_public_access_block\" \"bad\" { block_public_acls = false }"
    }
  ],
  "metadata": {
    "pull_request": 42
  }
}
```

`changed_files` can include full proposed content. `proposed_diff` can also be supplied as a unified diff; the platform extracts added lines for policy evaluation.

## Response

```json
{
  "decision": "block",
  "blocking": true,
  "evidence_id": "guardrail-abc123",
  "violations_total": 1,
  "violations": [
    {
      "kind": "iac_security",
      "rule_id": "IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED",
      "severity": "high"
    }
  ],
  "required_actions": [
    "Fix blocking policy violations",
    "Run validation before merge",
    "Re-submit this endpoint before PR merge"
  ]
}
```

## MCP Tool

The same capability is available through:

`POST /mcp`

Tool name:

`evaluate_change_guardrails`

Example:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "evaluate_change_guardrails",
    "arguments": {
      "repo": "acme/infra",
      "tool_source": "mcp-agent",
      "changed_files": [
        {
          "file_path": "sg.tf",
          "content": "cidr_blocks = [\"0.0.0.0/0\"]"
        }
      ]
    }
  }
}
```

If the decision is `block`, MCP returns `isError: true`.

## External Findings Ingestion

`POST /v1/integrations/findings/ingest`

Use this when a security tool such as Wiz, Snyk, or a custom scanner wants to send findings into the governance workflow.

```json
{
  "tool_source": "snyk",
  "integration_type": "sca",
  "findings": [
    {
      "external_id": "SNYK-123",
      "title": "Critical vulnerable package",
      "severity": "critical",
      "repo": "acme/app",
      "file_path": "requirements.txt"
    }
  ]
}
```

The API returns a `batch_id`, severity counts, top findings, and persisted `finding_ids`. It records an audit event but does not automatically create a PR.

## External Findings Queue

`GET /v1/integrations/findings`

Lists persisted findings for the current organization. Supports `limit`, `severity`, `status`, and `tool_source` filters.

`GET /v1/integrations/findings/{finding_id}`

Returns one persisted finding with source evidence and write-path status.

`POST /v1/integrations/findings/{finding_id}/write-path`

Promotes a finding into a guarded write-path fix request. The platform evaluates the proposed or evidence-derived change through guardrails first, marks the finding as `fix_requested`, and returns the generated `request_id`.

## Write-Path Fix Requests

`POST /v1/write-path/fix-requests`

Use this when an external tool wants the platform to start a governed fix workflow.

```json
{
  "tool_source": "wiz",
  "finding_id": "WIZ-123",
  "repo": "acme/infra",
  "desired_outcome": "Fix public SSH exposure",
  "changed_files": [
    {
      "file_path": "sg.tf",
      "content": "resource \"aws_security_group_rule\" \"ssh\" { cidr_blocks = [\"0.0.0.0/0\"] }"
    }
  ]
}
```

The platform evaluates guardrails first. If the proposed change violates policy, the request is returned as `blocked_by_guardrails`.

## Vendor Admin Visibility

`GET /platform/security-truth`

Requires `x-platform-key`. Returns platform-operator metrics for recent external findings, high/critical open items, blocked write-path changes, and recent guardrail events.

`POST /platform/security-truth/findings/{finding_id}/write-path`

Requires `x-platform-key`. Lets a vendor/platform admin promote an external finding into a guarded write-path request on behalf of the owning organization. This still runs guardrails and remains human-approval/validation gated.

## Positioning

Use this API as the mandatory pre-merge guardrail for:

- AI coding assistants
- CI/CD systems
- remediation bots
- security tools that want to create fixes, not just findings
- infrastructure drift response workflows
