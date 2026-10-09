# AI providers

The assistant (CipherLens / PQC Scout) is provider-agnostic. Point it at whatever you already have — a hosted API, a self-hosted endpoint, or your own code — without editing the source.

Nothing in this platform outside `backend/services/llm/` knows which provider is in use.

- [Quick start](#quick-start)
- [What each provider supports](#what-each-provider-supports)
- [Configuring each provider](#configuring-each-provider)
- [Bring your own model](#bring-your-own-model)
- [Configuration reference and precedence](#configuration-reference-and-precedence)
- [Per-organization providers](#per-organization-providers)
- [Turning AI off entirely](#turning-ai-off-entirely)
- [What data is sent to a model](#what-data-is-sent-to-a-model)
- [Behaviour you can rely on](#behaviour-you-can-rely-on)
- [Checking your configuration](#checking-your-configuration)
- [Adding an adapter](#adding-an-adapter-contributors)

---

## Quick start

```bash
# A hosted API
PQC_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Anything OpenAI-compatible, by base URL (Groq, OpenRouter, Together, vLLM, LM Studio, llama.cpp)
PQC_LLM_PROVIDER=openai-compatible
PQC_LLM_BASE_URL=https://api.groq.com/openai/v1
PQC_LLM_MODEL=llama-3.3-70b-versatile
PQC_LLM_API_KEY=gsk_...
PQC_LLM_TOOLS=1                 # this endpoint does support tool calling

# A local model, no key
PQC_LLM_PROVIDER=ollama
PQC_LLM_MODEL=llama3.1

# No model at all
PQC_LLM_DISABLED=1
```

Then prove it:

```bash
python scripts/check-integrations.py --only ai             # configuration, no network
python scripts/check-integrations.py --only ai --check-ai  # one cheap read, proves the key
```

…or press **Send a test prompt** in the console under **Data Control → 06 / Model provider**, which makes one real, receipted call and shows exactly what came back.

If you set none of the `PQC_LLM_*` variables, nothing changes from how this platform behaved before the provider layer existed: Anthropic when `ANTHROPIC_API_KEY` is set, otherwise OpenAI when `OPENAI_API_KEY` is set, otherwise the built-in answerer.

---

## What each provider supports

| `PQC_LLM_PROVIDER` | Needs a key | Default model | Tool calling | Streaming | Context window | System prompt | Token usage | Cost |
|---|---|---|---|---|---|---|---|---|
| `anthropic` | yes | `claude-opus-5` | yes | yes | 200,000 | separate field | reported | from your prices |
| `openai` | yes | `gpt-4o-mini` | yes | yes | set it yourself | `system` message | reported | from your prices |
| `azure-openai` | yes | your deployment | yes | yes | set it yourself | `system` message | reported | from your prices |
| `gemini` | yes | `gemini-2.0-flash` | yes | yes | 1,000,000 | separate field | reported | from your prices |
| `openai-compatible` | usually | set it yourself | **off unless `PQC_LLM_TOOLS=1`** | yes | set it yourself | `system` message | reported | provider-reported (OpenRouter) or from your prices |
| `ollama` | no | `llama3.1` | **off unless `PQC_LLM_TOOLS=1`** | yes | set it yourself | `system` message | reported | free, and that is known |
| `builtin` | no | `builtin-rules` | no | yes (chunked) | n/a | none | n/a | free, and that is known |
| `custom` | your choice | your choice | your choice | your choice | your choice | your choice | your choice | your choice |

Two columns deserve a note.

**Tool calling is declared off by default for `openai-compatible` and `ollama`.** "OpenAI-compatible" says nothing about whether a particular server implements function calling, and whether Ollama can do it depends on the model you pulled, not on Ollama. A tool request that the server quietly ignores comes back as prose, and the agent would wait for tool calls that never arrive. So you opt in with `PQC_LLM_TOOLS=1`. Without it the assistant answers from stored evidence, without tools, and **says so in the answer** — that is a supported, tested configuration, not a degraded one.

**"Streaming"** means the provider's streaming wire protocol, which the adapters implement and the test suite exercises against recorded fixtures. The platform's own default is still to assemble the complete response before releasing any of it, because the tenant's data boundary scans a model's output for credential patterns and withholds the response if it finds one — a guarantee that incremental pass-through would break. The console sees chunks either way, so it behaves identically. Set `PQC_LLM_WIRE_STREAM=1` to use the provider's streaming protocol on the wire (lower time-to-first-byte at the provider, same gated delivery to the browser).

**Cost.** There is no built-in price table. A stale hard-coded price on an operator's screen is worse than "unknown", so cost is reported only when the provider returns one (OpenRouter does) or when you configure `PQC_LLM_PRICE_INPUT_PER_MTOK` / `PQC_LLM_PRICE_OUTPUT_PER_MTOK` for the model you are running. Every number carries a `cost_basis` of `provider_reported`, `price_table` or `unknown`, and none of it is billing: your provider's invoice is authoritative.

---

## Configuring each provider

### Anthropic

```bash
PQC_LLM_PROVIDER=anthropic          # or just set the key and leave this unset
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_AGENT_MODEL=claude-opus-5     # optional
ANTHROPIC_AGENT_EFFORT=high             # low | medium | high | xhigh | max
ANTHROPIC_AGENT_MAX_TOKENS=16000        # keep inside AGENT_TIMEOUT
```

This is the default and keeps its original behaviour: adaptive thinking, a prompt-cache breakpoint on the static system prefix, Anthropic-native tool definitions, and no automatic retries inside the SDK (every attempt must re-check the tenant's policy).

### OpenAI

```bash
PQC_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
PQC_LLM_MODEL=gpt-4o-mini           # or OPENAI_AGENT_MODEL / OPENAI_MODEL
```

Requests carry `store: false`, so neither prompt nor completion is retained for training.

### Azure OpenAI

Azure differs in three ways: the model is a **deployment** in the URL, `api-version` is required, and the credential is an `api-key` header.

```bash
PQC_LLM_PROVIDER=azure-openai
PQC_LLM_BASE_URL=https://my-resource.openai.azure.com
PQC_LLM_AZURE_DEPLOYMENT=gpt-4o-mini-prod
PQC_LLM_API_VERSION=2024-10-21
PQC_LLM_API_KEY=...
```

The request URL becomes `{base}/openai/deployments/{deployment}/chat/completions?api-version={version}`. If you paste a full deployment URL into `PQC_LLM_BASE_URL`, the adapter appends only the `api-version`.

### Google Gemini

```bash
PQC_LLM_PROVIDER=gemini
PQC_LLM_API_KEY=...                 # Google AI Studio key
PQC_LLM_MODEL=gemini-2.0-flash
```

The key travels in the `x-goog-api-key` header, never in the URL — a URL reaches logs, proxies and the signed Data Control receipt. Tool schemas are narrowed to the subset Gemini's `functionDeclarations` accepts (`additionalProperties`, `$schema`, `default`, `maxItems`, `minItems` and `examples` are stripped), because Gemini rejects the whole request otherwise.

### Any OpenAI-compatible endpoint

One adapter covers every gateway and self-hosted server that implements `/v1/chat/completions`.

```bash
PQC_LLM_PROVIDER=openai-compatible
PQC_LLM_BASE_URL=<see below>
PQC_LLM_MODEL=<the server's model name>
PQC_LLM_API_KEY=<if the endpoint wants one>
PQC_LLM_TOOLS=1                     # only if the endpoint supports tool calling
PQC_LLM_HEADERS={"HTTP-Referer":"https://your-app.example"}   # gateway routing headers
```

| Target | `PQC_LLM_BASE_URL` |
|---|---|
| Groq | `https://api.groq.com/openai/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Together | `https://api.together.xyz/v1` |
| vLLM | `http://127.0.0.1:8000/v1` |
| LM Studio | `http://127.0.0.1:1234/v1` |
| llama.cpp server | `http://127.0.0.1:8080/v1` |

Naming one of those directly also fills the URL in, so `PQC_LLM_PROVIDER=groq` plus a model is enough; it resolves to this adapter with Groq's base URL. An explicit `PQC_LLM_BASE_URL` always wins, which is what you want in front of a corporate proxy.

A non-HTTPS destination is refused unless it is loopback (`localhost`, `127.0.0.1`, `::1`), and a URL carrying something that looks like a credential in its query string is refused outright.

### Ollama

```bash
PQC_LLM_PROVIDER=ollama
PQC_LLM_BASE_URL=http://127.0.0.1:11434    # the default
PQC_LLM_MODEL=llama3.1
PQC_LLM_TOOLS=1                            # only if the pulled model supports it
```

Ollama's own `/api/chat` is used, not its OpenAI-compatible shim: `options.num_predict` rather than `max_tokens`, `stream: false` sent explicitly (Ollama streams by default), tool arguments as real objects, and newline-delimited JSON for the streaming protocol. If you paste the `/v1` URL by mistake, the adapter strips it.

### The built-in answerer

```bash
PQC_LLM_PROVIDER=builtin
```

Deterministic rules over this workspace's own data — the same engine behind `/assistant/chat`. No request leaves the process. It is a first-class provider, which is what makes "no AI configured" a deliberate mode rather than an error path.

---

## Bring your own model

### Configuration only

For most self-hosted servers and gateways, `openai-compatible` with a base URL is all you need — see above. No code, no restart of anything but the process, and no fork of this repository.

### In code

When your model is not reachable through any of the shapes above — an internal inference service, a message queue, a model with a bespoke auth dance — write an adapter.

```bash
PQC_LLM_PROVIDER=custom
PQC_LLM_CUSTOM_MODULE=my_package.my_provider
```

Copy [`examples/custom_llm_provider.py`](../examples/custom_llm_provider.py) and change the three places it marks. The loader accepts any of:

1. `get_provider(settings)` — a factory returning a provider instance.
2. a class named `Provider`, constructed with the resolved `Settings`.
3. exactly one subclass of `services.llm.base.Provider` **defined in** that module.

The contract is five methods plus a declaration:

```python
capabilities()                                        -> Capabilities
start(system, history, message)                       -> Conversation
complete(conv, tools, *, org_id, purpose, policy_version) -> Completion
add_assistant(conv, completion)                       -> None
add_tool_results(conv, results)                       -> None
```

Subclassing `services.llm.base.Provider` gives you `start()`, `stream()`, `check()`, `describe()` and the data-boundary dispatch for free, so in practice you write `capabilities()` and `complete()`. If you declare `tools=False`, the two conversation methods are never called.

Three rules are not optional:

1. **Send the request through `self._dispatch(payload, invoke, ...)`.** That is the tenant's data boundary: it authorises the call against the organization's Data Control policy, pins the destination and model, minimises the payload, signs a receipt, and scans the response for credential patterns. `payload` must be the canonical OpenAI-shaped `{"model", "messages", ...}` dict — that is what the boundary can read and digest — and `invoke(clean)` translates it to your wire format and performs the single request. Use `services.llm.transport.post_json` so retries, backoff, timeouts, proxy and redirect handling, response-size limits and typed errors behave like every other provider.
2. **Raise `services.llm.base.LLMError(kind, message, remedy=...)` and nothing else.** `kind` decides what happens next. Never let a raw exception out; never put a key, a header value or any part of the prompt in the message.
3. **Tell the truth in `capabilities()`.** If you declare `tools=True` and ignore the tool definitions, the agent waits for tool calls that never come.

**Validation, not tracebacks.** The loader checks the import path is a dotted module name, that the module imports, that it exposes exactly one provider, that the five methods exist and are callable, that `capabilities()` returns a `Capabilities`, and that it names a provider and a model. Every failure is an `LLMError(kind="config")` naming what was wrong and how to fix it. If the module is broken, the assistant answers from the built-in rules with that message attached, rather than returning a 500.

A per-organization override may **not** select `custom`: it names Python this server imports, which is an operator decision, not a tenant's.

---

## Configuration reference and precedence

Highest wins:

1. **`PQC_LLM_DISABLED=1`** → the built-in answerer, always. Checked before the organization is consulted, which is what makes it impossible to override per tenant.
2. **The organization's stored override** (see below).
3. **`PQC_LLM_PROVIDER`** → the operator's choice for the deployment.
4. **Today's behaviour** → `ANTHROPIC_API_KEY` if set, else `OPENAI_API_KEY`, else the built-in answerer.

| Variable | Default | Meaning |
|---|---|---|
| `PQC_LLM_PROVIDER` | unset | `anthropic`, `openai`, `azure-openai`, `gemini`, `openai-compatible`, `ollama`, `builtin`, `custom`. Common aliases (`claude`, `azure`, `google`, `groq`, `openrouter`, `vllm`, `lmstudio`, `off`…) are accepted |
| `PQC_LLM_MODEL` | per provider | Model name |
| `PQC_LLM_BASE_URL` | per provider | API root |
| `PQC_LLM_API_KEY` | unset | Credential. `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `PQC_AI_LOCAL_API_KEY` are still honoured for their providers |
| `PQC_LLM_HEADERS` | unset | Extra headers as JSON (`{"X-Tenant":"acme"}`) or `k=v,k=v`. `Host`, `Content-Type`, `Content-Length`, `Connection`, `Transfer-Encoding` and `Accept-Encoding` are refused, as is any name or value containing CR or LF |
| `PQC_LLM_API_VERSION` | `2024-10-21` (Azure) | Azure `api-version` |
| `PQC_LLM_AZURE_DEPLOYMENT` | falls back to `PQC_LLM_MODEL` | Azure deployment name |
| `PQC_LLM_TEMPERATURE` | `0.1` | Clamped to 0.0–2.0 |
| `PQC_LLM_MAX_TOKENS` | `3000` (`16000` for Anthropic via `ANTHROPIC_AGENT_MAX_TOKENS`) | Clamped to 256–200,000 |
| `PQC_LLM_TIMEOUT` | `60` (`AGENT_TIMEOUT` for Anthropic) | Seconds, clamped to 1–600 |
| `PQC_LLM_RETRIES` | `2` | Clamped to 0–5. Retries `429`, timeouts, connection failures and 5xx with 0.5s/1s/2s backoff; `401`, `403`, `404` and `400` are never retried |
| `PQC_LLM_TOOLS` | adapter's own answer | `1`/`0` override of the tool-calling capability |
| `PQC_LLM_STREAM` | adapter's own answer | `1`/`0` override of the streaming capability |
| `PQC_LLM_WIRE_STREAM` | unset | `1` uses the provider's streaming protocol on the wire. Delivery to the browser stays gated either way |
| `PQC_LLM_CONTEXT_WINDOW` | per provider | Context window to report where the adapter cannot know it |
| `PQC_LLM_PRICE_INPUT_PER_MTOK` | unset | Your input price per million tokens |
| `PQC_LLM_PRICE_OUTPUT_PER_MTOK` | unset | Your output price per million tokens |
| `PQC_LLM_CUSTOM_MODULE` | unset | Dotted import path, with `PQC_LLM_PROVIDER=custom` |
| `PQC_LLM_DISABLED` | unset | `1` forces the built-in answerer for the whole deployment |

---

## Per-organization providers

A customer can run the assistant on their own model and their own key, from **Data Control → 06 / Model provider**, or over the API:

```
GET    /ai-control/provider        # active provider, capability matrix, usage. No credential, ever.
PUT    /ai-control/provider        # set this organization's override (admin)
DELETE /ai-control/provider        # fall back to the deployment's own provider (admin)
POST   /ai-control/provider/test   # one real, receipted call (admin)
```

- The key and any gateway headers are sealed with the deployment's vault key (`PQC_VAULT_MASTER_KEY`). No read path returns the plaintext — `GET` reports `api_key_present` and the *names* of stored headers, nothing more. Submitting an empty `api_key` leaves the stored one in place, so the model can be changed without the secret being handed back out.
- **Tenant isolation** (docs/SECURITY_REVIEW_SUMMARY.md): every statement is scoped by `organization_id`, taken from the verified request context and never from the body; the wildcard organization is refused; on Postgres the row-level-security variable is set for the connection. There is no listing endpoint and no way to name another organization. A customer may only ever read or set their own.
- `custom` is not selectable per organization, and `PQC_LLM_DISABLED` is not a field here.
- An override changes the destination and the model, which invalidates the approved Data Control policy. The next model call is refused with *"Model destination changed; customer reapproval is required"* until an organization admin reviews and approves the policy again. That is deliberate: a customer approves a specific destination, not a category.
- In the Data Control policy the destination for every brought-your-own provider is `byo`, under `approved_external`. The resolved URL and model are pinned into the approved policy exactly as the first-party destinations are.

---

## Turning AI off entirely

```bash
PQC_LLM_DISABLED=1
```

With that set:

- `run_agent_stream` answers from the built-in rules **before** the tenant's policy is consulted, so a customer's approved policy cannot re-enable a model call the operator has disabled.
- `PUT /ai-control/provider` is refused with a 409 naming the variable.
- `scripts/check-integrations.py --only ai` reports it as a configured, deliberate state rather than a missing provider.
- Every answer says so: *"PQC_LLM_DISABLED=1: this deployment makes no external model calls. Answered from built-in rules."*

Separately, and independently, each organization can set its Data Control mode to `off`, which blocks model calls for that tenant only. Both are enforced; neither depends on the other.

---

## What data is sent to a model

This is the whole list, and it is also served at `GET /ai-control/provider` (`data_sent`) and shown on the Data Control page, so the answer in the product and the answer in this file cannot drift.

**Sent:**

- The static PQC Scout system prompt — application text, no customer data.
- The question typed in CipherLens, plus the dashboard counters the console attaches to it: the route name, the organization id, the role, and whole-number totals (assets, repositories, open remediations, readiness percentages, a count of advisories).
- Up to the last few turns of the conversation, as plain text, truncated.
- The JSON result of each read-only tool the model asks for. In practice that is **only** the bounded organization posture summary: the Data Control filter strips every tool except `get_org_posture` from the request, whatever the agent declares.

**Never sent:**

- API keys, tokens, passwords or private keys. A credential pattern anywhere in the request blocks the call **before any network I/O**; the same pattern in a response withholds the response with `request.output_blocked` in the receipt.
- Raw scan payloads, certificates, file contents or source code — unless the organization has separately approved free text for the remediation workflow, which is what code generation requires and which the console labels as such.
- Request bodies, headers, cookies or query values from monitored traffic.
- Images, files or any message block the filter does not recognise: those are rejected rather than stripped.

**With free text withheld** (the default), the question itself never leaves: the model receives only the allowlisted cryptographic metadata summary, and the console says *"Metadata-only AI: your free-text question is withheld."*

**Two leaks fixed while building this layer.** The console's dashboard context used to include the signed-in user's identifier (`actor`) and the full text of every UI advisory. Neither is needed to answer a posture question and both could carry identifiers or server message text into a prompt, so the context now sends the role and an advisory *count*. See `copilotContext()` in `backend/static/index.html`.

Every dispatch is recorded in the organization's signed receipt chain: the pinned destination, the model, an HMAC digest of the exact bytes sent, the size, and whether free text was permitted — but never the prompt or the completion. Export them from **Data Control → 04 / Evidence**.

---

## Behaviour you can rely on

Whatever the provider:

- **Tool calling works where it is supported.** Where it is not, the assistant answers without tools and says so in the response, rather than failing. The `tools` capability is what decides, and it is declared, not guessed.
- **Streaming works where it is supported.** Where it is not, the single response is emitted as one stream of chunks, so the console behaves the same.
- **Timeouts and retries.** Per-request timeout, and retries with 0.5s/1s/2s backoff for rate limits, timeouts, connection failures and 5xx. A bad key, an unknown model or a malformed request is never retried.
- **One typed error.** `LLMError` carries a `kind` (`auth`, `not_found`, `rate_limit`, `timeout`, `connection`, `server`, `bad_request`, `refusal`, `config`, `blocked`), the HTTP status when there was one, and a `remedy`. The message never contains a credential, a header value or any part of the prompt — nor the provider's own error body, which can quote the request back.
- **A provider outage degrades, it does not dead-end.** Any degradable failure falls back to the built-in answerer with a visible note naming the provider and the reason. The one exception is `blocked`: if the tenant's own Data Control policy refused the call, degrading would route around the customer's decision, so that surfaces as an error.
- **A refusal is reported.** A provider that declines a turn produces an explanation and a category, not an empty answer.
- **Usage and cost are recorded per request** where the provider reports them, and **`unknown`** where it does not. Visible to operators on the Data Control page and in `GET /ai-control/provider`.
- **The answer names what produced it.** The `provider` event carries the provider and model that made the call, `/agent/chat` returns it as `answered_by`, and the console prints it under every answer. A built-in answer says so explicitly.

---

## Checking your configuration

```bash
# Configuration only. Names the provider, how it was selected, and what is missing.
python scripts/check-integrations.py --only ai --offline

# Adds one cheap read per provider to prove the credential and the endpoint.
python scripts/check-integrations.py --only ai --check-ai
```

The network check is behind `--check-ai` and `--offline` overrides it, so the self-test never surprises you with an outbound request.

In the console, **Data Control → 06 / Model provider** shows the active provider, its model, whether tools and streaming are available, the resolved destination, the capability table for every shipped adapter, token use so far, and **Send a test prompt** — which makes one real call through the whole path and shows the reply, the model that answered, the usage and the latency, or the typed error and its remedy.

---

## Adding an adapter (contributors)

An adapter is one module in `backend/services/llm/`. Use `openai_shape.py` if your provider speaks `/v1/chat/completions`; otherwise start from `ollama.py`, which is the smallest adapter with its own wire format.

1. **Write the module.** Subclass `Provider` (or `OpenAIShaped`), set `id`, and implement `capabilities()`, `check()`, `complete()`, `add_assistant()` and `add_tool_results()`. Set `privacy_provider = "byo"` unless your provider is one the Data Control policy names directly.
2. **Build the canonical payload before dispatch, translate inside it.** `_dispatch` hands the data boundary an OpenAI-shaped dict so it can minimise and digest the real text; the `invoke(clean)` callback turns that into your wire format. `gemini.py` and `ollama.py` both do this and are the pattern to copy.
3. **Go through `transport`.** `post_json` and `post_lines` are the only functions in this package that open a socket, which is what lets the test suite mock exactly one seam and guarantees no test reaches a network.
4. **Register it** in `registry.ADAPTERS` and add its name (plus any aliases) to `config.PROVIDER_IDS` / `config.ALIASES`.
5. **Add the fixtures.** `backend/test_llm_providers.py` is parameterised over every adapter: add a recorded request/response pair and your adapter inherits the whole suite — request shape, response parsing, the tool-call round trip, stream assembly, the capability matrix, error classification, retry and backoff, and the assertion that no prompt contains a secret. Fixtures are hand-written from the provider's published API shape; **do not record a real response containing real data**.
6. **Document it** in the table at the top of this file, in `docs/OPERATOR_CONSOLE_GUIDE.md`, and in `.env.prod.example`.
7. **Teach `scripts/check-integrations.py`** how to probe it, in `_AI_KEY_VARS` and `_ai_reachability_probe`.

Two things reviewers will look for: that `capabilities()` is honest (an adapter that claims tools it does not implement breaks the agent silently), and that no error message, log line or `describe()` output can contain a credential — `Settings.redacted()` exists for exactly that reason and is the only shape any surface outside the package should see.
