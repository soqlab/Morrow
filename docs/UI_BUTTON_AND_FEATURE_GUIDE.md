# Morrow UI Button and Feature Guide

This guide explains the visible UI controls in Morrow: what each button means, when to use it, what it sends to the backend, and what result to expect.

Use this document when demoing the product, onboarding an operator, or explaining the workflow to a customer.

## Enterprise pages and admin routes

### Public launch page

URL: `/launch`

Use this for buyer-facing positioning. It explains the product claim, the live evidence routing
fabric, Quantum Airlock, Trust Passport, and the controlled pilot shape.

### Enterprise Admin overview

URL: `/enterprise-admin`

Use this to explain the admin layer to an enterprise buyer or internal operator. It is not the live
operations console. It describes customer lifecycle, go-live gates, tenant isolation, Airlock
evidence, incidents, and audit packages.

### Vendor Admin portal

URL: `/vendor-admin/`

Use this for real vendor operations. It requires the platform admin key and should not be linked
from the customer console as a normal customer feature.

### Traffic Monitor

URL: `/vendor-admin/traffic.html`

Use this for platform-admin-only IP and request monitoring. It calls `/platform/traffic/summary`
and `/platform/traffic/events` with `x-platform-key`. It shows source IP, request path, method,
status code, latency, organization id, actor role, blocked requests, rate limits, errors, and slow
routes. It intentionally does not store request bodies, query strings, cookies, authorization
headers, or uploaded files.

The export buttons call `/platform/traffic/export.ndjson` and `/platform/traffic/otel` for SIEM and
OpenTelemetry ingestion. Destructive actions such as clearing the buffer require an `owner` or
`operator` platform admin role; `support` and `auditor` are read-only.

Production note: set `PQC_TRUST_PROXY_HEADERS=1` only behind a trusted reverse proxy. Otherwise the
monitor uses the direct client IP from the ASGI server.

### Guide & Tutorial

Location: customer console sidebar.

Use this as the in-product operator manual. It now includes the Enterprise-ready launch path,
Quantum Airlock, Trust Passport, Enterprise Admin page, and production go-live gates.

### Automated cryptographic agility middleware / CAM

Location: Overview -> Strategic capability layer -> `Build CAM`.

What it does:

- calls `POST /crypto-mesh/middleware-plan`
- generates a transparent CAM/API package with Envoy ingress gateway, egress sidecar, Linux
  `iptables` capture, rollback scripts, telemetry proof, Docker Compose, and Kubernetes manifests
- keeps payload inspection disabled and submits only runtime handshake proof

What it does not do automatically:

- it does not intercept a customer's network until they deploy the gateway or sidecar
- it does not remove the need for destination CIDRs, DNS/LB routing, certificates, and rollback
  approval
- it does not fix application-layer crypto inside request bodies

### Autonomous predictive security mesh

Location: Overview -> Strategic capability layer -> `Open mesh`.

What it does:

- calls `GET /autonomous-mesh/capability-truth`
- shows the truth status for the advanced modules: eBPF discovery, entropy hunting, multi-hop contagion, dynamic
  Q-Day, multi-variant PRs, canary traffic shifting, HSM/KMS drift enforcement, crypto-anomaly
  SIEM/XDR feeds, continuous compliance proof, and insurance proof-of-agility
- points operators to API Explorer for the runnable package-generation and simulation endpoints

What it does not do automatically:

- it does not install kernel probes or HSM collectors on customer systems
- it does not shift production traffic until a customer-approved provider integration supplies
  credentials and change approval
- it does not claim formal ZK-SNARK compliance proofs; current proofs are hash commitments
- it does not use sample/default graph or upstream values for production risk claims
- it does not hard-code cloud KMS/HSM support or inspect packet payloads

## 1. Login and actor controls

### Clear Token

Use this when the browser has an old or expired login token.

What it does:

- removes the saved bearer token from browser local storage
- clears the current hosted-auth session token used by API calls
- helps recover from `jwt token is expired` or unauthorized UI state

When to use it:

- hosted login stops working
- you changed users
- an old Auth0 token is still stored in the browser

### Login

Use this to start the hosted identity-provider login flow.

What it does:

- opens the configured login URL from `/auth/config`
- authenticates the user through the configured provider, such as Auth0
- returns the browser to `/ui/` with a token

Who can use it:

- any hosted user with a configured account

### Logout

Use this to leave the hosted session.

What it does:

- opens the configured logout URL
- returns the browser to the app after logout when configured
- does not delete application data

### Viewer Demo

Use this in local development mode to act as a read-only user.

What it does:

- sets local header-style identity to role `viewer`
- lets you view dashboards, scans, assets, reports, and remediations
- blocks write actions such as scan creation, approval, validation, and credential management

Important:

- this is intended for local/header auth mode, not hosted JWT mode

### Operator Demo

Use this in local development mode to act as an operator.

What it does:

- sets local header-style identity to role `operator`
- allows normal daily workflow actions such as scanning, asset classification, remediation review, validation, and PR creation

### Admin Demo

Use this in local development mode to act as an administrator.

What it does:

- sets local header-style identity to role `admin`
- allows credential management, organization setup, synthetic scan workflows, and admin-only operations

## 2. Top navigation buttons

### Load last scan

Use this to reload the most recent scan remembered by the browser.

What it does:

- reads the last scan ID from browser local storage
- calls the scan result endpoint for that scan
- repopulates the result table, migration plan, baseline controls, and related dashboard state

When to use it:

- after refreshing the page
- when returning to a previous scan without running a new one

### JSON

Use this to inspect the raw data returned by the latest scan.

What it does:

- opens a modal with the current scan result JSON
- shows fields that may not be visible in the compact UI

When to use it:

- debugging
- checking exact API payloads
- copying evidence for engineering review

### Plan

Use this to view the migration plan for the selected scan.

What it does:

- calls `/scans/{scan_id}/migration-plan`
- shows ordered remediation guidance based on findings
- groups risk into actionable migration steps

When to use it:

- after a scan has findings
- when explaining what the security team should fix first

### Export CSV

Use this to download scan results as a spreadsheet-friendly file.

What it does:

- calls `/scans/{scan_id}/export.csv`
- exports the selected scan results

When to use it:

- sharing scan evidence with auditors
- offline analysis
- importing results into another reporting tool

### Dashboard

Use this to open the organization dashboard.

What it does:

- loads compliance summary data
- loads ROI metrics and drift analytics
- shows scan overview and trends when a scan is selected
- shows CI/CD enforcement gate controls

When to use it:

- first screen in demos
- daily operating review
- compliance posture summary

### Collections

Use this to manage reusable scan target groups.

What it does:

- opens the collections modal
- lets users save, load, scan, and delete groups of targets

Example:

- `Production APIs`
- `Patient Platform External`
- `Cloudflare Demo`

### Schedules

Use this to manage recurring scans.

What it does:

- opens the schedules modal
- lets users create schedules from collections
- lets users run, enable, disable, and delete schedules

When to use it:

- continuous monitoring
- daily or weekly scans
- demoing recurring security checks

### Policies

Use this to inspect the current active policy view.

What it does:

- opens the policies modal
- calls `/policies/active`
- shows the active default policy profile, source, scanner checks, remediation rules, validation rules, CI gate behavior, and drift policy

Important:

- this is a read-only policy explanation view
- it is not yet a full policy authoring screen
- if this button returns `404`, the backend version is older than the UI and needs the `/policies/active` endpoint deployed

### Integrations

Use this to manage outbound notifications, event rules, Cloudflare settings, and webhook delivery state.

What it does:

- opens the integrations modal
- lets admins/operators configure webhooks and event routing
- shows delivery history and retry controls
- includes Cloudflare connector controls

### Remediations

Use this to manage code-fix workflows.

What it does:

- opens the remediations modal
- lets operators create suggestions, approve/reject, validate, create PRs, mark merged, and check drift

When to use it:

- after an asset is linked to a repository
- when turning a finding into a code change

### Audit Logs

Use this to inspect governance events.

What it does:

- opens the audit log modal
- lists recent allowed/denied actions and sensitive workflow events

When to use it:

- compliance review
- troubleshooting access failures
- proving who approved or triggered an action

### Fix Next

Use this to open the prioritized remediation queue for the current scan.

What it does:

- calls `/fix-next`
- ranks assets by severity and business metadata
- shows what should be fixed first

When to use it:

- after a scan completes
- when triaging many findings

## 3. Code-to-cloud sync controls

### Connect + Sync Repos

Use this when a customer gives you a GitHub token for a demo or first setup.

Required input:

- GitHub token

Optional inputs:

- credential name
- GitHub organization or user
- visibility: `all`, `private`, or `public`

What it does:

- verifies the token with GitHub before saving it
- stores the token as an encrypted org-scoped Vault credential
- syncs repositories visible to that token
- fills the resulting `credential_id` into the advanced sync and remediation credential fields

Why it matters:

- this is the simplest connection path for a live presentation
- the customer only needs to grant a fine-grained token or install access
- after sync, assets can be linked to repositories and remediations can create validated PRs

What it does not do:

- it does not reveal the token after saving
- it does not modify repositories during sync
- it does not create a pull request until a remediation is approved, validated, and explicitly sent to PR creation

### Clear Token Field

Use this after pasting or connecting a GitHub token.

What it does:

- clears the token input box in the browser
- leaves the encrypted Vault credential unchanged

Why it matters:

- the token should not stay visible in the UI after connection

### Sync GitHub Repos

Use this after creating a GitHub credential in the vault.

Required inputs:

- `GitHub credential_id`
- optional GitHub organization name

What it does:

- calls the GitHub sync endpoint
- fetches repositories visible to the credential
- stores repository names and URLs in the platform database

Why it matters:

- remediations need repositories before they can fetch files or create PRs
- asset-to-repo correlation needs synced repository records

What it does not do:

- it does not scan code for vulnerabilities by itself
- it does not create PRs
- it does not change customer repositories

### Correlate Assets->Repos

Use this after GitHub repositories are synced and assets exist.

Required input:

- `GitHub credential_id`

What it does:

- searches synced repository content for asset hints such as hostnames
- attempts to link assets to the repository that likely owns them
- updates asset `repository_id` when a match is found

Why it matters:

- security findings often fail because nobody knows which code repository owns the fix
- this button creates the bridge from external endpoint to code ownership

Important limitation:

- correlation is heuristic; if it does not find a match, set the repository manually on the asset

## 4. Scan controls

### Start scan

Use this to scan the targets in the target input box.

Required input:

- one or more targets such as `www.cloudflare.com:443`

What it does:

- creates a durable scan job
- queues background work through Celery
- polls job status until results are ready
- stores scan results and per-asset scan history

What it checks:

- TLS posture
- certificate details
- chain confidence
- legacy TLS support
- weak cipher posture
- PQC-readiness signals

### Set Baseline

Use this to save the current scan as the comparison baseline.

What it does:

- records the selected scan as the baseline for assets in that scan
- enables future diff comparisons

When to use it:

- after a known-good scan
- before a migration project
- before changing TLS infrastructure

### Diff vs Baseline

Use this to compare the current scan against the saved baseline.

What it does:

- identifies new findings, resolved findings, and unchanged findings
- marks regressions and improvements
- fills the diff panel

When to use it:

- after a later scan
- to prove risk improved
- to detect regression after a deployment

## 5. Diff panel controls

### All

Shows all diff results: regressions, improvements, unchanged findings, and neutral changes.

### Regressions

Shows only items that became worse compared with the baseline.

Use it for:

- incident review
- release gate review
- identifying newly introduced risk

### Improvements

Shows only items that improved compared with the baseline.

Use it for:

- reporting progress
- showing remediation impact

### Clear

Clears the diff panel and removes diff highlighting from the current view.

## 6. Collections modal buttons

### Refresh

Reloads the collection list from the backend.

Use it after:

- creating a collection
- deleting a collection
- another user changes collections

### Load

Loads the selected collection into the collection form.

What it does:

- fills collection name and targets text
- lets you edit or reuse the selected collection

### Delete

Deletes the selected collection.

What it does:

- removes the collection record for the active organization
- does not delete scan history or assets

### Save

Creates or updates a collection.

Required inputs:

- collection name
- targets text

What it does:

- stores a reusable group of scan targets

### Apply to targets

Copies the selected collection targets into the main scan input box.

What it does:

- does not start a scan
- only prepares the target list

### Scan

Starts a scan from the selected collection.

What it does:

- calls the collection scan endpoint
- creates a scan job using targets saved in the collection

## 7. Schedules modal buttons

### Create

Creates a recurring scan schedule.

Required inputs:

- collection ID
- interval in minutes
- enabled/disabled state

What it does:

- saves a schedule that Celery beat can run
- calculates next run time

### Refresh

Reloads the schedule list from the backend.

### Run now

Immediately runs the selected schedule.

What it does:

- starts a scan for the schedule's collection immediately
- does not wait for the next scheduled interval

### Enable / Disable

Turns a schedule on or off.

What it does:

- enabled schedules can run automatically
- disabled schedules remain saved but do not run automatically

### Delete

Deletes the selected schedule.

What it does:

- removes the schedule record
- does not delete its collection, scan results, or assets

## 8. Asset editor buttons

### Load

Loads an asset record into the editor.

Required input:

- asset key, usually `hostname:port`

What it does:

- fetches asset metadata
- auto-creates a blank asset record if missing
- fills owner, team, environment, criticality, tags, notes, and repository fields

### History

Shows scan history for the selected asset.

What it does:

- fetches previous scan snapshots for that asset
- shows risk and posture changes over time

### Save

Saves asset metadata.

Fields saved:

- owner
- team
- environment
- criticality
- confidentiality lifetime
- tags
- notes
- repository ID

Why it matters:

- this turns raw scan data into owned operational work
- repository ID enables remediation workflows

## 9. Remediations modal buttons

### Suggest Fix

Creates an AI-assisted remediation suggestion.

Required inputs:

- asset key
- repository ID or selected repository
- file path
- vulnerability description
- GitHub credential ID

What it does:

- fetches the current file from GitHub
- sends context to the AI provider
- receives a proposed patch or replacement file
- applies guardrails
- stores original and suggested content in a remediation record

What it does not do:

- it does not directly change GitHub
- it does not create a PR
- it does not bypass human review

### Refresh

Reloads the remediation list.

Use it after:

- creating a suggestion
- approval/rejection
- validation
- PR creation
- drift checks

### Load

Loads the selected remediation details.

What it shows:

- status
- asset
- repository
- file path
- original content
- suggested content
- validation history
- PR URL
- drift state

### Validate

Runs the validation sandbox for the selected remediation.

Required input:

- GitHub credential ID

What it does:

- downloads a temporary copy of the repository
- writes the suggested file into the temporary workspace
- runs Terraform or generic validation
- runs general IaC security policy checks where applicable
- stores stdout, stderr, exit code, command list, sandbox mode, IaC findings, and validation status

What you can see after it runs:

- Validation decision: whether PR creation is allowed or blocked
- Validation details JSON: repository, file path, git ref, validator, commands, sandbox mode, IaC policy result, and validation environment
- Validation stdout: normal validator output
- Validation stderr: errors and failure reasons
- Recent validation jobs: previous sandbox runs for the remediation

Why it matters:

- PR creation is normally blocked until validation passes
- the details panel is the evidence trail for what the sandbox actually did

### Drift Check

Checks whether the merged fix has changed later.

Required input:

- GitHub credential ID

What it does:

- fetches the current file from GitHub
- compares it with the expected fixed content
- marks drift as `clean`, `drifted`, or `check_failed`
- can create a drift follow-up remediation

### Revalidate Drift

Runs validation again for a drift follow-up workflow.

Use it when:

- drift was detected
- a follow-up remediation needs to be checked before another PR

### Acknowledge Drift

Marks drift as reviewed or temporarily accepted.

What it does:

- records acknowledgement metadata
- keeps an audit trail

Important:

- acknowledging drift does not necessarily fix the underlying issue

### Approve

Approves the selected remediation suggestion.

What it does:

- changes the remediation status to approved
- records review note/context
- allows validation and PR creation to proceed

### Reject

Rejects the selected remediation suggestion.

What it does:

- marks the suggestion as rejected
- prevents it from moving through the normal PR path

Use it when:

- the AI suggestion is wrong
- the file path is wrong
- the fix needs a different design

### Create PR

Creates a GitHub pull request for the selected remediation.

Required conditions:

- remediation is approved
- latest validation passed, unless admin override is allowed
- GitHub credential has write/PR permissions

What it does:

- creates a branch
- writes the suggested content to the selected file
- commits the change
- opens a GitHub PR
- stores PR URL and branch metadata

### Mark Merged

Manually marks a remediation PR as merged.

What it does:

- updates remediation merge state
- records merge timestamp

When to use it:

- webhook delivery is not configured
- demoing the lifecycle manually
- GitHub webhook failed and an operator needs to correct state

Preferred production path:

- GitHub webhook should mark merged automatically

## 10. Audit log modal buttons

### Refresh

Reloads recent audit records.

What it does:

- fetches audit logs for the active organization
- shows actor, role, action, decision, resource, reason, and timestamp

### Close

Closes the audit modal.

## 11. Fix Next panel buttons

### Refresh

Reloads the prioritized fix list.

What it does:

- calls `/fix-next` for the current scan
- recalculates ranking based on findings and asset metadata

### Close

Closes the Fix Next panel.

## 12. Dashboard buttons

### Refresh

Reloads dashboard data.

What it does:

- reloads compliance report
- reloads ROI metrics
- reloads drift analytics
- reloads scan overview where applicable

### Save view

Saves the current dashboard filters in browser local storage.

What it does:

- stores filter choices locally for reuse
- does not change backend data

### Load

Loads a saved dashboard view from browser local storage.

### Delete

Deletes a saved dashboard view from browser local storage.

### Check gate

Runs the CI/CD enforcement gate decision.

What it does:

- calls the status-check endpoint
- returns pass/fail based on repository policy state
- mirrors the same decision a GitHub/GitLab status check would use

Use it to explain:

- how Morrow moves from advisor mode to blocking mode
- whether a repository is currently safe to merge

### Load trend

Loads trend metrics for the selected grouping and time window.

What it does:

- calls `/metrics/trends`
- shows changes over time by owner, team, environment, or criticality

## 13. Integrations modal buttons

### Refresh

Reloads all integration panels.

What it refreshes:

- outbound webhooks
- webhook delivery events
- integration settings
- event rules
- Cloudflare connector status

### Close

Closes the integrations modal.

## 14. Outbound webhook buttons

### Save

Creates or updates an outbound webhook.

Inputs:

- name
- URL
- secret or credential ID
- events list
- enabled state

What it does:

- stores a destination for event notifications
- signs deliveries when a secret is configured

Examples of events:

- `validation.failed`
- `remediation.merged`
- `remediation.drifted`
- `remediation.drift_followup_created`

### Edit

Loads an existing webhook into the form.

What it does:

- does not change data until Save is clicked

### Delete

Deletes the selected webhook destination.

What it does:

- stops future deliveries to that destination
- does not delete old audit logs

## 15. Integration settings buttons

### Save

Saves general integration settings.

Examples:

- certificate expiring-soon threshold
- suppressed event recording behavior
- Cloudflare credential ID

## 16. Cloudflare buttons

### Refresh

Reloads Cloudflare connector status, verification state, zones, policy, enforcement, and audit state.

### Verify token

Checks whether the configured Cloudflare token is valid.

What it does:

- calls Cloudflare token verification through the backend
- reports whether the token works

### Save enforcement

Saves whether Cloudflare policy enforcement is enabled.

Important:

- enforcement controls whether policy changes may be applied, depending on backend configuration

### Clear audit

Clears stored Cloudflare apply audit state.

Use it when:

- resetting demo state
- removing stale Cloudflare apply result details

### Dry-run

Runs a mock Cloudflare policy application.

What it does:

- evaluates desired settings without changing a real Cloudflare zone
- useful for demos and safe testing

## 17. Event rule buttons

### Clear

Clears the event rule form.

### Save Rule

Creates or updates an event routing rule.

Inputs can include:

- rule name
- enabled state
- selected webhooks
- event types
- severity filters
- rule IDs
- environments
- teams
- criticalities
- tags
- cooldown minutes
- quantum score minimum

What it does:

- controls which events are sent to which webhook destinations

### Edit

Loads an existing rule into the form.

### Delete

Deletes the selected event rule.

### Test rules on last scan

Tests event rules against events derived from the latest scan.

What it does:

- previews which rules would fire
- helps debug notification routing before relying on it in production

## 18. Webhook delivery buttons

### Clear

Clears local delivery filters in the UI.

What it does:

- does not delete backend delivery records

### Retry failed now

Retries failed or pending webhook deliveries.

What it does:

- calls the webhook retry endpoint
- attempts delivery again according to backend retry rules

Use it when:

- a webhook endpoint was temporarily down
- DNS or network issue has been fixed
- you want to force a retry instead of waiting

## 19. Close buttons and backdrop clicks

Most modals include `Close` buttons and also close when clicking outside the modal box.

What they do:

- close the current modal
- do not change backend data
- do not cancel already queued background jobs

## 20. Recommended first demo sequence

Use this sequence when showing the product end to end:

1. `Dashboard` - show current posture
2. `Start scan` - scan a real endpoint
3. asset `Load` and `Save` - add ownership metadata
4. `Collections` then `Save` - create a reusable target group
5. `Schedules` then `Create` - enable continuous scanning
6. `Sync GitHub Repos` - import code repositories
7. `Correlate Assets->Repos` - link endpoint to code owner
8. `Remediations` then `Suggest Fix` - create a proposed fix
9. `Approve` then `Validate` - review and sandbox-check the fix
10. `Create PR` - move the fix into GitHub
11. `Mark Merged` or GitHub webhook - track merge
12. `Drift Check` - prove Day 2 governance
13. `Dashboard` - show ROI, verified closure, and drift analytics

## 21. Where data goes when buttons are clicked

Most buttons call the backend API. The backend stores durable product state in Postgres and queues background work through Redis/Celery.

Stored in Postgres:

- organizations
- repositories
- assets
- scan results
- collections
- schedules
- remediations
- validation jobs
- webhooks
- event rules
- webhook delivery records
- audit logs

Stored in browser local storage:

- API base URL
- bearer token
- demo actor context in local mode
- last scan ID
- saved dashboard views

Stored in GitHub only after PR creation:

- remediation branch
- committed file change
- pull request

## 22. Safety model

Buttons that only read data:

- Dashboard
- JSON
- Plan
- Export CSV
- Load last scan
- Refresh buttons
- Load buttons
- History
- Fix Next
- Audit Logs

Buttons that create or modify product data:

- Start scan
- Set Baseline
- Save collection
- Delete collection
- Create schedule
- Enable/Disable schedule
- Delete schedule
- Save asset
- Suggest Fix
- Approve
- Reject
- Validate
- Drift Check
- Acknowledge Drift
- Save webhook
- Save Rule
- Retry failed now

Buttons that can affect external systems:

- Sync GitHub Repos: reads GitHub repository metadata
- Correlate Assets->Repos: reads GitHub repository content for matching
- Create PR: writes a branch, commit, and pull request in GitHub
- Verify token: checks Cloudflare token validity
- Cloudflare enforcement/apply paths: can affect Cloudflare if real apply mode is enabled
- Webhook retry: sends HTTP requests to configured webhook destinations


