# Quantum Readiness Platform Q&A

This document explains the platform in plain language for investors, buyers, operators, and non-technical stakeholders.

It focuses on the problem, why it matters, what the platform does, and what it does not claim.

---

## 1. What problem does this platform solve?

The platform helps enterprises manage the transition from today's public-key cryptography to post-quantum readiness.

Most companies do not have a clean answer to these questions:

- where are we using quantum-vulnerable cryptography?
- which websites, APIs, and portals protect long-lived sensitive data?
- who owns each system?
- which repository or infrastructure configuration controls the fix?
- what can we improve today?
- what is blocked by cloud/CDN/browser/certificate authority support?
- did the migration change pass validation?
- did the public endpoint actually improve after deployment?
- did someone later undo the safer configuration?
- can we prove progress to auditors, customers, or leadership?

The platform turns that problem into a managed workflow:

1. discover public crypto exposure
2. assess quantum relevance
3. assign ownership
4. create a migration path
5. validate supported changes
6. open normal engineering pull requests
7. verify externally after deployment
8. monitor drift
9. produce evidence

---

## 2. Is this just another vulnerability scanner?

No.

A normal scanner usually stops at:

> Here is a problem.

This platform tries to continue the loop:

> Here is the affected asset, the quantum relevance, the owner, the migration stage, the blocker, the repository path, the suggested change, the validation result, the pull request, the verification result, and the drift history.

The value is not only detection.

The value is operational control over the migration.

---

## 3. Why does quantum matter if quantum computers are not breaking websites today?

The immediate pain is not that every website is being broken by a quantum computer today.

The immediate pain is that large enterprises are facing a multi-year cryptographic migration that they cannot easily inventory, assign, execute, or prove.

Current public-key cryptography such as RSA and elliptic-curve cryptography is expected to be vulnerable to future cryptographically relevant quantum computers.

Enterprises need to prepare before the deadline arrives because migration is slow and distributed across:

- public websites
- APIs
- login portals
- CDNs
- load balancers
- certificates
- cloud providers
- Kubernetes ingress
- Terraform
- platform teams
- application teams
- security teams

The hard part is not only cryptography.

The hard part is coordination.

---

## 4. What is "harvest now, decrypt later"?

Harvest-now/decrypt-later means an attacker may capture encrypted traffic today and store it.

If the data remains valuable for many years, and future quantum computers become capable of breaking the cryptography that protected it, the attacker may decrypt that data later.

This is not equally important for every website.

Low concern examples:

- public marketing pages
- public product pages
- short-lived non-sensitive data

High concern examples:

- healthcare records
- banking data
- identity information
- legal documents
- government information
- defense data
- enterprise secrets
- trade secrets
- any data that remains sensitive for 5, 10, or 20 years

The platform helps identify which systems may have that kind of long-lived exposure.

---

## 5. Does the platform prove that a quantum computer can break this website today?

No.

That would not be a credible claim.

The platform does not say:

> A quantum computer is breaking this website today.

It says:

> This public system depends on cryptography that may be vulnerable to future quantum computers, and the organization needs a migration plan.

That distinction matters.

The platform is about readiness, migration, and proof.

---

## 6. Does the platform make every website quantum-proof today?

No.

No responsible platform should claim that.

Full quantum-safe deployment depends on the wider ecosystem:

- browser support
- certificate authority support
- CDN support
- load balancer support
- cloud provider support
- server software support
- client compatibility
- standards and compliance requirements

The platform cannot force every provider and browser to support full post-quantum TLS immediately.

What it can do is:

- detect current RSA/ECC dependency
- identify harvest-now/decrypt-later relevance
- show what can be fixed now
- track provider blockers
- prepare crypto-agility
- validate supported changes
- prove progress
- monitor drift

The credible claim is:

> We help enterprises move internet-facing systems toward quantum-safe readiness and prove migration progress.

---

## 7. If companies already build secure websites, where is this platform useful?

A company can build a secure website today and still have quantum migration risk.

That is because most secure websites today still depend on classical public-key cryptography such as:

- RSA
- ECDSA
- ECDH
- traditional TLS certificates
- traditional TLS handshakes
- traditional signing and key exchange

That is normal. It does not mean the website was built badly.

The issue is not:

> This website is insecure against normal attackers today.

The issue is:

> This system depends on cryptography that must be inventoried, migrated, monitored, and proven ready before the post-quantum transition becomes urgent.

For example, a hospital patient portal may look perfectly healthy:

- HTTPS works
- the certificate is valid
- login is secure
- the app has no obvious bug

But the enterprise may still not know:

- which public endpoints depend on RSA or elliptic-curve cryptography
- which portals protect data that remains sensitive for 10+ years
- which CDN, load balancer, certificate, or repo controls the crypto posture
- which team owns the migration
- which fixes are possible today
- which items are blocked by cloud/CDN/browser/provider support
- whether a fix was validated
- whether the endpoint actually improved after deployment
- whether someone later changed the config back

That is where the platform is useful.

The platform is not saying:

> Your website is broken.

It is saying:

> Your enterprise needs a controlled migration path from today's classical crypto posture toward quantum-safe readiness.

---

## 8. What if a company already uses modern crypto?

Then the platform still has value.

The result may be:

> This system is currently in good shape.

But the platform can still provide:

- evidence that the public TLS posture is modern
- proof that the asset is classified
- owner and team accountability
- repository linkage
- provider support status
- policy decision history
- continuous monitoring
- drift detection if someone weakens the configuration later

This matters for:

- audits
- cyber insurance
- customer security reviews
- compliance evidence
- internal governance
- board-level migration reporting

In that case, the product does not create panic. It creates proof.

---

## 9. What exactly are we proving in a demo?

The demo should prove that quantum migration is an enterprise coordination problem, not a single scanner result.

The demo should show:

1. Discovery
   - the platform scans public portals and APIs

2. Ownership
   - each asset is assigned to an owner, team, environment, and criticality

3. Migration roadmap
   - the platform shows what can be fixed now and what is blocked by provider support

4. Code connection
   - the platform links public systems to the repositories or infrastructure files that control the crypto posture

5. Remediation workflow
   - the platform can create migration candidates, validate changes, and open pull requests when repository access is available

6. Evidence
   - the platform tracks validation, verified closure, drift, audit logs, and machine-readable proof

The simple investor explanation is:

> Quantum migration is not one code change. It is an enterprise coordination problem. Companies have thousands of websites, APIs, certificates, load balancers, backups, and repositories. They need to know what depends on vulnerable classical crypto, who owns it, what can be fixed now, what is blocked by provider support, and they need proof that the fixes happened and stayed fixed. This platform provides that control plane.

---

## 10. Does it help secure data moving over the internet?

Yes, but in a specific way.

The platform helps secure data in transit by improving and governing the cryptography used by the public website or API.

It does not sit inside the network and encrypt traffic itself like a VPN, proxy, or TLS library.

Instead:

- the website/API uses HTTPS/TLS to protect traffic
- the platform checks whether that TLS/crypto setup is strong, modern, owned, and quantum-ready
- the platform helps the company fix weak or non-agile configurations in the systems that control TLS

So if data is moving between:

```text
customer browser -> company website/API
```

the platform helps by checking and improving the public encryption layer protecting that traffic.

It can help identify and drive fixes for:

- old TLS versions
- weak ciphers
- missing TLS 1.3
- certificate problems
- RSA/ECC classical crypto dependency
- lack of crypto-agility
- provider blockers for hybrid/post-quantum TLS
- unmanaged TLS/certificate policy
- drift when someone weakens the configuration later

The simplest explanation:

> The platform does not carry customer traffic. It governs the cryptography that protects customer traffic.

---

## 11. What does the platform do step by step?

### Step 1: Discover

The platform scans a public website or API.

Example:

```text
www.bank.com:443
```

It checks:

- certificate type
- key algorithm, such as RSA or ECC
- TLS versions
- TLS 1.3 support
- cipher posture
- certificate chain health
- provider clues, such as Cloudflare, AWS, GCP, Azure, or customer-managed TLS

### Step 2: Assess quantum relevance

It translates technical facts into business-oriented quantum readiness signals:

- harvest-now/decrypt-later risk
- classical crypto dependency
- crypto-agility score
- provider support status
- blocker status
- immediate hardening actions
- post-quantum migration actions

### Step 3: Add business context

The company classifies the asset:

- owner
- team
- environment
- criticality
- confidentiality lifetime
- tags

Example:

```text
owner: digital-banking
team: platform
environment: prod
criticality: high
confidentiality lifetime: 10y+
```

This matters because quantum urgency depends heavily on how long the data remains sensitive.

### Step 4: Build the migration plan

The platform creates a staged migration path:

1. inventory public cryptography
2. classify data sensitivity
3. prepare crypto agility
4. check hybrid/post-quantum provider support
5. create a validated migration pull request
6. verify externally and monitor drift

### Step 5: Separate "fix now" from "blocked later"

Some actions can usually happen now:

- enable TLS 1.3
- remove weak ciphers
- fix certificate chain issues
- automate certificate rotation
- move TLS policy into infrastructure-as-code
- assign ownership
- prepare repositories for crypto agility

Some actions may be blocked:

- provider does not support required hybrid/post-quantum controls yet
- CDN support is incomplete
- cloud load balancer support is incomplete
- certificate authority support is not ready
- browser/client compatibility is not ready
- owning repository is unknown

The platform records both.

### Step 6: Link to the repository

When GitHub is connected, the platform can link the public asset to the code or infrastructure repository that controls the fix.

Example:

```text
asset: www.bank.com:443
repo: bank/platform-infra
file: prod/load-balancer.tf
```

This solves a common enterprise failure:

> Security finds the issue, but nobody knows where the fix lives.

### Step 7: Suggest a remediation

The platform can suggest a code/configuration change.

Examples:

- Terraform TLS policy update
- Cloudflare policy update
- Nginx configuration update
- Envoy configuration update
- Kubernetes ingress change
- certificate rotation workflow
- crypto-agility variable/configuration change

### Step 8: Validate safely

Before a pull request is opened, the platform validates the proposed change in a temporary workspace.

It captures:

- validation status
- stdout
- stderr
- exit code
- policy checks
- sandbox details

This reduces the risk of sending a bad infrastructure change to engineering.

### Step 9: Create a pull request

If validation passes, the platform opens a normal GitHub pull request.

Engineers still review and merge through their existing workflow.

The platform does not bypass engineering controls.

### Step 10: Verify after deployment

After a fix is merged and deployed, the platform scans again.

It checks whether the public endpoint actually improved.

This matters because:

> A merged pull request is not proof. External verification is proof.

### Step 11: Monitor drift

If someone later changes the configuration and weakens the crypto posture again, the platform detects drift.

This makes the product useful after the first migration wave.

### Step 12: Produce evidence

The platform produces evidence for:

- security leaders
- auditors
- regulators
- customers
- board reporting
- compliance teams

Evidence includes:

- scanned asset
- quantum relevance
- owner/team
- migration stage
- blocker
- validation result
- PR status
- verified closure
- drift state
- audit trail

---

## 12. What problem does the Quantum Migration page solve?

The Quantum Migration page is the portfolio view.

It helps answer:

- which assets have quantum scan data?
- which assets have high harvest-now/decrypt-later risk?
- which assets have actionable migration paths?
- which assets are blocked?
- which provider is involved?
- what is the crypto-agility score?
- which migration stage is each asset in?
- what is the next action?

This gives leaders a program view, not just a scan result.

---

## 13. Can an enterprise upload a whole list of systems at once?

Yes.

The platform supports bulk enterprise onboarding.

An operator can paste a list such as:

```text
portal.company.com:443
api.company.com:443
login.company.com:443
payments.company.com:443
admin.company.com:443
```

The platform can then:

- create asset records for all systems
- apply default owner/team/environment/criticality/confidentiality context
- save the list as a collection
- start one bulk scan
- optionally connect a GitHub token
- sync repositories
- attempt hostname-to-repository correlation
- build the Quantum Migration portfolio

This is the enterprise flow.

The company does not need to onboard one website at a time.

Important reality:

The platform can automatically correlate systems to repositories only when enough signals exist, such as hostnames appearing in code, infrastructure configuration, Terraform files, DNS/CDN records, or cloud metadata.

If a mapping is uncertain, the platform marks it for human confirmation instead of pretending it knows.

Investor explanation:

> Enterprises can bring their whole public surface. The platform scans it, builds a quantum migration inventory, correlates systems to owners and repos where possible, flags unknowns for review, and turns the inventory into validated migration work.

---

## 14. What is the investor-level pitch?

Quantum migration will be a major enterprise coordination problem.

Most companies do not know where their quantum-vulnerable cryptography is, which systems protect long-lived data, who owns each migration, what is blocked by providers, and how to prove progress.

This platform gives them the control plane.

It finds exposure, prioritizes risk, assigns ownership, creates migration paths, validates changes, integrates with engineering workflows, verifies outcomes, monitors drift, and produces evidence.

Short version:

> We help enterprises discover quantum-vulnerable public cryptography, migrate what can be migrated today, track what is blocked, and prove progress toward quantum-safe readiness.

---

## 15. What should not be claimed?

Avoid saying:

- "We make every website quantum-proof today."
- "Quantum computers are breaking all websites right now."
- "We decrypt customer traffic."
- "We replace TLS."
- "We remove the need for cloud/CDN/browser support."

Use this instead:

- "We govern the cryptography that protects customer traffic."
- "We identify quantum-vulnerable public crypto dependencies."
- "We prioritize systems with long-lived sensitive data."
- "We generate and validate migration actions where supported."
- "We track provider blockers."
- "We prove progress and monitor drift."

---

## 16. What is the best one-sentence explanation?

The platform helps enterprises manage post-quantum migration by discovering quantum-vulnerable public cryptography, assigning ownership, creating validated migration paths, tracking blockers, and proving readiness progress over time.

---

## 17. What was added for a better demo?

The product now has a buyer-facing Demo Lab.

The Demo Lab is different from the normal operator screens.

Normal operator screens are for daily work:

- scans
- assets
- collections
- schedules
- GitHub sync
- remediations
- validation
- webhooks
- audit logs

The Demo Lab is for explaining the full story to a non-technical person.

It shows:

- the customer website/API being assessed
- why harvest-now/decrypt-later matters
- what quantum readiness evidence is collected
- how ownership is assigned
- how the repository path fits into the story
- how sandbox validation reduces change risk
- how verification and drift monitoring create proof

It also has a controlled seed flow.

That means if the customer has not given GitHub access yet, the platform can still create a safe demo evidence package:

- demo repository record
- demo asset
- demo quantum-readiness scan
- demo remediation
- demo validation result
- demo audit event
- demo report

This avoids a weak demo where nothing meaningful appears because GitHub access is missing.

---

## 18. What is the Quantum Readiness Report?

The Quantum Readiness Report is an executive evidence page.

It is available at:

```text
/org/quantum-readiness-report.html
```

It summarizes:

- total assets
- assets with quantum migration data
- actionable migration paths
- blocked assets
- average crypto-agility score
- engineering hours saved
- MTTR reduction
- verified-closed remediations
- drift reverted
- top quantum migration items
- next action for each asset

This is meant for:

- investors
- CISOs
- security leaders
- auditors
- enterprise buyers

It is not only a technical JSON response. It is a human-readable evidence artifact.

---

## 19. What is the controlled demo repository flow?

For a real customer deployment, the platform should connect to the customer's real repository through a GitHub App or token.

For a demo, that is not always possible.

So the platform now supports a controlled Demo Lab repository flow.

It creates an example repository record:

```text
demo/customer-edge-infra
```

The simulated repository contains a TLS policy example:

- before: TLS 1.2 and weak cipher assumptions
- after: TLS 1.3, weak ciphers disabled, crypto-agility owner added, post-quantum migration stage tracked

The point is not to pretend this changed a real customer's infrastructure.

The point is to show the complete operating loop:

1. discover quantum-vulnerable public crypto
2. assign business ownership
3. map to infrastructure code
4. propose a migration change
5. validate it in the sandbox
6. record evidence
7. show the report

When a real GitHub credential is available, the same product flow can move from demo evidence to real repository sync, validation, PR creation, merge tracking, verification, and drift checks.

---

## 20. What should be built next?

The strongest next additions are:

1. A real demo repository hosted in GitHub with Terraform examples.
2. A public demo website controlled by the project.
3. A full scripted demo that connects the demo website to the demo repo.
4. Provider-specific migration playbooks for Cloudflare, AWS, Google, Azure, Fastly, and Akamai.
5. A vendor console for cross-tenant support views.

The priority should be:

- first make the demo predictable
- then make machine-readable evidence APIs polished
- then make real GitHub/customer onboarding smoother

---

## 21. What changed when the platform became more machine-to-machine?

The platform now has API-first control-plane endpoints.

The goal is to let other systems ask the platform for decisions and evidence instead of relying on humans to download files.

Important machine-readable endpoints:

- `GET /v1/org/{organization_id}/readiness`
  - organization-level quantum readiness, ROI, drift, and top next actions

- `GET /v1/assets/{asset_key}/evidence`
  - evidence for one public website/API
  - includes latest scan, quantum readiness, policy decision, remediations, validations, and evidence hash

- `GET /v1/evidence/remediations/{remediation_id}`
  - evidence package for one remediation

- `GET /v1/evidence/repos/{owner/repo}`
  - evidence package and gate decision for one repository

- `GET /v1/repos/{owner/repo}/gate`
  - machine decision for CI/CD systems

- `GET /v1/org/{organization_id}/policy`
  - active organization policy-as-code

- `PUT /v1/org/{organization_id}/policy`
  - update organization policy-as-code

- `POST /v1/repositories/discover-ownership`
  - score likely asset-to-repository ownership mappings

- `GET /v1/providers/capabilities`
  - provider capability model for Cloudflare, AWS, Google, Azure, Fastly, Akamai, self-managed TLS, and unknown providers

This moves the product toward being a security automation API, not only a dashboard.

---

## 22. What is policy-as-code in this platform?

Policy-as-code means the organization can define rules as JSON.

Example policy settings include:

- minimum TLS version
- whether unknown providers should block
- whether every asset needs an owner
- whether every asset needs a repository link
- whether validation is required before PR creation
- whether CI gates require verified-closed remediation
- whether critical assets fail the merge gate
- whether IaC policy findings fail the merge gate
- allowed providers

The policy is used by evidence APIs and CI/CD gate decisions.

This lets an enterprise integrate the platform into automated workflows.

---

## 23. What MCP tools are available for other AI agents?

The `/mcp` endpoint now exposes tools for IDE assistants and external agents.

Tools include:

- `check_iac_compliance`
- `check_repo_enforcement`
- `get_asset_evidence`
- `get_repo_evidence`
- `discover_repo_ownership`
- `get_provider_capabilities`
- `get_org_policy`

This means another AI tool can ask:

- "Is this Terraform compliant?"
- "Does this repository pass the security gate?"
- "What evidence exists for this asset?"
- "Which repo probably owns this endpoint?"
- "What provider blocker exists?"
- "What policy is active for this organization?"

---

## 24. What was added after moving further toward machine communication?

The next development added more automation-first pieces.

### Local demo repository template

A controlled demo repository template now exists in:

```text
demo/customer-edge-infra/
```

It contains Terraform-style files with intentional demo weaknesses:

- weak TLS policy assumptions
- missing crypto-agility owner
- open SSH example
- public S3 access-block example

This is not pushed to GitHub automatically. It is a local template that can later become the real demo GitHub repository.

### Content-based repository ownership discovery

`POST /v1/repositories/discover-ownership` can now accept repository file contents.

That means the platform can score ownership using more than repository names.

It can detect signals such as:

- hostname appearing inside Terraform
- root domain appearing inside repo content
- team name appearing in repository name
- domain tokens matching repository names

This is closer to real enterprise onboarding, where endpoint-to-repo ownership is often discovered from infrastructure code.

### Provider playbooks

Provider playbooks were added:

```text
GET /v1/providers/{provider}/playbook
```

Supported playbooks include:

- Cloudflare
- AWS
- Google
- Azure
- Fastly
- Akamai
- customer-managed TLS
- unknown provider

Each playbook gives:

- what can be fixed now
- what must be verified with the provider
- what evidence should be collected

### Signed evidence envelope

Evidence APIs now include an integrity envelope.

Each evidence response includes:

- `evidence_hash`
- `evidence_integrity`

If `MORROW_EVIDENCE_SIGNING_KEY` is configured, the platform returns an HMAC signature.

If no signing key is configured, the platform still returns a SHA-256 digest and marks the evidence as unsigned.

### Autonomous remediation candidates

The platform can now generate machine-readable remediation candidates:

```text
POST /v1/remediation-candidates
```

This looks for high-risk quantum migration assets and returns candidate fix work.

It can optionally create candidate remediation records when a repository is linked.

This is a step toward an autonomous remediation queue while still keeping human review before real PR creation.

### Policy evaluation events

The platform can evaluate policy across assets:

```text
POST /v1/policy/evaluate
```

It returns pass/warn/block decisions.

If `emit_events` is enabled, it can emit policy warning/block events into the platform event system for webhook delivery.

---

## 25. What does the Automation UI show?

The UI now exposes the machine-to-machine layer through an `Automation` button.

It shows:

- autonomous remediation candidates
- provider playbooks
- policy-as-code JSON
- policy decisions
- asset evidence with evidence hash/signature metadata

This is not meant to replace the API. It is a control panel for seeing what the APIs are doing.

For a machine-first platform, the real integration points remain the `/v1/...` APIs and `/mcp` endpoint.

---

## 26. What changed in the UI navigation?

The UI was simplified so it no longer exposes every feature as a separate top-level button.

The top navigation now uses grouped menus:

- `Operate`
  - bulk onboarding
  - load last scan
  - collections
  - schedules

- `Quantum`
  - quantum migration roadmap
  - remediations
  - policies
  - automation

- `Evidence`
  - audit logs
  - integrations
  - fix-next
  - machine-readable evidence

- `Help`
  - how-to tutorial
  - demo guide
  - JSON and migration plan tools

A new `How to use` page explains the product in simple terms and gives a recommended first demo path.

---

## 27. What changed in the second UI cleanup?

The navigation was tightened again.

Changes:

- The old `Help` dropdown was removed.
- A dedicated `Guide` button now sits beside the main actions.
- Dropdown menus now auto-close when another dropdown opens.
- Dropdown menus close after selecting an item.
- The help/tutorial page is larger and more detailed.
- The visual style was pushed further toward an iOS/macOS glass interface.

The `Guide` page now works as a product usage manual. It explains:

- what each main button does
- what input the user should enter
- what each grouped menu contains
- how to run the first scan
- how to read scan results
- how to classify an asset
- how the GitHub/repository remediation flow works
- what validation, PR creation, verification, and drift mean
- the best practical workflow from scan to evidence

## New Development Modules: Migration Factory and HNDL Storage Audit

The platform now includes two additional API-first development modules inside the Automation area.

### 1. Post-Quantum Migration Factory prototype

Purpose:

- find legacy crypto usage inside pasted repository/code snippets
- identify RSA encryption, RSA signatures, ECDH/ECDSA, and static TLS policy patterns
- return a migration recipe instead of only saying there is a problem

Main endpoint:

- `POST /v1/code/crypto-discovery`
- `POST /v1/code/github-crypto-discovery`

Current status:

- prototype discovery and migration-plan logic is implemented
- pasted snippet discovery is implemented
- real GitHub repository file discovery is implemented when a GitHub credential id and `owner/repo` are supplied
- it can create candidate remediation records when the asset and synced repository context are available
- it does not yet rewrite full legacy applications automatically
- next step would be targeted rewrite recipes plus tests for specific languages/frameworks

### 2. Data-at-rest HNDL storage audit prototype

Purpose:

- score cloud storage/backups for harvest-now-decrypt-later risk
- highlight long-lived sensitive data, old backups, large datasets, weak/unknown encryption, and legacy key dependencies

Main endpoint:

- `POST /v1/cloud/hndl-audit`
- `POST /v1/cloud/aws-s3-hndl-inventory`

Current status:

- API accepts storage metadata and returns risk scoring
- UI includes a sample audit in Automation
- AWS S3, GCP Cloud Storage, and Azure Blob connector endpoints exist with safe dry-run behavior
- live inventory requires provider-specific SDK dependencies, org-scoped Vault credentials, and `dry_run=false`

Recommended order from here:

1. connect the Migration Factory to real GitHub repository file discovery
2. exercise live cloud storage inventory against scoped test credentials
3. revisit Edge post-quantum only when there is a clear target customer such as drones, vehicles, or industrial IoT

## CareHealth demo project created

A separate healthcare demo project was created at:

- `C:\Users\Samsung\Desktop\carehealth-demo-platform`

Purpose:

- provide a controlled healthcare demo repository
- represent multiple portals and teams
- keep visible website code safe/simple
- place controlled demo findings in infrastructure/config files
- support the end-to-end workflow: scan asset, classify ownership, connect repo, discover crypto/config findings, create remediation candidate, validate, PR, verify, and monitor drift

Key files:

- `ownership/services.yaml`
  - asset ownership, teams, criticality, and data lifetime
- `infra/*-tls.tf`
  - portal TLS policy examples
- `infra/storage-backups.tf`
  - long-lived sensitive backup examples for HNDL discussion
- `infra/security-baseline.tf`
  - general IaC security examples
- `config/crypto-config.java`
  - controlled legacy RSA/ECDSA-style crypto discovery target
- `config/nginx-*.conf`
  - controlled TLS configuration examples
- `scripts/DEMO_FLOW.md`
  - short operating guide for using the repo with this platform

Important:

- this is a separate project from `morrow`
- it should be pushed to GitHub before testing real repository discovery
- do not put real secrets, real patient data, or real cloud credentials in it

## Platform Phase 1 update: onboarding and GitHub connection

The platform UI now exposes the first Core Product workflow more directly.

Main navigation additions:

- `Onboard`
  - opens the portfolio onboarding flow
  - lets the operator paste domains, classify them, optionally connect GitHub, run a scan, and build the migration portfolio

- `Connect GitHub`
  - jumps directly to the encrypted GitHub token connection panel
  - stores the token in Vault
  - syncs repositories
  - saves the resulting credential id locally for later validation/remediation actions

Why this matters:

- the end-to-end product starts with onboarding real systems and repositories
- repository sync is required before the platform can connect public crypto posture to code ownership
- this is the first step toward the full workflow: scan asset, classify, connect repo, discover crypto/config issues, create remediation candidate, validate, PR, verify, and monitor drift

Repository discovery update:

- the home screen now includes a `Synced repositories` panel
- after `Connect GitHub` or `Sync GitHub Repos`, the operator can load synced repositories in one place
- each synced repository has a `Scan crypto` action
- repository crypto scan looks for legacy RSA, ECDSA, ECDH, DH, TLS, JWT, and related crypto/config patterns
- results are grouped by file so an operator can see where the problem lives
- if the operator provides an asset key and enables candidate creation, the platform can create tracked remediation candidates from repo findings
- `Use in Remediation` selects the repository in the remediation workflow and reuses the saved GitHub credential id

Asset-to-repo ownership update:

- the main screen now includes an `Asset-to-repo link` panel
- operators can load current assets and synced repositories, then link one asset to one repository
- the asset editor also includes a `repository` selector, so owner/team/environment/criticality and repo ownership can be saved together
- selecting an asset pre-fills the repo scan asset key, which makes it easier to turn repository crypto findings into tracked remediation candidates
- this closes the practical ownership gap: the platform can show not only that a public endpoint has quantum/crypto risk, but which code repository is responsible for fixing it

Product UX update:

- primary navigation now focuses on the normal work paths:
  - `Live Product`
  - `Workflow`
  - `Onboarding`
  - `Remediation Queue`
  - `Guide`
- `Workflow` opens a guided command center for the full loop: scan, classify, connect repo, link asset, scan repo crypto, review work, validate/PR, verify/drift
- every workflow step shows whether it is complete, what metric proves completion, what is blocked, and which button moves the operator forward
- advanced tools are grouped under dropdown menus instead of being shown as too many top-level buttons
- `Remediation Queue` is the operator-first view of the fix workflow
- the queue summarizes candidate fixes, work needing validation, PR/verified items, drift status, owning asset, repository, file path, and next safe action
- complex app-code crypto findings are presented as migration tasks, while config/Terraform findings are treated as safer validation candidates
- the older advanced `Remediations` modal still exists for detailed actions such as approve, reject, validate, create PR, mark merged, and drift checks

Migration Tasks update:

- `Quantum -> Migration Tasks` opens the engineering task board for complex app-code crypto migration
- use it when repository discovery finds RSA, ECDSA, ECDH, DH, JWT, Java keystore, or OpenSSL usage that should not be auto-rewritten
- tasks move through `Open`, `Planned`, `In progress`, `Done`, and `Accepted risk`
- each task shows the asset, repository, file, legacy dependency, target migration direction, confidence, safety reason, and recommended workflow
- repository crypto scan now has a `Create migration tasks` checkbox
- safe Terraform/config findings can become remediation candidates; complex app-code findings become migration tasks
- this is the correct enterprise behavior because it separates safe automated config fixes from sensitive cryptography refactoring that needs tests and a rollout plan

Repository crypto discovery update:

- detection now covers more enterprise crypto signals:
  - RSA encryption/key transport
  - RSA signatures
  - ECDH/ECDSA and named elliptic curves
  - static TLS policy/configuration
  - Java keystores and truststores
  - OpenSSL RSA/TLS usage
  - JWT signing and verification algorithm dependencies
  - certificate/private-key material indicators
- results are grouped by service/app folder so owners can split work by system
- results are also grouped by crypto boundary:
  - identity/token boundary
  - certificate/keystore boundary
  - native crypto library boundary
  - TLS edge configuration boundary
  - application crypto boundary
- certificate/private-key indicators are manual-review items, not auto-remediation candidates

Data-at-rest HNDL update:

- AWS S3 inventory is now the first live storage connector path
- dry-run mode is available from the UI and does not call AWS
- live mode uses a Vault credential containing JSON with `aws_access_key_id`, `aws_secret_access_key`, and optional `aws_session_token`
- the connector lists accessible S3 buckets and sampled objects, then sends them through the HNDL scoring engine
- sensitive names like `backup`, `database`, `patient`, `customer`, `pii`, `phi`, and `archive` increase the score
- old objects, large objects, weak/unknown encryption, and provider-managed keys also increase the score
- optional object-level encryption checks use `head_object`; this gives better evidence but needs broader AWS permissions and can be slower
- GCP Cloud Storage inventory is now available as a second connector path
- dry-run mode is available from the UI and does not call GCP
- live mode uses a Vault credential containing Google service-account JSON
- the connector lists accessible Cloud Storage buckets and sampled blobs, then sends them through the HNDL scoring engine
- customer-managed encryption keys are detected where object/bucket metadata exposes them
- Azure Blob Storage inventory is now available as a third connector path
- dry-run mode is available from the UI and does not call Azure
- live mode uses a Vault credential containing either `connection_string`, or `account_url` / `account_name` plus `account_key` or `sas_token`
- the connector lists accessible containers and sampled blobs, then sends them through the HNDL scoring engine
- encryption scopes are detected where blob metadata exposes them

GitHub/repo onboarding update:

- the Live Product page now has a four-step repository onboarding strip:
  1. credential
  2. sync repos
  3. link asset
  4. scan code
- the platform shows an ownership map of assets and their linked repositories
- unlinked assets are marked as needing a repo before code-level remediation can be trusted
- operators can request ownership suggestions based on hostnames, root-domain tokens, asset teams, and repository names
- high-confidence suggestions can be auto-linked; medium/low-confidence matches stay manual-review
- operators can use an asset directly as the context for the next repo crypto scan
- the flow is designed to make the core message visible: scan findings only become enterprise value when they are connected to code ownership and actionable migration work

Repo scan work package update:

- after a repo crypto scan, the UI now shows a work package summary
- it separates safe config fixes, complex migration tasks, and manual-review items
- it shows how much work is already tracked as remediation candidates or migration tasks
- it provides direct routing to the remediation queue, migration task board, asset evidence, and rerun-with-work-creation flow
- this makes the repository scan easier to demo because it explains what the platform created and what the operator should do next

Go-live readiness update:

- the Live Product console now includes a readiness checklist
- it checks assets, classification, GitHub credential, repo sync, asset-to-repo links, work packages, review state, validation evidence, PR workflow, and verified closure
- each row shows ready / review / needed status
- this helps operators understand what is missing before attempting a real GitHub validation/PR demo

Backend architecture update:

- HNDL storage scoring/inventory logic has been moved into `backend/services/hndl.py`
- generic repository ownership scoring and crypto/config discovery logic has been moved into `backend/services/repo_discovery.py`
- remediation guardrails, PR readiness checks, branch naming, PR title/body generation, and candidate content resolution have been moved into `backend/services/remediation_workflow.py`
- GitHub pull-request API calls for repo metadata, branch creation, file updates, and PR creation have been moved into `backend/services/github_pr.py`
- shared HNDL request/data models now live in `backend/schemas.py`
- the repo discovery service is generic and uses hostnames, root-domain tokens, team metadata, repository names, and optional repository-file evidence
- it does not contain healthcare-specific or demo-specific assumptions

Onboarding wizard update:

- `Onboarding` is now a guided six-step workflow instead of a single technical form
- steps are:
  1. company / organization context
  2. paste and normalize domains
  3. classify owner, team, environment, criticality, confidentiality, and tags
  4. optional GitHub token connection
  5. review and run onboarding
  6. review result and choose next action
- the wizard shows endpoint counts before running
- domain input is normalized to `host:443` where possible
- after onboarding, the operator can jump directly to dashboard, asset-to-repo linking, or remediation queue
- this makes first use clearer for non-technical operators and keeps GitHub optional until the customer is ready to connect code ownership

Operator console update:

- the live product page now has a `Next best action` strip
- it changes based on current product state:
  - no assets -> start onboarding
  - assets but no repos -> connect GitHub
  - repos but unlinked assets -> link assets to repos
  - linked assets but no candidates -> scan repo crypto
  - candidates exist -> open remediation queue
  - proof exists -> review dashboard/evidence
- the page also has a workflow status board showing assets, repos, linked assets, candidates, validated items, PRs, verified closures, and drift
- empty scan results now explain what to do next instead of only saying there are no results
- the live product page now shows runtime health for demo/deployment smoke checks, using `/health/deep` when available and falling back to `/health`

Remediation queue board update:

- `Remediation Queue` is now a Kanban-style workflow board
- columns are:
  - `Candidates`
  - `Review`
  - `Validate`
  - `Pull Request`
  - `Verified / Drift`
- each card shows status, asset, repo, file path, origin, safety label, drift status, and next safe action
- direct card actions include approve, reject, validate, create PR, open evidence, open details, and drift check
- validation, PR creation, and drift checks require a connected/saved GitHub credential id
- labels distinguish safe config paths from human migration tasks so complex app-code crypto changes are not presented as blind auto-rewrites

Settings page update:

- the main navigation now includes `Settings`
- Settings centralizes local operator defaults:
  - organization id
  - default owner/team/environment/criticality/confidentiality
  - saved GitHub credential id
  - API base URL
  - runtime health check
- Settings can apply defaults into the onboarding wizard
- Settings can apply a saved GitHub credential id into repo/remediation workflows
- `Clear Local UI State` only clears browser-side preferences and cached form state; it does not delete backend data, credentials, assets, repositories, remediations, scans, or audit logs

CI/CD gate hardening update:

- `POST /integrations/ci/status-check` now supports dry-run policy decisions and optional GitHub commit status or GitHub Check Run publishing.
- In dry-run mode, the endpoint returns the merge decision without writing to GitHub.
- In publish mode, the caller supplies `github_credential_id`, `repo`, and commit `ref`; the platform posts the `morrow/security-policy` status or check run back to GitHub.
- The gate can fail even for an unsynced repository when changed IaC snippets contain policy violations, such as public SSH ingress.
- This is the next step toward making the platform a real CI/CD enforcement control instead of only a dashboard.
- publish_mode=status uses the classic commit status API; publish_mode=check_run uses the GitHub Checks API for richer PR display when the token has Checks permission.

Idempotency hardening update:

- The backend now accepts `Idempotency-Key` or `X-Idempotency-Key` headers on selected write operations.
- PR creation, validation job creation, remediation suggestion, GitHub repository crypto discovery, autonomous remediation candidates, and cloud HNDL inventory endpoints use idempotency protection so a retry or double-click with the same key returns the original response instead of creating duplicate work.
- CI status/check publishing uses idempotency protection so repeated requests do not create duplicate GitHub status/check side effects.
- If the same key is reused with a different request body, the API returns `409` to prevent accidental key misuse.
- If the same key is already running, the API returns `409` instead of starting a second side effect.
PR lifecycle webhook hardening update:

- The GitHub webhook receiver now handles more than merged PRs.
- `pull_request.closed` with `merged=true` marks matching remediations as `merged`.
- `pull_request.closed` with `merged=false` marks matching remediations as `pr_closed`.
- `pull_request.reopened` moves matching remediations back to `pr_created` unless they are already verified closed.
- `pull_request.synchronize` marks matching remediations as `pr_updated` so force-push/new-commit activity is visible.
- These lifecycle updates are matched by PR URL and recorded through audit/events where possible.
GitHub history storage update:

- The backend now records GitHub PR lifecycle webhook events in a queryable history table.
- The backend also records GitHub commit status / Check Run publish attempts when CI gate publishing is enabled.
- Operators can inspect these through `GET /integrations/github/pr-events` and `GET /integrations/github/status-publishes`.
- This adds an audit-friendly trail for PR lifecycle and CI gate publishing separate from the remediation row itself.
Branch cleanup visibility update:

- The backend now exposes branch cleanup state through `GET /remediations/branches/cleanup/status`.
- Admins can still run bulk cleanup through `POST /remediations/branches/cleanup`.
- Admins can also cleanup one remediation branch through `POST /remediations/{id}/branch/cleanup`.
- This makes post-verified-closure repository hygiene visible instead of hidden inside the background task.
Runtime traffic inventory update:

- The platform now has a runtime traffic import layer for telemetry/log evidence.
- It does not packet-sniff production traffic. Instead, it accepts machine-readable observations from safer sources such as CDN logs, load balancer logs, service mesh telemetry, ingress logs, or manually exported traffic samples.
- Main endpoints:
  - `POST /v1/runtime/traffic/import`
  - `GET /v1/runtime/traffic/observations`
  - `GET /v1/runtime/assets`
- Imported observations are normalized into `host:port` asset keys.
- The platform stores source, provider, protocol, TLS version, cipher, status code, path sample, observation counts, and first/last seen timestamps.
- When enabled, runtime import can automatically create or update asset records and mark them with `observed_from_runtime` metadata and a `runtime-observed` tag.
- This closes part of the live-production blind spot: the platform can now ingest evidence that a system is actually seen in production traffic, not only discovered by a manual domain list or repository scan.
- This is still not full passive network capture; internal private services require logs/telemetry imports from the customer's environment.

GitHub App enterprise flow update:

- The platform now exposes GitHub App setup and repository-access diagnostics.
- New endpoints:
  - `GET /integrations/github-app/status`
  - `POST /integrations/github-app/repo-diagnostics`
- The status endpoint shows installation count, synced installations, credential readiness, and next setup steps without exposing secrets.
- The repo diagnostics endpoint checks whether a repository is in `owner/repo` format, whether the credential is ready, whether a repo-scoped token can be resolved, and optionally whether GitHub repository metadata is reachable.
- Diagnostic responses intentionally do not return GitHub tokens.
- This is the enterprise-preferred path because GitHub Apps provide scoped installation access instead of relying on personal access tokens.

Organization membership and tenant-admin update:

- The platform now has an organization membership model.
- Each membership stores organization id, user id, role, display name, email, status, created time, and updated time.
- Supported roles remain `viewer`, `operator`, and `admin`.
- New APIs:
  - `GET /organizations/{organization_id}/members`
  - `POST /organizations/{organization_id}/members`
  - `PATCH /organizations/{organization_id}/members/{user_id}`
  - `DELETE /organizations/{organization_id}/members/{user_id}`
  - `GET /auth/memberships`
- `/auth/context` now returns current membership, all memberships for the user, and allowed action descriptions.
- If a user has an active membership in the active organization, that membership role overrides the role header or JWT role for that organization.
- Customer admins can manage members only inside their active organization.
- Viewer/operator users cannot manage members.
- Member changes are audited.

Validation sandbox hardening update:

- The platform now exposes validation sandbox policy and evidence through APIs.
- New endpoints:
  - `GET /validation/sandbox-profile`
  - `GET /validation-jobs/{validation_job_id}/evidence`
- The sandbox profile reports isolation mode, Docker availability, Docker image/CPU/memory limits when applicable, timeout limits, stdout/stderr limits, network posture, secret scrubbing, path traversal protections, and the current security boundary.
- Validation command execution now records timeout metadata and truncates captured output to configured limits.
- Validation evidence packages state whether secrets were scrubbed, path traversal checks were used, archive extraction checks were used, timeouts were enforced, and stdout/stderr were captured.
- Production recommendation remains Docker validation mode with `--network none` for stronger isolation.
