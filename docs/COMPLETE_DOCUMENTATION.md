# Morrow Complete Documentation

This is the single documentation bundle for Morrow.

Current release evidence: the dated production-release record is maintained privately
records the verified checks, incomplete checks and deployment-owner requirements,
including the 1 October dependency follow-up. It is not a production launch approval.

Current AI trust addendum: [Customer Data Control](CUSTOMER_DATA_CONTROL.md)
documents the default-off AI gateway, customer-approved destinations and workflows,
offline metadata filter, signed processing receipts, stop action and opt-in support.
The live controls are at `/ui/#data-control`; the public explanation is at
`/ui/ai-trust.html`. AI is read-only and its privacy guarantees have explicit limits.

Current addendum: [Website gateway deployment and verification](WEBSITE_GATEWAY.md)
covers the customer-controlled reverse proxy, ownership checks, WAF policies,
compatibility tests, privacy boundary, and remaining deployment requirements.
The generated bundle below is a historical snapshot, not a production approval.

Current security addendum: [Authentication, administrator visibility and retained traffic logs](SECURITY_LOGGING.md)
describes the real event sources, privacy boundary, retention, failure behavior,
and remaining SSO/session and production verification requirements.
See [SECURITY_LOGGING.md](SECURITY_LOGGING.md) for the implemented logging scope (the dated verification record is kept privately)
for executed checks and the remaining local launch blockers.

Current operator addendum (September 2026):

- [Operator Console Guide](OPERATOR_CONSOLE_GUIDE.md): the rebuilt operator console at `/vendor-admin/`
  (sign-in with SSO, MFA and break-glass; navigation; dashboard metric definitions; Customer 360; usage and
  adoption; per-organization rate limits; alert routing; support sessions; invitations;
  announcements and maintenance; background jobs; audit; the go-live gate; onboarding and incident
  runbooks; environment variable reference).
- Customer Onboarding Runbook (maintained privately; commercial pilot material): covers invite links and
  rate limits.
- [Production Deployment Runbook](PRODUCTION_DEPLOYMENT_RUNBOOK.md), section 5a: required production
  settings for operator SSO and MFA, break-glass, support sessions, alert routing, Redis and vault
  key rotation.
- Identity-provider setup detail stays in [Operator SSO, MFA and break-glass](#operator-sso-mfa-and-break-glass)
  near the end of this file.
- Customer-facing explanations live in the console under **Help › Guide & Tutorial**.

It is intentionally split into two major sections:

- Non-Technical Documentation: product explanation, user workflows, UI button guide, cloud trial, and local trial
- Technical Documentation: architecture, API reference, database model, runtime operations, and deployment notes

Generated: 2026-05-13 14:05:20 +02:00

Generated from:
- `docs/NON_TECHNICAL_EXPLANATION.md`
- `docs/QUANTUM_PLATFORM_QA.md`
- `docs/USER_GUIDE.md`
- `docs/UI_BUTTON_AND_FEATURE_GUIDE.md`
- `docs/TRY_IT_IN_THE_CLOUD.md`
- `docs/TRY_IT_ON_YOUR_MACHINE.md`
- `docs/TECHNICAL_REFERENCE.md`
- `docs/API_REFERENCE.md`
- `docs/DATA_MODEL_AND_OPERATIONS.md`

---

# Section 1: Non-Technical Documentation

This section is for founders, buyers, operators, auditors, demo users, and non-engineering readers. It explains what the product does, how to use it, how every visible UI button works, and how to try it without needing to understand the internal codebase.

---

## Non-Technical Part: Quantum Platform Q&A

# Quantum Readiness Platform Q&A

This document explains the platform in plain language for investors, buyers, operators, and non-technical stakeholders.

It focuses on the problem, why it matters, what the platform does, and what it does not claim.

### What problem does this platform solve?

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

### Is this just another vulnerability scanner?

No.

A normal scanner usually stops at:

> Here is a problem.

This platform tries to continue the loop:

> Here is the affected asset, the quantum relevance, the owner, the migration stage, the blocker, the repository path, the suggested change, the validation result, the pull request, the verification result, and the drift history.

The value is not only detection.

The value is operational control over the migration.

### Why does quantum matter if quantum computers are not breaking websites today?

The immediate pain is not that every website is being broken by a quantum computer today.

The immediate pain is that large enterprises are facing a multi-year cryptographic migration that they cannot easily inventory, assign, execute, or prove.

Current public-key cryptography such as RSA and elliptic-curve cryptography is expected to be vulnerable to future cryptographically relevant quantum computers.

Enterprises need to prepare before the deadline arrives because migration is slow and distributed across public websites, APIs, login portals, CDNs, load balancers, certificates, cloud providers, Kubernetes ingress, Terraform, platform teams, application teams, and security teams.

The hard part is not only cryptography.

The hard part is coordination.

### What is harvest-now/decrypt-later?

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

### Does the platform prove that a quantum computer can break this website today?

No.

That would not be a credible claim.

The platform does not say:

> A quantum computer is breaking this website today.

It says:

> This public system depends on cryptography that may be vulnerable to future quantum computers, and the organization needs a migration plan.

That distinction matters.

The platform is about readiness, migration, and proof.

### Does the platform make every website quantum-proof today?

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

### Does it help secure data moving over the internet?

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

The simplest explanation:

> The platform does not carry customer traffic. It governs the cryptography that protects customer traffic.

### What does the platform do step by step?

1. Discover public websites and APIs.
2. Assess quantum relevance.
3. Add business context such as owner, team, environment, criticality, and confidentiality lifetime.
4. Build a staged migration plan.
5. Separate fix-now work from provider-blocked work.
6. Link the asset to the repository where the fix lives.
7. Suggest a remediation.
8. Validate the change safely.
9. Create a pull request.
10. Verify after deployment.
11. Monitor drift.
12. Produce evidence.

### What problem does the Quantum Migration page solve?

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

### Can an enterprise upload a whole list of systems at once?

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

The platform can then create asset records, apply default business context, save a collection, start one bulk scan, optionally connect GitHub, sync repositories, attempt hostname-to-repository correlation, and build the Quantum Migration portfolio.

This is the enterprise flow. The company does not need to onboard one website at a time.

If repo ownership is uncertain, the platform should flag it for human confirmation instead of pretending it knows.

### What is the investor-level pitch?

Quantum migration will be a major enterprise coordination problem.

Most companies do not know where their quantum-vulnerable cryptography is, which systems protect long-lived data, who owns each migration, what is blocked by providers, and how to prove progress.

This platform gives them the control plane.

It finds exposure, prioritizes risk, assigns ownership, creates migration paths, validates changes, integrates with engineering workflows, verifies outcomes, monitors drift, and produces evidence.

Short version:

> We help enterprises discover quantum-vulnerable public cryptography, migrate what can be migrated today, track what is blocked, and prove progress toward quantum-safe readiness.

### What should not be claimed?

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

### What is the best one-sentence explanation?

The platform helps enterprises manage post-quantum migration by discovering quantum-vulnerable public cryptography, assigning ownership, creating validated migration paths, tracking blockers, and proving readiness progress over time.

---

## Non-Technical Part: Plain English Explanation

# Morrow Explained in Plain English

This document explains Morrow for a non-technical reader.

It avoids assuming you know software engineering, cloud infrastructure, cybersecurity, GitHub, Terraform, Docker, databases, or AI terminology.

The goal is simple:

- explain what the software does
- explain why each part exists
- explain what the technical words mean
- explain how the whole system works from start to finish

## Page 1: The simple idea

Morrow is a security workflow platform.

In simple terms, it helps a company answer this question:

> Are our public websites, APIs, and internet-facing systems using safe modern cryptography, and if not, how do we fix them in code?

The product is now explicitly focused on post-quantum readiness, not only ordinary TLS hygiene.

The key question it helps answer is:

> Could this public system expose long-lived sensitive data to harvest-now/decrypt-later quantum risk, and what can we safely change today to move toward quantum-safe readiness?

The platform does not claim that every website can be made fully "quantum proof" immediately. That depends on browser, certificate authority, CDN, load balancer, cloud provider, and server support. Instead, it separates the work into:

- what is quantum-vulnerable today, such as RSA or elliptic-curve cryptography
- what can be fixed immediately, such as TLS 1.3, weak cipher cleanup, certificate hygiene, and crypto-agility configuration
- what depends on provider support, such as hybrid or post-quantum TLS controls
- which team and repository own the migration
- whether a proposed migration change passed validation
- whether later scans prove the system improved
- whether drift later undid the safer crypto posture

Current scan output includes a staged quantum migration plan:

1. inventory public cryptography
2. classify data sensitivity and confidentiality lifetime
3. prepare crypto agility with TLS/certificate hardening
4. check hybrid/PQC support for the provider or TLS terminator
5. create a validated migration pull request
6. verify the external posture and monitor drift

The UI also shows a provider capability section. It does not blindly claim that Cloudflare, AWS, GCP, Azure, Nginx, Envoy, Apache, or other stacks are fully quantum-safe. It marks provider support as a required check, records blockers, and still recommends immediate hardening and crypto-agility work that can be done today.

The operational UI now includes a dedicated Quantum Migration page. This page is the main queue for the post-quantum program. It shows:

- total assets in scope
- assets with quantum scan data
- actionable migration paths
- blocked assets
- average crypto-agility score
- harvest-now/decrypt-later risk counts
- provider counts
- stage counts
- each asset's owner, team, environment, provider, algorithm, current stage, blockers, and next action

The investor demo also uses an in-app setup screen instead of browser prompts. The presenter can enter the target website/API, optionally paste a GitHub token, and then run a slower guided walkthrough with explanatory popups.

Most companies have public systems such as:

- a public website
- a login page
- a customer portal
- a patient portal
- an API for mobile apps
- an admin portal
- a payment or checkout system

These systems normally use HTTPS. HTTPS depends on cryptography. Cryptography is the math and technology that keeps traffic private and trusted.

Morrow checks those public systems and looks for crypto and TLS posture issues.

TLS is the technology behind HTTPS. When you see a padlock in the browser, TLS is part of what makes that work.

PQC means post-quantum cryptography.

Post-quantum cryptography is about preparing for a future where quantum computers may break some older cryptographic systems. Most companies are not fully ready for that yet. Morrow helps them understand where they are and move toward safer, more flexible crypto setups.

The product does not stop at saying:

- "There is a problem."

It tries to continue the work:

- it finds the issue
- it stores the issue
- it links the issue to the team and repository that owns it
- it asks AI to suggest a code fix
- it validates the suggested fix
- it opens a pull request in GitHub
- it verifies the fix after merge
- it keeps checking later in case the fix is undone

That full loop is the important part.

The product is not only a scanner. It is a scanner plus remediation workflow.

## Page 2: What problem this solves

Security teams often find issues, but fixing them is hard.

A normal security workflow looks like this:

1. A scanner finds a problem.
2. A security person writes a ticket.
3. Someone tries to find the right engineering team.
4. The engineering team asks where the problem is in code.
5. Someone manually investigates.
6. A fix is written.
7. A pull request is opened.
8. Maybe it gets merged.
9. Maybe nobody checks whether the problem is actually gone.
10. Later, someone may accidentally undo the fix.

That workflow is slow and fragile.

Morrow is designed to make this workflow more direct.

Instead of only producing alerts, it tries to connect:

- the public system
- the security issue
- the business owner
- the engineering team
- the source code repository
- the proposed code fix
- the validation result
- the pull request
- the final proof that the issue is closed

This is important because a security issue is only truly useful when somebody can act on it.

For example, if a healthcare company has:

- `portal.carehealth.com:443`

Morrow can treat that as an asset.

An asset is simply something the company wants to monitor. In this product, an asset is usually a public internet endpoint, like a website or API.

Then the company can label the asset:

- owner: `digital-health`
- team: `platform`
- environment: `prod`
- criticality: `high`
- tags: `healthcare`, `phi`, `patient-facing`, `internet`

These labels matter because they turn a raw technical finding into business context.

Instead of saying:

- "There is an issue on this hostname."

The product can say:

- "There is an issue on the production patient portal owned by the digital health platform team."

That is much more useful.

## Page 3: The main objects in the software

The software uses a few important objects.

### Asset

An asset is something scanned.

Examples:

- `www.company.com:443`
- `api.company.com:443`
- `portal.hospital.com:443`
- `auth.company.com:443`

The `:443` part means port 443. Port 443 is the standard port for HTTPS.

Think of an asset as:

- a public digital doorway into the company

### Scan

A scan is a check performed against one or more assets.

The scan collects technical facts such as:

- what TLS version is used
- what certificate is served
- what cryptographic key type is used
- whether weak TLS settings are present
- whether the certificate is valid
- whether the certificate chain looks complete

Think of a scan as:

- a security inspection

### Finding

A finding is something the scan noticed.

Examples:

- certificate expires soon
- old TLS version is supported
- weak cipher is accepted
- TLS 1.3 is not enabled
- certificate chain is incomplete

Think of a finding as:

- one specific issue or observation

### Repository

A repository is where source code or configuration lives.

In this product, repositories usually come from GitHub.

Examples:

- `company/platform-infra`
- `company/api-config`
- `company/edge-network`

Think of a repository as:

- the folder of code where engineers make changes

### Remediation

A remediation is a proposed fix.

It connects:

- the asset
- the problem
- the repository
- the file to change
- the suggested new content
- the validation result
- the pull request

Think of a remediation as:

- a fix workflow

### Pull request

A pull request is a proposed code change in GitHub.

Engineers review it, comment on it, approve it, and merge it.

Think of a pull request as:

- a formal request to change code

### Verified closed

Verified closed means the product checked again after the fix and confirmed the issue is actually gone.

This is stronger than simply saying:

- "The pull request was merged."

Merged only means code changed.

Verified closed means the issue was checked again and confirmed fixed.

### Drift

Drift means the fix changed later.

For example:

- the pull request fixed a file
- later someone edited the same file
- now the file no longer matches the expected fixed version

The product can detect that.

Think of drift as:

- the fix becoming unstable or being undone over time

## Page 4: The full workflow in plain language

Here is the full workflow from beginning to end.

### Step 1: Choose what to scan

The user enters public endpoints such as:

- `portal.company.com:443`
- `api.company.com:443`
- `auth.company.com:443`

These are the systems the company wants to monitor.

### Step 2: Run a scan

The scanner connects to the endpoint and collects TLS and certificate information.

It checks the public security posture of the endpoint.

It does not need to log in to the application.

It is checking the public TLS/crypto layer.

### Step 3: Store the result

The system saves the scan result in the database.

This matters because the company can compare current and past posture.

Without history, a scan is only a snapshot.

With history, the company can see improvement or regression.

### Step 4: Classify the asset

The user sets ownership metadata.

Examples:

- owner: `platform-lead`
- team: `platform`
- environment: `prod`
- criticality: `high`

This tells the company who should act.

### Step 5: Link the asset to a repository

The platform links the public endpoint to the code repository that likely owns the fix.

For example:

- `portal.company.com:443`
- linked to `company/platform-infra`

This is one of the most important steps.

Security findings often fail because nobody knows where the fix belongs.

### Step 6: Create a remediation suggestion

The system fetches a file from GitHub.

Then it sends context to the AI:

- the asset
- the vulnerability
- the current file content
- the requested fix

The AI returns either:

- a proposed diff
- or a full updated file

### Step 7: Human review

A human reviews the suggestion.

The human can:

- approve it
- reject it

This is important because AI should not blindly change production code.

### Step 8: Validate the change

Before opening a pull request, the product validates the proposed change.

For Terraform files, it can run Terraform checks.

Terraform is explained later in this document, but in simple terms:

- Terraform is a tool that describes cloud infrastructure as code
- validation checks whether the proposed infrastructure code is structurally valid

### Step 9: Create a pull request

If validation passes, the platform creates a GitHub pull request.

This puts the fix into the normal engineering workflow.

Engineers can review and merge it.

### Step 10: Track merge

When the pull request is merged, GitHub sends an event to the product.

The product marks the remediation as merged.

### Step 11: Verify closure

A later scan checks whether the issue is actually gone.

If the issue is gone, the remediation becomes:

- `verified_closed`

### Step 12: Monitor for drift

After closure, the system keeps checking whether the fixed code changes later.

If it does, the product marks drift and can create a follow-up remediation.

This gives the company a continuous control loop.

## Page 5: Why GitHub matters

GitHub is where many companies store code.

Engineers use GitHub to:

- store files
- review changes
- approve changes
- merge changes into the main codebase

Morrow connects to GitHub so it can turn security findings into real code changes.

Without GitHub integration, the scanner can still find problems.

With GitHub integration, the product can go further:

- find the repository
- read the relevant file
- suggest a code change
- validate the change
- create a pull request
- track whether the pull request was merged

### What is a GitHub App?

A GitHub App is a secure way for software to access GitHub repositories.

Instead of using one personal user's password or token, a GitHub App has controlled permissions.

For example, it may be allowed to:

- read repository contents
- create branches
- create pull requests
- receive webhook events

This is safer than using a personal access token for everything.

In simple terms:

- a GitHub App is an official integration identity for software

### What is a webhook?

A webhook is a message sent from one system to another when something happens.

For example:

- GitHub pull request is merged
- GitHub sends a webhook to Morrow
- Morrow receives the message
- Morrow marks the remediation as merged

Think of a webhook as:

- an automatic notification between systems

The product also has outbound webhooks.

Outbound webhooks mean Morrow can notify other systems, such as:

- Slack
- Discord
- an internal monitoring system
- a custom company endpoint

## Page 6: What Docker does

Docker is a packaging tool.

Software often needs many things to run:

- Python version
- installed libraries
- operating system tools
- Terraform
- environment variables
- startup commands

If every developer installs those manually, things break easily.

Docker packages the application and its dependencies into a container.

Think of Docker as:

- a sealed box that contains the app and the tools it needs

In this project, Docker is used to run:

- the API service
- the background worker
- the scheduler

The local Docker setup also starts:

- Postgres database
- Redis queue
- webhook test receiver

### What is a container?

A container is a lightweight environment where an application runs.

It is not exactly a full computer, but it behaves like a small isolated runtime.

The benefit is consistency.

The app should run the same way on:

- your laptop
- a test server
- a cloud deployment

### Why Docker matters for this product

Morrow uses Docker because the product is not just one script.

It needs:

- web server
- worker
- scheduler
- database
- queue
- validation tools

Docker makes that easier to run consistently.

## Page 7: What Terraform does

Terraform is an infrastructure-as-code tool.

That means it lets you describe cloud infrastructure using files.

Instead of clicking around in a cloud dashboard to create resources, you write a configuration file that says:

- create this database
- create this network
- create this web service
- create this Redis cache
- create these secrets
- connect these services together

Terraform then applies that plan in the cloud.

Think of Terraform as:

- a blueprint and construction manager for cloud infrastructure

### Why Terraform matters here

Morrow needs cloud infrastructure such as:

- Cloud Run service
- Cloud SQL database
- Redis
- Secret Manager
- Artifact Registry
- service accounts
- network configuration

Terraform lets those be created repeatably.

This is useful because:

- the same infrastructure can be recreated
- deployments are documented as code
- private-cloud customer deployments become easier
- changes can be reviewed before they are applied

### Terraform in the validation workflow

Terraform also appears in a second place.

Some customer infrastructure is written in Terraform.

For example, a company may define its load balancer or TLS settings in Terraform.

If Morrow suggests a change to a Terraform file, the platform can run Terraform validation to check whether the new file is valid.

So Terraform is used in two ways:

- to deploy Morrow infrastructure
- to validate customer infrastructure code changes

## Page 8: What the database does

The database stores the product state.

Without a database, the system would forget everything after a restart.

Morrow uses PostgreSQL, often called Postgres.

Postgres stores structured information such as:

- organizations
- users' organization context
- repositories
- assets
- scan results
- remediations
- validation jobs
- audit logs
- webhook events
- drift details

Think of Postgres as:

- the product's long-term memory

### What is Cloud SQL?

Cloud SQL is Google's managed database service.

Instead of the company managing database servers directly, Google runs the database service.

Cloud SQL handles things like:

- database hosting
- backups
- storage
- maintenance options

In this project, Cloud SQL is the managed Postgres database for the cloud deployment.

### What is Redis?

Redis is a fast in-memory data store.

In this product, Redis is mainly used as a queue for background jobs.

For example:

- the API receives a scan request
- the API puts a job in Redis
- the worker picks up the job
- the worker runs the scan
- the worker stores the result in Postgres

Think of Redis as:

- the job mailbox between the web app and background workers

Postgres is long-term memory.

Redis is short-term job coordination.

## Page 9: What FastAPI and Celery do

### FastAPI

FastAPI is the web server framework.

It is the part of the software that receives browser and API requests.

For example, when a user clicks "Start scan", the browser sends a request to FastAPI.

FastAPI then decides what to do:

- validate the request
- create a scan record
- queue a background job
- return a response

Think of FastAPI as:

- the front desk of the application

It receives requests and routes them to the right internal logic.

### API

API means application programming interface.

An API is how software talks to software.

The UI is one client of the API.

Scripts and integrations can also call the API.

Examples:

- `GET /health`
- `POST /scans`
- `GET /assets`
- `POST /remediations/suggest`

### Celery

Celery is a background job system.

Some tasks take longer than a normal web request should take.

Examples:

- running scans
- syncing GitHub repositories
- validating remediation code
- checking drift
- sending webhook retries

Celery lets the API hand work to workers.

Think of Celery as:

- the task dispatcher and worker system

### Celery worker

A worker is a process that performs background jobs.

For example:

- worker receives scan job
- worker scans target
- worker stores result

### Celery beat

Celery beat is the scheduler.

It tells Celery when recurring jobs should run.

For example:

- run this collection scan every day
- drain webhook queue periodically
- check drift on a schedule

Think of Celery beat as:

- the alarm clock for recurring work

## Page 10: What Cloud Run and Secret Manager do

### Cloud Run

Cloud Run is a Google Cloud service for running containers.

Instead of managing servers directly, you give Cloud Run a Docker image and say:

- run this as a web service
- run this as a worker
- scale it within these limits

Morrow uses Cloud Run for:

- the API service
- worker processes
- scheduler process

Think of Cloud Run as:

- a managed place to run the Docker containers

### Artifact Registry

Artifact Registry stores Docker images.

Before Cloud Run can run the app, the Docker image has to be stored somewhere.

Artifact Registry is that storage location.

Think of it as:

- the container image warehouse

### Secret Manager

Secret Manager stores sensitive values.

Examples:

- database URL
- OpenAI API key
- vault encryption key
- GitHub webhook secret

These values should not be committed to Git or hardcoded in source files.

Secret Manager gives the cloud runtime access to them securely.

Think of Secret Manager as:

- a secure password vault for cloud services

### Service account

A service account is an identity used by software.

Humans log in with user accounts.

Software services use service accounts.

The Morrow runtime service account is allowed to:

- read needed secrets
- connect to cloud services
- run with controlled permissions

Think of a service account as:

- a non-human user for cloud software

## Page 11: What Auth0, JWT, and roles do

### Authentication

Authentication answers:

- who are you?

When a user logs in, the system verifies identity.

### Authorization

Authorization answers:

- what are you allowed to do?

For example:

- a viewer can read
- an operator can run workflows
- an admin can manage credentials and sensitive setup

### Auth0

Auth0 is an identity provider.

It handles login.

Instead of Morrow building its own password system, Auth0 can handle:

- user accounts
- login page
- tokens
- identity claims

Think of Auth0 as:

- the login provider

### JWT

JWT stands for JSON Web Token.

A JWT is a signed digital token that says who the user is and what claims they have.

Claims are pieces of information in the token.

Examples:

- user ID
- role
- organization ID

Morrow reads the JWT and uses it to decide:

- who the actor is
- what role they have
- what organization they belong to

### Roles

The product uses three basic roles:

- viewer
- operator
- admin

Viewer:

- can look at dashboards, assets, reports, scans, and remediation status

Operator:

- can run scans, approve fixes, validate remediations, and operate day-to-day workflows

Admin:

- can manage credentials, organizations, sensitive configuration, and setup actions

Roles matter because not every user should be able to change credentials or create code changes.

## Page 12: What OpenAI does in the product

OpenAI is used for AI-assisted remediation suggestions.

The product sends the model context such as:

- what asset has the issue
- what the vulnerability is
- what file is being changed
- what the current file content is

The model returns a suggested fix.

The product expects either:

- a diff
- or the full updated file content

This suggestion is not automatically trusted.

The product adds safety steps:

- guardrails block dangerous categories like IAM and firewall changes
- a human must review and approve
- validation must pass before PR creation
- GitHub PR review still happens

Think of AI here as:

- a code suggestion assistant

It is not the final authority.

The final authority is the workflow:

- review
- validation
- pull request
- merge
- verification

## Page 13: What validation means

Validation means checking the suggested fix before it reaches GitHub as a pull request.

This matters because AI can make mistakes.

Validation is a safety gate.

For Terraform files, validation can check:

- formatting
- initialization
- syntax validity
- whether Terraform accepts the file

If validation passes, the product can create a pull request.

If validation fails, the product blocks the pull request unless an admin overrides.

Validation stores:

- status
- stdout
- stderr
- exit code
- details

In plain terms:

- stdout is normal command output
- stderr is error output
- exit code is the numeric result of a command

Exit code `0` usually means success.

Non-zero exit codes usually mean failure.

## Page 14: What the validation sandbox is

The sandbox is still part of the product, but it needs a precise explanation.

In this product, the sandbox means:

- a temporary validation workspace
- created for one remediation check
- separate from the real GitHub repository
- used to test the proposed file change before a pull request is created

Think of it as:

- a safe rehearsal area for the proposed fix

The product does not let the AI suggestion immediately change the real repository.

Instead, the validation flow works like this:

1. the remediation suggestion is stored
2. a human approves it
3. the platform creates a validation job
4. the worker downloads a copy of the GitHub repository
5. the worker creates a temporary folder
6. the worker writes the proposed file into that temporary copy
7. the worker runs validation commands
8. the worker stores the pass or fail result
9. pull request creation is blocked unless validation passed

For Terraform files, the sandbox can run:

- Terraform formatting check
- Terraform initialization without using the real backend
- Terraform validation

The phrase "without using the real backend" matters.

Terraform often has a backend where it stores infrastructure state. During validation, the product uses:

- `terraform init -backend=false`

In plain English, this means:

- prepare Terraform enough to validate the files
- do not connect to or modify the real infrastructure state backend

That makes validation safer.

The sandbox also uses a timeout. If the command takes too long, the job fails instead of running forever.

Important limitation:

- this is a validation sandbox, not a high-security hostile-code isolation system

By default, it runs inside the application worker container, in a temporary directory, with command timeouts, file-path safety checks, archive extraction checks, and a scrubbed command environment.

The stricter Docker isolation mode can run Terraform validation in a separate per-job container with network disabled and resource limits. That is stronger, but it is still not the same as a separate micro-VM or full hostile-code execution jail.

That is useful for validating normal infrastructure-code changes, but it should not be described as a military-grade security boundary.

For a stricter enterprise deployment, a future hardening step would be:

- run each validation job in a separate locked-down container
- remove unnecessary network access during validation
- use a temporary service account with minimal permissions
- delete the whole execution environment after each job

The current practical meaning is:

- AI suggestions are tested away from the real repository
- failed suggestions are blocked
- normal users cannot create a pull request unless validation passed
- admins can override validation only if policy allows it

## Page 15: What compliance reporting does

The compliance report gives evidence.

It answers questions such as:

- how many assets are tracked?
- how many have open risk?
- how many remediations exist?
- how many fixes passed validation?
- how many fixes were merged?
- how many were verified closed?
- how many drifted later?
- what recent alerts happened?

This matters for:

- security leaders
- auditors
- compliance teams
- engineering managers
- customer reporting

The dashboard is the human-friendly view.

The JSON report is the machine-readable view.

JSON is a structured data format that software can read.

Think of the compliance report as:

- a proof package showing what was found, what was fixed, and what stayed fixed

## Page 16: Real-life example, healthcare company

Imagine a healthcare company with these public systems:

- `portal.carehealth.com:443`
- `api.carehealth.com:443`
- `auth.carehealth.com:443`
- `staff.carehealth.com:443`

These systems may handle sensitive healthcare workflows.

The company creates assets:

- patient portal
- API gateway
- authentication system
- clinician dashboard

It labels them:

- owner: `digital-health`
- team: `platform`
- environment: `prod`
- criticality: `high`
- tags: `healthcare`, `phi`, `patient-facing`, `internet`

Then it creates a collection:

- `Patient Platform External`

The collection includes:

- portal
- API
- auth

Then it creates a schedule:

- scan daily

If a scan finds a TLS or crypto posture issue, the platform links the asset to a repository such as:

- `carehealth/platform-infra`

Then it creates a remediation suggestion.

The remediation may change an infrastructure file that controls:

- TLS policy
- load balancer settings
- edge configuration
- certificate settings

The change is validated.

Then a pull request is created.

After merge, the platform verifies closure.

Later, if someone changes the file again and breaks the expected fix, drift detection catches it.

That is the real business value:

- security finding becomes code fix
- code fix becomes verified evidence
- evidence stays monitored over time

## Page 17: What the dashboard means

The dashboard is the control screen.

It helps different people answer different questions.

Security leader:

- are we getting safer?
- how many issues remain?
- how much was verified closed?
- what drifted?

Operator:

- what needs action today?
- what validation failed?
- what drifted?
- what needs follow-up?

Engineering manager:

- which team owns this?
- what fixes are waiting?
- what PRs exist?
- what is blocked?

Auditor:

- what evidence exists?
- when was it fixed?
- was it verified?
- was there drift?

Important dashboard fields:

- assets total
- open assets
- remediation status counts
- validated passed total
- verified closed total
- drifted total
- compliance readiness score
- recent alerts

In plain terms:

- assets total = how many things are tracked
- open assets = how many still need attention
- remediations total = how many fixes exist in the workflow
- validated passed = how many fixes passed checks
- verified closed = how many were proven fixed
- drifted = how many changed again later

## Page 18: Why the product matters

The strongest value of Morrow is that it connects security and engineering.

Many tools stop at:

- here is a vulnerability

This product tries to continue to:

- here is the owner
- here is the repo
- here is the suggested code change
- here is the validation result
- here is the pull request
- here is the verified closure
- here is drift monitoring afterward

That matters because companies do not only need to know what is wrong.

They need a repeatable way to fix it and prove it stayed fixed.

The product is especially relevant for:

- SaaS companies
- healthcare systems
- financial services
- government contractors
- security-conscious enterprises
- companies preparing for crypto agility and post-quantum migration

In one sentence:

Morrow turns external crypto and TLS risk into validated code remediation and verified evidence.

## Page 19: Glossary in simple words

### API

A way for software systems to talk to each other.

### Asset

A system or endpoint the company scans and tracks.

### Auth0

A login provider.

### Celery

A background job system.

### Cloud Run

Google's service for running containers without managing servers.

### Cloud SQL

Google's managed database service.

### Docker

A way to package software and its dependencies into a repeatable container.

### Drift

When something that was fixed later changes and no longer matches the expected fixed state.

### FastAPI

The Python web framework that receives requests and powers the API.

### GitHub

A platform where engineers store and review code.

### GitHub App

A secure integration identity that lets the product access GitHub repositories.

### JWT

A signed login token that proves who a user is and what claims they have.

### OpenAI

The AI provider used to generate remediation suggestions.

### Postgres

The main database. It stores product state.

### Pull request

A proposed code change in GitHub.

### Redis

A fast job queue used by background workers.

### Remediation

A proposed fix workflow.

### Secret Manager

A secure place to store sensitive cloud values.

### Terraform

A tool that describes cloud infrastructure as code and can validate infrastructure files.

### TLS

The security protocol behind HTTPS.

### Vault

The product's encrypted credential storage.

### Verified closed

The product checked after the fix and confirmed the issue is actually gone.

### Webhook

An automatic message sent from one system to another when something happens.

---

## Non-Technical Part: User Guide

# Morrow User Guide

This guide explains how to use Morrow as an operator, security lead, or administrator.

It covers:

- login and access
- first-time setup
- scanning
- assets, ownership, and environment metadata
- collections and schedules
- repository sync and linking
- remediations
- validation, pull requests, and verification
- drift detection
- webhooks and notifications
- dashboard and compliance reporting
- deployment and runtime configuration
- common troubleshooting steps

## 1. What the product does

Morrow is a workflow platform for external crypto and TLS risk.

At a high level it does this:

1. scans internet-facing assets
2. stores the results and keeps history
3. links assets to the repository that owns the fix
4. creates an AI-assisted remediation suggestion
5. validates the suggested change before opening a PR
6. opens the PR in GitHub
7. verifies the issue is actually closed after merge
8. keeps monitoring for drift later

The product is strongest when used as a continuous loop, not a one-off scan tool.

## 2. User roles

The app uses three main roles.

- `viewer`
  - can read dashboards, assets, scans, reports, and remediation state
  - cannot change data or trigger write actions

- `operator`
  - can scan, classify assets, create remediations, validate, approve, and run most day-to-day operations

- `admin`
  - can manage credentials, organizations, auth-sensitive actions, synthetic verification scans, and operational setup

## 3. How to access the app

### Hosted / SaaS mode

Open the application URL in a browser and log in through the configured identity provider.

Example hosted URLs:

- app UI: `https://YOUR_DEPLOYED_HOST/ui/`
- machine-readable org report: `https://YOUR_DEPLOYED_HOST/org/compliance-report?format=json`

### Local Docker mode

From `backend/`:

```powershell
docker compose up -d
```

Then open:

- UI: `http://localhost:8000/ui/`
- health check: `http://localhost:8000/health`

### Local Python mode

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Then open:

- UI: `http://localhost:8000/ui/`

## 4. Login and session handling

The platform supports two auth patterns:

- `headers` mode
  - mainly for local development and tests
  - the UI can simulate actor/role headers

- `jwt` mode
  - for hosted environments
  - the UI uses a real bearer token from the identity provider

### If you see `jwt token is expired`

Clear the stored token in the browser and log in again.

In the browser console:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

Then click `Login` again.

## 5. First-time setup checklist

Use this order for a clean first setup.

### Step 1: confirm the organization context

In a multi-tenant deployment, every asset, repo, remediation, and report belongs to an organization.

If you are in a new environment, confirm:

- your organization exists
- your token or local actor context resolves to the correct `org_id`

### Step 2: add credentials to the vault

Credentials are stored through the vault API and used by GitHub, webhooks, and optional connectors.

Supported patterns include:

- `github_app`
- `github`
- `webhook`
- `generic`

Example API call:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/vault/credentials" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin"} `
  -ContentType "application/json" `
  -Body '{"name":"github-app-main","provider":"github_app","secret":"<secret or key material>","meta":{}}'
```

Important:

- normal credential listing hides the raw secret
- only admins should use reveal or rotate actions

### Step 3: sync GitHub App installations

If you use a GitHub App credential, sync installations first:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/github-app/sync-installations" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"async_mode":false}'
```

Then list installations:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/integrations/github-app/installations" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Step 4: sync repositories for an installation

Use the returned `installation_id`:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/github-app/sync-repositories" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"installation_id":112874196,"async_mode":false}'
```

Then confirm repositories exist:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/repositories" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Step 5: set up webhook destinations if needed

Create outbound webhooks for alerts such as:

- `validation.failed`
- `remediation.merged`
- `remediation.drifted`
- `remediation.drift_followup_created`

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"name":"ops-channel","url":"https://example.com/webhook","secret":"shared-secret","events":["validation.failed","remediation.merged"],"enabled":true}'
```

## 6. The main screens and what they are for

### Dashboard

Use it to answer:

- how much risk exists now
- how much is being fixed
- how many remediations are verified closed
- how many items drifted later

The dashboard is the best opening screen for demos and the best daily posture view for operators and security leads.

### Assets

Use it to:

- open a specific asset
- assign owner, team, environment, and criticality
- attach tags
- inspect scan history
- confirm repository linkage

### Repositories

Use it to:

- confirm GitHub sync worked
- inspect which repos exist in the platform
- cross-check repo-to-asset linkage

### Collections

Use it to save reusable scan target groups.

### Schedules

Use it to run recurring scans from collections.

### Remediations

Use it to:

- create suggestions
- review content
- approve or reject
- validate
- create PRs
- inspect verified closure
- inspect drift and follow-up work

### Integrations / webhooks

Use it to:

- manage outbound notifications
- test webhook delivery
- inspect webhook delivery failures

### Compliance report

Use it to:

- generate machine-readable evidence
- inspect summary metrics
- review remediation and drift state
- feed dashboards or external systems

## 7. Running a scan

There are two scan styles:

- synchronous scan: `POST /scan`
- asynchronous scan: `POST /scans`

The UI typically uses a simple scan workflow. For automation and persistence testing, the async path is the more complete flow.

### One-time scan (simple)

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scan" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"targets":["www.cloudflare.com:443"]}'
```

This returns scan results directly.

### Persistent async scan

Create the scan:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scans" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"targets":["www.cloudflare.com:443"]}'
```

Poll status:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/scans/<scan_id>" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

Fetch stored results:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/scans/<scan_id>/results" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### What scan results mean

Important fields include:

- `host`
- `port`
- `risk_level`
- `tls_version`
- `key_type`
- `sig_algorithm`
- `findings`
- `pqc_recommendation`
- `quantum_risk_score`

Use scans to establish current exposure and to build historical trends.

## 8. Managing assets

An asset is the operational object that ties scan results to ownership and downstream workflow.

### Open or create an asset record

If an asset is not yet classified, opening it creates a blank metadata record.

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### Recommended asset fields

Set these consistently:

- `owner`
  - accountable individual or group
  - example: `web-team`

- `team`
  - delivery team responsible
  - example: `platform`

- `environment`
  - use a fixed vocabulary
  - recommended:
    - `prod`
    - `staging`
    - `dev`

- `criticality`
  - recommended:
    - `low`
    - `medium`
    - `high`

- `tags`
  - example:
    - `internet`
    - `tls`
    - `customer-facing`

### Update asset metadata

Example:

```powershell
Invoke-RestMethod -Method Put -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"owner":"web-team","team":"platform","environment":"prod","criticality":"high","tags":["internet","tls"]}'
```

### Asset history

Asset history shows how risk changed over time.

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443/history" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 9. Collections

A collection is a saved group of targets.

Use collections when:

- you want repeatable scans
- you want to schedule recurring checks
- you want to separate environments or customers

### Create a collection

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/collections" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"name":"Cloudflare Demo","targets_text":"www.cloudflare.com:443"}'
```

### Run a collection

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/collections/1/scan" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 10. Schedules

A schedule runs a collection automatically on an interval.

### Create a schedule

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/schedules" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"} `
  -ContentType "application/json" `
  -Body '{"collection_id":1,"interval_minutes":1440,"enabled":true}'
```

### Schedule fields

- `collection_id`
  - the collection being monitored

- `interval_minutes`
  - scan frequency

- `enabled`
  - whether the schedule is active

### Run a schedule immediately

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/schedules/1/run-now" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

## 11. Repository linkage and correlation

Repository linkage is the bridge from asset risk to code ownership.

### Automatic correlation

The platform supports a correlation pass that searches repo content for asset hints.

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/correlate-assets" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"credential_id":15,"asset_limit":500,"async_mode":false}'
```

### Manual repository linkage

If correlation does not link an asset automatically, set the repository manually on the asset.

Example:

```powershell
Invoke-RestMethod -Method Put -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"owner":"web-team","team":"platform","environment":"prod","criticality":"high","tags":["internet","tls"],"repository_id":1}'
```

This is a valid operational fallback and often the fastest path for demos or early deployments.

## 12. Compliance gate

The compliance gate answers:

- does this repository have linked critical assets?

### Run the gate

Example:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/compliance/gate?repo=yasseennandally/hello-world" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"}
```

### How to read the result

- `status = PASS`
  - no linked critical asset currently fails the gate

- `status = FAIL`
  - one or more linked critical assets still carry critical posture

Use the compliance gate to move from "scan result" to "release / policy decision".

## 13. Creating a remediation

A remediation is a proposed code fix tied to:

- an asset
- a repository
- a file
- a vulnerability description

### Create a suggestion

Example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/suggest" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"asset_key":"www.cloudflare.com:443","repository_id":1,"file_path":"demo_asset_match.tf","vulnerability":"Critical TLS exposure for a production internet-facing asset. Update this infrastructure to improve post-quantum crypto agility and remove weak TLS posture assumptions.","github_credential_id":15}'
```

### What the remediation stores

- `original_content`
- `suggested_content`
- `suggested_fix`
- lifecycle status
- later PR, merge, verify, and drift metadata

### Guardrails

The remediation layer blocks certain unsafe change classes, including:

- IAM changes
- firewall changes
- AWS security group changes

If a suggestion request contains forbidden classes, the API returns a guardrail error instead of creating a remediation.

## 14. Approval and rejection

After suggestion, a remediation should be reviewed.

### Approve

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/approve" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"looks good"}'
```

### Reject

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/reject" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"needs a different approach"}'
```

## 15. Validation sandbox

Validation is the safety gate between AI output and GitHub PR creation.

The sandbox is a temporary validation workspace used for a proposed remediation.

It does not edit the real GitHub repository. The worker downloads a copy of the repository, writes the suggested file into a temporary directory, runs validation commands there, stores the result, and then the temporary workspace is discarded.

Current behavior:

- `.tf`, `.tfvars`, and `.hcl` files use the Terraform validator
- other files use a generic content sanity validator
- commands run with a timeout
- command execution uses a scrubbed environment so application secrets are not passed into validation subprocesses
- repository archive extraction rejects unsafe paths before files are unpacked
- output is stored in a validation job
- PR creation is blocked unless the latest validation passed, unless an admin explicitly overrides it

Important limitation:

- default mode is a validation workspace, not a separate high-security VM or micro-VM isolation boundary

Optional Docker isolation can run Terraform validation in a separate per-job container with network disabled, dropped capabilities, and CPU/memory limits. This is stronger than default workspace mode, but still should not be treated as a micro-VM hostile-code boundary.

Set `PQC_VALIDATION_ISOLATION_MODE=docker` and configure `PQC_VALIDATION_DOCKER_IMAGE` if your runtime has Docker access and you want this stricter mode.

For Terraform, the platform runs:

- `terraform fmt`
- `terraform init -backend=false`
- `terraform validate`

### Run validation

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/validate" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"validator_type":"auto","async_mode":false,"timeout_seconds":180}'
```

### How to read validation output

- `status = passed`
  - the proposed content is valid for the selected validator

- `status = failed`
  - the change is blocked from PR creation unless an admin overrides

Important fields:

- `validator_type`
- `exit_code`
- `stdout`
- `stderr`
- `details.commands`

## 16. Creating a pull request

After a remediation is approved and validation has passed, create the PR.

### Create PR

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/create-pr" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"branch_prefix":"fix/pqc-remediation","allow_unvalidated":false}'
```

### Notes

- branch names include the remediation id, timestamp, and unique suffix to avoid retry collisions
- if GitHub still reports a branch collision, retry the create PR action
- normal operators should not set `allow_unvalidated=true`
- admins can override validation if policy allows it

## 17. Merge and verification

### Merge

Once the PR is merged, the platform can mark the remediation as merged:

- automatically through the GitHub webhook
- or manually through the API

Manual example:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/mark-merged" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"merged_at":"2026-05-09T11:53:37Z"}'
```

### Verify closure

After merge, the platform expects a later scan to confirm the issue is actually closed.

If the next relevant result is clean enough, the remediation moves to:

- `verified_closed`

For demos or controlled verification, admins can use the synthetic scan path:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/scans/synthetic" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"scan_id":"verify-close-demo","results":[{"host":"www.cloudflare.com","port":443,"risk_level":"low","findings":[]}],"auto_close_merged":true}'
```

## 18. Drift detection

Drift means the repo content later diverged from the expected fixed state.

### Run drift check

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/drift/check" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"remediation_id":1,"github_credential_id":15,"async_mode":false}'
```

### Drift states

- `clean`
  - repo content still matches expected fixed content

- `drifted`
  - repo content diverged and needs attention

- `check_failed`
  - the drift check could not complete

### Acknowledge drift

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/drift/acknowledge" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"note":"accepted temporarily"}'
```

### Revalidate drift

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/remediations/1/drift/revalidate" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"github_credential_id":15,"async_mode":false}'
```

### Drift follow-up remediations

When drift is detected, the system can auto-create a follow-up remediation with:

- `origin_kind = drift_followup`
- `parent_remediation_id` pointing back to the original item

## 19. Dashboard and compliance report

### Dashboard

The dashboard is the best summary screen.

Use it to watch:

- current open assets
- remediation pipeline state
- validation coverage
- verified closures
- drift totals
- recent alerts

### Compliance report

Machine-readable report:

```text
/org/compliance-report?format=json
```

The report includes:

- organization metadata
- summary counts
- vulnerabilities / asset posture
- remediation lifecycle state
- validation status
- merged and verified-close timestamps
- drift status
- recent alerts and audit summary

This is the best artifact for audits, dashboards, and API consumers.

## 20. Outbound webhooks and notifications

Use outbound webhooks to push events into Slack-compatible, Discord-compatible, or generic endpoints.

### Create a webhook

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"} `
  -ContentType "application/json" `
  -Body '{"name":"ops","url":"http://webhook_sink:9001/hook","secret":"shared-secret","events":["validation.failed","remediation.merged","remediation.drifted","remediation.drift_followup_created"],"enabled":true}'
```

### Test it

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/integrations/webhooks/1/test" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

### Inspect delivery history

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/integrations/webhook-events?limit=20" `
  -Headers @{"x-user-role"="admin";"x-user-id"="sec-admin";"x-org-id"="org-alpha"}
```

Use this to troubleshoot:

- delivery failures
- retry scheduling
- event payloads

## 21. Optional Cloudflare connector

The app includes Cloudflare connector settings and dry-run policy support.

Use it if you want to:

- attach a Cloudflare credential
- inspect zones
- verify token access
- preview or dry-run policy application

This is optional and not required for the core PQC remediation workflow.

## 22. Deployment and configuration reference

This section covers the main runtime settings you are likely to change.

### Core runtime

| Variable | Meaning |
|---|---|
| `PQC_MAIN_DB_BACKEND` | Main app database backend. Use `postgres` for shared/cloud mode or local SQLite flow when appropriate. |
| `PQC_PRODUCT_DATABASE_URL` | Main Postgres connection string for app data. |
| `DATABASE_URL` | General database URL used by some integrations and older paths. |
| `CELERY_BROKER_URL` | Redis broker for background jobs. |
| `CELERY_RESULT_BACKEND` | Redis result backend for background tasks. |
| `PQC_VAULT_MASTER_KEY` | Encryption root for stored vault secrets. |
| `OPENAI_API_KEY` | Required for remediation suggestion generation. |
| `OPENAI_MODEL` | Optional override for the model used in remediation generation. |
| `PQC_API_KEY` | Optional API key protection for scan routes and docs. |
| `PQC_DEFAULT_ORG_ID` | Default organization id in non-hosted or simplified local setups. |
| `PQC_DEFAULT_ROLE` | Default role when using local header mode. |

### Auth

| Variable | Meaning |
|---|---|
| `PQC_AUTH_MODE` | `headers` for local/dev, `jwt` for hosted auth. |
| `PQC_AUTH_REQUIRED` | Force authenticated access when true. |
| `PQC_AUTH_PROVIDER_NAME` | Label shown in the UI, such as `Auth0`. |
| `PQC_AUTH_LOGIN_URL` | Hosted login URL used by the UI. |
| `PQC_AUTH_LOGOUT_URL` | Hosted logout URL used by the UI. |
| `PQC_AUTH_TOKEN_HELP` | Helper text shown in the UI. |
| `PQC_AUTH_JWT_ISSUER` | Expected JWT issuer. |
| `PQC_AUTH_JWT_AUDIENCE` | Expected JWT audience. |
| `PQC_AUTH_JWT_JWKS_URL` | JWKS endpoint for RS256 token verification. |
| `PQC_AUTH_JWT_SECRET` | Shared secret if using HS256 instead of JWKS. |
| `PQC_AUTH_USER_ID_CLAIM` | User id claim name, usually `sub`. |
| `PQC_AUTH_ROLE_CLAIM` | Role claim name. |
| `PQC_AUTH_ORG_ID_CLAIM` | Organization id claim name. |
| `PQC_AUTH_JWT_ALGORITHMS` | Allowed JWT algorithms. |
| `PQC_AUTH_CLOCK_SKEW_SECONDS` | JWT clock skew tolerance. |

### Scan / API limits

| Variable | Meaning |
|---|---|
| `PQC_RATE_LIMIT_WINDOW_SECONDS` | Rate-limit window length. |
| `PQC_RATE_LIMIT_MAX_REQUESTS` | Max requests allowed in that window. |
| `PER_TARGET_TIMEOUT` | Target-level scan timeout. |

### Local Docker defaults

The local Docker stack is configured in `backend/compose.yml`.

It expects:

- Postgres
- Redis
- API
- worker
- beat

If you change Dockerfile dependencies, rebuild the images:

```powershell
docker compose build api worker beat
docker compose up -d --force-recreate api worker beat
```

## 23. Recommended naming standards

Use a fixed vocabulary for the metadata fields so reports stay clean.

### Environment

Recommended values:

- `prod`
- `staging`
- `dev`

### Criticality

Recommended values:

- `low`
- `medium`
- `high`

### Team

Use real delivery team names only.

Examples:

- `platform`
- `backend`
- `network`
- `security`

### Owner

Use one of:

- a real accountable person
- a real owning group

Do not mix many naming styles for the same responsibility.

## 24. Troubleshooting

### `jwt token is expired`

Clear the stored UI token and log in again:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

### Local validation says Terraform is not installed

Your local containers are stale. Rebuild them:

```powershell
docker compose build api worker beat
docker compose up -d --force-recreate api worker beat
```

### Asset is scanned but not visible in `/assets`

Scan history and asset inventory are different concepts.

Open the asset directly or classify it explicitly:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/assets/www.cloudflare.com:443" `
  -Headers @{"x-user-role"="operator";"x-user-id"="operator-user"}
```

### Automatic correlation did not link the repo

Run repo sync again, then either:

- retry correlation
- or manually set `repository_id` on the asset

Manual linkage is an acceptable operational workflow.

### PR creation fails with a GitHub branch conflict

Branch names are generated with a unique suffix. If GitHub still reports a collision, retry the create PR action.

### Validation fails before PR creation

Read:

- `exit_code`
- `stderr`
- `details.commands`

Fix the proposed content or reject the remediation.

### Webhooks are queued but not delivered

Inspect:

- `/integrations/webhook-events`

Check:

- destination URL
- DNS reachability
- shared secret
- retry state

## 25. Suggested operating routine

Use this loop daily or per release window:

1. check the dashboard
2. review new alerts
3. scan key collections
4. classify new assets
5. confirm repository links
6. run compliance gate on important repos
7. create or review remediations
8. validate fixes
9. create PRs
10. verify closure after merge
11. review drift and follow-up work

## 26. Demo-friendly workflow

If you need to demonstrate the product, use this sequence:

1. dashboard
2. collection
3. scan
4. asset metadata
5. repository linkage
6. schedule
7. remediation suggestion
8. validation
9. PR
10. verified closure
11. drift
12. compliance report

This keeps the narrative clean:

- detect
- own
- fix
- validate
- prove
- monitor

---

## Non-Technical Part: UI Button and Feature Guide

# Morrow UI Button and Feature Guide

This guide explains the visible UI controls in Morrow: what each button means, when to use it, what it sends to the backend, and what result to expect.

Use this document when demoing the product, onboarding an operator, or explaining the workflow to a customer.

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

---

## Non-Technical Part: Try It In The Cloud

# Morrow: Try It In The Cloud

This guide is for someone using Morrow through a hosted web URL in a browser.

It is intentionally non-technical. It explains:

- how to access the hosted app
- what must already be set up
- what "deployment" means in practice
- how to try the product with a real-world example

This guide is for two kinds of people:

- end users who just want to log in and use the product
- admins who need to prepare the hosted environment first

## 1. What "cloud" means here

In the cloud version, users do not install the product on their own machine.

They:

- open a browser
- go to the app URL
- log in
- use the product

Examples:

- vendor-hosted: `https://app.your-company.com`
- private company deployment: `https://security.company-internal.com`

For the current demo environment, the hosted UI is:

- `https://YOUR_DEPLOYED_HOST/ui/`

## 2. Who needs to do deployment

Most users do not deploy anything.

If you are an end user:

- you only need the URL and a login

If you are the platform admin:

- you or your vendor must deploy the platform first
- then you give users the URL

In practice:

- SaaS/hosted model:
  - the platform is already deployed
  - users only access it through the URL
- private cloud model:
  - your company deploys it into its own cloud account
  - users still access it through a browser URL after that

## 3. What must be set up before anyone can use it

Before end users can try the hosted app, the environment should already have:

- a working app URL
- working login/authentication
- at least one organization or tenant
- at least one user account
- background jobs running
- database connected

If you want to use repository and remediation features, the environment should also have:

- a GitHub App credential configured
- the GitHub App installed in at least one repository or organization
- GitHub installations synced
- repositories synced into Morrow

If you want to use AI remediation suggestions, the environment should also have:

- the AI provider key configured

If you want notifications, the environment should also have:

- at least one outbound webhook destination configured

## 4. What an admin should verify before sharing the URL

Ask the admin to verify these before a trial or demo:

- the app opens in a browser
- users can log in
- the dashboard loads
- scans can run
- repositories are visible if GitHub is connected
- remediations can be created if GitHub and AI are configured

If any of that is missing, users can still view the dashboard and run basic scans, but the full workflow will not be available.

## 5. What access information a user needs

Ask the admin for:

- the web app URL
- your login account
- your role:
  - viewer
  - operator
  - admin
- confirmation that GitHub integration is enabled if you want remediation and PR features

## 6. Real-life examples of what to scan

Do not think of the product as "scan Cloudflare".

Cloudflare was only a safe public demo target.

In real life, you scan your own internet-facing systems.

### Healthcare example

Examples of real targets:

- `portal.carehealth.com:443`
- `api.carehealth.com:443`
- `auth.carehealth.com:443`
- `staff.carehealth.com:443`

### SaaS example

- `app.acme.com:443`
- `api.acme.com:443`
- `auth.acme.com:443`

### E-commerce example

- `www.shopco.com:443`
- `checkout.shopco.com:443`
- `api.shopco.com:443`

An asset in Morrow is usually a public endpoint like:

- `hostname:port`

## 7. Open the hosted app

Open the app URL in your browser.

Example:

- `https://YOUR_DEPLOYED_HOST/ui/`

If the environment is healthy, you should see the login option and then the main dashboard after signing in.

## 8. Log in

Click:

- `Login`

Then complete the sign-in flow.

When login succeeds, you should be returned to the app.

### If login looks broken

If you see an error like:

- `jwt token is expired`

clear the old session in the browser.

Open the browser console and run:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

Then log in again.

## 9. Start at the dashboard

The dashboard is the main summary screen.

It shows the current operating picture for the organization, including:

- tracked assets
- open risk
- remediations
- validated fixes
- verified closures
- drifted fixes
- compliance readiness score

Use it to answer:

- what risk exists right now
- what is being fixed
- what was confirmed closed
- what drifted later

You do not need to understand every field on the first day.

## 10. Pick one real endpoint for a first trial

For a first cloud trial, start with one public endpoint that your organization actually owns.

Examples:

- healthcare portal:
  - `portal.carehealth.com:443`
- SaaS app:
  - `app.acme.com:443`
- website:
  - `www.example.com:443`

Start with one target only. That makes the first walkthrough easier.

## 11. Run your first scan

In the app:

1. find the scan input
2. enter your endpoint, for example:
   - `portal.carehealth.com:443`
3. start the scan

What happens:

- the platform checks the endpoint
- stores the result
- calculates risk and posture details
- keeps that result for later review

After it finishes, inspect:

- risk level
- TLS version
- certificate details
- PQC recommendation

## 12. Open the asset

After the scan, go to:

- `Assets`

Open the asset you just scanned.

This asset page is where you add business context so the result becomes actionable.

## 13. Fill in owner, team, environment, and criticality

Set these fields on the asset:

- `owner`
  - who is accountable
- `team`
  - who should fix it
- `environment`
  - where it runs
- `criticality`
  - how important it is to the business
- `tags`
  - optional labels for grouping and search

### Healthcare example values

For `portal.carehealth.com:443`:

- owner = `digital-health`
- team = `platform`
- environment = `prod`
- criticality = `high`
- tags =
  - `healthcare`
  - `phi`
  - `patient-facing`
  - `internet`

### SaaS example values

For `app.acme.com:443`:

- owner = `customer-platform`
- team = `backend`
- environment = `prod`
- criticality = `high`
- tags =
  - `saas`
  - `customer-facing`
  - `internet`

Why this matters:

- owner = accountability
- team = routing
- environment = prioritization
- criticality = business importance
- tags = easier filtering later

## 14. Review asset history

Still on the asset page, inspect the history section.

This shows how the asset changed over time, including:

- scan timestamps
- risk levels
- posture changes

This is useful for:

- trend review
- audits
- demos

## 15. Create a collection

A collection is a saved group of targets.

Use collections when you want a repeatable scan set.

Example collections:

- `Patient Platform External`
- `Customer Login Surface`
- `Production APIs`

In the app:

1. open `Collections`
2. create a new collection
3. give it a clear business name
4. add one or more targets
5. save it

Example:

- collection name: `Patient Platform External`
- targets:
  - `portal.carehealth.com:443`
  - `api.carehealth.com:443`
  - `auth.carehealth.com:443`

## 16. Create a schedule

A schedule runs a collection automatically.

Use it when you want continuous monitoring instead of one-time scans.

In the app:

1. open `Schedules`
2. create a schedule
3. choose the collection
4. set the interval
5. enable it

Practical examples:

- daily for production websites
- every 12 hours for critical login endpoints
- weekly for lower-priority systems

What this gives you:

- repeatable scanning
- updated asset history
- fresh risk data without manual work

## 17. Check repositories

Open:

- `Repositories`

If GitHub integration is already configured, you should see synced repositories there.

Examples:

- `carehealth/platform-infra`
- `carehealth/api-infra`
- `acme/edge-config`

Why this matters:

- scanning tells you what is wrong
- repository linkage tells you where the fix belongs

## 18. Confirm the asset is linked to the right repository

Go back to the asset page and check whether the asset is linked to a repository.

Examples:

- `portal.carehealth.com:443` -> `carehealth/platform-infra`
- `api.carehealth.com:443` -> `carehealth/api-infra`

If the asset is linked, the platform can drive a code-level workflow.

If it is not linked, ask the admin to:

- sync GitHub installations
- sync repositories
- run correlation
- or attach the repository manually

## 19. Open remediations

Go to:

- `Remediations`

This is where the fix workflow lives.

A remediation record usually includes:

- the asset
- the linked repository
- the file to change
- the issue description
- the suggested fix
- the validation result
- the PR link
- merge status
- verification status
- drift status

## 20. Create a remediation suggestion

If the environment has GitHub and AI configured, create a remediation using:

- the scanned asset
- the linked repository
- the file path to change

Real-life examples of files that may be changed:

- Terraform for load balancer or ingress config
- edge/CDN config stored in GitHub
- TLS policy config
- infrastructure code that controls certificates or gateway behavior

What happens:

- the platform loads the current file from GitHub
- builds a suggestion from the finding and file context
- stores the original and suggested content

Then you can review:

- original content
- suggested content
- suggested diff

## 21. Approve or reject the remediation

After reviewing the suggestion:

- approve it if it is acceptable
- reject it if it needs a different approach

This human control step matters.

The platform is designed to assist engineering, not bypass review.

## 22. Validate the remediation

Once approved, run:

- `Validate`

This checks the candidate change before it becomes a pull request.

For infrastructure code, validation may include things like:

- formatting checks
- syntax checks
- tool validation steps

When validation passes, you should see a passed result.

If validation fails:

- review the output
- adjust the proposed change
- validate again

## 23. Create the pull request

When validation passes, create the PR.

The platform will:

- create a branch
- update the file
- commit the change
- open a GitHub pull request

You should then see:

- a PR URL
- a new remediation status reflecting PR creation or merge progress

## 24. Review the PR in GitHub

Open the PR URL to review:

- the code diff
- the changed file
- the branch
- the merge state

This is where the workflow moves into normal engineering review and merge.

## 25. Verified closure

After the PR is merged, the platform can later verify that the issue is actually gone.

That final state is:

- `verified_closed`

This is stronger than "merged".

It means:

- a fix was proposed
- a PR was created
- the PR was merged
- the issue was checked again
- the system confirmed the issue is closed

## 26. Drift detection

Sometimes a fix is merged and later changed by a human or a later code update.

That is drift.

The platform can detect that later and show:

- `drifted`

When drift happens, the platform can also create a follow-up remediation automatically.

That means the product does not stop at merge. It keeps watching afterward.

## 27. Use the dashboard again

After you have:

- scanned real assets
- classified them
- linked them to repositories
- created remediations
- validated fixes
- created PRs

go back to the dashboard.

Now it becomes the operating screen for the program.

Use it to see:

- current risk
- remediation throughput
- validated fixes
- verified closures
- drift
- recent alerts

## 28. Use the compliance report

Open the machine-readable report if your organization needs evidence or integration output.

Example:

- `https://YOUR_DEPLOYED_HOST/org/compliance-report?format=json`

This report is useful for:

- audit evidence
- internal dashboards
- security reporting
- external integrations

If you do not want raw JSON, stay in the dashboard. The dashboard is the human-facing summary of the same workflow.

## 29. Best first cloud trial

If you want the shortest realistic trial, do this:

1. open the app URL
2. log in
3. open the dashboard
4. scan one real endpoint your organization owns
5. open the asset
6. set owner, team, environment, and criticality
7. create a collection
8. create a schedule
9. open repositories
10. confirm repository linkage
11. open remediations
12. inspect an existing remediation or create one if the environment is ready
13. review validation, PR, and closure state
14. return to the dashboard

That is enough to understand the cloud product.

## 30. What end users should not need to do

End users should not need to:

- deploy servers
- configure databases
- set up background workers
- manually wire authentication
- manually configure GitHub tokens

If users are being asked to do that, the environment has not been prepared properly yet.

## 31. What admins still need to set up behind the scenes

Admins may still need to set up:

- the hosted deployment itself
- DNS/domain and TLS
- login/authentication provider
- GitHub App and repository access
- AI key for remediation suggestions
- outbound webhooks for alerts
- user accounts and roles

That is normal. Those are environment setup tasks, not day-to-day user tasks.

## 32. If something goes wrong

### Login fails

Clear the stored browser token and log in again:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

### Dashboard opens but scans fail

Ask the admin to verify:

- API and workers are healthy
- your role allows scanning
- the environment is fully configured

### Repositories are missing

GitHub setup is probably incomplete.

Ask the admin to:

- sync GitHub App installations
- sync repositories

### Asset is not linked to a repository

Ask the admin to:

- rerun correlation
- or attach the repository manually

### Remediation creation fails

Common reasons:

- repository is not linked
- GitHub access is not configured
- the file path is wrong
- AI provider is not configured
- the suggestion could not be applied cleanly

### Validation fails

That usually means the proposed fix needs review before it is safe to send to GitHub. Check the validation output and adjust the remediation.

## 33. What to try next

After your first hosted run, try these:

- add more real assets
- create more collections by business area
- create production schedules
- compare scan history across time
- review validated fixes
- review verified-closed remediations
- review drifted remediations
- open the compliance report

If GitHub is fully configured, then also try:

- create a new remediation
- validate it
- create a PR
- follow it through merge and verified closure

---

## Non-Technical Part: Try It On Your Machine

# Morrow: Try It On Your Machine

This guide is for someone who just wants to run the product locally and click through it.

It avoids most technical detail.

## What you need

Before you start, make sure you have:

- a Windows, Mac, or Linux machine
- Docker Desktop installed and running
- the Morrow project folder on your machine

If you do not have Docker Desktop yet, install that first.

## What this local run gives you

When you run the app locally, you get:

- the web app
- the scan engine
- the background worker
- the database
- the scheduler

You will be able to:

- open the dashboard
- run scans
- create assets and metadata
- create collections and schedules
- try remediation flows
- inspect reports

## 1. Start Docker Desktop

Open Docker Desktop and wait until it shows that Docker is running.

Do not skip this step.

## 2. Open the project folder

Open PowerShell or Terminal.

Go to the backend folder.

Example on Windows:

```powershell
cd C:\Users\Samsung\Desktop\pqc-scanner\backend
```

## 3. Start the app

Run:

```powershell
docker compose up -d
```

What this does:

- starts the web app
- starts the worker
- starts the scheduler
- starts Postgres
- starts Redis

The first start can take a little longer.

## 4. Open the local app

Open this in your browser:

- `http://localhost:8000/ui/`

If the page does not open immediately, wait 20 to 30 seconds and refresh once.

## 5. Check that it is working

Open this in the browser:

- `http://localhost:8000/health`

You should see:

```json
{"status":"ok"}
```

If you see that, the local app is running.

## 6. Understand the local login behavior

In local mode, the app usually runs in a simple development auth mode.

That means:

- you normally do not need a real external login
- the local UI may let you act as a demo user or operator directly

If the UI shows role or actor controls, use:

- role: `operator`
- actor/user: anything simple, for example `local-user`

If the UI does not ask for login and just opens, that is also fine.

## 7. First thing to look at: the Dashboard

When the app opens, start with the Dashboard.

The dashboard shows:

- how many assets exist
- how many remediations exist
- how many fixes passed validation
- how many were verified closed
- how many drifted later
- overall readiness score

You do not need to understand every field at first.

Just use it as the main summary screen.

## 8. Create your first scan

Use a simple public target for testing.

Recommended example:

- `www.cloudflare.com:443`

In the UI:

1. find the scan input
2. enter `www.cloudflare.com:443`
3. click the button to start the scan

What happens:

- the app checks the external endpoint
- it stores the result
- it gives you TLS and crypto posture details

After it completes, you should be able to inspect the result in the app.

## 9. Create your first asset record

After scanning, go to the Assets section.

Open the asset:

- `www.cloudflare.com:443`

Now fill in some simple metadata.

Use these example values:

- owner: `web-team`
- team: `platform`
- environment: `prod`
- criticality: `high`
- tags:
  - `internet`
  - `tls`

Why this matters:

- it gives the asset ownership
- it gives the dashboard more meaning
- it helps route work later

## 10. Create your first collection

A collection is just a saved list of targets.

Use it when you want repeatable scans.

In the UI:

1. open `Collections`
2. create a new collection
3. name it:
   - `Cloudflare Demo`
4. add the target:
   - `www.cloudflare.com:443`
5. save it

Now you have a reusable target group.

## 11. Create your first schedule

A schedule runs a saved collection automatically.

In the UI:

1. open `Schedules`
2. create a new schedule
3. choose:
   - collection: `Cloudflare Demo`
4. choose an interval
   - for testing, use something short if available
   - for realistic use, daily is better
5. enable it

Now the app can keep scanning that target automatically.

## 12. Check the asset history

Go back to the asset page for:

- `www.cloudflare.com:443`

Open the history section.

This shows:

- when the asset was scanned
- what risk level it had
- how it changed over time

That is useful for demos and for trend tracking.

## 13. Look at repositories

Open the Repositories section.

If your environment is already set up with GitHub integration, you should see synced repositories there.

If you do not see any repositories, that usually means:

- GitHub sync has not been done yet
- or the environment is not configured for GitHub yet

That is normal for a first local try.

You can still explore the scan, asset, collection, schedule, and report parts without GitHub.

## 14. Try the compliance report

Open:

- `http://localhost:8000/org/compliance-report?format=json`

This is the machine-readable report.

It shows:

- asset posture
- remediation summary
- validation summary
- drift summary
- audit summary

If you do not want to read raw JSON, just return to the Dashboard.

The dashboard presents the same story in a friendlier way.

## 15. Try the dashboard again

Now that you have:

- a scan
- an asset
- metadata
- a collection
- a schedule

go back to the Dashboard.

It should make more sense now.

Use it to answer:

- what assets are being watched
- what risk exists
- what work has been created
- what still needs attention

## 16. Optional: try remediations

This part depends on a configured GitHub credential and repository sync.

If your environment already has that set up, you can:

1. open `Remediations`
2. create a suggestion for a linked asset/repo
3. review the suggested fix
4. approve it
5. validate it
6. create a PR

If your local setup does not already have GitHub credentials configured, skip this part for now.

You can still fully explore the scanning, asset, schedule, dashboard, and report features.

## 17. How to stop the app

When you are done, go back to PowerShell or Terminal and run:

```powershell
docker compose down
```

If you want to start it again later, use:

```powershell
docker compose up -d
```

## 18. Common issues

### The page does not load

Check:

- Docker Desktop is running
- `docker compose up -d` finished
- `http://localhost:8000/health` returns `{"status":"ok"}`

### I see an auth error

If you are in local mode, refresh the page.

If the UI has stale login data, open browser console and run:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

### A scan fails

Try a known public target first:

- `www.cloudflare.com:443`

That removes most local data-entry mistakes.

### Repositories or remediations are missing

That usually means your local environment is not yet configured with GitHub credentials and repository sync.

This does not block basic scanning and dashboard use.

## 19. The simplest good first run

If you want the shortest possible path, do exactly this:

1. start Docker Desktop
2. run:

```powershell
cd C:\Users\Samsung\Desktop\pqc-scanner\backend
docker compose up -d
```

3. open:
   - `http://localhost:8000/ui/`
4. run a scan for:
   - `www.cloudflare.com:443`
5. open the asset and set:
   - owner = `web-team`
   - team = `platform`
   - environment = `prod`
   - criticality = `high`
6. create a collection named:
   - `Cloudflare Demo`
7. create a schedule for that collection
8. go back to the dashboard

That is enough to understand the basic product.

## 20. What to try next

After your first run, try these next:

- scan a second target
- add more asset tags
- compare asset history over time
- create multiple collections
- test a second schedule
- explore the compliance report JSON

If GitHub is configured in your environment, then next try:

- repository sync
- remediation suggestion
- validation
- PR creation

---

---

# Section 2: Technical Documentation

This section is for engineers, platform operators, security architects, and deployment owners. It explains the implementation, APIs, data model, runtime behavior, and operations model.

---

## Technical Part: Technical Reference

# Morrow Technical Reference

This document is the codebase-level technical reference for the current repository state.

It complements:

- `docs/USER_GUIDE.md`
- `docs/TRY_IT_ON_YOUR_MACHINE.md`
- `docs/TRY_IT_IN_THE_CLOUD.md`

Primary source files:

- `backend/app.py`
- `backend/db.py`
- `backend/db_postgres.py`
- `backend/tasks.py`
- `backend/scanner.py`
- `backend/policy.py`
- `backend/migration.py`
- `backend/remediation_validation.py`
- `backend/remediation_drift.py`
- `backend/events.py`
- `backend/integrations/github.py`
- `backend/integrations/github_app.py`
- `backend/integrations/gcp.py`
- `backend/vault_db.py`
- `backend/vault_crypto.py`
- `backend/static/index.html`
- `infra/gcp/cloudrun/`

## 1. System summary

Morrow is an end-to-end remediation loop, not only a TLS scanner.

It does all of the following:

- scans public endpoints for TLS, certificate, and PQC-readiness posture
- stores current and historical scan results
- tracks asset ownership and business metadata
- links assets to repositories
- creates migration guidance and prioritization views
- generates AI remediation suggestions
- validates candidate fixes before PR creation
- opens PRs in GitHub
- tracks merged PRs through GitHub webhook events
- verifies closure using later scan evidence
- checks for drift after merge
- emits webhook notifications
- records audit events
- exposes organization-level compliance reporting

The main workflow is:

1. detect
2. classify
3. link to code ownership
4. suggest fix
5. validate fix
6. create PR
7. mark merged
8. verify closed
9. monitor for drift

## 2. Runtime architecture

### 2.1 Components

The runtime has three application roles:

- API
  - FastAPI service
  - serves both JSON API and static UI
- worker
  - Celery worker
  - runs scans, validation, sync, correlation, and drift tasks
- beat
  - Celery beat scheduler

The container entrypoint is in `backend/entrypoint.sh` and switches behavior using `APP_COMPONENT`.

### 2.2 Storage and queues

The system uses:

- PostgreSQL
  - primary runtime database in current compose and cloud setups
- Redis
  - Celery broker and result backend
- in-memory API cache
  - `_SCANS` in `backend/app.py`
  - only for short-lived scan acceleration

Legacy SQLite support still exists in `backend/db.py`, but current production-like runtime is Postgres-backed.

### 2.3 Frontend

The frontend is a static HTML/JavaScript UI in:

- `backend/static/index.html`

FastAPI mounts it at:

- `/ui/`

Root `/` redirects to `/ui/`.

There is no separate frontend build pipeline in the current implementation.

### 2.4 Deployment targets

Local/container deployment:

- `backend/compose.yml`

Cloud deployment:

- `infra/gcp/cloudrun/`
- `infra/gcp/modules/private-cloud/`
- `infra/gcp/private-cloud-demo/`
- `scripts/setup-enterprise.sh`

The cloud stack provisions:

- Artifact Registry
- VPC and subnet
- Cloud SQL Postgres
- Memorystore Redis
- Secret Manager
- Cloud Run API
- Cloud Run worker pools

The private-cloud module packages the same stack for customer-owned VPC deployments. It supports a two-phase bootstrap where the customer first creates the private infrastructure and Artifact Registry, then builds/pushes the backend image, adds required secrets, deploys runtime services, and runs Alembic migrations through a one-off Cloud Run Job.

## 3. Execution model

### 3.1 Synchronous scan

Endpoint:

- `POST /scan`

Behavior:

- runs targets inline
- returns results and summary immediately
- does not create the full queued scan lifecycle

Use case:

- quick testing
- simple UI smoke flows

### 3.2 Asynchronous durable scan

Endpoint:

- `POST /scans`

Behavior:

- validates target list
- creates a durable scan row
- enqueues Celery task `pqc.run_scan_task`
- worker updates progress and stores results
- results are fetched later via `/scans/{scan_id}` and `/scans/{scan_id}/results`

This is the main durable scan path.

### 3.3 Synthetic scan

Endpoint:

- `POST /scans/synthetic`

Behavior:

- admin-only
- seeds synthetic results directly into storage
- useful for tests, demos, and verification workflows
- can auto-close merged remediations if the synthetic result proves closure

### 3.4 Scheduler authority

Two scheduling paths exist:

- legacy in-process scheduler in `backend/app.py`
- Celery beat scheduler in the deployed runtime

Important detail:

- when `WORKER_ROLE` is set, the in-process scheduler is disabled
- in Docker and Cloud Run, Celery beat is the intended scheduler authority

## 4. Feature inventory

### 4.1 Scanner

Implemented in:

- `backend/scanner.py`

The scanner collects:

- TLS handshake details
- certificate issuer and subject
- SAN coverage
- key type and key detail
- signature algorithm
- TLS version support
- accepted TLS 1.2 ciphers
- weak cipher acceptance
- ALPN
- OCSP stapling metadata
- OCSP/CRL reachability
- chain completeness and confidence
- verification failures and reasons

Important output fields include:

- `risk_level`
- `quantum_risk_level`
- `quantum_risk_score`
- `pqc_relevance`
- `pqc_recommendation`

### 4.2 Policy engine

Implemented in:

- `backend/policy.py`

The policy layer turns scanner facts into:

- findings
- severity
- risk level
- risk score
- PQC relevance
- aggregate summaries

Rule areas include:

- expired and expiring certs
- certificate verification failures
- incomplete chains
- hostname mismatch
- legacy TLS support
- weak ciphers
- lack of TLS 1.3
- RSA key exchange
- RSA and ECDSA certificate presence as migration signals

### 4.3 Migration planning

Implemented in:

- `backend/migration.py`

It maps finding rule IDs to ordered migration steps with:

- step title
- why it matters
- affected assets
- evidence samples

Exposed by:

- `GET /scans/{scan_id}/migration-plan`

### 4.4 Baselines and diffs

Features:

- set explicit per-asset baseline
- set baselines from an entire scan
- compare current scan against baseline
- compute per-asset new, resolved, and unchanged findings
- show top regressions and improvements

Core implementation lives in:

- `backend/app.py`
- `backend/db.py`
- `backend/db_postgres.py`

### 4.5 Asset inventory

Assets add business context on top of scan targets.

Fields include:

- `asset_key`
- `owner`
- `team`
- `environment`
- `criticality`
- `confidentiality_lifetime`
- `notes`
- `tags`
- `metadata`
- `repository_id`

Important behavior:

- `GET /assets/{asset_key}` auto-creates a blank asset if missing
- asset history comes from persisted `scan_results`
- assets can be manually linked to repositories

### 4.6 Collections and schedules

Collections:

- saved target sets using `targets_text`

Schedules:

- interval-based recurring scans
- store interval in minutes
- can be run immediately with `run-now`

### 4.7 Fix-next prioritization

Endpoint:

- `GET /fix-next`

Purpose:

- rank assets from a scan by priority score
- combine findings and asset metadata into a triage queue

### 4.8 Metrics and dashboard data

Endpoints:

- `GET /metrics/scan/{scan_id}/overview`
- `GET /metrics/trends`
- `GET /org/compliance-report`
- `GET /org/{organization_id}/metrics`
- `GET /org/{organization_id}/drift-analytics`

Aggregates include:

- open assets
- risk distribution
- remediation throughput
- validation pass rates
- verified closure rates
- drift counts
- developer-hours-saved estimate
- engineering-hours-saved per 100 remediations
- MTTR reduction estimate versus configured manual baseline
- manual non-compliant changes reverted through drift follow-up remediations
- compliance readiness score

### 4.9 Multi-tenancy

The product has an organization model implemented in the application and data layer.

Key pieces:

- request org context middleware in `backend/app.py`
- org-aware storage functions in `backend/db.py` and `backend/db_postgres.py`

Important current detail:

- tenancy is app-scoped
- database Row-Level Security is not implemented

### 4.10 Auth and RBAC

Auth modes:

- `headers`
  - local/manual mode using `x-user-id`, `x-user-role`, `x-org-id`
- `jwt`
  - hosted mode using verified bearer tokens

Public routes:

- `/`
- `/ui/*`
- `/health`
- `/auth/config`

`/auth/context` exposes effective session details.

Roles:

- `viewer`
- `operator`
- `admin`

Role enforcement is applied on selected routes using `_require_role`, with audit logging on both allow and deny outcomes.

### 4.11 Vault and credentials

Implemented in:

- `backend/vault_db.py`
- `backend/vault_crypto.py`

Secrets are:

- encrypted at rest using Fernet
- stored in Postgres table `credentials`

Current uses include:

- GitHub PATs
- GitHub App private keys
- GCP service account JSON
- Cloudflare API tokens
- webhook secrets

Important current detail:

- credentials are org-scoped by `organization_id`
- credential names are unique per organization, not globally

### 4.12 GitHub PAT integration

Implemented in:

- `backend/integrations/github.py`

Primary use:

- repository sync using a PAT-style credential

### 4.13 GitHub App integration

Implemented in:

- `backend/integrations/github_app.py`

Capabilities:

- build GitHub App JWT
- fetch installation access token
- resolve installation for repo
- mint repo-scoped token
- sync installations
- sync installation repositories

This is the preferred model for remediation, validation, and PR creation.

### 4.14 GCP sync

Implemented in:

- `backend/integrations/gcp.py`

Purpose:

- sync assets from Google Cloud using a vault-stored service account

### 4.15 Repository correlation

Implemented as Celery task:

- `pqc.correlate_assets`

Purpose:

- heuristically link assets to repositories by searching repository content for asset identifiers

Important nuance:

- correlation is heuristic, not guaranteed
- manual repository linkage remains a valid fallback

### 4.16 Remediation suggestion

Endpoint:

- `POST /remediations/suggest`

Flow:

1. resolve repository
2. resolve GitHub token
3. fetch current file from GitHub
4. build LLM prompt
5. call OpenAI
6. accept either a unified diff or full replacement content
7. apply diff if needed
8. strip wrapper text
9. run guardrails
10. persist remediation

Current guardrails explicitly block suggestions touching:

- IAM
- firewall
- security group resources

### 4.17 Validation

Implemented in:

- `backend/remediation_validation.py`

Capabilities:

- download repository archive
- apply proposed file content in temp workspace
- detect validator type
- run generic or Terraform validation

Sandbox model:

- validation runs in a Python `tempfile.TemporaryDirectory`
- the GitHub repository is downloaded as an archive into that temporary workspace
- archive extraction rejects unsafe paths and zip path traversal
- `file_path` is normalized and rejected if it contains path traversal
- the proposed `suggested_content` is written into the temporary repository copy
- validator commands run with a timeout and captured stdout/stderr/exit code
- validator subprocesses run with a minimal scrubbed environment instead of inheriting application secrets
- the temporary workspace is deleted after the validation function exits
- the latest passed validation is required before PR creation unless an admin uses `allow_unvalidated`

Security boundary note:

- default mode is an ephemeral validation workspace inside the API/worker container
- optional Docker mode runs Terraform validation in a separate per-job container with `--network none`, dropped Linux capabilities, no-new-privileges, CPU/memory limits, and a scrubbed environment
- Docker mode is enabled with `PQC_VALIDATION_ISOLATION_MODE=docker` and requires Docker access plus `PQC_VALIDATION_DOCKER_IMAGE`
- Docker mode is stronger than the default workspace mode, but it is still not a micro-VM or kernel-level hostile-code boundary

Current validator types:

- `auto`
- `terraform`
- `generic`

Terraform validation runs:

- `terraform fmt -check`
- `terraform init -backend=false`
- `terraform validate`

### 4.18 PR creation

Endpoint:

- `POST /remediations/{id}/create-pr`

Behavior:

- remediation must be approved
- remediation normally must have a passed validation
- admin can override with `allow_unvalidated`
- branch is created
- file is updated
- PR is opened
- remediation moves to `pr_created`
- branch, base branch, and GitHub credential metadata are stored for later branch cleanup
- PR body can include a link back to the remediation dashboard when `PQC_APP_BASE_URL` or `PQC_PUBLIC_APP_URL` is set

Current branch naming pattern:

- `{branch_prefix}-{remediation_id}-{timestamp}-{suffix}`

The timestamp and suffix make normal PR retries collision-resistant while preserving readable branch names.

After a remediation reaches `verified_closed`, `pqc.cleanup_remediation_branches` can delete the remediation branch from GitHub. The cleanup skips protected/default branches and records cleanup status, timestamp, error text, and attempt count on the remediation.

### 4.19 Merge tracking and verified closure

Merge tracking happens by:

- manual mark-merged endpoint
- GitHub webhook receiver

Webhook endpoint:

- `POST /integrations/github/webhook`

Behavior:

- optionally verifies `X-Hub-Signature-256`
- only acts on merged `pull_request` close events
- matches PR URL to remediation
- marks remediation merged
- emits merge event

Verified closure is driven by later scan evidence and stored as:

- `verification_scan_id`
- `closed_at`
- remediation status `verified_closed`

### 4.20 Drift detection

Implemented in:

- `backend/remediation_drift.py`

Capabilities:

- fetch current file from GitHub
- reconstruct expected post-fix content
- compare current vs expected content
- compute hashes and unified diff
- set drift state:
  - `clean`
  - `drifted`
  - `check_failed`
- auto-create follow-up remediation
- allow acknowledgement
- allow revalidation

### 4.21 Notifications and event rules

Implemented in:

- `backend/events.py`

Capabilities:

- outbound webhook registration
- delivery queue
- HMAC signing
- retry with backoff
- rules with filters and cooldown logic

Built-in event types include:

- `scan.completed`
- `scan.failed`
- `cert.expired`
- `cert.expiring_soon`
- `pqc.not_ready`
- `scan.regression`
- `validation.failed`
- `remediation.merged`
- `remediation.drifted`
- `remediation.drift_followup_created`
- `remediation.drift_acknowledged`

### 4.22 Cloudflare integration

Capabilities currently present:

- connect existing Cloudflare credential from vault
- rotate token
- verify token
- list zones
- store simple policy
- preview desired zone settings
- toggle enforcement
- mock apply
- apply policy to real zone
- inspect and clear Cloudflare audit state

Important note:

- this is a parallel integration feature set
- parts of it are explicitly dry-run friendly

### 4.23 Compliance gate

Endpoint:

- `GET /api/v1/compliance/gate?repo=owner/repo`
- `POST /integrations/ci/status-check`

Current logic:

- load assets linked to repo
- inspect latest scan posture for each linked asset
- return `FAIL` only if one or more linked assets are currently `critical`
- status-check mode can also inspect changed IaC snippets and fail the merge gate on general security policy violations
- status-check mode can optionally publish the resulting success/failure state back to GitHub as either a commit status or Check Run when a GitHub credential id and commit SHA are supplied

Medium/high findings do not fail the gate unless represented as `critical`.

### 4.23.1 General IaC security prototype

Implemented in:

- `backend/iac_security.py`

Current prototype rules:

- `IAC_OPEN_SSH_TO_INTERNET`
  - detects Terraform security group ingress that exposes SSH to a public CIDR
- `IAC_AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED`
  - detects incomplete S3 public access block controls

The remediation validation sandbox includes this policy check after generic/Terraform validation. This demonstrates that the same golden loop can validate non-crypto infrastructure fixes, not only PQC/TLS migrations.

### 4.23.2 MCP interface

Endpoint:

- `POST /mcp`

This is a lightweight JSON-RPC MCP-style interface for IDE assistants and external AIs. It supports:

- `tools/list`
- `tools/call` for `check_iac_compliance`
- `tools/call` for `check_repo_enforcement`

The goal is to let an external assistant ask whether a Terraform snippet or repository is compliant with the current organization policy before code is merged.

### 4.24 Audit logging

Audit records include:

- actor
- role
- action
- resource
- decision
- reason
- details JSON
- hash-chain fields

Postgres adds triggers to reject update/delete on `audit_logs`.

### 4.25 Observability and health

Runtime observability includes:

- structured JSON request logs with `organization_id`, method, path, status code, and latency
- optional Sentry exception capture through `SENTRY_DSN`
- Cloud Logging-compatible exception logs when Sentry is not configured
- `/health/deep` for Postgres and Redis connectivity checks
- optional deep `/health` behavior with `PQC_HEALTH_DEEP=1`

### 4.26 Organization lifecycle

Organization lifecycle controls include:

- admin archive endpoint that marks an organization subscription as `archived`
- admin delete endpoint that defaults to archive mode
- explicit purge mode for controlled deletion of org-scoped repositories, scans, remediations, webhooks, event rules, audit logs, collections, schedules, credentials, and related records

## 5. Code map

- `backend/app.py`
  - FastAPI app, middleware, orchestration, endpoints
- `backend/scanner.py`
  - raw TLS/certificate scanning
- `backend/policy.py`
  - finding generation and risk scoring
- `backend/migration.py`
  - migration-plan generation
- `backend/tasks.py`
  - Celery app and background tasks
- `backend/remediation_validation.py`
  - validator execution
- `backend/remediation_drift.py`
  - post-merge drift logic
- `backend/services/hndl.py`
  - HNDL object scoring and AWS/GCP/Azure storage inventory helpers
- `backend/services/repo_discovery.py`
  - generic repository ownership scoring and crypto/config discovery logic
- `backend/services/remediation_workflow.py`
  - remediation guardrails, next-action helpers, queue grouping, PR readiness checks, branch naming, PR title/body generation, and candidate content resolution
- `backend/services/github_pr.py`
  - GitHub API wrappers for branch creation, file updates, repository metadata, and pull request creation
- `backend/schemas.py`
  - shared request/data models extracted from the main FastAPI app
- `backend/idempotency.py`
  - Idempotency-Key handling for retry-safe write actions
- `backend/events.py`
  - outbound notifications and rules
- `backend/db.py`
  - legacy SQLite and dispatch layer
- `backend/db_postgres.py`
  - Postgres storage and schema
- `backend/vault_db.py`
  - encrypted credential storage
- `backend/vault_crypto.py`
  - Fernet encryption/decryption
- `backend/integrations/github.py`
  - PAT sync
- `backend/integrations/github_app.py`
  - GitHub App token minting and sync
- `backend/integrations/gcp.py`
  - GCP sync
- `backend/static/index.html`
  - static UI

## 6. Non-obvious implementation details

### 6.1 Org-scoped versus global tables

Org-scoped data includes:

- organizations
- repositories
- assets
- asset_tags
- baselines
- scan_results
- remediations
- validation_jobs
- audit_logs
- github_installations
- collections
- schedules
- scans
- webhooks
- webhook_events
- event_rules
- event_rule_fires

Global/shared tables currently include:

- integrations_settings

### 6.2 Scans are org-scoped

Top-level scans rows and scan_results carry organization context so scan audit trails and reporting can be tied to the owning tenant.

### 6.3 Credentials are org-scoped

Vault credentials carry `organization_id`. List, reveal, rotate, and token resolution paths only return credentials in the active organization context.

### 6.4 Collections and schedules are org-scoped

Collections and schedules carry `organization_id`; list/get/update/delete operations resolve through the active organization context.

### 6.5 The UI is intentionally thin

The UI mostly:

- calls backend endpoints
- stores API base
- stores bearer token
- reads `/auth/config`
- reads `/auth/context`

Most business logic is backend-side.

### 6.6 Vendor vs customer visibility

Customer-visible data is scoped to the active organization:

- dashboard and compliance report
- ROI metrics and drift analytics
- scans, scan results, assets, collections, and schedules
- repositories, remediations, validation jobs, PR URLs, verified closure, and drift state
- outbound webhooks, webhook delivery events, event rules, and audit logs
- CI gate and MCP compliance answers for the active organization

Vendor/operator-only visibility exists outside the normal customer UI:

- organization list, archive, and purge APIs
- Cloud Run logs and health
- Cloud SQL operational access and backups
- Secret Manager metadata and runtime secret wiring
- Terraform state and deployment outputs
- cross-tenant database inspection for support, if the vendor has database credentials

There is no polished cross-tenant vendor console yet. Vendor operations are currently done through admin APIs, cloud console, Terraform, logs, or direct database inspection.

### 6.7 Hosted auth is functional but transitional

The hosted auth bridge works with bearer tokens and current JWT config, but a full browser-native code+PKCE flow would still be a natural hardening step.

## 7. Testing map

Important tests:

- `backend/test_compliance_gate.py`
- `backend/test_sprint12_remediations.py`
- `backend/test_sprint13_rbac_audit_guardrails.py`
- `backend/test_sprint14_multitenancy.py`
- `backend/test_sprint14_github_app_bridge.py`
- `backend/test_sprint14_schema_migrations.py`
- `backend/test_sprint18_compliance_report.py`
- `backend/test_sprint19_drift_notifications.py`
- `backend/test_sprint20_drift_response.py`
- `backend/test_postgres_runtime_switch.py`
- `backend/test_postgres_cutover_utils.py`
- `backend/test_saas_auth_jwt.py`

Coverage areas:

- compliance gate
- remediation lifecycle
- RBAC and audit
- multi-tenancy
- GitHub App flows
- schema migration
- compliance report
- drift notifications and follow-up remediation
- Postgres cutover/runtime dispatch
- JWT auth

## 8. Current technical debt

- `backend/app.py` is large and mixes concerns
- FastAPI startup/shutdown uses lifespan handlers
- runtime timestamp generation uses timezone-aware UTC helpers; legacy stored rows may still contain older naive strings
- some shared tables weaken tenancy hardening
- repository correlation is heuristic
- remediation PR branches use unique suffixes to avoid normal retry collisions

## 9. Supporting technical docs

Use these alongside this file:

- `docs/API_REFERENCE.md`
- `docs/DATA_MODEL_AND_OPERATIONS.md`

---

## Technical Part: API Reference

# Morrow API Reference

This file is the grouped route inventory for `backend/app.py`.

It is not a generated OpenAPI dump. It is the maintainers' reference:

- method and path
- purpose
- main request fields
- important behavior notes

All API routes also accept the `/v1` prefix through compatibility middleware, for example `/v1/health` and `/v1/remediations`.

## 1. UI and health

- `GET /`
  - redirects to `/ui/`

- `GET /ui/*`
  - static frontend served from `backend/static/index.html`

- `GET /health`
  - health probe
  - returns `{"status":"ok"}`

- `GET /health/deep`
  - deep health probe
  - verifies Postgres and Redis connectivity

## 2. Auth and session context

- `GET /auth/config`
  - public
  - returns hosted auth mode/config for the UI
  - fields include:
    - `mode`
    - `required`
    - `provider_name`
    - `login_url`
    - `logout_url`
    - `token_help`
    - `bearer_token_supported`
    - `manual_actor_supported`

- `GET /auth/context`
  - returns effective session context
  - fields include:
    - `authenticated`
    - `auth_mode`
    - `organization_id`
    - `actor_id`
    - `actor_role`
    - `auth_error`

## 3. Organizations

- `GET /organizations`
  - admin-only
  - list organizations

- `POST /organizations`
  - admin-only
  - upsert organization
  - request:
    - `id`
    - `name`
    - `plan_type`
    - `subscription_status`

- `POST /organizations/{organization_id}/archive`
  - admin-only
  - marks an organization as archived

- `DELETE /organizations/{organization_id}`
  - admin-only
  - query:
    - `mode` (`archive|purge`, defaults to `archive`)
  - archive mode marks inactive; purge mode deletes org-scoped data

## 4. Compliance reporting

- `GET /org/compliance-report`
  - operator/admin
  - query:
    - `format` (`json` only)
    - `remediation_limit`
    - `asset_limit`
    - `audit_limit`
    - `include_audit`
  - returns organization summary, vulnerabilities, remediations, audit summary, recent alerts

- `GET /org/{organization_id}/metrics`
  - operator/admin
  - returns ROI metrics, engineering-hours-saved estimate, MTTR reduction, and drift analytics

- `GET /org/{organization_id}/drift-analytics`
  - operator/admin
  - returns day-2 governance metrics for drift events and reverted non-compliant changes

## 5. Scan execution

- `POST /scan`
  - legacy synchronous scan
  - request:
    - `targets: [string]`
  - response:
    - `count`
    - `results`
    - `summary`

- `POST /scans`
  - queued durable scan
  - request:
    - `targets: [string]`
  - response:
    - `job_id`
    - `id`
    - `status`
    - `created_at`
    - `progress`

- `POST /scans/synthetic`
  - admin-only
  - inject synthetic results
  - request:
    - `scan_id`
    - `created_at`
    - `results`
    - `auto_close_merged`

- `GET /scans/{scan_id}`
  - get durable scan status/progress

- `GET /scans/{scan_id}/results`
  - get scan with results and summary

- `GET /scans`
  - list recent scan rows
  - query:
    - `limit`

## 6. Baselines and diffs

- `GET /baselines`
  - list baselines

- `POST /baselines`
  - set explicit baseline for one asset
  - request:
    - `host`
    - `port`
    - `baseline_scan_id`

- `POST /baselines/from-scan/{scan_id}`
  - set baselines for all assets in a scan

- `GET /scans/{scan_id}/diff`
  - compare scan to explicit `baseline_scan_id` or stored per-asset baselines

## 7. Assets and inventory

- `GET /assets`
  - list assets
  - query filters:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `tag`
    - `limit`

- `GET /assets/{asset_key}`
  - get asset
  - auto-creates a blank asset record if absent

- `PUT /assets/{asset_key}`
  - upsert/update asset metadata
  - request:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `confidentiality_lifetime`
    - `tags`
    - `notes`
    - `metadata`
    - `repository_id`

- `GET /assets/{asset_key}/history`
  - historical scan snapshots for the asset

- `GET /tags`
  - list distinct tags

## 8. Repositories

- `GET /repositories`
  - list repositories

- `GET /repositories/{name}`
  - get repository by `owner/repo`

## 9. Migration planning and exports

- `GET /scans/{scan_id}/migration-plan`
  - ordered migration steps from current findings

- `GET /scans/{scan_id}/export.csv`
  - export scan results as CSV

## 10. Prioritization and metrics

- `GET /fix-next`
  - prioritized asset list from a scan
  - query:
    - `scan_id`
    - `limit`
    - `min_severity`
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `tag`

- `GET /metrics/scan/{scan_id}/overview`
  - scan overview metrics
  - query:
    - `owner`
    - `team`
    - `environment`
    - `criticality`
    - `top_n`

- `GET /metrics/trends`
  - time-series rollup
  - query:
    - `days`
    - `group_by` (`team|environment|owner|criticality`)
    - `metric` (`avg_score|avg_findings|assets_with_findings`)
    - `top_groups`

## 11. Collections and schedules

- `GET /collections`
  - list collections

- `POST /collections`
  - create/update collection
  - request:
    - `name`
    - `targets_text`

- `GET /collections/{collection_id}`
  - get collection

- `DELETE /collections/{collection_id}`
  - delete collection

- `POST /collections/{collection_id}/scan`
  - start scan from collection targets

- `GET /schedules`
  - list schedules

- `POST /schedules`
  - create schedule
  - request:
    - `collection_id`
    - `interval_minutes`
    - `enabled`

- `GET /schedules/{schedule_id}`
  - get schedule

- `PUT /schedules/{schedule_id}`
  - update schedule
  - request:
    - `interval_minutes`
    - `enabled`

- `DELETE /schedules/{schedule_id}`
  - delete schedule

- `POST /schedules/{schedule_id}/run-now`
  - immediate schedule execution

## 12. Jobs

- `GET /jobs/{job_id}`
  - query Celery result state and metadata

## 13. Integrations: GCP and GitHub

- `POST /integrations/gcp/sync`
  - sync GCP assets
  - request:
    - `credential_id`
    - `project_id`
    - `async_mode`

- `POST /integrations/github/sync`
  - sync GitHub repositories using PAT-style credential
  - request:
    - `credential_id`
    - `org`
    - `visibility`
    - `async_mode`

- `POST /integrations/github/connect-token`
  - simple UI-oriented GitHub connection flow
  - verifies a pasted GitHub token, stores it encrypted as an org-scoped Vault credential, and optionally syncs repositories
  - request:
    - `token`
    - `org`
    - `visibility`
    - `credential_name`
    - `sync_now`
  - response includes:
    - `credential_id`
    - `verified_as`
    - `sync`
  - plaintext token is never returned

- `GET /integrations/github-app/installations`
  - list synced GitHub App installations

- `POST /integrations/github-app/sync-installations`
  - sync GitHub App installations
  - request:
    - `credential_id`
    - `async_mode`

- `POST /integrations/github-app/sync-repositories`
  - sync repositories for one installation
  - request:
    - `credential_id`
    - `installation_id`
    - `async_mode`

- `POST /integrations/correlate-assets`
  - repository correlation job
  - request:
    - `credential_id`
    - `asset_limit`
    - `async_mode`

## 14. Integrations: webhooks and rules

- `POST /integrations/webhooks`
  - create/update outbound webhook
  - request:
    - `id`
    - `name`
    - `url`
    - `secret`
    - `credential_id`
    - `events`
    - `enabled`

- `GET /integrations/webhooks`
  - list configured outbound webhooks

- `DELETE /integrations/webhooks/{webhook_id}`
  - delete outbound webhook

- `POST /integrations/webhooks/{webhook_id}/test`
  - send signed test ping

- `GET /integrations/webhook-events`
  - list queued/sent/failed delivery records

- `POST /integrations/webhook-events/retry`
  - force retry pass for pending/failed deliveries

- `GET /integrations/settings`
  - get integration settings
  - includes generic settings and Cloudflare connector state

- `PUT /integrations/settings`
  - update settings
  - currently supports:
    - `cert_expiring_soon_days`
    - `record_suppressed_events`
    - `cloudflare_credential_id`

- `GET /integrations/rules`
  - list event rules

- `POST /integrations/rules`
  - create/update event rule
  - request can include:
    - `name`
    - `enabled`
    - `webhook_ids`
    - `event_types`
    - `min_severity`
    - `rule_ids`
    - `quantum_score_min`
    - `environments`
    - `teams`
    - `criticalities`
    - `tags`
    - `cooldown_minutes`

- `DELETE /integrations/rules/{rule_id}`
  - delete event rule

- `POST /integrations/rules/test`
  - test rules against a scan-derived event set

## 15. Vault credentials

Vault credential operations are scoped to the active organization context. The same credential name may exist in different organizations.

- `POST /vault/credentials`
  - admin-only
  - create vault credential

- `GET /vault/credentials`
  - operator/admin
  - list credentials without plaintext secret

- `GET /vault/credentials/{cred_id}`
  - operator/admin
  - get one credential without plaintext secret by default

- `GET /vault/credentials/{cred_id}/reveal`
  - operator/admin
  - reveal decrypted secret
  - sensitive endpoint

- `POST /vault/credentials/{cred_id}/rotate`
  - admin-only
  - rotate credential secret in place

## 16. Cloudflare integration

- `POST /integrations/cloudflare/connect`
  - connect existing vault credential to Cloudflare connector
  - request:
    - `credential_id`

- `POST /integrations/cloudflare/rotate`
  - rotate connected Cloudflare token
  - request:
    - `secret`
    - `credential_id` (optional)
    - `reason`

- `GET /integrations/cloudflare/status`
  - connector status summary

- `POST /integrations/cloudflare/verify`
  - verify token using Cloudflare `/user/tokens/verify`

- `GET /integrations/cloudflare/zones`
  - list zones

- `GET /integrations/cloudflare/my-ip`
  - return caller IP for allow-list help

- `GET /integrations/cloudflare/summary`
  - combined connection/verify/zones summary

- `GET /integrations/cloudflare/policy`
  - get current Cloudflare policy profile

- `POST /integrations/cloudflare/policy`
  - set current policy profile
  - request:
    - `min_tls`
    - `force_https`

- `GET /integrations/cloudflare/policy-preview`
  - preview desired zone settings from policy

- `GET /integrations/cloudflare/audit`
  - inspect last apply audit fields

- `GET /integrations/cloudflare/enforcement`
  - get enforcement toggle

- `POST /integrations/cloudflare/enforcement`
  - set enforcement toggle
  - request:
    - `enabled`

- `POST /integrations/cloudflare/audit/clear`
  - clear Cloudflare apply audit state

- `POST /integrations/cloudflare/zones/mock/apply-policy`
  - dry-run/mock policy apply without real zone
  - request:
    - `current_always_use_https`
    - `current_min_tls_version`
    - `policy_override`

- `POST /integrations/cloudflare/zones/{zone_id}/apply-policy`
  - apply policy to real zone
  - query:
    - `dry_run` (`0|1`)

## 17. Compliance gate

- `GET /api/v1/compliance/gate`
  - query:
    - `repo`
  - returns PASS/FAIL based on linked critical assets

- `POST /integrations/ci/status-check`
  - operator/admin
  - GitHub/GitLab-compatible merge/status-check response
  - evaluates linked asset policy and changed IaC snippets
  - can optionally publish a GitHub commit status or GitHub Check Run when `publish_to_github=true`
  - request:
    - `repo`
    - `ref`
    - `provider`
    - `require_verified_closed`
    - `changed_files`
    - `github_credential_id`
    - `publish_to_github`
    - `publish_mode` (`status` or `check_run`)
    - `target_url`

- `POST /iac/security/check`
  - operator/admin
  - checks Terraform/IaC text for general security policy violations
  - current prototype rules:
    - public SSH ingress
    - incomplete S3 public access block

- `POST /mcp`
  - operator/admin
  - lightweight JSON-RPC MCP-style endpoint for IDE/AI assistants
  - supports:
    - `tools/list`
    - `tools/call` with `check_iac_compliance`
    - `tools/call` with `check_repo_enforcement`

## 18. Remediations

- `GET /remediations`
  - viewer/operator/admin
  - query:
    - `status`
    - `repo_id`
    - `asset_key_str`
    - `drift_status`
    - `parent_remediation_id`
    - `origin_kind`
    - `limit`

- `GET /remediations/{remediation_id}`
  - viewer/operator/admin
  - get remediation record

- `GET /remediations/{remediation_id}/validations`
  - viewer/operator/admin
  - list validation jobs for one remediation

- `GET /validation-jobs/{validation_job_id}`
  - viewer/operator/admin
  - get validation job

- `POST /remediations/suggest`
  - operator/admin
  - request:
    - `asset_key`
    - `repository_id` or `repository`
    - `file_path`
    - `vulnerability`
    - `github_credential_id`
    - `ref`

- `POST /remediations/{remediation_id}/approve`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/reject`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/validate`
  - operator/admin
  - request:
    - `github_credential_id`
    - `ref`
    - `validator_type`
    - `async_mode`
    - `timeout_seconds`

- `POST /remediations/{remediation_id}/create-pr`
  - operator/admin
  - request:
    - `github_credential_id`
    - `branch_prefix`
    - `base_branch`
    - `title`
    - `body`
    - `allow_unvalidated`

- `POST /remediations/drift/check`
  - operator/admin
  - request:
    - `remediation_id`
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/branches/cleanup`
  - admin-only
  - deletes recorded remediation branches after verified closure
  - request:
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/{remediation_id}/drift/acknowledge`
  - operator/admin
  - request:
    - `note`

- `POST /remediations/{remediation_id}/drift/revalidate`
  - operator/admin
  - request:
    - `github_credential_id`
    - `async_mode`

- `POST /remediations/{remediation_id}/mark-merged`
  - operator/admin
  - request:
    - `merged_at`

- `GET /remediations/branches/cleanup/status`
  - viewer/operator/admin
  - lists verified-closed remediation branch cleanup state
  - query:
    - `status`
    - `limit`

- `POST /remediations/branches/cleanup`
  - admin-only
  - bulk branch cleanup for verified-closed remediations
  - request:
    - `github_credential_id`
    - `async_mode`
    - `limit`

- `POST /remediations/{remediation_id}/branch/cleanup`
  - admin-only
  - cleanup one remediation branch
  - request:
    - `github_credential_id`

## 19. Audit

- `GET /audit/logs`
  - operator/admin
  - query:
    - `limit`
    - `actor_id`
    - `action`
    - `decision`

- `GET /audit/logs/export.csv`
  - operator/admin
  - exports filtered audit logs as CSV

## 20. Inbound GitHub webhook

- `POST /integrations/github/webhook`
  - GitHub webhook receiver
  - verifies `X-Hub-Signature-256` if `GITHUB_WEBHOOK_SECRET` is configured
  - handles `pull_request` close/merge, close-without-merge, reopen, and synchronize events
  - marks matching remediation(s) by PR URL as merged, pr_closed, pr_created, or pr_updated

- `GET /integrations/github/pr-events`
  - viewer/operator/admin
  - list recorded PR lifecycle webhook events
  - query:
    - `pr_url`
    - `limit`

- `GET /integrations/github/status-publishes`
  - viewer/operator/admin
  - list GitHub commit status / Check Run publish attempts
  - query:
    - `repo`
    - `limit`

---

## Technical Part: Data Model And Operations

# Morrow Data Model and Operations

This file covers:

- persistent data model
- runtime configuration
- local and cloud deployment details
- operations and maintenance notes
- testing and troubleshooting map

## 1. Storage model

The system uses three storage classes:

- PostgreSQL
  - main application database
  - current runtime target in compose and cloud
- Redis
  - Celery broker and result backend
- in-memory API cache
  - short-lived `_SCANS` map in `backend/app.py`

Legacy SQLite code still exists in `backend/db.py`, but current production-like runtime is Postgres-backed.

## 2. Main PostgreSQL tables

### 2.1 `organizations`

Purpose:

- tenant records

Fields:

- `id`
- `name`
- `plan_type`
- `subscription_status`
- `created_at`
- `updated_at`

### 2.2 `repositories`

Purpose:

- GitHub repositories linked into the platform

Fields:

- `id`
- `organization_id`
- `name`
- `html_url`
- `created_at`
- `updated_at`

Constraint:

- unique per `(organization_id, name)`

### 2.3 `assets`

Purpose:

- tracked endpoints plus ownership metadata

Fields:

- `organization_id`
- `asset_key`
- `owner`
- `team`
- `environment`
- `criticality`
- `confidentiality_lifetime`
- `notes`
- `metadata_json`
- `repository_id`
- `updated_at`

Primary key:

- `(organization_id, asset_key)`

### 2.4 `asset_tags`

Purpose:

- normalized tags per asset

Fields:

- `organization_id`
- `asset_key`
- `tag`

### 2.5 `baselines`

Purpose:

- baseline scan ID per asset

Fields:

- `organization_id`
- `asset_key`
- `baseline_scan_id`
- `set_at`

### 2.6 `scans`

Purpose:

- top-level durable scan rows

Fields:

- `id`
- `organization_id`
- `status`
- `created_at`
- `progress_json`
- `error_text`
- `results_json`
- `summary_json`
- `job_id`
- `job_state`
- `job_started_at`
- `job_finished_at`

Important note:

- scoped by `organization_id`; scan audit trails are tenant-owned.

### 2.7 `scan_results`

Purpose:

- historical per-asset scan snapshots for trends and asset history

Fields:

- `id`
- `organization_id`
- `asset_key`
- `scan_id`
- `scanned_at`
- `risk_level`
- `quantum_score`
- `findings_count`
- `pqc_relevance`
- `tls_version`
- `key_type`
- `sig_algorithm`
- `owner`
- `team`
- `environment`
- `criticality`

### 2.8 `remediations`

Purpose:

- fix workflow records

Fields:

- `id`
- `organization_id`
- `asset_key`
- `repo_id`
- `vulnerability`
- `file_path`
- `original_content`
- `suggested_fix`
- `suggested_content`
- `status`
- `pr_url`
- `pr_branch`
- `pr_base_branch`
- `github_credential_id`
- `branch_cleanup_status`
- `branch_cleanup_at`
- `branch_cleanup_error`
- `branch_cleanup_attempts`
- `review_note`
- `merged_at`
- `verification_scan_id`
- `closed_at`
- `parent_remediation_id`
- `origin_kind`
- `drift_followup_remediation_id`
- `drift_status`
- `last_drift_checked_at`
- `drift_detected_at`
- `drift_acknowledged_at`
- `drift_acknowledged_by`
- `drift_ack_note`
- `drift_details_json`
- `created_at`
- `updated_at`

### 2.9 `validation_jobs`

Purpose:

- validation execution history

Fields:

- `id`
- `organization_id`
- `remediation_id`
- `validator_type`
- `status`
- `git_ref`
- `job_id`
- `stdout`
- `stderr`
- `exit_code`
- `details_json`
- `created_at`
- `updated_at`
- `finished_at`

### 2.10 `audit_logs`

Purpose:

- governance trail

Fields:

- `id`
- `organization_id`
- `actor_id`
- `actor_role`
- `action`
- `resource_type`
- `resource_id`
- `decision`
- `reason`
- `details_json`
- `prev_hash`
- `entry_hash`
- `created_at`

Postgres hardening:

- update/delete triggers reject mutation

### 2.11 `github_installations`

Purpose:

- synced GitHub App installation metadata

Fields:

- `id`
- `organization_id`
- `installation_id`
- `account_login`
- `account_type`
- `target_type`
- `permissions_json`
- `repositories_count`
- `suspended_at`
- `created_at`
- `updated_at`

### 2.12 `webhooks`

Purpose:

- outbound notification destinations

Fields:

- `id`
- `organization_id`
- `name`
- `url`
- `secret`
- `credential_id`
- `events_json`
- `enabled`
- `created_at`
- `updated_at`

Important note:

- scoped by `organization_id`; event delivery only targets webhooks in the active organization.

### 2.13 `webhook_events`

Purpose:

- delivery queue and delivery history

Fields:

- `id`
- `organization_id`
- `webhook_id`
- `created_at`
- `event_type`
- `dedupe_key`
- `payload_json`
- `status`
- `http_status`
- `error_text`
- `response_excerpt`
- `attempts`
- `last_attempt_at`
- `next_attempt_at`
- `claimed_at`
- `claimed_by`

### 2.14 `collections`

Purpose:

- saved target groups

Fields:

- `id`
- `organization_id`
- `name`
- `targets_text`
- `created_at`
- `updated_at`

Constraint:

- unique per `(organization_id, name)` in Postgres-backed deployments

### 2.15 `schedules`

Purpose:

- recurring collection scans

Fields:

- `id`
- `organization_id`
- `collection_id`
- `enabled`
- `interval_minutes`
- `created_at`
- `updated_at`
- `last_run_at`
- `next_run_at`
- `last_scan_id`

Important note:

- scoped by `organization_id` and linked to an org-scoped collection

### 2.16 `integrations_settings`

Purpose:

- generic key/value settings store

Fields:

- `key`
- `value`

### 2.17 `event_rules`

Purpose:

- notification matching and routing rules

Key fields in current schema include:

- `id`
- `organization_id`
- `name`
- `enabled`
- `webhook_ids_json`
- `event_types_json`
- `min_severity`
- `rule_ids_json`
- `environments_json`
- `teams_json`
- `criticalities_json`
- `tags_json`
- `cooldown_minutes`
- `quantum_score_min`
- `fire_mode`
- timestamps

### 2.18 `event_rule_fires`

Purpose:

- rule fire dedupe and cooldown tracking

Fields:

- `organization_id`
- `rule_id`
- `fingerprint`
- `last_fired_at`

## 3. Vault schema

Vault credentials are stored in:

- `credentials`

Fields:

- `id`
- `organization_id`
- `name`
- `provider`
- `secret_enc`
- `meta_json`
- `created_at`
- `updated_at`
- `last_rotated_at`

Secrets are encrypted using:

- `PQC_VAULT_MASTER_KEY`

## 4. Org-scoped vs global data

Org-scoped:

- organizations
- repositories
- assets
- asset_tags
- baselines
- scan_results
- remediations
- validation_jobs
- audit_logs
- github_installations
- credentials
- collections
- schedules
- scans
- webhooks
- webhook_events
- event_rules
- event_rule_fires

Global/shared in current schema:

- integrations_settings

This is one of the most important current architecture facts.

## 4.1 Vendor vs customer visibility

In hosted/SaaS mode, tenant visibility is controlled by:

- `organization_id` on stored data
- JWT organization claims or local `x-org-id` headers
- role checks for `viewer`, `operator`, and `admin`
- org-scoped database access functions

Customer users can see data for their active organization only:

- their assets
- their scans and scan results
- their repositories
- their remediations, validation jobs, PR links, verified-closed state, and drift state
- their collections and schedules
- their outbound webhooks, webhook delivery events, and event rules
- their audit logs
- their compliance report, ROI metrics, drift analytics, CI gate result, and MCP compliance responses

Customer users cannot see other organizations' data through normal API/UI flows when auth is configured with tenant-specific organization claims.

Vendor/operator visibility is different:

- through cloud/provider access, the vendor can inspect infrastructure logs, Cloud Run service health, Secret Manager metadata, Cloud SQL backups, Terraform state, and deployment status
- through admin API endpoints, the vendor can list organizations, archive organizations, purge organizations, inspect audit logs, and perform operational setup
- through direct database access, the vendor can inspect all tenant data in the hosted database for support and incident response

Current UI note:

- the customer UI exposes the active organization's dashboard, scans, assets, remediations, compliance report, ROI cards, and CI gate checks
- there is not yet a separate polished vendor console for cross-tenant management
- vendor-only operations currently happen through admin APIs, cloud console, logs, Terraform outputs, or direct database inspection

Security caveat:

- application-level tenant scoping is implemented
- database Row-Level Security is still a recommended future hardening step for stronger shared-SaaS isolation

## 5. Runtime environment variables

### 5.1 Database and backend selection

- `PQC_MAIN_DB_BACKEND`
- `PQC_PRODUCT_DATABASE_URL`
- `DATABASE_URL`
- `PQC_SCANNER_DB`

### 5.2 Vault

- `PQC_VAULT_MASTER_KEY`

### 5.3 Auth

- `PQC_AUTH_MODE`
- `PQC_AUTH_REQUIRED`
- `PQC_AUTH_PROVIDER_NAME`
- `PQC_AUTH_LOGIN_URL`
- `PQC_AUTH_LOGOUT_URL`
- `PQC_AUTH_TOKEN_HELP`
- `PQC_AUTH_JWT_ISSUER`
- `PQC_AUTH_JWT_AUDIENCE`
- `PQC_AUTH_JWT_JWKS_URL`
- `PQC_AUTH_JWT_SECRET`
- `PQC_AUTH_USER_ID_CLAIM`
- `PQC_AUTH_ROLE_CLAIM`
- `PQC_AUTH_ORG_ID_CLAIM`
- `PQC_AUTH_CLOCK_SKEW_SECONDS`
- `PQC_AUTH_JWT_ALGORITHMS`

### 5.4 Defaults and request limits

- `PQC_DEFAULT_ROLE`
- `PQC_DEFAULT_ORG_ID`
- `PQC_API_KEY`
- `PQC_RATE_LIMIT_WINDOW_SECONDS`
- `PQC_RATE_LIMIT_MAX_REQUESTS`

### 5.5 AI

- `OPENAI_API_KEY`
- `OPENAI_MODEL`

### 5.6 GitHub webhook

- `GITHUB_WEBHOOK_SECRET`

### 5.7 Celery and Redis

- `REDIS_PASSWORD`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`

### 5.8 Runtime behavior

- `APP_COMPONENT`
- `WORKER_ROLE`
- `ENABLE_INPROCESS_SCHEDULER`
- `PER_TARGET_TIMEOUT`
- `HOST`
- `PORT`
- `CELERY_LOGLEVEL`
- `CELERY_CONCURRENCY`
- `BEAT_SCHEDULE_PATH`

### 5.9 Background sync and drift tuning

- `GITHUB_SYNC_CREDENTIAL_ID`
- `GITHUB_SYNC_ORG`
- `GITHUB_SYNC_VISIBILITY`
- `CORRELATE_ASSET_LIMIT`
- `GCP_SYNC_CREDENTIAL_ID`
- `GCP_SYNC_PROJECT_ID`
- `PQC_WEBHOOK_DRAIN_LIMIT`
- `PQC_WEBHOOK_MAX_ATTEMPTS`
- `PQC_WEBHOOK_LEASE_SECONDS`
- `PQC_DRIFT_CHECK_LIMIT`
- `PQC_GITHUB_DRIFT_CREDENTIAL_ID`
- `PQC_BRANCH_CLEANUP_LIMIT`
- `CORRELATE_DEEP_SCAN`
- `CORRELATE_DEEP_SCAN_MAX_FILES`
- `CORRELATE_DEEP_SCAN_MAX_DEPTH`
- `CORRELATE_DEEP_SCAN_MAX_KB`

### 5.10 Validation isolation

- `PQC_VALIDATION_ISOLATION_MODE`
  - `workspace` by default
  - `docker` to run Terraform validation in a per-job Docker container
- `PQC_VALIDATION_DOCKER_IMAGE`
  - Docker image used for isolated Terraform validation
  - default: `ghcr.io/opentofu/opentofu:1.8.6`
- `PQC_VALIDATION_DOCKER_CPUS`
  - CPU limit for the validation container
- `PQC_VALIDATION_DOCKER_MEMORY`
  - memory limit for the validation container

### 5.11 Observability

- `PQC_STRUCTURED_LOGS`
  - defaults to enabled; emits JSON logs for Cloud Logging
- `PQC_LOG_LEVEL`
  - root log level for API and worker logs
- `SENTRY_DSN`
  - optional Sentry DSN for exception capture
- `SENTRY_TRACES_SAMPLE_RATE`
  - optional Sentry tracing sample rate
- `PQC_ENVIRONMENT`
  - environment label attached to Sentry events
- `PQC_HEALTH_DEEP`
  - if enabled, `/health` also verifies Postgres and Redis; `/health/deep` always performs deep checks
- `PQC_APP_BASE_URL` / `PQC_PUBLIC_APP_URL`
  - public UI base URL used for GitHub PR link-back metadata

## 6. Local Docker deployment

`backend/compose.yml` starts:

- `redis`
- `postgres`
- `webhook_sink`
- `api`
- `worker`
- `beat`

Important defaults:

- Postgres exposed on host `5433`
- API exposed on host `8000`
- webhook sink exposed on `9001`

All application services use:

- Postgres as main DB
- Redis for Celery
- vault key from env
- OpenAI config from env

## 7. Container image behavior

`backend/Dockerfile`:

- base image: `python:3.11-slim`
- installs Terraform into the image
- installs Python requirements
- copies source into `/app`
- uses `entrypoint.sh`

Technical consequence:

- default Terraform validation runs inside the same runtime image with a temporary workspace and scrubbed environment
- optional Docker isolation runs Terraform validation in a separate per-job container with network disabled and resource limits

## 8. Cloud deployment

Terraform under `infra/gcp/cloudrun/` provisions:

- required GCP APIs
- Artifact Registry repo
- private VPC and subnet
- private service networking
- Cloud SQL Postgres
- Memorystore Redis
- runtime service account
- Secret Manager secrets
- Cloud Run API
- Cloud Run worker pools

### 8.0 Private-cloud / VPC package

Enterprise private-cloud packaging lives in:

- `infra/gcp/modules/private-cloud/`
  - reusable customer-owned GCP module
  - provisions Artifact Registry, VPC, private service networking, Cloud SQL Postgres, Memorystore Redis, Secret Manager, Cloud Run API, Celery worker pool, and Celery beat worker pool
- `infra/gcp/private-cloud-demo/`
  - thin investor/customer demo root module that wraps the reusable module
- `scripts/setup-enterprise.sh`
  - two-phase bootstrap script for clean customer projects

The bootstrap script:

1. applies Terraform with `deploy_runtime=false`
2. builds and pushes the backend image into the customer's private Artifact Registry
3. writes required Secret Manager versions
4. applies Terraform with `deploy_runtime=true`
5. runs Alembic migrations using a one-off Cloud Run Job inside the VPC

This deployment keeps Postgres, Redis, secrets, runtime identities, and container images inside the customer-controlled project. It is the preferred packaging model for banks, government contractors, healthcare systems, and other customers with strict data sovereignty requirements.

### 8.1 Two-phase deploy model

Current flow:

1. `deploy_runtime = false`
   - create infra and secret containers
2. add missing secret versions manually
3. set `deploy_runtime = true`
4. apply again to deploy runtime

Manual secrets still required after first apply:

- OpenAI API key
- vault master key

Generated automatically:

- database URL
- Celery broker URL
- Celery result backend
- GitHub webhook secret

### 8.2 Terraform auth variables

Terraform wires hosted auth config into Cloud Run using variables such as:

- `auth_mode`
- `auth_required`
- `auth_provider_name`
- `auth_login_url`
- `auth_logout_url`
- `auth_jwt_issuer`
- `auth_jwt_audience`
- `auth_jwt_jwks_url`
- `auth_jwt_algorithms`
- `auth_user_id_claim`
- `auth_role_claim`
- `auth_org_id_claim`

## 9. Operations

### 9.1 Minimum health checks

- GET /health for the default liveness check
- GET /health/deep or PQC_HEALTH_DEEP=1 for Postgres and Redis probing
- `GET /auth/config`
- UI load on `/ui/`

For background runtime:

- verify worker is running
- verify beat is running
- verify Redis reachable
- verify Postgres reachable

### 9.2 Common admin tasks

- sync GitHub App installations
- sync repositories
- rotate vault credentials
- review failed validation jobs
- review drifted remediations
- clean up verified-closed remediation branches
- review ROI metrics and MTTR reduction evidence
- review CI/CD enforcement gate failures
- archive or purge inactive organizations
- retry webhook deliveries
- review audit logs

### 9.3 Backup targets

Critical backup targets:

- Postgres database
- Secret Manager values
- Terraform state

Redis is operational state, not the main system of record.

### 9.4 Logging and troubleshooting surfaces

- API logs
- worker logs
- beat logs
- audit logs
- webhook event records
- validation job stdout/stderr
- structured JSON request logs with `organization_id`
- optional Sentry events when `SENTRY_DSN` is configured

### 9.5 Hosted auth reset

Most common hosted auth issue:

- expired browser token

Current browser-side reset:

```javascript
localStorage.removeItem("pqc_auth_bearer_token");
location.reload();
```

## 10. Testing and verification

### 10.1 Main regression suites

Recommended grouped run:

- `backend/test_compliance_gate.py`
- `backend/test_sprint12_remediations.py`
- `backend/test_sprint13_rbac_audit_guardrails.py`
- `backend/test_sprint14_multitenancy.py`
- `backend/test_sprint14_github_app_bridge.py`
- `backend/test_sprint14_schema_migrations.py`
- `backend/test_sprint18_compliance_report.py`
- `backend/test_sprint19_drift_notifications.py`
- `backend/test_sprint20_drift_response.py`
- `backend/test_postgres_cutover_utils.py`
- `backend/test_postgres_runtime_switch.py`
- `backend/test_saas_auth_jwt.py`

### 10.2 Key manual flows

- login
- scan
- asset metadata
- collection and schedule
- GitHub App sync
- repository sync
- remediation suggestion
- validation
- PR creation
- merge webhook
- verified closure
- automatic branch cleanup after verified closure
- drift detection
- ROI metrics
- CI/CD status-check enforcement
- general IaC security check
- MCP compliance check from an IDE assistant
- compliance report

### 10.3 ROI and enforcement evidence

The investor-facing metrics endpoint is:

- `GET /org/{organization_id}/metrics`

It reports:

- engineering hours saved total
- engineering hours saved per 100 remediations
- target attainment against 200 hours per 100 remediations
- MTTR reduction versus `PQC_ROI_MANUAL_MTTR_HOURS`
- drift events caught
- drift follow-ups created
- manual non-compliant changes reverted

The CI/CD enforcement endpoint is:

- `POST /integrations/ci/status-check`

It returns a status-check shaped response with:

- `state = success`
- `state = failure`
- merge-blocking policy violations

The general IaC security prototype is:

- `POST /iac/security/check`

Current rules detect open SSH ingress and incomplete S3 public access block settings.

The lightweight MCP interface is:

- `POST /mcp`

It lets external IDE assistants call `check_iac_compliance` or `check_repo_enforcement`.

## 11. Current operational caveats

- hosted auth works but is not yet a full browser-native OIDC client
- correlation may not always auto-link assets
- compliance gate currently fails only on `critical` linked assets

## 12. Obvious future hardening areas

- keep lifespan startup/shutdown coverage in regression tests
- normalize any legacy naive timestamp rows during future data migrations
- consider database RLS for stronger shared-SaaS isolation
- split `backend/app.py` into routers/services
- improve correlation behavior for GitHub App-only environments
- move hosted auth from token-in-URL bridge toward full code+PKCE

---

---

# Part: Quantum Platform Q&A Update

The latest investor/demo additions are documented in `docs/QUANTUM_PLATFORM_QA.md`.

New buyer-facing capabilities:

- Demo Lab page for a slow, visual, non-technical walkthrough.
- Controlled Demo Lab seed flow that creates demo asset, repository, scan, remediation, validation evidence, audit event, and report without requiring GitHub access.
- Quantum Readiness Report at `/org/quantum-readiness-report.html`.
- Bulk enterprise onboarding for many endpoints at once.
- Quantum Migration portfolio showing HNDL risk, provider status, blockers, migration stage, and next action.

Important claim boundary:

- The platform should not claim every website becomes quantum-proof immediately.
- It should claim that it discovers quantum-vulnerable public cryptography, assigns ownership, creates validated migration paths where supported, tracks provider blockers, and proves progress over time.

---

# Part: Machine-to-Machine Control Plane Update

The platform now includes API-first v1 endpoints for machine communication.

New control-plane APIs include:

- `GET /v1/org/{organization_id}/readiness`
- `GET /v1/assets/{asset_key}/evidence`
- `GET /v1/evidence/remediations/{remediation_id}`
- `GET /v1/evidence/repos/{owner/repo}`
- `GET /v1/repos/{owner/repo}/gate`
- `GET /v1/org/{organization_id}/policy`
- `PUT /v1/org/{organization_id}/policy`
- `POST /v1/repositories/discover-ownership`
- `GET /v1/providers/capabilities`

The intent is to move from human file exports toward automation-ready evidence, policy decisions, CI/CD gate decisions, repository ownership scoring, and provider capability intelligence.

The MCP endpoint also exposes additional tools for external agents:

- `get_asset_evidence`
- `get_repo_evidence`
- `discover_repo_ownership`
- `get_provider_capabilities`
- `get_org_policy`

These tools allow IDE assistants and other AI systems to ask whether code, assets, or repositories comply with the active organization policy.

Additional machine-communication development:

- Local controlled demo repository template: `demo/customer-edge-infra/`.
- Content-based ownership discovery through `repository_files` on `/v1/repositories/discover-ownership`.
- Provider migration playbooks through `/v1/providers/{provider}/playbook`.
- Evidence integrity envelopes with `evidence_hash` and optional HMAC signing through `PQC_EVIDENCE_SIGNING_KEY`.
- Autonomous remediation candidates through `/v1/remediation-candidates`.
- Policy evaluation and optional policy events through `/v1/policy/evaluate`.

---

# Part: Current Product UX and Operator Workflow

This section reflects the current working product experience.

## 1. Main pages

The primary UI is organized around these top-level actions.

### Live Product

The main operator console.

It contains:

- next best action strip
- workflow status board
- runtime health check
- GitHub connection panel
- synced repository panel
- asset-to-repo linking panel
- scan target input
- results table
- asset editor

The next best action changes based on state:

- no assets: start onboarding
- assets but no repos: connect GitHub
- repos but unlinked assets: link assets to repos
- linked assets but no candidates: scan repo crypto
- candidates exist: open remediation queue
- proof exists: review dashboard/evidence

### Workflow

The guided command center for the complete product loop.

It shows eight steps:

1. scan website/API
2. classify asset
3. connect repository
4. link asset to repository
5. discover repository crypto
6. review queue and migration tasks
7. validate and create PR
8. verify closure and monitor drift

For each step it shows:

- whether the step is complete
- what metric proves it is complete
- what is missing or blocked
- the primary action to move forward

This page is intended to reduce confusion during demos and real use. It turns scattered product capabilities into one ordered workflow.

### Onboarding

The first-use wizard.

Steps:

1. company / organization context
2. paste and normalize domains
3. classify owner, team, environment, criticality, confidentiality, and tags
4. optionally connect GitHub
5. review and run onboarding
6. review result and choose next action

The onboarding wizard can:

- normalize domains into `host:443`
- create/update assets
- save a collection
- start a scan
- optionally sync repositories
- optionally correlate assets to repositories
- jump to dashboard, repo linking, or remediation queue

### Remediation Queue

The operator workflow board.

Columns:

- Candidates
- Review
- Validate
- Pull Request
- Verified / Drift

Cards show:

- asset
- status
- source/origin
- repo
- file
- drift status
- safety label
- next safe action

Direct actions include:

- approve
- reject
- validate
- create PR
- open evidence
- open details
- drift check

Safety model:

- Terraform/config files are treated as safer validation candidates.
- Complex app-code crypto findings are treated as human migration tasks.
- The platform should not blindly rewrite legacy crypto code without targeted recipes and tests.

### Migration Tasks

Migration Tasks are the safe workflow for complex application-code crypto findings.

Use them when repository discovery finds patterns such as RSA, ECDSA, ECDH, DH, JWT algorithm usage, or Java keystore usage inside application code.

Why this exists:

- changing application cryptography can break login, token verification, certificates, clients, APIs, and partner integrations
- these changes need a migration recipe, test plan, rollout plan, and human owner
- the platform should not pretend every legacy crypto finding is safe to auto-rewrite

The `Migration Tasks` board tracks:

- open tasks
- planned tasks
- in-progress tasks
- completed tasks
- accepted-risk exceptions

Each task records:

- asset
- repository
- file path
- rule id
- legacy crypto dependency
- target migration direction
- confidence
- safety reason
- recommended workflow

Repository crypto scans can create migration tasks automatically when `Create migration tasks` is enabled. Safe Terraform/config findings can still become remediation candidates; complex app-code findings become migration tasks instead.

### Repository Crypto Discovery

Repository discovery looks for crypto migration signals in code and configuration.

Current detection areas include:

- RSA encryption/key transport
- RSA signatures
- ECDH/ECDSA and named elliptic curves
- static TLS policy/configuration
- Java keystores and truststores
- OpenSSL RSA/TLS usage
- JWT signing and verification algorithm dependencies
- certificate/private-key material indicators

Results are grouped by:

- file path
- service/app folder
- crypto boundary

Crypto boundaries include:

- identity/token boundary
- certificate/keystore boundary
- native crypto library boundary
- TLS edge configuration boundary
- application crypto boundary

The purpose is not to blindly rewrite every match. The purpose is to separate:

- safe config/IaC candidates that can move through validation and PR
- app-code crypto migration tasks that need tests, compatibility checks, and rollout planning
- sensitive certificate/private-key findings that require security review and possible rotation

### Data-at-Rest HNDL Inventory

The platform also tracks harvest-now/decrypt-later risk for stored data, not only traffic in motion.

The first live cloud connector path is cloud object-storage inventory.

AWS S3 inventory:

- operators can run a safe dry-run from the UI
- live mode uses an org-scoped Vault credential
- the credential secret should be JSON with `aws_access_key_id`, `aws_secret_access_key`, and optional `aws_session_token`
- the connector lists accessible S3 buckets and sampled objects
- object names are checked for sensitive patterns such as `backup`, `database`, `patient`, `customer`, `pii`, `phi`, and `archive`
- old, large, sensitive, weakly encrypted, or provider-managed encrypted objects receive higher HNDL risk
- optional object-level encryption inspection uses `head_object`; it is more accurate but slower and needs broader S3 permissions

GCP Cloud Storage inventory:

- operators can run a dry-run from the UI
- live mode uses an org-scoped Vault credential
- the credential secret should be Google service-account JSON
- the connector lists accessible Cloud Storage buckets and sampled blobs
- bucket/object names are checked for sensitive patterns such as `backup`, `database`, `patient`, `customer`, `pii`, `phi`, and `archive`
- customer-managed encryption keys are identified where metadata exposes them
- Google-managed encryption is flagged for key/control review when data is long-lived or sensitive

Azure Blob Storage inventory:

- operators can run a dry-run from the UI
- live mode uses an org-scoped Vault credential
- the credential secret should contain either `connection_string`, or `account_url` / `account_name` plus `account_key` or `sas_token`
- the connector lists accessible containers and sampled blobs
- container/blob names are checked for sensitive patterns such as `backup`, `database`, `patient`, `customer`, `pii`, `phi`, and `archive`
- encryption scopes are identified where blob metadata exposes them
- platform-managed encryption is flagged for key/control review when data is long-lived or sensitive

This gives the operator a machine-readable storage risk feed for long-lived encrypted backups and archives across AWS S3, GCP Cloud Storage, and Azure Blob Storage.

### GitHub Repo Onboarding and Ownership Map

The Live Product page includes a guided repository onboarding flow.

It shows four steps:

1. credential
2. sync repositories
3. link assets to repositories
4. scan repository crypto/config

The simple path is:

- paste a fine-grained GitHub token
- store it encrypted in Vault
- sync repository metadata
- link each important website/API asset to its owning repo
- run repo crypto discovery
- create remediation candidates or migration tasks

The ownership map shows which assets are linked and which still need a repository owner. This is the operational bridge between an external finding and the engineering team that can fix it.

The platform can also score ownership suggestions. It compares asset hostnames, root-domain tokens, teams, repository names, and optional repository file evidence. Operators can:

- load suggested links for manual review
- select a suggested asset/repo pair
- apply a suggested link
- auto-link only high-confidence matches

Important behavior:

- repository sync reads metadata and repository files; it does not change customer code
- the token field is cleared after connection
- synced repositories can be used for remediation suggestions, validation, drift checks, and PR creation
- complex app-code crypto findings become migration tasks instead of blind automatic rewrites

### Repo Scan Work Package

After a repository crypto scan, the UI builds a work package.

The work package summarizes:

- safe config fixes
- complex migration tasks
- manual security-review items
- tracked remediation candidates
- tracked migration tasks
- linked asset context
- recommended next action

The operator can route from the work package to:

- remediation queue
- migration task board
- asset evidence
- rerun scan with tracked work creation enabled

This makes the repository scan useful immediately. Instead of only showing technical matches, the platform separates what can be validated as a safe config fix from what needs engineering migration planning.

### Go-Live Readiness Checklist

The Live Product page includes a go-live readiness checklist for the tenant.

It checks:

- assets exist
- business context is classified
- GitHub credential is selected
- repositories are synced
- assets are linked to repositories
- repo work package exists
- human review has started
- validation evidence exists
- PR workflow has been exercised
- verified closure evidence exists

This is meant for operators before a real customer or investor demo. It shows which pieces of the end-to-end workflow are ready and which pieces still need setup.

### Guide

The in-app operating manual.

It explains:

- what each main page does
- which menu to use
- how onboarding works
- how scan results should be read
- how GitHub/repo ownership works
- how the remediation queue works
- how sandbox validation works
- what Settings controls mean

### Settings

Local operator settings and safe runtime controls.

Settings includes:

- organization id
- default owner/team/environment/criticality/confidentiality
- saved GitHub credential id
- API base URL
- runtime health check
- browser-only UI reset

Important:

- `Clear Local UI State` only clears browser preferences and cached form values.
- It does not delete Postgres data, credentials, assets, repositories, remediations, scans, or audit logs.

### Asset Evidence

The asset editor includes an `Evidence` button.

It opens a complete proof package for one asset:

- asset key
- owner/team/environment/criticality/confidentiality
- linked repository
- latest scan posture
- TLS version
- key type
- signature algorithm
- HNDL / quantum readiness
- provider and PQC support status
- policy decision
- remediation records
- latest validation status
- PR URL
- drift status
- evidence hash / integrity envelope

Actions:

- copy evidence JSON
- open remediation queue
- run policy check for the asset

This is the clearest asset-level answer to:

- what is this system?
- who owns it?
- what risk was found?
- what code owns the fix?
- what evidence proves progress?

### Scan result actions

Each expanded scan result row includes asset workflow actions:

- `Create / Update Asset`
  - creates or updates the asset record from the scan result
  - uses Settings defaults for owner, team, environment, criticality, and confidentiality
  - adds default tags: `internet`, `tls`, `pqc`

- `Open Evidence`
  - creates/loads the asset if needed
  - opens the Asset Evidence drawer

- `Link Repo`
  - creates/loads the asset if needed
  - scrolls to the asset-to-repo linking panel
  - preselects the asset so the operator can choose a synced repository

This makes the first workflow clearer:

1. scan endpoint
2. create/classify asset
3. open evidence
4. link repository
5. continue to repo crypto scan and remediation queue

## 2. Current end-to-end workflow

Recommended operating flow:

1. open Settings and set defaults if needed
2. open Onboarding
3. paste customer domains
4. normalize and classify them
5. run onboarding and scan
6. connect GitHub when the customer is ready
7. link assets to repositories
8. scan repository crypto/config files
9. create remediation candidates
10. open Remediation Queue
11. approve or reject candidates
12. validate safe changes in sandbox
13. create PR
14. track merge
15. rescan and verify closure
16. monitor drift
17. use Dashboard/evidence/audit for proof

## 3. Current tested-local runtime

Local Docker runtime uses:

- API on `http://localhost:8000`
- UI on `http://localhost:8000/ui/`
- Postgres on Docker service `postgres`
- Redis on Docker service `redis`
- worker and beat containers for background jobs
- API without Uvicorn `--reload` inside Docker

Minimum health checks:

- `GET /health`
- `GET /health/deep`

`/health/deep` checks:

- API
- Postgres
- Redis

The Live Product page now exposes runtime health directly in the UI.

Docker note:

- local Docker intentionally avoids Uvicorn auto-reload because Windows/macOS bind mounts can trigger low-level `WatchFiles` filesystem watcher errors after laptop restarts or file edits
- after changing backend code, restart the API container or rebuild images when dependencies change

## 4. Current limitations before deployment

These should be tested or completed before cloud deployment:

- run a real GitHub token/repository end-to-end test
- confirm repo crypto discovery on the controlled demo repository
- confirm candidate creation with linked asset + synced repo
- validate a safe Terraform/config candidate
- create a real PR in a test repository
- mark merged and verify closure
- run drift check
- run multi-tenant smoke checks
- deploy updated image to cloud

Current product claim boundary:

- The platform helps manage quantum-readiness migration.
- It discovers quantum-relevant crypto exposure, assigns ownership, maps risk to repositories, creates safe remediation candidates, validates supported fixes, tracks PRs, verifies closure, and monitors drift.
- It should not claim that every website can be made fully quantum-proof today.
- Some migration depends on cloud/CDN/browser/provider support for hybrid or PQC-enabled protocols.

## 5. Repository crypto discovery safety classes

Repository crypto discovery now classifies findings before they become work.

Safety classes:

- `safe_config_candidate`
  - usually Terraform, HCL, YAML, JSON, config, TLS policy, NGINX, or similar infrastructure/config files
  - can usually become a narrow remediation candidate
  - still requires human review and sandbox validation

- `migration_task`
  - usually application code such as Java, Go, Python, JavaScript, C/C++, C#, Ruby, or PHP
  - should become an engineering migration task, not a blind automatic rewrite
  - requires compatibility review, rollout planning, and tests

- `manual_review`
  - ambiguous file type or context
  - requires engineer review before deciding whether it is a safe config fix or a migration task

Each repo finding can include:

- `safety_class`
- `confidence`
- `safety_reason`
- `recommended_workflow`
- `can_create_candidate`

The UI shows these labels in repository crypto results and remediation candidate output.

### Runtime traffic inventory

The platform can now ingest runtime traffic observations from logs or telemetry. This complements active endpoint scanning and repository analysis by showing which assets are actually seen in production traffic.

New APIs:

- `POST /v1/runtime/traffic/import`
- `GET /v1/runtime/traffic/observations`
- `GET /v1/runtime/assets`

Imported observations can auto-create asset records, add `runtime-observed` tagging, and store runtime metadata such as source, provider, protocol, TLS version, cipher, observed count, and first/last seen timestamps.

### GitHub App enterprise diagnostics

The platform can now show whether GitHub App onboarding is ready for PR automation.

New endpoints:

- `GET /integrations/github-app/status`
- `POST /integrations/github-app/repo-diagnostics`

These endpoints help operators answer:

- is the GitHub App credential configured?
- are installations synced?
- can the platform resolve a repo-scoped token?
- is the target repository reachable?
- is it safe to attempt validation/PR creation?

Secrets and tokens are not returned in diagnostics.

### Organization membership and tenant administration

The platform now supports org-scoped memberships for tenant administration.

New behavior:

- Users can belong to organizations with a role: `viewer`, `operator`, or `admin`.
- Active membership role overrides request header/JWT role inside that organization.
- Customer admins can manage members only for the active organization.
- Member changes are audited.
- `/auth/context` returns membership details and allowed action summaries.

New APIs:

- `GET /organizations/{organization_id}/members`
- `POST /organizations/{organization_id}/members`
- `PATCH /organizations/{organization_id}/members/{user_id}`
- `DELETE /organizations/{organization_id}/members/{user_id}`
- `GET /auth/memberships`

### Validation sandbox hardening

The platform now exposes validation sandbox policy and per-job validation evidence.

New APIs:

- `GET /validation/sandbox-profile`
- `GET /validation-jobs/{validation_job_id}/evidence`

These APIs make the validation boundary visible to operators and auditors. They show whether validation runs in workspace or Docker mode, whether network is disabled, whether secrets are scrubbed, timeout/output limits, path traversal protections, and captured command evidence.

### Backend router extraction

The first architecture cleanup step moved validation-related routes into:

- `backend/routers/validation.py`

The route URLs stayed the same, so existing UI/API clients do not need changes.

### GitHub App router extraction

GitHub App routes were moved into:

- `backend/routers/github_app.py`

The route URLs stayed the same, so existing UI/API clients do not need changes.

## Organization router extraction update

The tenant organization and membership routes have been moved into a dedicated backend router:

```text
backend/routers/organizations.py
```

The public API paths did not change. This is an internal enterprise-readiness cleanup so organization management, member RBAC, membership listing, and audit logging are isolated from the main application file.

Validated focused backend coverage:

- organization membership RBAC
- multi-tenancy behavior
- validation sandbox profile/evidence
- GitHub App enterprise diagnostics
- runtime traffic import
- PR workflow hardening

## Remediation and PR workflow router update

The remediation and GitHub PR workflow routes now live in:

```text
backend/routers/remediations.py
```

The public URLs did not change. This extraction covers remediation listing, suggestion, approval/rejection, validation, PR creation, drift checks, branch cleanup, drift acknowledgement/revalidation, and manual merge marking.

This continues the backend enterprise-readiness cleanup by making the PR workflow easier to maintain, test, and harden separately from the main app module.

## Evidence and reporting router update

Evidence and report APIs now live in:

```text
backend/routers/evidence.py
```

The public API paths did not change. This router covers organization compliance reports, organization readiness, quantum migration portfolio access, drift analytics, asset evidence, remediation evidence, repository evidence, and repository gate decisions.

This cleanup prepares the platform for the next board-level additions: Quantum Risk Index, regulatory mapping, and audit-ready evidence/report APIs.

## Board-level Quantum Risk Index update

The platform now exposes first-pass board-level risk APIs.

New backend service:

```text
backend/services/board_risk.py
```

New APIs:

```text
GET /v1/org/{organization_id}/qri
GET /v1/org/{organization_id}/regulatory-alignment
```

The QRI score is a 0-100 quantum-safe maturity score built from inventory coverage, open exposure reduction, crypto-agility, validated execution, provider/config blocker control, and Day-2 drift governance.

The regulatory alignment endpoint maps platform evidence to NIST SP 800-227, FIPS 140-3, and DORA-oriented control areas. It is designed for board/compliance conversations, but it does not claim legal certification.

## GitHub PR blocking enforcement update

The CI/status-check path now behaves more like a real enterprise merge gate.

`POST /integrations/ci/status-check` now returns whether the PR should be blocked, which check context should be required in GitHub branch protection, and fix suggestions for each violation.

The policy layer also has a default banned crypto rule for RSA-2048 signals in EU/EU-like regions. This is the first implementation of the "global cryptographic policy" concept, where a CISO policy can block PRs that violate organization crypto rules.

The practical result:

- clean repositories return `merge_gate: allowed`
- violating repositories return `merge_gate: blocked`
- GitHub status/check publishing includes actionable violation text
- branch protection can use `pqc-scanner/security-policy` as the required check context

## Certificate lifecycle and Shadow IT update

The platform now has backend APIs for practical crypto-governance automation.

New APIs:

```text
GET /v1/governance/certificates
GET /v1/governance/shadow-it
```

Certificate lifecycle checks classify assets as expired, expiring soon, healthy, or unknown based on the latest scan evidence.

Shadow IT detection compares runtime-observed endpoints against the managed asset inventory. It flags endpoints that are missing from inventory, missing an owner, missing a repository link, or missing scan evidence.

This turns the runtime traffic foundation into an operational security control: the platform can now help teams find unmanaged TLS endpoints they did not know they owned.

## Remediation Feed / PR-Canvas update

The platform now exposes a backend work-feed API for the future actionable remediation UI.

New APIs:

```text
GET /work/remediation-feed
GET /v1/work/remediation-feed
```

The response contains a summarized board and action cards generated from remediations and crypto migration tasks. Each card includes the owning asset/repository/file, current status, board column, priority, next action, action URL, validation status, and safe-to-apply/blocker metadata.

This is the first backend piece for the "anti-report" workflow: instead of only producing PDF/JSON reports, the system can drive a live queue of remediations that operators process directly.

## Remediation Feed UI update

The Remediation Queue screen now uses the `/v1/work/remediation-feed` backend instead of only listing raw remediation rows. It shows action-card columns for candidates, review, validation, PR workflow, verified/drift monitoring, and migration tasks.

This keeps the current URL and existing UI shell stable while preparing for the later Palantir-style animated command-center redesign.

## Board-level dashboard widgets update

The Dashboard now shows a board-level quantum risk posture section. It summarizes QRI, regulatory alignment, work queue state, certificate lifecycle alerts, and shadow IT exposure using the backend APIs.

This advances the executive dashboard requirement while keeping the current UI stable for later visual redesign.

## Policy management UI update

The Policies modal now lets admins load, edit, save, and evaluate the organization policy-as-code profile. It also includes a helper to add the RSA-2048 EU banned-crypto policy used by PR blocking.

This moves global cryptographic policy enforcement from hidden backend defaults into an operator-visible governance surface.

## Runtime traffic log ingestion update

Runtime traffic import now accepts raw log lines through `raw_logs` and `log_format` on `/v1/runtime/traffic/import`. The backend parses common JSON/text access log patterns into runtime observations and asset records.

This is the next step toward live production traffic coverage and reduces reliance on static code/repository analysis only.

## Runtime traffic UI update

The main operator console now includes a Runtime Traffic panel. Operators can paste raw edge/access logs, import runtime observations, view runtime-observed assets, and load Shadow IT findings.

This makes the runtime/network evidence workflow available from the UI while keeping the current URL stable.

## GitHub App diagnostics UI update

The GitHub connection panel now includes GitHub App status, installation sync, repository sync, and repository diagnostics controls. This makes GitHub App readiness visible before starting a live PR workflow.

## PR readiness update

The remediation workflow now includes a PR readiness API:

```text
GET /remediations/{remediation_id}/pr-readiness
GET /v1/remediations/{remediation_id}/pr-readiness
```

It checks whether a remediation is approved, has a linked `owner/repo`, has a target file, has suggested content or a diff, has a GitHub credential id, and has a latest passing validation job. With `check_live_repo=true`, it also runs GitHub App repository diagnostics.

The response gives operators a direct `next_action` such as `approve`, `validate`, `create_pr`, `track_pr`, or `verify_close`, plus concrete blockers. This closes a safety gap between validation and live PR mutation.

## PR readiness UI update

The Remediation Queue now has a `PR Readiness` action on approved/validated remediation cards. The `Create PR` action also runs readiness first and blocks unsafe PR creation with concrete reasons.

This means the UI no longer jumps directly from a queue card to GitHub mutation. It first verifies approval, validation, repository linkage, file target, suggested content, GitHub credential id, and optional live repo diagnostics.

## End-to-end readiness checklist update

The platform now has an E2E readiness API and Dashboard section:

```text
GET /readiness/e2e
GET /v1/readiness/e2e
```

It aggregates evidence for the original 25-step full test plan and marks each step as `ready`, `warning`, or `blocked`. The Dashboard shows the readiness percentage, blocked count, warnings, and top blockers so the team can see exactly what remains before the final live money-flow demo.

The Dashboard checklist now includes action buttons. Operators can click `Do next` or `Run top blocker` to jump into the relevant workflow: GitHub App status, scan, asset onboarding, correlation, remediation queue, webhooks/integrations, audit logs, or compliance report JSON.

## E2E readiness handoff export update

The E2E readiness checklist now has compact handoff exports:

```text
GET /readiness/e2e/export?format=markdown
GET /readiness/e2e/export?format=json
GET /v1/readiness/e2e/export?format=markdown
GET /v1/readiness/e2e/export?format=json
```

The Dashboard can open the compact blocker handoff or copy a Markdown handoff. This is intended for release notes, demo prep, and internal status sharing before running the final live enterprise flow.

## Modelled output label: `model_basis`

Any response that carries figures the platform did not observe in the customer's own environment (projections, planning assumptions, curated reference data, or seed records) includes a top-level `model_basis` object:

```json
"model_basis": {
  "kind": "model",
  "summary": "One plain sentence: what this is and what it is not.",
  "assumptions": ["Short statements of each assumption used"],
  "sources": ["Citation or URL"],
  "as_of": "YYYY-MM"
}
```

- `kind: "model"` — computed from stated assumptions; a scenario, not a forecast.
- `kind: "reference"` — curated guidance or public facts, correct as of `as_of`.
- `kind: "seed"` — starter records shipped with the product, not customer data.

The builder is `services/model_basis.py`. Endpoints that carry it:

| Endpoint | kind | Notes |
|---|---|---|
| `GET /qday/countdown` | model | Scenario years from the Q-Intel model (10% / 50% / 90%); CNSA 2.0 items are target dates whose `status` only says whether the date passed |
| `GET /q-intel/model` | model | Adds `reference_years`, `logical_qubits_required`, `seed_milestone_count` |
| `GET /q-intel/feed` | seed | Each milestone has `is_seed` and `kind` (`seed` or `ingested`); `error_rate` is null when the source did not state one |
| `GET /qday-forecast`, `/qday-forecast/milestones`, `/qday-forecast/threat-actors` | model / seed / reference | Threat actors are not provided (`threat_actors: []`) |
| `GET /hndl/dashboard`, `GET /hndl/timeline` | model | `assumptions` lists the full break-probability table and per-port data values; dashboard adds `q_day_year_source` |
| `GET/POST /actuarial/individual`, `POST /actuarial/portfolio` | model | |
| `GET /quantum-sim/graph`, `POST /quantum-sim/detonate` | model | Break times are scenario assumptions |
| `GET /contagion/graph`, `POST /contagion/simulate` | model | Only organizations observed in your scans are counted |
| `POST /roi-calculator` | model | Breach costs cite IBM Cost of a Data Breach Report 2024 |
| `POST /red-team/simulate`, `POST /red-team/qday-event` | model | Scenario years from the Q-Intel model |
| `GET /dark-matter/map` | model | Observed keys only; no adversary harvest estimates |
| `POST /attribution/analyze` | reference | Neutral network facts; `attribution_provided: false` |
| `GET /peer-benchmark` | reference | `available: false` — no peer data source is connected |
| `GET /qtisn/dashboard` (and join/signal/membership/history) | model | `network_scope: "local"` |
| `GET /vendor-scorecard`, `/summary`, `POST /vendor-scorecard/compare` | reference | No platform-authored vendor scores |
| `GET /providers/capabilities` | reference | Generic guidance, not current provider support |

### Q-Day single source of truth

`services/q_intel.py` computes every Q-Day year shown in the product. `/qday/countdown`, the `/hndl/dashboard` default year, `/qday-forecast`, the ROI and actuarial curves and the red-team simulation all read `q_day_reference()`. The model counts the largest logical-qubit demonstration among the recorded milestones, grows it at the rate implied by IBM's published fault-tolerance roadmap, and compares it with the logical qubits Shor's algorithm needs (2n+2 for RSA, Häner et al. 2017; 9n+2⌈log₂n⌉+10 for ECC, Roetteler et al. 2017). Seed milestones were checked against their linked sources; figures that could not be verified are left null.

### Deployment values in generated artifacts

Generated artifacts no longer carry placeholder domains or identifiers. Set these in the environment (see `.env.prod.example`); when unset, the value is omitted:

- `PQC_PUBLIC_BASE_URL` — links in CI workflows and SARIF, credential JSON-LD context, fallback did:web domain.
- `PQC_DID_WEB_DOMAIN` — did:web issuer domain for verifiable credentials.
- `PQC_STATUS_PAGE_URL` — status page in incident communication templates.
- `PQC_PRIVATE_ENTERPRISE_OID` — OID (under your IANA Private Enterprise Number) for the hybrid-certificate PQC extension.

### Demo Lab

`POST /demo/lab/seed` works only when `PQC_ENVIRONMENT` is `local`, `dev`, `development`, `test` or `testing`; `PQC_ALLOW_DEMO_IN_PRODUCTION` does not re-enable it. `GET /auth/config` exposes `environment` (`local`, `staging` or `production`) and `demo_lab_available`. Seeded records are marked with source `demo-lab` (asset tag and metadata, scan id prefix `demo-lab-`, remediation `origin_kind: demo_lab`, validation job prefix `demo-lab-validation-`, audit actor `demo-lab`).

## Operator SSO, MFA and break-glass

The vendor admin portal (`/vendor-admin/`) signs operators in three ways. Code: `backend/services/operator_auth.py`, `backend/routers/operator_auth.py`, `backend/static_admin/admin-auth.js`. Tests: `backend/test_admin_sso_mfa.py`.

| Method | `auth_method` | Identity in the audit trail | Where it is allowed |
|---|---|---|---|
| SSO (OpenID Connect, authorization code + PKCE) | `sso` | the operator's email | everywhere; the production default |
| Named operator key (`PQC_PLATFORM_OPERATORS`) | `operator_key` | the operator name | everywhere; needs MFA when MFA is required |
| Shared key (`PQC_PLATFORM_ADMIN_KEY`) | `shared_key` locally, `break_glass` in production/staging | `platform-admin` | local/test as before; production/staging only with `PQC_ALLOW_BREAK_GLASS_KEY=1` |

Every platform admin event now records `auth_method` and `email` (under `details.operator`).

### SSO flow

1. `GET /vendor-admin/sso/start` loads the issuer's discovery document, stores a single-use state (hashed), nonce and PKCE verifier server-side for 10 minutes, binds the state to the browser in an HttpOnly `SameSite=Lax` cookie scoped to `/vendor-admin/sso`, and redirects to the IdP.
2. `GET /vendor-admin/sso/callback` requires the state to match the cookie and the stored row, exchanges the code with the PKCE verifier (client secret via `client_secret_basic`, or `client_secret_post` if that is all the IdP supports), and verifies the ID token against the issuer's JWKS: RS/PS/ES algorithms only, `iss`, `aud` (and `azp` for multi-audience tokens), `exp`/`iat` with 60 s leeway, `nonce`, and `email_verified`.
3. The email must be on `PQC_ADMIN_OPERATOR_ROLES` (and inside `PQC_ADMIN_OIDC_ALLOWED_DOMAINS` when set). With no roster, members of the allowed domains get `PQC_ADMIN_OIDC_DOMAIN_ROLE` (default `auditor`). Nobody is provisioned; unknown emails are refused and audited as `platform.operator_sign_in_denied`. The role is re-read from the roster on every request, so removing an email ends that person's access at once.
4. A session row is created (only the SHA-256 of the session id is stored) and two cookies are set: `pqc_admin_session` (HttpOnly, `SameSite=Strict`, `Path=/`, `Secure` except on localhost) and `pqc_admin_csrf` (readable). Sessions expire after `PQC_ADMIN_SESSION_ABSOLUTE_SECONDS` (8 h) or `PQC_ADMIN_SESSION_IDLE_SECONDS` (30 min) without a request.
5. Cookie-authenticated writes must send `x-csrf-token`, which equals the CSRF cookie and is also returned by `GET /platform/whoami`. A request that carries `x-platform-key` is authenticated by the key and ignores the cookie.

`POST /platform/session/logout` ends the session (CSRF-checked while the session is valid) and clears the cookies. `GET /platform/operator-sessions` lists console sessions (also returned as `operator_sessions` by `GET /platform/sessions`), and `POST /platform/operator-sessions/{session_ref}/revoke` with a reason ends one.

`GET /platform/auth-config` is public and returns only `sso_enabled`, `sso_start_url`, `mfa_required`, `break_glass_allowed` and `environment`. `GET /platform/whoami` adds `auth_method`, `email`, `mfa` (enrolled, elevated, recovery codes left, last verified), `session` (expiry) and `csrf_token`.

### MFA (TOTP)

RFC 6238: HMAC-SHA1, 30-second steps, 6 digits, implemented with the Python standard library. The secret is encrypted at rest with the vault key (`vault_crypto`, Fernet over `PQC_VAULT_MASTER_KEY`), so MFA needs that key but not Postgres. Codes are accepted one step either side of now; a step that was already used is refused (replay protection); 5 failed attempts in 5 minutes lock the identity until the window passes (`platform.mfa_rate_limited`, severity high). Ten recovery codes are issued at enrolment, stored as SHA-256 hashes, and each works once.

| Route | Purpose |
|---|---|
| `GET /platform/mfa/status` | the caller's enrolment |
| `POST /platform/mfa/enroll/start` | new secret, `otpauth://` URI and a QR code rendered locally (`services/qr_svg.py`, no external request) |
| `POST /platform/mfa/enroll/confirm` `{code}` | activates MFA and returns the recovery codes once |
| `POST /platform/mfa/verify` `{code}` or `{recovery_code}` | elevates the session, or refreshes step-up |
| `POST /platform/mfa/recovery-codes/regenerate` `{code}` | replaces all recovery codes |
| `GET /platform/mfa/operators` | owner: every enrolment |
| `POST /platform/mfa/reset` `{identity, reason}` | owner with step-up: removes another operator's MFA and ends their sessions (`platform.mfa_reset`) |

Policy: `PQC_ADMIN_REQUIRE_MFA` defaults to on when `PQC_ENVIRONMENT` is `production`/`prod`/`staging`, off otherwise. When MFA is required, or the identity has enrolled, an SSO session is only elevated after a code; until then only whoami, the MFA routes and logout answer (`401` with `mfa_enrolment_required` or `mfa_required`). A named operator key counts as verified for 8 hours after `POST /platform/mfa/verify` with that key.

Step-up: purge, a deleting retention run, state migration, org-wide session revocation, API key rotation, a customer plan change and MFA reset call `require_step_up()`, which answers `403` `mfa_step_up_required` unless a code was verified within `PQC_ADMIN_STEP_UP_SECONDS` (15 min). The console prompts for a code and retries. The shared key has no identity and is not asked for step-up; in production it is break-glass only and audited.

### Break-glass

In production and staging the shared `PQC_PLATFORM_ADMIN_KEY` is refused with `403 break_glass_disabled` unless `PQC_ALLOW_BREAK_GLASS_KEY=1`. With the flag, every write and the first read of each route per minute records `platform.break_glass_used` with severity high (method, path, client address, user agent), and `GET /platform/notifications` raises a critical `break_glass` item for 24 hours. The alert dispatcher computes the go-live gate in-process and never uses the shared key. Locally and in test the shared key behaves as before.

`GET /platform/go-live-gate` requires three more checks: `admin_sso` (issuer, client id and a roster or domains), `admin_mfa_required`, and `admin_break_glass_disabled`.

### Identity provider set-up

Register a web application with redirect URI `https://<your host>/vendor-admin/sso/callback`, scopes `openid email profile`, and grant type authorization code (PKCE S256).

| IdP | `PQC_ADMIN_OIDC_ISSUER` | Notes |
|---|---|---|
| Okta | `https://<org>.okta.com` (org server) or `https://<org>.okta.com/oauth2/default` | Web app integration; assign the operators' group. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Use the tenant-specific issuer, never `common`. Add the optional `email` claim, or set `PQC_ADMIN_OIDC_EMAIL_CLAIM=preferred_username` and `PQC_ADMIN_OIDC_REQUIRE_EMAIL_VERIFIED=0` (Entra does not emit `email_verified`). |
| Google Workspace | `https://accounts.google.com` | OAuth client of type Web application, consent screen Internal; set `PQC_ADMIN_OIDC_ALLOWED_DOMAINS` to your Workspace domain. |

### Environment files with a byte order mark

`backend/.env` files saved by Windows tools start with a UTF-8 BOM. `services/env_file.py` parses them BOM-tolerantly, and `app.py` repairs variables that a BOM-unaware loader (python-dotenv via `uvicorn --env-file`) defined with the BOM in front of the name. The PowerShell parsers in `start-local-server.ps1`, `prod-preflight.ps1`, `prod-handoff.ps1` and `check-go-live-gate.ps1` strip it too (Windows PowerShell 5.1's `Get-Content` already does). The vault start-up warning and failed deferred-schema warnings pass through `redact_secrets`, which removes values of secret-named environment variables, URL passwords and `NAME=value` pairs for secret names.

### Rotating the vault master key

`PQC_VAULT_MASTER_KEY` seals: vault credentials (`credentials.secret_enc`, Postgres), gateway site keys (`gateway_sites.data.sealed_key`), operator TOTP secrets (`platform_operator_mfa.secret_enc`), GitHub OAuth tokens (`github_tokens.access_token`, with the key derivation in `services/github_oauth.py`) and alert channel targets (`platform_alert_channels.target_sealed`, `fernet:` prefix; email recipient lists are stored `plain:`). `scripts/rotate-vault-master-key.py` re-encrypts all of them.

1. Put the portal in maintenance mode or stop the API and workers, and take a database backup.
2. Provide the keys in the environment only: `PQC_VAULT_MASTER_KEY` (current) and `PQC_VAULT_MASTER_KEY_NEW`. To generate the new key instead, pass `--generate-new-key-file PATH`: the file is created exclusively with owner-only permissions and the key is never printed.
3. Dry run (the default): `backend/.venv/Scripts/python.exe scripts/rotate-vault-master-key.py`. Every value is decrypted with the old key, re-encrypted, re-read and decrypted with the new key inside open transactions, which are then rolled back. The JSON report lists row counts per target. Exit code 2 lists row ids that do not decrypt with the current key; nothing is changed.
4. Apply: add `--apply`. Each database is one transaction (`BEGIN IMMEDIATE` on SQLite, row locks on Postgres). With several databases, all are prepared and verified before any commits; if a later commit fails, earlier ones are restored to their original ciphertexts (exit code 3).
5. Store the new key as `PQC_VAULT_MASTER_KEY` in the secret manager, restart every API and worker replica, check a vault read, a gateway and an MFA sign-in, then destroy the old key and the key file.

Not re-encryptable, because the vault key is used as an HMAC key rather than to encrypt: SAML-issued session tokens (users sign in again), the HS256 fallback in the JWT verifier, security-journal subject references (new events get new pseudonyms, so correlation with older events by subject reference breaks), and evidence signatures when `PQC_EVIDENCE_SIGNING_KEY` is unset (older evidence no longer verifies; set a dedicated evidence key before rotating).
