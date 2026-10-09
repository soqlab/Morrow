# PQC Scanner Explained in Plain English

This document explains PQC Scanner for a non-technical reader.

It avoids assuming you know software engineering, cloud infrastructure, cybersecurity, GitHub, Terraform, Docker, databases, or AI terminology.

The goal is simple:

- explain what the software does
- explain why each part exists
- explain what the technical words mean
- explain how the whole system works from start to finish

## Page 1: The simple idea

PQC Scanner is a security workflow platform.

In simple terms, it helps a company answer this question:

> Are our public websites, APIs, and internet-facing systems using safe modern cryptography, and if not, how do we fix them in code?

Most companies have public systems such as:

- a public website
- a login page
- a customer portal
- a patient portal
- an API for mobile apps
- an admin portal
- a payment or checkout system

These systems normally use HTTPS. HTTPS depends on cryptography. Cryptography is the math and technology that keeps traffic private and trusted.

PQC Scanner checks those public systems and looks for crypto and TLS posture issues.

TLS is the technology behind HTTPS. When you see a padlock in the browser, TLS is part of what makes that work.

PQC means post-quantum cryptography.

Post-quantum cryptography is about preparing for a future where quantum computers may break some older cryptographic systems. Most companies are not fully ready for that yet. PQC Scanner helps them understand where they are and move toward safer, more flexible crypto setups.

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

PQC Scanner is designed to make this workflow more direct.

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

PQC Scanner can treat that as an asset.

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

PQC Scanner connects to GitHub so it can turn security findings into real code changes.

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
- GitHub sends a webhook to PQC Scanner
- PQC Scanner receives the message
- PQC Scanner marks the remediation as merged

Think of a webhook as:

- an automatic notification between systems

The product also has outbound webhooks.

Outbound webhooks mean PQC Scanner can notify other systems, such as:

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

PQC Scanner uses Docker because the product is not just one script.

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

PQC Scanner needs cloud infrastructure such as:

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

If PQC Scanner suggests a change to a Terraform file, the platform can run Terraform validation to check whether the new file is valid.

So Terraform is used in two ways:

- to deploy PQC Scanner infrastructure
- to validate customer infrastructure code changes

## Page 8: What the database does

The database stores the product state.

Without a database, the system would forget everything after a restart.

PQC Scanner uses PostgreSQL, often called Postgres.

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

PQC Scanner uses Cloud Run for:

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

The PQC Scanner runtime service account is allowed to:

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

Instead of PQC Scanner building its own password system, Auth0 can handle:

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

PQC Scanner reads the JWT and uses it to decide:

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

The strongest value of PQC Scanner is that it connects security and engineering.

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

PQC Scanner turns external crypto and TLS risk into validated code remediation and verified evidence.

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
