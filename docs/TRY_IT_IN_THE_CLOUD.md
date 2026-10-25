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
localStorage.removeItem("morrow_auth_bearer_token");
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
- post-quantum recommendation

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
localStorage.removeItem("morrow_auth_bearer_token");
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
