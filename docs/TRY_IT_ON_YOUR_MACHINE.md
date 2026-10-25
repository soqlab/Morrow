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
cd C:\Users\Samsung\Desktop\morrow\backend
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
localStorage.removeItem("morrow_auth_bearer_token");
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
cd C:\Users\Samsung\Desktop\morrow\backend
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
