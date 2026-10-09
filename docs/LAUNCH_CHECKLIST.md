# Launch checklist

**Written for: you, deciding whether this is ready to put in front of strangers.**

Three things are launching at once and they have different readiness bars:

| | What it is | Blocked by |
|---|---|---|
| **The hosted site** | `your-domain.com`: the marketing pages, the free check, the trial request form, the customer console | a server, a domain, an identity provider |
| **The admin portal** | `/vendor-admin`: you, running the business | operator SSO and MFA on the real deployment |
| **The public repository** | the MIT release on your forge, mirrored to GitHub | nothing technical; it is ready |

The engineering is done. What is left is mostly decisions, accounts and one lawyer.

---

## Part 1 — Before the site is reachable

Follow [deploy/single-host/README.md](../deploy/single-host/README.md), which is the sequenced
version of this. The decisions it needs from you:

- [ ] **A domain.** Everything else references it. `PQC_PUBLIC_BASE_URL` has to match it exactly
      or the registry advertises links that do not resolve.
- [ ] **A server.** Hetzner CPX22 or equivalent: 3 vCPU, 4 GB, 80 GB.
- [ ] **An identity provider** for customer sign-in. The go-live gate requires RS256 with a JWKS
      URL, so this cannot be skipped or faked. Auth0's free tier covers 25,000 monthly users;
      Zitadel or Keycloak self-host on the same box if you would rather own it.
- [ ] **A second OIDC application** for operator sign-in to `/vendor-admin`, plus
      `PQC_ADMIN_OPERATOR_ROLES=you@your-domain.com=owner`.
- [ ] **Generate and store the four secrets.** `PQC_VAULT_MASTER_KEY` decrypts every stored
      customer credential — lose it and a restored backup is unreadable ciphertext.
- [ ] **Set the trial caps.** `PQC_TRIAL_API_CALLS_PER_MIN` and `PQC_TRIAL_SCANS_PER_HOUR`
      (`.env.prod.example` suggests 60 and 10). They are applied as a real rate-limit override when
      you approve a request. Leave them at 0 and a trial organization runs on the same limits as a
      paying one. There used to be a plan-based tier that could cap them; it went with the billing
      code, so an operator override is now the only per-organization limit there is.
- [ ] **An outbound mail sender** so invitations and alerts arrive. Any SMTP provider; the trial
      flow works without it (you copy the invitation link by hand) but that does not scale past
      the first few.

## Part 2 — Before you tell anyone

- [ ] **`/platform/go-live-gate` answers `go`.** Thirty required checks. Do not launch around a
      failing one; each exists because of something that went wrong.
- [ ] **A backup has been restored.** Not taken — restored, onto a scratch server.
      `deploy/single-host/backup.sh` covers Postgres, the SQLite feature store and (encrypted) the
      env file. A backup you have never restored is a guess.
- [ ] **Walk the customer path yourself.** Submit `/trial`, approve it from **Customers → Trial
      requests**, accept the invitation, sign in, run a scan, export the CBOM. End to end, as a
      stranger, on the real deployment.
- [ ] **MFA enrolled on your operator account.** The self-enrolment window closes once the first
      owner has an authenticator, so do this before anyone else is enrolled.
- [ ] **Tenant isolation verified on the real database**: `POST /platform/tenant-isolation/verify`.
      It creates probe data and removes it.
- [ ] **A second organization exists** and you have confirmed it cannot see the first. Row-level
      security is enforced by Postgres, but confirm it where it runs.

## Part 3 — Before the free checker faces the public

`PQC_PUBLIC_CHECK_ENABLED=0` in production until all five exist. This is the only part of the
platform that connects to a machine the requester may not own, which is a different kind of
responsibility from scanning your own estate.

- [x] Terms that bind without a signup step — `/public-check/terms`
- [x] An acceptable-use policy — `/public-check/acceptable-use`
- [x] A privacy notice covering the requester *and* the party checked — `/public-check/privacy`
- [ ] **A monitored abuse mailbox with a stated response time.** Set
      `PQC_PUBLIC_CHECK_ABUSE_CONTACT`, and replace the placeholder on `/abuse`. A mailbox nobody
      reads is worse than none, because the page promises it.
- [ ] **Egress addresses and reverse DNS on `/scanner`.** They depend on this server. Until they
      are published, an operator who wants to block the service has to identify it by behaviour,
      which is how egress ranges get blocklisted wholesale.
- [ ] **A lawyer has read the five pages.** They are drafts and they say so. I am not a lawyer and
      they are not legal advice. The open questions are listed at the bottom of
      `/public-check/privacy`: lawful basis for each processing activity, whether the checked party
      is a data subject, whether a legitimate-interests assessment survives, retention, and
      international transfer for the Certificate Transparency lookup.

The registry at `/r/{domain}` is part of this: it keeps results permanently, which the privacy
notice now discloses. Mass seeding is **not** switched on and should not be until the abuse mailbox
is real — see [PUBLIC_REGISTRY_DESIGN.md](PUBLIC_REGISTRY_DESIGN.md) §5 for why passive
Certificate Transparency seeding is safe at any scale and active measurement is not.

## Part 4 — Publishing the code

- [ ] **Stand up the forge** — `../quantum-forge/docs/FORGE_SETUP.md`. Gitea, Postgres, Caddy,
      nightly backups.
- [ ] **Publish from a clean history**: `./scripts/publish-clean-repo.sh ~/Desktop/pqc-scanner
      Sprint35 git@git.yourdomain.com:you/airlock-command.git`. It exports only tracked files,
      compares every real value in your local `backend/.env` against the export, and refuses if
      one appears.
- [ ] **Mirror to GitHub** for discovery: `./scripts/mirror-to-github.sh`, or the forge's own push
      mirror. Say in the GitHub description that issues live on the forge.
- [ ] **Move `../pqc-scanner-private/` into a private repository.** It holds the full security
      review, pricing and go-to-market material. Right now it exists only on this laptop.
- [ ] **Rotate any credential ever pasted outside git** — into a chat, a terminal you screen-shared,
      a file you emailed. Cheap now, expensive later.
- [ ] **Decide where the demo videos live, and back them up.** `demo/video/` is 1.3 GB on this
      laptop and only 460 KB of it is tracked — the `.gitignore` already excludes the MP4s and WAV
      masters, so a public clone stays small. But that means the finished videos exist in exactly
      one place: here. Put them in object storage or release assets, both to serve them from the
      site and so a disk failure does not take them.

## Part 5 — Market ready, as distinct from technically ready

- [x] **Pricing decided: there isn't any.** The hosted service is free and the platform is MIT.
      `/pricing` says so and explains what free does and does not mean, and the billing code has
      been removed (revision 0009 drops its tables).
- [ ] **Know what actually limits you, which is not money.** Scanning is close to free: a TLS scan
      is one socket and a handshake, the platform never clones a repository, and a fixed-price VPS
      costs the same whether it serves ten scans or a hundred thousand. There is no per-scan meter
      to worry about. What does limit you, in the order it will bite:
      - **Your own time.** You approve every workspace by hand. That is the bottleneck, and the
        reason verified-domain self-serve is the next thing worth building.
      - **crt.sh's goodwill.** The free checker reads Certificate Transparency from a third party,
        with a politeness throttle (`PQC_PUBLIC_CHECK_CT_MIN_INTERVAL_SECONDS`). Being a heavy
        user gets you rate-limited or blocked. That is a cost in access, not in money. Set
        `PQC_PUBLIC_CHECK_CT_TOKEN` if you move to CertSpotter, and watch for CT failures — the
        page reports them honestly rather than guessing, so they show up as missing data.
      - **Concurrency.** Four checks at once, a 32-deep queue, 240 an hour globally. A flood
        produces 429s and a queue, not a cost. Raise the numbers only with the server in front
        of you.
      - **Disk, slowly.** The registry is append-only but stores one row per *change* in an
        endpoint's cryptography, not per scan; the traffic journal prunes at 7 days and the check
        log at 30. Put a disk alert on the box and forget about it.

      A real bill only appears if you move to Cloud Run with managed Postgres, which charges per
      request, or serve `demo/video/` off the box.
- [ ] **Say what happens if you stop.** Free with no SLA is honest, but an organisation planning a
      migration against a 2030 deadline needs to know the answer. It is already a good one: the
      source is MIT and published, so they can run their own copy. Make sure that sentence is
      somewhere they will read it — it is on `/pricing` now.
- [ ] **One real customer or pilot** who has run the full path and will say something about it.
      Everything else on this list is you talking about yourself.
- [ ] **Decide what happens when a trial expires.** Nothing currently does — the *invitation*
      expires (168 hours by default) but the organization does not, so a trial stays a trial with
      trial caps and no end date. That is fine while you can see every trial on one screen, and a
      problem at a hundred. Deliberately not built: a mechanism that locks people out is one you
      want to design on purpose rather than inherit.
- [ ] **No customer-facing view of their own limits.** A trial owner learns their caps from
      `X-RateLimit-Limit` on every response and from the refusal when they hit one, which is how
      most APIs do it, but there is no screen for it. `/trial` says exactly that rather than
      promising a screen.
- [ ] **Know your answer to "where is my data?"** You can answer it well — Postgres row-level
      security, a documented data boundary, customer-controlled AI with an operator kill switch,
      `/data-boundary` and `/security` already written. It will be the first question from every
      serious buyer.
- [x] **Nothing to bill, so nothing to set up.** No Stripe, no Polar, no merchant account, no
      Mauritius banking question, and no billing code: it was removed rather than left dormant.
      Recovering it means reverting the removal commit, which is why it went in as one commit.

---

## What is deliberately not on this list

**Self-service signup.** `/auth/register` is admin-only and a trial request is reviewed by a
person. That is a choice, not a gap: an authenticated account can scan arbitrary hosts, and none of
the free checker's guardrails apply to the full scanner. Open signup would make this a free
reconnaissance service pointed at other people's infrastructure, from your IP addresses, under your
name. The staged path is to launch with review, then build verified-domain self-serve — where
scanning is limited to domains the account has proved it controls — which is the only design that
makes open signup safe.

**A status page, SOC 2, a SIEM integration, SSO for customers.** All real asks from real buyers,
none of them a launch blocker. Wait until someone asks; the answer "not yet, and here is when"
costs you nothing at this stage.
