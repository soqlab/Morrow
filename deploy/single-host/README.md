# Deploying to one server

**Written for: you, bringing the hosted site up for the first time.**

One VPS runs everything: the API, the worker, the scheduler, Redis, Postgres and Caddy for TLS.
This is the right shape until you have real traffic, and moving to Cloud Run or Kubernetes later is
a compose file and a DNS record — `infra/gcp/cloudrun` and `infra/helm` are already in the
repository for that day.

Work through this in order. The finish line is the go-live gate answering `go`, which is a real
gate: thirty required checks, and it refuses on things people normally discover in production.

## 0. What you need before you start

| | |
|---|---|
| A server | 3 vCPU, 4 GB RAM, 80 GB disk. Hetzner CPX22 (~€8/month) is enough for the first hundred customers. Ubuntu 24.04. |
| A domain | With an **A record** pointing at the server's IP, and a second for `www`. Do this first: the certificate cannot be issued until DNS resolves. |
| An identity provider | The go-live gate requires RS256 with a JWKS URL, so customer sign-in needs a real IdP. Auth0's free tier covers 25,000 monthly users and is what `.env.prod.example` is already written for. If you would rather own it, Zitadel or Keycloak run on this same box — more operational surface, no vendor. |
| Docker | `curl -fsSL https://get.docker.com | sh` and the compose plugin. |

Nothing here needs a Stripe account. Billing is provider-neutral (`backend/services/billing_core.py`):
invoice directly, take cards through Polar, or leave both dormant.

## 1. Put the code on the server

```bash
sudo mkdir -p /srv && sudo chown "$USER" /srv
git clone <your forge URL> /srv/pqc-scanner
cd /srv/pqc-scanner
```

## 2. Secrets

Four values must be generated, and three of them cannot be rotated casually afterwards:

```bash
cp .env.prod.example .env.prod
chmod 600 .env.prod

python3 - <<'PY'
import secrets
print("POSTGRES_PASSWORD=" + secrets.token_urlsafe(32))
print("PQC_PLATFORM_ADMIN_KEY=" + secrets.token_urlsafe(48))
print("PQC_VAULT_MASTER_KEY=" + secrets.token_urlsafe(48))
print("PQC_AIRLOCK_SIGNING_KEY=" + secrets.token_urlsafe(48))
PY
```

`PQC_VAULT_MASTER_KEY` decrypts every stored customer credential. If you lose it, a restored
backup comes back as unreadable ciphertext — so it belongs in your password manager before you
paste it anywhere, and `scripts/rotate-vault-master-key.py` exists for the day you need to change
it. `PQC_AIRLOCK_SIGNING_KEY` signs evidence; changing it invalidates signatures already issued.

Then fill in the rest of `.env.prod`. The ones this overlay needs beyond the example file:

```ini
SITE_DOMAIN=your-domain.com
ACME_EMAIL=you@your-domain.com
POSTGRES_PASSWORD=<generated above>
DATABASE_URL=postgresql://pqc:<that same password>@db:5432/pqc

PQC_PUBLIC_BASE_URL=https://your-domain.com
PQC_ALLOWED_HOSTS=your-domain.com,www.your-domain.com
PQC_CORS_ORIGINS=https://your-domain.com
```

`PQC_PUBLIC_BASE_URL` is load-bearing beyond cosmetics: every canonical link, every badge URL and
every invitation link is built from it. Wrong, and the registry advertises an address that does not
resolve.

## 3. Bring it up

```bash
C="docker compose -f docker-compose.prod.yml -f deploy/single-host/compose.yml --env-file .env.prod"

$C build
$C up -d db redis
$C run --rm -e AUTO_MIGRATE=1 api true     # migrations, once, explicitly
$C up -d
$C logs -f caddy                            # watch the certificate issue, then Ctrl-C
```

Migrations run as their own step rather than at container start. `AUTO_MIGRATE` at boot against a
Postgres that is not ready yet is what put the open-source quick start into a restart loop: the
container died before serving once, and the only symptom was a container that kept restarting.

Open `https://your-domain.com`. The landing page leads with the free check, which needs no account.

## 4. Check the production safety rules before you trust it

```bash
set -a && . ./.env.prod && set +a
python3 -c "import sys; sys.path.insert(0,'backend'); import app; print(app._production_startup_blockers() or 'config OK')"
```

Then the gate itself, which is the real answer:

```bash
curl -s -H "x-platform-key: $PQC_PLATFORM_ADMIN_KEY" \
  https://your-domain.com/platform/go-live-gate | python3 -m json.tool
```

`scripts/check-go-live-gate.ps1 -BaseUrl https://your-domain.com` prints the same thing as a list
of failures with the fix for each, and takes an operator session instead of the key.

It reports `status: "go"` or `"no_go"` with every failed check and the fix for each. Expect
`no_go` on the first run; work the list down. The checks that usually need real decisions are the
IdP ones (`auth_mode`, `jwt_config`, `jwt_algorithms`, `auth_issuer`) and the operator sign-in ones
(`admin_sso`, `admin_mfa_required`, `admin_break_glass_disabled`).

The shared platform key is **break-glass only** in production. Once operator SSO and MFA are
configured, you sign in to `/vendor-admin` as a named operator and the key goes back in the
password manager.

## 5. Your own operator account

Two separate things: who you sign in as, and what the roster says you may do.

**Operator SSO.** Register `/vendor-admin` as an OIDC application with your IdP (the same one from
step 0 — a second application, not the customer one), then:

```ini
PQC_ADMIN_OIDC_ISSUER=https://your-tenant.auth0.com/
PQC_ADMIN_OIDC_CLIENT_ID=...
PQC_ADMIN_OIDC_CLIENT_SECRET=...
PQC_ADMIN_OIDC_REDIRECT_URI=https://your-domain.com/vendor-admin/sso/callback
PQC_ADMIN_OIDC_ALLOWED_DOMAINS=your-domain.com
PQC_ADMIN_OIDC_REQUIRE_EMAIL_VERIFIED=1

# The roster. "owner" is the ceiling; the others are operator, support and auditor.
PQC_ADMIN_OPERATOR_ROLES=you@your-domain.com=owner
```

**A named key, optionally**, for scripts and for break-glass — not for signing in day to day:

```bash
$C run --rm api python -m services.platform_operators --name you@your-domain.com --role owner
```

It prints a key once and the JSON entry to add to `PQC_PLATFORM_OPERATORS`. The key itself is never
stored — only its SHA-256 — so a lost key is replaced, not recovered.

**Then enrol your authenticator, as the first thing you do.** MFA self-enrolment is open only
during a bootstrap window, and that window closes the moment the first *owner* holds an
authenticator — deliberately, because until then there is nobody with standing to approve one.
Every enrolment inside the window is audited at high severity and raised as a notification, so it
is visible rather than merely permitted. Sign in, enrol, and the window shuts behind you.

An operator account on a public deployment gets probed within hours of DNS resolving, and this one
can read every tenant.

## 6. Backups, before you have anything to lose

```bash
# Encrypt the env file into the backup, or a restore gives you ciphertext you cannot read.
echo "BACKUP_GPG_RECIPIENT=you@your-domain.com" >> .env.prod
echo "BACKUP_REMOTE=b2:your-backup-bucket" >> .env.prod   # any rclone remote

( crontab -l 2>/dev/null; echo "15 3 * * * cd /srv/pqc-scanner && ./deploy/single-host/backup.sh >> backups/backup.log 2>&1" ) | crontab -
./deploy/single-host/backup.sh      # run it once now and read the output
```

Then **restore it once, onto a scratch server**, while nothing depends on it. A backup you have
never restored is a guess, and the backup script tells you so in its own comments.

## 7. Firewall

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp          # your own access
sudo ufw allow 80,443/tcp      # Caddy
sudo ufw enable
```

Postgres and Redis are on the compose network and are never published. The API publishes only to
`127.0.0.1` by default, so Caddy reaches it and the internet does not.

## 8. The free checker, which is off until you turn it on

`PQC_PUBLIC_CHECK_ENABLED` is `1` for self-hosters and `0` in `.env.prod.example` on purpose. It is
the only part of the platform that connects to a machine the requester may not own, and five things
must exist before it faces the public:

1. Terms that bind without a signup step — drafted, at `/public-check/terms`.
2. An acceptable-use policy — drafted, at `/public-check/acceptable-use`.
3. A privacy notice covering both the requester and the party checked — drafted, at `/public-check/privacy`.
4. **A monitored abuse mailbox**, with a response time, set in `PQC_PUBLIC_CHECK_ABUSE_CONTACT`. Still yours to supply.
5. **The egress addresses and reverse DNS** on `/scanner`, which depend on this server. Still yours to supply.

The five pages are drafts marked for counsel. They are not legal advice and I am not a lawyer.

Turn it on with `PQC_PUBLIC_CHECK_ENABLED=1` once 4 and 5 are real.

## 9. Smoke test what a stranger sees

```bash
for p in / /check /trial /pricing /security /r/example.com /robots.txt; do
  printf "%-18s %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' https://your-domain.com$p)"
done
```

`/r/example.com` answering 404 is correct — no record exists until someone checks that domain.
Everything else should be 200. Then run a check from `/check` on a domain you own, and confirm the
record appears at `/r/<that-domain>` with a working badge.

Last, submit `/trial` yourself and approve it from **Customers → Trial requests** in
`/vendor-admin`. That is the whole path a customer takes, and it is the one worth walking before
anyone else does.

## Updating later

```bash
cd /srv/pqc-scanner && git pull
$C build
$C run --rm -e AUTO_MIGRATE=1 api true
$C up -d
```

Take a backup first. `$C run --rm` for migrations means a failed migration stops before the new
containers replace the working ones.
