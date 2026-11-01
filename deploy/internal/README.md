# Morrow inside your company network (no internet)

**Written for: the IT or security team installing Morrow on a company server that has no
internet access.**

Morrow runs entirely on your server. It makes no connection outside your network: no licence
check, no telemetry, no updates fetched, no fonts or scripts from other sites. Scans go only to
the hosts your team enters.

## What you need

| | |
|---|---|
| A Linux server | 2 vCPU, 2 GB RAM, 20 GB disk. Any distribution with Docker Engine and the compose plugin. |
| An internal name | For example `morrow.corp.example`, resolving to the server in your internal DNS. |
| A certificate | For that name, from your company certificate authority (`cert.pem` with the full chain, and `key.pem`). |
| The bundle | `morrow-offline-<version>.tar.gz`, copied to the server by whatever route your network allows. |

## Install

```sh
tar -xzf morrow-offline-<version>.tar.gz
cd morrow-offline-<version>
sha256sum -c SHA256SUMS        # the images arrived intact
sh setup.sh                    # loads the images, creates morrow.env with new secrets
```

Then:

1. **`.env`**: set `SITE_ADDRESS` to your internal name.
2. **`morrow.env`**: set the same name in `MORROW_PUBLIC_BASE_URL`, `MORROW_ALLOWED_HOSTS` and
   `MORROW_CORS_ORIGINS`. Then set the first administrator in `MORROW_ADMIN_EMAIL` and
   `MORROW_ADMIN_PASSWORD`. The password needs at least 10 characters, including a digit.
3. **`tls/`**: put `cert.pem` and `key.pem` here.
4. **`ca/`** (optional): put your company root certificate here as `company.crt`. Morrow will
   then trust your internal GitLab or mail server the way your own machines do.
5. Start it:

```sh
docker compose up -d
docker compose ps              # "morrow" turns healthy after about a minute
```

Open `https://<your internal name>` and sign in as the first administrator. Invite colleagues
under **Administration › Invitations**. Without a mail server, use **Copy invite link** and
send the link yourself.

**Save `MORROW_VAULT_MASTER_KEY` from `morrow.env` in your password manager.** It encrypts stored
credentials, such as code-host tokens. Without it, a restored backup can't read them.

## What works without the internet

| Feature | Offline |
|---|---|
| TLS and SSH scans of internal hosts, by name or IP address | Yes |
| Inventory, findings, reports, CBOM export, evidence | Yes |
| Fixes opened as merge requests on your own GitLab, Gitea/Forgejo or GitHub Enterprise | Yes. Connect it under **Code hosts**. |
| Invitations and password resets by email | Yes, with your internal mail server (`MORROW_SMTP_*`) |
| AI assistant | Yes, with your own model on your network: Ollama, vLLM, LM Studio or any OpenAI-compatible server. See `MORROW_LLM_*` in `morrow.env`. |
| Public certificate-transparency lookups, GitHub.com, cloud account discovery | Off. These are internet services. |

## Updating

Bring in the new bundle the same way, then:

```sh
tar -xzf morrow-offline-<new version>.tar.gz
cd morrow-offline-<new version>
gunzip -c images.tar.gz | docker load
cp ../morrow-offline-<old version>/{.env,morrow.env} .
cp -r ../morrow-offline-<old version>/{tls,ca} .
docker compose up -d
```

Your data is kept: it lives in the `morrow_morrow-data` Docker volume, not in the folder.

## Backups

All data is one SQLite database in the `morrow_morrow-data` volume. To take a copy while Morrow
is running:

```sh
docker compose exec morrow python3 -c "import sqlite3; sqlite3.connect('/data/morrow.db').backup(sqlite3.connect('/data/backup.db'))"
docker compose cp morrow:/data/backup.db ./morrow-backup-$(date +%F).db
```

Keep the backup together with `morrow.env`, or at least with `MORROW_VAULT_MASTER_KEY`.

## Behind your own reverse proxy

If you already run a load balancer or proxy with TLS, you can drop the `caddy` service. Point
your proxy at the `morrow` container on port 8000, and have it pass `X-Forwarded-For` and
`X-Forwarded-Proto`. Publish the port by adding `ports: ["8000:8000"]` to the `morrow` service.

## Building the bundle

On a machine with internet and Docker, from the repository:

```sh
sh deploy/internal/make-bundle.sh
```

This writes `dist/morrow-offline-<date>-<commit>.tar.gz`.
