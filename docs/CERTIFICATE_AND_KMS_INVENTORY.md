# Certificate-manager and cloud KMS inventory

Morrow can read the inventory that an organization's certificate managers and cloud key services
already hold. It puts every certificate and key into the asset inventory and grades each one for
quantum risk.

> **Tested against documented responses only.** Each connector was built from the vendor's
> published API reference (listed below). The test suite (`backend/test_cert_inventory.py`) uses
> fixtures shaped like the vendor's documented example responses. None of these connectors has
> been run against a live Keyfactor, Venafi, DigiCert, AWS, Azure or Google Cloud account. See
> [What a live account still has to confirm](#what-a-live-account-still-has-to-confirm).

## Read-only

Morrow only lists, searches and describes. It never issues, renews, revokes, retires, imports,
rotates, disables or deletes a certificate or a key. The code does not reference any vendor write
endpoint. The only POST requests are these:

- the TLS Protect Cloud certificate search
- token requests to TPP, Azure AD and Google OAuth
- the AWS JSON protocol, which sends every action as a POST, including `ListKeys` and `DescribeKey`

Where a vendor offers a read-only credential, use one.

| Source | What is read | API reference |
|---|---|---|
| Keyfactor Command | `GET /KeyfactorAPI/Certificates`, paged with `PageReturned`/`ReturnLimit` | [Certificates GET](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificatesGET.htm), [common headers](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/Web%20API%20Common%20Features.htm) |
| Venafi TLS Protect Cloud | `POST /outagedetection/v1/certificatesearch` (header `tppl-api-key`), paged with `paging.pageNumber`/`pageSize` | [SaaS API overview (regions, auth)](https://mim.pan.dev/api-endpoints/saas/certificate-manager-saas-api), [certificate search](https://mim.pan.dev/api-endpoints/saas/certificates-search-get-by-expression), [vcert search types](https://github.com/Venafi/vcert/blob/master/pkg/venafi/cloud/search.go) |
| Venafi Trust Protection Platform | `POST /vedauth/authorize/oauth` (scope `certificate`), then `GET /vedsdk/certificates/?Limit&Offset&OptionalFields=KeyAlgorithm,KeySize,Subject,Issuer` | [Authorize/OAuth](https://docs.venafi.com/Docs/current/TopNav/Content/SDK/AuthSDK/r-SDKa-POST-AuthorizeOAuth.php), [GET Certificates](https://docs.venafi.com/Docs/25.3/TopNav/Content/SDK/WebSDK/r-SDK-GET-Certificates.php) |
| DigiCert CertCentral | `GET /services/v2/order/certificate` (header `X-DC-DEVKEY`, `offset`/`limit`, issued orders), then `GET /order/certificate/{id}` for thumbprint, serial, key size and CSR | [List orders](https://dev.digicert.com/certcentral-apis/services-api/orders/list-orders.html), [Order info](https://dev.digicert.com/md/certcentral-apis/services-api/orders/order-info.md) |
| AWS KMS | `ListKeys` (`Limit`/`Marker`) and `DescribeKey` (`KeySpec`) per region, SigV4-signed | [ListKeys](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html), [DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) |
| Azure Key Vault | `GET {vault}/keys` (`nextLink`), then `GET {kid}` per key for `kty`, `crv` and the RSA modulus, api-version 2025-07-01 | [Get Keys](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys), [Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key) |
| Google Cloud KMS | locations → `keyRings` → `cryptoKeys` → `cryptoKeyVersions` (`algorithm`), paged with `pageToken` | [keyRings.list](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/list), [cryptoKeyVersions.list](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list), [algorithms](https://docs.cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm) |

The cloud KMS connectors take the same credential shapes as Cloud discovery:

- AWS: an access key, a secret key and an optional session token.
- Azure: a tenant ID, a client ID and a client secret.
- Google Cloud: a service-account JSON key.

They also reuse its request signing and token code in `services/cloud_discovery.py`. The Google
token is always requested from `oauth2.googleapis.com`. It never uses the metadata server, and it
ignores any `token_uri` in the pasted key file.

## Console and API

To open the console page, go to **Console → Deep Scanners → Secrets → Cloud discovery →
Certificate managers & KMS inventory**, or open `/ui/cert-sources.html` directly. On that page you
can:

- add a connection
- run **Test connection**
- run **Sync now**
- choose a scheduled interval
- remove a connection
- see each connection's last sync and the synced inventory

| Route | Role |
|---|---|
| `GET /cert-sources/providers` | any |
| `GET /cert-sources` | viewer+ |
| `POST /cert-sources` `{provider, fields, label, schedule_hours}` | admin |
| `POST /cert-sources/{id}/test` | operator+ |
| `POST /cert-sources/{id}/sync` | operator+ |
| `PUT /cert-sources/{id}/schedule` `{schedule_hours}` | admin |
| `DELETE /cert-sources/{id}` | admin |
| `GET /cert-inventory?source_id=&risk=&limit=` | viewer+ |

Every route is also served under `/v1`.

## How the data lands

- **Asset per certificate or key.** Each item is written to `org_cert_inventory`, a feature-store
  table scoped by `org_id`. It is also written onto an inventory asset with `db.upsert_asset`,
  under `metadata.cert_inventory[<connection id>]`. Each asset is tagged `source:<provider>`,
  `inventory:certificate|key` and `quantum-risk:<level>`. An owner, team or note that a person set
  on the asset is never overwritten.
- **Deduplication.** A certificate whose fingerprint matches one seen by a recent TLS scan is put
  on that scan's `host:port` asset. The TLS scanner now records `cert_sha1` and `cert_sha256` for
  the leaf certificate. Any other certificate goes on `cert:<fingerprint>`, so a certificate
  reported by two managers is one asset. A key goes on `kms:<provider>:<id>`.
- **Classification.** Quantum risk comes from `services/fips_pq.classify_algorithm`, the same table
  the rest of the platform uses. A SHA-1 or MD5 signature raises the risk to at least that
  algorithm's level.
- **Removal.** A certificate or key that a source stops reporting is dropped from that source's
  rows, and its entry is taken off the asset. Removing a connection does the same for everything
  it reported. The asset row itself stays.

## Safety

- **Credentials.** They are sealed with the platform vault key (`vault_crypto`) when they arrive.
  No route ever returns them.
- **Customer-supplied URLs.** This covers the Keyfactor and TPP server addresses. Each must be
  HTTPS on port 443 and resolve only to public addresses. It is checked when the connection is
  added and again before every sync.
  - Azure vaults must be `https://<name>.vault.azure.net`.
  - AWS, Google, DigiCert and Venafi Cloud use fixed vendor hosts.
  - Redirects are never followed.
  - Every follow-up URL a server returns must stay on the host that was checked. This covers TPP
    and Keyfactor paging, the Azure `nextLink` and Azure key IDs.
  - A Morrow installed inside a company network can reach an internal Keyfactor or TPP with
    `MORROW_CERT_SOURCES_ALLOW_PRIVATE=1`. `MORROW_CODE_HOSTS_ALLOW_PRIVATE=1` is honoured too,
    because it is the same deployment decision. Never set either on a shared hosted instance.
- **Rate limits.** HTTP 429 and 503, and AWS `ThrottlingException`, are retried up to five times
  with exponential backoff. The wait follows `Retry-After` and is capped at 60 seconds.
- **Bounds.** Each sync is capped at 50,000 items and 20,000 requests. DigiCert order details are
  fetched for at most 2,000 orders per sync. Responses are capped at 16 MB.
- **Authentication failures.** These come back as a 400 that says what to fix for that vendor. For
  example, Keyfactor wants the username as `DOMAIN\user`, Venafi Cloud wants the right region, and
  AWS needs `kms:ListKeys` and `kms:DescribeKey`.
- **Scheduled sync.** It is off for every connection by default. Celery beat runs
  `morrow.sync_due_cert_sources` every 15 minutes. That task only syncs connections that someone
  set to 6, 12, 24 or 168 hours.

## What a live account still has to confirm

These points come from loose or missing vendor documentation. Each one is read defensively in the
code, but only a real account can confirm it.

- **Keyfactor.** Whether `ReturnLimit` above 50 is honoured on large installs. The exact
  `KeyAlgorithm`/`KeyTypeString` text for EC certificates. Which metadata field names hold the
  owner (`Email-Contact`, `Owner` and others are tried).
- **TLS Protect Cloud.**
  - Whether `certificatesearch` accepts a body with only `paging` and no `expression`.
  - Whether `pageNumber` starts at 0. Repeated pages are detected and stop the walk.
  - The response field names for key and signature algorithms and for ownership: `keyStrength`,
    `encryptionType`, `keyCurve`, `signatureAlgorithm` and `ownership`. The public reference does
    not render the response schema.
- **TPP.** Paging behaviour on very large folders. The listing does not return the signature
  algorithm or a contact/owner, so those fields stay empty.
- **DigiCert.** Whether `filters[status]=issued` is the right filter for active certificates. The
  key algorithm is not a documented field. It is read from the order's CSR when present, otherwise
  inferred from `key_size` and marked `key_algorithm_inferred`. Real rate limits.
- **AWS.** SigV4 signing with `content-type` and `x-amz-target` in the signed headers. The test
  checks the header list but not a signature computed by AWS.
- **Azure.** Whether the Key Vault Reader role alone allows `GET {kid}`. HSM-backed `oct` keys
  carry no size, so they are classified "unknown".
- **Google Cloud.** Whether `projects.locations.list` is available to `roles/cloudkms.viewer`. You
  can also list locations explicitly instead.
