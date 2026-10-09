# Platform Autopatch Runbook

Platform autopatch is governed self-healing for this software's own codebase. It never pushes to `main`, never auto-merges, and never auto-deploys.

## Allowed Flow

1. Intake an issue from CI, dependency scan, runtime logs, or manual operator report.
2. Generate a diagnosis and patch plan.
3. Human operator reviews and approves the plan.
4. System prepares draft PR metadata: branch name, PR title, PR body, risk level, rollback note.
5. A maintainer creates/applies the patch branch or wires the next automation step.
6. CI must pass.
7. Human reviewer merges.
8. Human/operator deploys through the normal release process.

## Forbidden Actions

- Direct push to `main`.
- Auto-merge.
- Auto-deploy.
- Secret rotation without operator confirmation.
- Auth/security/payment/data-deletion changes without explicit review.

## Vendor Admin Usage

Open `/vendor-admin/`, load the platform key, then use `Platform Autopatch`.

Statuses:

- `needs_review`: intake exists, no approval yet.
- `approved`: human approved PR preparation.
- `pr_ready`: branch name and draft PR body are prepared.
- `rejected`: operator declined the patch plan.

## API

- `POST /platform/autopatches`
- `GET /platform/autopatches`
- `GET /platform/autopatches/{id}`
- `POST /platform/autopatches/{id}/approve`
- `POST /platform/autopatches/{id}/reject`
- `POST /platform/autopatches/{id}/prepare-pr`

All endpoints require `x-platform-key`.

## Enterprise Positioning

Call this governed autopatching, not autonomous self-modifying software. Enterprise buyers should hear: "The system can prepare a reviewed draft PR with tests and evidence; humans approve merge and deploy."
