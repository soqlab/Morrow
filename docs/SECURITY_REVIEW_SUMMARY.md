# Security Review — Summary (September 2026)

This is the public summary of an adversarial security review carried out against the platform in
September 2026. The full 860-line report, including the reproduction transcripts for each finding,
is kept privately: it documents three hardening items that are not yet complete, and publishing
working exploit detail for an unfixed issue would be irresponsible. See
[docs/OPEN_SOURCE_READINESS.md](OPEN_SOURCE_READINESS.md) for the reasoning behind that decision.

Publishing this summary rather than nothing is deliberate. A security review that found real bugs
and fixed them is evidence of a healthy project; silence is not.

## Method

The review was adversarial rather than a checklist: each candidate issue had to be *reproduced*
against a running server before it counted as a finding, and each fix had to be demonstrated by a
test that failed before the change and passed after it.

Everything ran against throwaway infrastructure on loopback only — a dedicated server instance with
its own database and freshly generated secrets, a mock OIDC provider, and an ephemeral Postgres. No
production system, customer data or real credential was involved at any point.

## Outcome

**Seventeen findings were raised** (sixteen from this review, plus one imported from a separate
staging dry-run). **Fourteen are fixed**, each with a named regression test that now runs as part of
the ordinary suite. The reproductions were originally written as `xfail(strict=True)` tests, so a
fix that regressed would fail the build rather than pass silently.

The classes of issue found and fixed:

| Class | What was wrong |
|---|---|
| **Cross-tenant data access** | Several endpoints did not scope reads to the caller's organisation. This was the most serious category and the reason multi-tenant isolation is now listed first in [SECURITY.md](../SECURITY.md)'s in-scope section. |
| **Privilege escalation** | A role could reach an action above its level through an endpoint that did not re-check authorisation. |
| **Credential exposure in responses** | An endpoint returned stored integration secrets verbatim to a caller who should only have seen that they were configured. |
| **Session and token handling** | Revocation did not take effect everywhere it should have; token lifetimes and caches were tightened. |
| **Vendor support-session boundary** | The scope a support session grants over a customer workspace was narrower in intent than in implementation. |
| **Outbound request forgery** | The webhook SSRF guard did not pin the port, and address checking was strengthened against DNS rebinding. |

Verification after remediation: the full suite green, plus five browser smoke tests covering the
console, the operator portal and the public pages.

## What is not finished

Three hardening items remain open. They are stated here by class, without the endpoint names,
payloads or repro steps that would make them directly actionable:

1. **An organisation-listing endpoint is broader than it should be.** It is readable by an
   authenticated administrator of any workspace and returns workspace metadata — not the contents of
   another tenant's estate. Narrowing it is a change to both front ends as well as the API, because
   it is the data source behind the workspace switcher, and a careless fix logs people out of their
   own workspace. Recorded rather than rushed.
2. **The customer console is served with a Content-Security-Policy that permits inline script.** The
   operator portal is already on a strict policy. The console is a large single-file application with
   inline script blocks, and removing them is a restructuring job rather than a header change. This
   weakens defence-in-depth against cross-site scripting; it is not itself an XSS.
3. **There is a first-owner enrolment window for multi-factor authentication.** On a brand-new
   deployment, before the first owner has enrolled, the enrolment endpoints cannot require a factor
   that does not yet exist. An attacker who controlled that first owner's session before enrolment
   could enrol on their behalf. This is inherent to bootstrapping a factor in-band; it closes as soon
   as the first owner enrols. **Operators of a fresh deployment should enrol immediately** — a new
   open-source installation sits precisely in this window.

Items 1 and 2 are also listed in [SECURITY.md](../SECURITY.md) under *Known gaps*.

## Also worth knowing

The review recorded what it could **not** test, which is as important as what it did:

- Payment integration flows were not exercised.
- Stored cross-site scripting was only partially covered — a number of DOM-writing sites in the
  console were not individually audited.
- Revocation behaviour across multiple API replicas was not tested under load.
- Break-glass access was not exercised in a strict-production configuration.
- Rate-limit bypass via a spoofed forwarded-for header was not tested.

None of these is a known bug. They are untested areas, and that is why they are named: an honest map
of where the assurance stops is more useful than an implied claim of completeness.

## Scope of this document

This summary describes one review at one point in time. It is not a certification, not a third-party
penetration test, and not a statement that the platform is free of vulnerabilities. There has been
no SOC 2, ISO 27001 or external security audit — see
[docs/BUYER_SECURITY_FAQ.md](BUYER_SECURITY_FAQ.md).

If you find something, including something worse than described above, please follow
[SECURITY.md](../SECURITY.md).
