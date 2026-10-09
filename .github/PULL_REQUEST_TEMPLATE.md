<!--
Thanks for contributing. Please read CONTRIBUTING.md if you have not already —
especially the house style section, which is short and explains why each
convention exists.

Keep one concern per pull request. A refactor plus a behaviour change in one
diff cannot be reviewed properly; please split them.
-->

## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!--
The reason, not a restatement of the diff. What was wrong, what could not be
done before, or what broke. Link the issue if there is one: Fixes #123
-->

## How I verified it

<!--
What you actually ran, and what you checked by hand. If you could not test
something, say so — an honest gap is reviewable, a silent one is not.
-->

- [ ] `cd backend && pytest -q` passes
- [ ] `cd backend && ruff check .` is clean
- [ ] Added tests that fail without this change
- [ ] Checked against Postgres as well as SQLite (required if this touches the data layer)

## Checklist

- [ ] Comments explain **why**, not what — and if this fixes a bug, a comment records what the
      broken behaviour was
- [ ] No invented data: nothing guesses a value it cannot determine, and unknown stays unknown
- [ ] Empty and insufficient-data states say so rather than showing a zero
- [ ] No new runtime dependency, or the pull request explains why one is needed
- [ ] No credential, token or real hostname added anywhere, including tests and fixtures
- [ ] `.env.example` updated if a setting was added
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Docs updated where this invalidates them
- [ ] No unrelated reformatting in the diff

## Anything a reviewer should know

<!--
Trade-offs you made, parts you are unsure about, follow-up work you deliberately
left out. Pointing at the risky part of your own diff makes review faster, not
weaker.
-->
