# Handoff: Release-preparation pass (2026-07)

Supersedes `2026-07-phase-6-close.md` as the most-recent brief. Read
`CLAUDE.md` for durable patterns/cadence and `DEFERRED.md` for what's
intentionally not done; read this for the moment-in-time framing the
release-prep pass ended on.

**Branch state, not a merged milestone.** All the work below is on
`claude/resolve-merge-conflicts-tMxSj`.

> **Update (maintainer delegated "do the best thing"):** Path B executed —
> packaging scoped honestly to source-distribution, version bumped to
> **0.1.0**, import-restructure recorded in `DEFERRED.md`. **PR #90** opened
> against `main` (cleanly mergeable; file diff = the 17 release-prep files).
> Remaining, deliberately left to the maintainer: **merge PR #90**, the
> **EPL-2.0 license**, the **package rename** (tied to the deferred Path A
> refactor), and **cutting a git tag** (after merge). The five-item list
> below is the original framing; three are now resolved (packaging → Path B,
> version → 0.1.0, PR → opened).

## What just landed

A release-readiness sweep across every angle that could be done *without a
positioning decision from the maintainer*. Sixteen commits, each pushed:

- **Merge-conflict resolution.** The branch was a stranded, disjoint Phase-0
  history (no common ancestor to `main`). Merged `main` in, resolved all 16
  add/add conflicts in `main`'s favor (verified `main` strictly supersets),
  tree reconciled byte-identical to `main`.
- **CI coverage.** The test job discovered only `envelope`; now runs all six
  import roots (envelope, mesh, integrations/mcp, bridge, federation,
  workspace). A break in the whole Phase 1–6 mesh layer used to go green.
- **Packaging.** Modernized `[project]` metadata (readme/license/authors/
  classifiers/URLs); **fixed a real install bug** — `cryptography` floor
  `>=41` → `>=42` (the X.509 layer needs the `*_utc` accessors); excluded
  tests/demos from the wheel (144 → 70 `.py`).
- **Release docs.** Root `README.md`, `SECURITY.md` (private-advisory flow),
  `CHANGELOG.md`, `CONTRIBUTING.md`, a `.github/pull_request_template.md`
  enforcing the project's real gates, and `.gitignore` for build artifacts.
- **Doc-vs-code accuracy.** Reconciled stale claims against shipped code:
  CLAUDE.md intro ("no network layer"), `security-foundations/README.md`
  ("Phase 0 bootstrap" / mTLS+policy-engine listed "out of scope" though
  shipped), protocol-spec + threat-model (mTLS framed as unbuilt), and
  "Phase 6 / deployment" → "Phase 7" for sandbox/image-admission in the
  threat model and compliance mapping. Fixed a dead plan-doc reference
  (`test_mcp_smoke.py` → `test_smoke.py`).

## State at handoff

- **961 tests green** across all six suites; `ruff` clean; `compileall`
  clean; the 48-entry proof-obligation gate passes.
- All five shipped demos/generators run (exit 0); the committed audit vector
  reproduces byte-identically.
- **Secrets hygiene clean** — no committed private keys; test seeds are
  `SHA-256` of public strings (re-derivable, non-secret).
- The wheel + sdist build and contain all three packages.

## The one real blocker: the installed wheel does not import

The wheel builds and installs but **fails on import**: modules import siblings
by bare name (`from audit import …`), which works only when each package dir
is itself on `sys.path` (the dev/test convention) — installed as `envelope.*`
the imports break. The package is usable from a **source checkout only**.

This is architectural, and measured (iter 16): making it a real installable
package (**Path A**) is *not* a mechanical refactor —

- **cross-package bare imports** (`mesh/tls_transport.py` does
  `from workload_ca import …`, but `workload_ca` is in *envelope*) rely on a
  flat `sys.path` holding every package dir at once;
- **dynamic string module refs** in `proof_obligations.py`
  (`importlib.import_module(<string>)`) that the CI gate depends on and a
  find-replace would miss;
- ~90 sibling imports + subdir imports + `__all__` lists.

So Path A is a **dedicated engineering phase**, not a loop task.

## Decisions the release is gated on (maintainer's call)

1. **Packaging model.** **Path B** (recommended): declare source-distributed,
   scope the wheel/`[project]` metadata to that reality — small, safe,
   reversible. **Path A**: the full package refactor above, as its own phase.
2. **Version + tag.** Still `0.0.1`, no tags. Bump to `0.1.0` and cut a tag?
3. **Distribution/package names.** `envelope`/`mesh`/`integrations` install as
   generic top-level names (collision risk) — rename to `walkietalkie_*`?
4. **License.** `LICENSE` is **EPL-2.0** (declared faithfully). Intentional for
   an embeddable substrate, or switch to MIT/Apache?
5. **Open the PR to `main`.** This branch is ready to PR; not opened (no
   explicit request).

## What this pass did NOT do

- Path A (the import refactor) — architectural, needs an explicit decision.
- Any positioning decision (version, license, package names, distribution
  model) — deliberately reserved for the maintainer.
- Marginal ceremony (issue templates, dependabot, CODEOWNERS) — skipped as
  low-value; `dependabot` also opens outward-facing PRs that are the
  maintainer's call.

## Priority-ordered next options

1. **Pick the packaging model.** Say "Path B" → executable in one slice
   (scope metadata, keep dev-install working, note in README/CHANGELOG).
   "Path A" → plan it as a phase.
2. **Cut the release identity** — version bump + tag + license confirmation.
3. **Open the PR to `main`** (populate the new PR template).

## Cadence + anti-patterns

Unchanged from CLAUDE.md: branch → substantive commit → PR → merge; the
six-suite + `ruff` gate; proof-obligation add/retire in the same commit; the
[RUNNABLE]/[REFERENCE] honesty labels; no refactor of v0 modules without an
explicit reason (which is exactly why Path A waits for a decision).
