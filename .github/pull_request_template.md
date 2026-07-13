<!--
WalkieTalkie is a security substrate — correctness and honesty over velocity.
Fill in what applies; delete what doesn't. See CONTRIBUTING.md and CLAUDE.md.
-->

## What & why

<!-- One or two sentences: what this change does and the reason for it. -->

## Plan reference

<!-- If this maps to a plan deliverable, cite it (e.g. "Phase 6 Track A A1").
     If it's release/maintenance work, say so. -->

## Security properties touched

<!-- Which of confidentiality / integrity / authenticity / authorization /
     auditability does this affect, if any? For each control, state its honesty
     label: [RUNNABLE] (in-process enforcement) or [REFERENCE] (model/generator
     whose enforcement needs deployment infra). Do not imply enforcement the
     substrate doesn't have. -->

## Checklist

- [ ] All six test suites pass (`envelope`, `mesh`, `integrations/mcp`, `bridge`, `federation`, `workspace`) and `ruff check security-foundations` is clean.
- [ ] New/changed behavior has deterministic, case-based tests in the style of the existing suites.
- [ ] **Proof obligations:** a new safety invariant adds a `ProofObligation` entry (pointing at its backing test) in the same commit; a retired one deletes its entry. `test_every_obligation_resolves` still passes.
- [ ] **Plan annotation:** a landed deliverable is marked `**Landed (v0):**` in the relevant `implementation-plan/phases/*.md`.
- [ ] **Inventory:** a new module has a primitive entry in `security-foundations/README.md`; user-facing changes have a `CHANGELOG.md` note under `[Unreleased]`.
- [ ] No secrets, private keys, or credentials added (test key material must be derivable from public seeds, as in `_regen_vectors.py`).
- [ ] Docs touched by this change still match the code (no claims the shipped behavior contradicts).

## Notes for reviewers

<!-- Anything non-obvious: trade-offs, a deferred follow-up (add it to DEFERRED.md),
     or context that helps review without scrolling. -->
