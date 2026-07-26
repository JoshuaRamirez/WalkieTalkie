# Contributing to WalkieTalkie

Thanks for your interest. WalkieTalkie is a **security substrate**, so the
contribution bar is correctness and honesty first — a change that weakens or
overstates a security property is worse than no change. This guide describes the
conventions the project already follows; `CLAUDE.md` is the fuller cold-start
brief.

## Ground rules

- **Security constraints are primary over feature velocity.** If a change trades
  a security property for convenience, it needs an explicit, reviewed rationale.
- **Never overclaim.** Capabilities are labelled **[RUNNABLE]** (real, tested,
  runs today) or **[REFERENCE]** (a runnable model/verifier whose *enforcement*
  needs deployment infrastructure). Keep that distinction honest in code and
  docs. The mesh runs over loopback — that bounds scale and reachability, not the
  security properties.
- **Defer out loud.** If you intentionally leave something unbuilt, add it to
  [`DEFERRED.md`](./DEFERRED.md) with the reasoning and category. Never defer
  silently.

## Development setup

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

> The X.509 layer needs `cryptography >= 42` for the modern certificate API. A
> system-packaged `cryptography 41` will fail to import — use the virtualenv.

## Running the checks

Each package and example is its own import root (some MCP subdirs have no
`__init__.py` and set up `sys.path` per test), so run the suites per-root:

```sh
for r in \
  security-foundations/envelope \
  security-foundations/mesh \
  security-foundations/integrations/mcp \
  security-foundations/integrations/mcp/bridge \
  security-foundations/integrations/mcp/federation \
  security-foundations/integrations/mcp/workspace ; do
  .venv/bin/python -m unittest discover -s "$r" -t "$r"
done
.venv/bin/python -m ruff check security-foundations
```

CI (`.github/workflows/test.yml`) runs the same `compileall`, `ruff`, and all six
suites on Python 3.11 and 3.12. Both must be clean before a change lands.

## The proof-obligation rule

The registry in
[`security-foundations/envelope/proof_obligations.py`](./security-foundations/envelope/proof_obligations.py)
names every safety invariant the substrate claims to enforce, each pinned to a
canonical test. The `test_every_obligation_resolves` gate fails CI if a backing
test is renamed or deleted.

- **Shipping a new safety invariant?** Add a `ProofObligation` entry pointing at
  its backing test, in the same change.
- **Intentionally retiring one?** Delete the entry in the same change.

A behavioural change to a security control without a corresponding test (and,
where it's a new invariant, a proof obligation) will not be accepted.

## Making a change

1. Branch from `main` (`git checkout -b <slug>`). External contributors: fork
   first, then open a PR from your fork.
2. Write the change with tests, in the deterministic, case-based style of the
   existing suites.
3. If it maps to a plan deliverable in
   [`implementation-plan/phases/`](./implementation-plan/phases/), annotate that
   deliverable with a `**Landed (v0):**` pointer to the module.
4. Update [`security-foundations/README.md`](./security-foundations/README.md)
   with a primitive entry for a new module, and add a `CHANGELOG.md` note under
   `[Unreleased]`.
5. Run the suites and `ruff` (above). Both clean.
6. Commit with a substantive message: what changed, why, and the test delta.
7. Open a pull request against `main`.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow
[`SECURITY.md`](./SECURITY.md) — reports go through GitHub's private advisory
flow.

## Do not

- Refactor or rewrite v0 modules without an explicit reason. The v0 contract is
  "this is what the substrate guarantees today"; replacing a module mid-flight is
  the wrong default.
- Add a dependency without justifying it — the substrate is deliberately
  small (`cryptography`, `jcs`).
