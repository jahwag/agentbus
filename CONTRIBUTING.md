# Contributing

Thank you for contributing to AgentBus.

## Development

Install Go 1.25.12 or newer, GNU Make, and `curl`. Before requesting review,
run:

```sh
make verify
make acceptance
make vulncheck
```

Run `make release-snapshot` as well when changing packaging or deployment
artifacts.

Keep delivery behavior test-first. Tests should assert public send, wait, and
acknowledgement semantics and crash recovery, rather than private SQL or
channel choreography. Database migrations are immutable after release: add a
numbered migration instead of editing an applied migration.

Update `PLAN.md`, an ADR, and operational documentation when a protocol or
deployment invariant changes. Do not weaken request, delivery, waiter,
retention, or security bounds to make a test pass.

## Pull requests

Open a focused pull request. Titles use Conventional Commits, for example
`fix(delivery): preserve a batch across restart`. Allowed types are `feat`,
`fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`, `perf`, and
`revert`. The repository uses squash merges, so the pull-request title becomes
the commit on `main`.

By contributing, you certify that you wrote or otherwise have the right to
submit the contribution under the repository's MIT License. Sign off commits
with Git's `--signoff` option to record that certification:

```sh
git commit --signoff -m "fix(delivery): preserve a batch across restart"
```

Do not submit third-party material without documented permission. Never add
credentials, databases, private hostnames, personal identifiers, or real
message payloads to fixtures, logs, issues, pull requests, or acceptance
evidence.

Participation in the project is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Security vulnerabilities must be reported privately as described in
[SECURITY.md](SECURITY.md).
