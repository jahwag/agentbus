# Release checks

This document defines the evidence required before publishing an AgentBus
release. It intentionally contains no hostnames, credentials, private message
content, operator identities, or organization-specific deployment details.

## Automated checks

Run from a clean checkout:

```sh
make verify
make acceptance
make vulncheck
make release-snapshot
make container-build
```

The release candidate is acceptable only when:

- formatting, module tidiness, vet, and the race-enabled test suite pass;
- authenticated send, wait, acknowledgement, restart, redelivery, pruning, and
  operator-dashboard acceptance pass;
- `govulncheck` reports no reachable known vulnerability;
- release archives contain both binaries, checksums, and SPDX SBOMs;
- release archives reproduce required third-party license notices;
- the release archive verification script passes;
- the container builds from its digest-pinned bases and runs as a non-root user;
- a full-history secret scan reports no unresolved finding.

## Release workflow

Version tags must identify commits reachable from `main`. The release workflow
repeats verification and acceptance, creates draft GitHub releases, generates
checksums and SPDX SBOMs, and publishes GitHub build-provenance attestations.

Before publishing the draft:

1. Verify the release notes and compatibility impact.
2. Download and verify one archive against `checksums.txt`.
3. Verify its GitHub provenance attestation.
4. Run the binaries' version commands on a supported platform.
5. Confirm `SECURITY.md` names the versions receiving security fixes.

Operational deployment validation belongs in private infrastructure records.
Only sanitized, reproducible product evidence belongs in this repository.
