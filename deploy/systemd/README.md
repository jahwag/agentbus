# systemd installation

The units assume a static, unprivileged `agentbus` account, binaries in
`/usr/local/bin`, and a protected admin credential. Run as root:

```sh
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin agentbus
install -m 0755 agentbus agentbusd agentbus-mcp-bridge /usr/local/bin/
install -d -m 0700 /etc/agentbus
umask 077
openssl rand -hex 32 > /etc/agentbus/admin-token
install -m 0644 deploy/systemd/agentbusd.service /etc/systemd/system/
install -m 0644 deploy/systemd/agentbus-prune.service /etc/systemd/system/
install -m 0644 deploy/systemd/agentbus-prune.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now agentbusd.service agentbus-prune.timer
```

`StateDirectory=agentbus` creates `/var/lib/agentbus`; the daemon tightens it to
mode 0700. Verify with `curl --fail http://127.0.0.1:7777/readyz`,
`systemctl status agentbusd`, and `journalctl -u agentbusd`.

Daemon and administrator CLI upgrades are coordinated across the binary pair.
The optional client-side `agentbus-mcp-bridge` can be rolled independently.
Copy each daemon/CLI artifact to a unique
temporary filename on the target filesystem, verify its checksum and
`--version` there, then stop the daemon and maintenance unit. Sync and rename
both staged files over their final paths, verify the installed checksums, and
only then restart. Never copy or `install` directly over an executable path:
another process can observe a partially written binary. Two independent
filesystem renames are not an atomic pair, so keep both units stopped between
them.
Schema startup is forward-only and refuses an unknown or checksum-mismatched
migration before mutation. The previous binary pair is usable for rollback only
while it understands the current database schema; after a schema migration,
restore the matching pre-upgrade cold backup as part of binary rollback.

For the M1 cold backup, stop the daemon and verify it exited, then copy the
complete `/var/lib/agentbus` directory to protected storage and checksum every
file. Clean shutdown normally checkpoints SQLite's WAL, but copy any remaining
`bus.db-wal` and `bus.db-shm` files with the main database. Never copy only a
live `bus.db` while WAL is enabled. Restore the backup into a fresh mode-`0700`,
agentbus-owned directory, start a schema-compatible binary against that copy,
and prove an outstanding delivery redelivers before replacing production state.
