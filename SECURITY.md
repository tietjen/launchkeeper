# Security policy

launchkeeper inspects and changes what macOS starts automatically. That is a
security-sensitive job, and the tool is built so that the *dangerous* half is
small, explicit and auditable. This document says what you can rely on, what
you cannot, and how to report a problem.

## What the tool guarantees (enforced in code, covered by tests)

- **The inventory is read-only.** Scanning never writes, never elevates,
  never uses a shell. All external commands are argv arrays through one seam.
- **Every mutation is dry-run by default.** `disable`, `enable`, `remove`,
  `restore` and `resetbtm` print a plan and change nothing unless `--apply`
  is given.
- **One gate, no bypass flag.** `com.apple.*` labels and anything under
  `/System` are refused by construction. There is no `--force`.
- **No backup, no delete.** `remove --apply` snapshots the launch directories
  first; if the snapshot cannot be written, nothing is removed.
- **Verified, not trusted.** After `--apply` the tool re-reads launchd (and,
  for deletions, the file system) and reports failure when the change is not
  visible. Exit codes alone prove nothing.
- **Everything is audited**, including refusals and dry-runs
  (`~/Library/Logs/launchkeeper/operations.log`).
- **Root only where root is needed**, through an interactive `sudo` seam in
  the tool's own process group. The tool never asks for blanket sudo.

## What the tool is not

It is not a malware scanner, antivirus, uninstaller or "system cleaner". Risk
hints are *review recommended* markers, never verdicts. Orphan detection is
conservative: unknown stays unknown.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
private vulnerability reporting on the repository ("Security → Report a
vulnerability"). You will get an acknowledgement within a few days and a fix
or a mitigation as soon as one is available; credit is given unless you prefer
otherwise.

Things that count as vulnerabilities here:

- any path by which user input reaches a shell or an argv position it should
  not reach,
- any way to make the gate reach `com.apple.*`, `/System`, or a path outside
  the allowlisted launch directories,
- a mutation that runs without `--apply`, without its snapshot, or without
  its verification,
- a false negative in orphan detection that makes `remove` delete a working
  component.

## Supported versions

Only the latest release receives fixes. Releases are universal macOS binaries,
signed with a Developer ID and notarized by Apple; verify the signature with
`codesign --verify --strict --verbose=2 launchkeeper` and the download with
`shasum -a 256 -c SHA256SUMS`.
