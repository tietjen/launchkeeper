# btmctl — macOS Background Service Inventory + Gated Remediation (V0.2)

Read-only CLI for taking stock of what macOS starts in the background:
LaunchAgents, LaunchDaemons, live `launchd` state, Background Task
Management (BTM) entries, and code-signature status — correlated into one
inventory, with orphan detection and risk hints. Since V0.2 it also
carries a deliberately separate, *gated* remediation module
(disable/enable/backup/restore).

Think "Sysinternals Autoruns for macOS, as a CLI". **It is not** a malware
scanner, antivirus, uninstaller or system cleaner.

## Design guarantee: inventory ↔ destructive ops stay separate

The scan pipeline is and stays write-free; remediation only *reads* it
(target resolution needs live loaded/enabled state). No command deletes
files as its purpose — V0.2 changes launchd *state* only (plus the
snapshot-based `restore`, which replaces a file from its own backup).
File removal as a feature remains a future, separately-designed step.

Remediation rules, enforced in code (not docs):

- **Dry-run is the default.** `disable`/`enable`/`restore` print a plan
  and execute nothing unless you add `--apply`.
- **A single gate, no bypass flag.** `com.apple.*` labels and anything
  under `/System` are refused by construction — there is no `--force`
  that reaches them. The gate is an allowlist, not a denylist.
- **Verified, not trusted.** After `--apply`, the executor re-reads
  launchd (`print` / `print-disabled`) and reports failure when the
  change is *not* visible — a zero exit code alone proves nothing.
- **Audit from the first version of writes.** Every operation —
  including refusals and dry-runs — is appended to
  `~/Library/Logs/btmctl/operations.log`.
- **System scope runs interactively.** System-domain commands go through
  one `sudo` seam with inherited stdio, so the password prompt is
  visible. btmctl never asks for blanket sudo and never uses a shell.
- **Injection-safe by structure.** Targets resolve from the scan (ids or
  unique name fragments); user input never becomes a shell command, and
  backup names cannot traverse paths.

## Usage

```
btmctl list                    # the inventory table (default command)
btmctl list --orphans          # only provably broken entries, with reasons
btmctl list --running          # only entries with a live process
btmctl list --user / --system  # restrict to one launchd domain
btmctl list --disabled         # entries flagged disabled (BTM/launchd)
btmctl list --all              # include Apple-internal bookkeeping entries
btmctl list --json             # machine-readable (audit/SIEM/Ansible)
btmctl inspect <id|name>       # one entry in full detail (by id or fragment)
btmctl doctor                  # health of the scan itself + orphan summary
btmctl doctor --json           # machine-readable health report

# V0.2 — remediation (all dry-run unless --apply)
btmctl disable <id|name>       # show the disable plan (override + unload)
btmctl disable <id|name> --apply   # execute it, then verify against launchd
btmctl enable <id|name> [--now] [--apply]  # undo; --now reloads the job
btmctl backup [--label <tag>]  # snapshot launch plists + disabled-override
                               # state (read-only, always safe)
btmctl restore <snapshot> [--apply]  # copy files back from a snapshot
```

Every remediation command accepts `--json`. Examples:

```
$ btmctl disable 07
DRY-RUN — nothing executed (dry-run is the default).
plan:
  1. /bin/launchctl disable gui/501/com.example.script
      persistent disable override (survives reboot, visible in print-disabled)
  2. /bin/launchctl bootout gui/501/com.example.script
      unload the running job

undo later with: btmctl enable 07
execute for real with: --apply

$ btmctl disable com.apple.Finder
REFUSED — Apple system component (com.apple.*) — read-only by policy
  this is a hard gate — no flag bypasses it
```

More examples:

```
$ btmctl doctor
macOS 26.6.2
  . plist sources: 3 dirs, 34 jobs read
  . launchctl print gui/501: ok (463 service lines)
  . launchctl print-disabled gui/501: ok
  . launchctl print system: ok (454 service lines)
  . launchctl print-disabled system: ok
  . sfltool dumpbtm: ok (127 records)
  . 69 items, 9 orphaned, 0 BTM entries uncorrelated
  no warnings

$ btmctl list --orphans
ID  NAME                    STATE    CONF  REASON
03  old-adobe-helper        -        high  executable missing: …
```

`doctor` checks the *tool's* view, not your system: if a data source
failed, it says so instead of pretending the inventory is complete.

## How it works

    LaunchAgent/Daemon plists ─┐
    launchctl print (live)   ──┤→ Correlation ──→ Orphan + Risk analysis
    sfltool dumpbtm (BTM)    ──┤     ↓                    ↓
    codesign -dvvv           ──┘  BackgroundItem ──→ table / JSON

Key model rule: **a BTM entry is not one plist.** macOS aggregates
launchd jobs, SMAppService/login-item helpers and legacy services into
BTM records. btmctl therefore correlates sources into normalized
`BackgroundItem`s (many evidence sources → one component) and reports a
correlation confidence instead of pretending precision it does not have.

Orphan detection is deliberately conservative: an item is flagged only
when a referenced on-disk target is *provably* missing (executable gone,
parent app bundle gone, broken symlink). Unknown stays unknown —
`suspicious` findings are rendered as `REVIEW RECOMMENDED` hints (e.g.
a shell-interpreter service, an executable under `/tmp`), never as a
malware claim.

No private Apple APIs. The tool never reads or edits Apple's internal BTM
databases (`attributions.plist` etc.) — it consumes the same public
`sfltool dumpbtm` output you can run yourself.

Remediation (V0.2) is a separate module that only *reads* that pipeline:
scan → resolve target → gate → plan → (dry-run | execute + verify). The
planner emits `launchctl` state changes only (`disable`/`enable`,
`bootout`/`bootstrap`); disable order is override-before-unload so a
keepAlive job cannot reload mid-plan. `backup` snapshots the four launch
directories plus `print-disabled` state with a SHA256 manifest;
`restore` will only copy back into those four directories, verifies each
staged copy against the manifest before and after writing, and can never
address `/System`.

## Development

```
swift build
swift test
```

Tests never shell out or touch real launchd state: all external commands
go through an injectable `CommandRunner`, and the pipeline is tested
end-to-end against captured fixtures (`Tests/Fixtures`, recorded live on
macOS 26.6.2 without sudo). The 73-test suite includes the V0.2 write
paths, driven by two test doubles: a stateful `FakeLaunchd` (its
`print`/`print-disabled` output reflects its current state, so
before/after a mutation can be asserted) and a copy-runner that
implements the `sudo cp` seam inside a temp directory. End-to-end tests
run the full engine — scan, resolve, gate, plan, apply, verify — against
temporary homes only; live mutation against real system state is a
separate, deliberate step.

BTM scan timeout: one `sfltool dumpbtm` attempt with a 45 s budget
(`BTMCTL_BTM_TIMEOUT` to override). A healthy dump completes in seconds;
a timeout means the call is blocked (sandbox/permissions), and the
report says so honestly instead of retrying into a longer dead wait.

## Roadmap

- **V0.2** ✅ — disable/enable (launchctl-state only) + snapshot backup
  (`~/Library/Application Support/btmctl/backups`) + restore, dry-run by
  default, single gate, audit log
- **V0.3** — remove + cleanup workflow + `sfltool resetbtm` (guarded)
- **V0.4** — app correlation via bundle IDs/Team IDs/Spotlight

All destructive features keep the rules in the spec: no `/System`
writes ever, no implicit wildcards, explicit target identity required,
audit log of every operation. File removal, when it comes, will be
designed separately — V0.2 deliberately does not delete anything.