# btmctl — macOS Background Service Inventory (V0.1)

Read-only CLI for taking stock of what macOS starts in the background:
LaunchAgents, LaunchDaemons, live `launchd` state, Background Task
Management (BTM) entries, and code-signature status — correlated into one
inventory, with orphan detection and risk hints.

Think "Sysinternals Autoruns for macOS, as a CLI". **It is not** a malware
scanner, antivirus, uninstaller or system cleaner.

## V0.1 guarantee: read-only by construction

V0.1 contains no code path that writes, deletes, unloads, disables or
resets anything. Every external command it runs is a read
(`launchctl print*`, `sfltool dumpbtm`, `codesign -dvvv`). Removal,
disable/enable, backup/restore and BTM reset are deliberately kept out of
this version — inventory and destructive operations never share a code
path. When they arrive later, they arrive with backup-first, dry-run and
explicit targets, and never touch `/System`.

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
```

Examples:

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

## Development

```
swift build
swift test
```

Tests never shell out or touch real launchd state: all external commands
go through an injectable `CommandRunner`, and the pipeline is tested
end-to-end against captured fixtures (`Tests/Fixtures`, recorded live on
macOS 26.6.2 without sudo). Destructive integration tests, when they
come, will run against temporary test services only.

BTM scan timeout: one `sfltool dumpbtm` attempt with a 45 s budget
(`BTMCTL_BTM_TIMEOUT` to override). A healthy dump completes in seconds;
a timeout means the call is blocked (sandbox/permissions), and the
report says so honestly instead of retrying into a longer dead wait.

## Roadmap

- **V0.2** — disable/enable/bootout + automatic backup-first + restore
  (`~/.local/share/btmctl/backups`), `--dry-run`
- **V0.3** — remove + cleanup workflow + `sfltool resetbtm` (guarded)
- **V0.4** — app correlation via bundle IDs/Team IDs/Spotlight

All destructive features will keep the rules in the spec: no `/System`
writes ever, no implicit wildcards, explicit target identity required,
audit log with SHA256 of every backup.