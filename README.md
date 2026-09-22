# btmctl — macOS Background Service Inventory + Gated Remediation (V0.4.3)

Read-only CLI for taking stock of what macOS starts in the background:
LaunchAgents, LaunchDaemons, live `launchd` state, Background Task
Management (BTM) entries, and code-signature status — correlated into one
inventory, with orphan detection and risk hints. Since V0.2 it also
carries a deliberately separate, *gated* remediation module
(disable/enable/backup/restore), and since V0.3 it can delete —
**one orphaned launch plist at a time, on top of a fresh backup**.
V0.4 adds **app correlation** to the read-only half: every item learns
its parent application, and orphan detection gains an independent
Spotlight second source.

Think "Sysinternals Autoruns for macOS, as a CLI". **It is not** a malware
scanner, antivirus, uninstaller or system cleaner.

## Design guarantee: inventory ↔ destructive ops stay separate

The scan pipeline is and stays write-free; remediation only *reads* it
(target resolution needs live loaded/enabled state). `disable`/`enable`
change launchd *state* only; `restore` replaces files from its own
backup. `remove` (V0.3) is the first file-deleting command and is kept
deliberately narrow: it deletes **one** backing launch `.plist`, and
only when four locks pass at once — the file is an allowlisted launch-dir
plist, not a symlink escape, and the entry is *provably orphaned*.
Nothing that still works is ever deleted — a working component leaves
via `disable` (reversible). This is the rule that keeps btmctl out of
`rm`-wrapper territory.

Remediation rules, enforced in code (not docs):

- **Dry-run is the default.** `disable`/`enable`/`remove`/`restore`
  print a plan and execute nothing unless you add `--apply`.
- **A single gate, no bypass flag.** `com.apple.*` labels and anything
  under `/System` are refused by construction — there is no `--force`
  that reaches them. The gate is an allowlist, not a denylist, and for
  `remove` it covers the file rules too (plist shape, allowlisted
  directory, symlink, orphaned) — one gate, not two.
- **No backup, no delete.** `remove --apply` writes a full launch-dir
  snapshot first, and if that snapshot cannot be written, nothing is
  removed. The undo hint names the exact snapshot.
- **Verified, not trusted.** After `--apply`, the executor re-reads
  launchd (`print` / `print-disabled`) — for `remove`, also the file
  system — and reports failure when the change is *not* visible. A
  zero exit code alone proves nothing; a `rm` that exits 0 having
  deleted nothing is caught by the post-run file read.
- **Audit from the first version of writes.** Every operation —
  including refusals and dry-runs — is appended to
  `~/Library/Logs/btmctl/operations.log`.
- **System scope runs interactively.** Commands that need root go through
  one `sudo` seam with inherited stdio *in btmctl's own process group*, so
  the password prompt is visible, echo is off, and sudo actually receives
  what you type (V0.4.2 — Foundation's `Process` had put the child into a
  background process group, which showed the password in clear text and
  never accepted it). Root is needed only where it is needed: `launchctl`
  for jobs in the `system` domain, `rm`/`cp` for files under `/Library`.
  A `/Library/LaunchAgents` agent is a *user-session* job with a
  root-owned file — btmctl unloads it as you and deletes it via sudo.
  btmctl never asks for blanket sudo and never uses a shell.
- **Injection-safe by structure.** Targets resolve from the scan (ids or
  unique name fragments); user input never becomes a shell command, and
  backup names cannot traverse paths.
- **App correlation is read-only and degrades honestly** (V0.4). Parent
  app = deepest `.app` bundle around the item's executable/path, bundle
  `Info.plist` for id/team/name. Spotlight (`mdfind`, read-only) is
  consulted ONLY when the bundle path is provably gone and a bundle id is
  known — a wedged or erroring index degrades to `unknown`, never to a
  "gone" verdict, and a missing id means no query at all.

## Installation (macOS 14+)

btmctl is one universal CLI binary (Apple silicon + Intel), signed with a
Developer ID and notarized by Apple. Test releases are published on Gitea:
<https://git.dev.paranoidsecurity.de/tj/macos-housecleaning-tool/releases>
(the source repository stays private while the tool is in multi-device
testing; the **Releases** unit is set to anonymous read, so the assets
download without a login or token).

### Option A — prebuilt release (no Xcode needed)

1. **Download** `btmctl-vX.Y.Z-macos-universal.tar.gz` and `SHA256SUMS`
   from the release page. Prefer `curl` over the browser: files fetched by
   curl carry no quarantine flag, so Gatekeeper never gets involved.
   ```
   BASE=https://git.dev.paranoidsecurity.de/tj/macos-housecleaning-tool/releases/download/v0.4.3
   curl -fsSLO "$BASE/btmctl-v0.4.3-macos-universal.tar.gz"
   curl -fsSLO "$BASE/SHA256SUMS"
   ```
   (Copying the tarball over AirDrop, scp or a NAS share works just as well.)
2. **Verify** the checksum, then unpack:
   ```
   shasum -a 256 -c SHA256SUMS
   tar -xzf btmctl-v0.4.3-macos-universal.tar.gz
   ```
3. **Install** into your PATH (`/usr/local/bin` needs sudo once):
   ```
   sudo install -m 755 btmctl-v0.4.3-macos-universal/btmctl /usr/local/bin/btmctl
   ```
4. **Check the signature and run the first scan:**
   ```
   codesign -dv --verbose=2 /usr/local/bin/btmctl   # Authority=Developer ID Application: Jan Tietjen (Y2LTPLFG6D)
   btmctl --version                                   # 0.4.3
   btmctl doctor                                      # read-only health check
   ```
   The first `doctor` after a macOS upgrade may report the BTM layer as
   timed out — the BTM daemon is migrating its store; run it again.

**Downloaded with a browser** (Safari, Finder)? The file carries the
quarantine flag, and Gatekeeper then checks Apple's notarization ticket
online — release binaries are notarized (since v0.4.1), so it passes. A bare CLI binary cannot carry a stapled ticket, so an
offline first run, or a copy made before the notarization run, may still
be refused; clear the flag before installing in that case:
```
xattr -d com.apple.quarantine btmctl-v0.4.3-macos-universal/btmctl
```

**Uninstall:** `sudo rm /usr/local/bin/btmctl`. btmctl keeps its data in
`~/Library/Logs/btmctl/operations.log` (audit log) and
`~/Library/Application Support/btmctl/` (backups, BTM snapshots) — delete
those only if you no longer need the undo history.

### Option B — build from source (Xcode 16+ / Swift 6)

```
git clone ssh://git@git.dev.paranoidsecurity.de:2222/tj/macos-housecleaning-tool.git
cd macos-housecleaning-tool
swift build -c release
sudo install -m 755 .build/release/btmctl /usr/local/bin/btmctl
```

### Cutting a release (maintainer)

```
scripts/release.sh 0.4.3                  # tests, universal build, codesign, dist/*.tar.gz + SHA256SUMS
scripts/release.sh 0.4.3 --notarize       # + Apple notarization (keychain profile, see script header)
# Notarize an already-shipped binary later (same bytes → same ticket, no re-release):
#   tar -xzf dist/btmctl-v0.4.3-macos-universal.tar.gz && ditto -c -k --keepParent btmctl-v0.4.3-macos-universal/btmctl n.zip
#   xcrun notarytool submit n.zip --keychain-profile SparkMenu --wait
scripts/release.sh 0.4.3 --upload         # + tag v0.4.3, Gitea release with assets (rbw must be unlocked)
```

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
                               # ids are positional per scan but IDENTICAL across
                               # list/inspect/disable/enable/remove: every command
                               # numbers the same full inventory (V0.4.3)
btmctl doctor                  # health of the scan itself + orphan summary
btmctl doctor --json           # machine-readable health report

# V0.2+ — remediation (all dry-run unless --apply)
btmctl disable <id|name>       # show the disable plan (override + unload)
btmctl disable <id|name> --apply   # execute it, then verify against launchd
btmctl enable <id|name> [--now] [--apply]  # undo; --now reloads the job
btmctl backup [--label <tag>]  # snapshot launch plists + disabled-override
                               # state (read-only, always safe)
btmctl restore <snapshot> [--apply]  # copy files back from a snapshot

# V0.3 — deletion, deliberately narrow
btmctl remove <id|name>        # plan: backup snapshot, unload, delete ONE
                               # orphaned launch plist (gated, dry-run)
btmctl remove <id|name> --apply  # execute — but only after the pre-delete
                               # snapshot is written; verified afterwards
                               # a job launchd still holds from a plist that is
                               # already gone is REFUSED here — the refusal names
                               # the working command (btmctl disable … --apply)

# V0.4 — the BTM database reset (the one non-restorable command)
btmctl resetbtm                # dry-run: shows the record count, names the
                               # audit snapshot that would be written,
                               # executes NOTHING
btmctl resetbtm --apply        # audit snapshot (full dumpbtm + sfltool
                               # archive), then sfltool resetbtm, then a
                               # post-dump: the reset is only "applied" if
                               # the database can be read afterwards
                               # NOT RESTORABLE: sfltool has no import — the
                               # snapshot is an audit artifact, not a backup
```

Note: `remove` refuses working components — they leave via `disable`
(reversible), never via deletion. Undo for a deletion is two steps:
`btmctl restore <snapshot> && btmctl enable <label> --now`. `resetbtm` has
no undo at all; its snapshot exists so the destruction is on record, and
registrations come back only as the owning apps run again.

# V0.4 — app correlation (read-only, always on)
`list` gains a dynamic `APP` column (parent application, shown only when
at least one item resolved one — a column of dashes would be noise).
`inspect` shows parent, bundle path, team and the confirmation state
(`present` / `missing` / `relocated` / `unknown`). Orphan detection uses
the Spotlight result as an independent second source: "executable missing"
is a file fact, "bundle ID not found via Spotlight" is the app-level
confirmation.

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

$ btmctl remove com.leftover.tool
DRY-RUN — nothing executed (dry-run is the default).
plan:
  1. /bin/launchctl bootout gui/501/com.leftover.tool
      unload the job before its file goes
  2. /bin/rm -- /Users/joe/Library/LaunchAgents/com.leftover.tool.plist
      delete the orphaned backing plist (--apply always snapshots the launch dirs first)

undo later with: btmctl restore <pre-remove backup> && btmctl enable com.leftover.tool --now
execute for real with: --apply
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
    .app Info.plist + mdfind ────┘  (V0.4 app context: parent app,
                                     Spotlight confirmation)

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

Remediation (V0.2+) is a separate module that only *reads* that pipeline:
scan → resolve target → gate → plan → (dry-run | execute + verify). The
planner emits `launchctl` state changes (`disable`/`enable`,
`bootout`/`bootstrap`); disable order is override-before-unload so a
keepAlive job cannot reload mid-plan, and remove order is unload-before-delete
so no file is pulled from under a loaded job. `backup` snapshots the four launch
directories plus `print-disabled` state with a SHA256 manifest;
`restore` will only copy back into those four directories, verifies each
staged copy against the manifest before and after writing, and can never
address `/System`. `remove` (V0.3) adds one file operation on top —
`rm -- <path>` through the same single argv-only, no-shell seam (via the
interactive sudo seam for system-domain plists) — and only after the
pre-delete snapshot. V0.4 adds the guarded `sfltool resetbtm` on top:
dry-run default, **no snapshot, no reset**, verify-after-mutate — living
honestly with the fact that `sfltool` has no import, so the pre-reset
snapshot is an audit artifact, not a backup.

## Development

```
swift build
swift test
```

Tests never shell out or touch real launchd state: all external commands
go through an injectable `CommandRunner`, and the pipeline is tested
end-to-end against captured fixtures (`Tests/Fixtures`, recorded live on
macOS 26.6.2 without sudo). The 155-test suite includes the V0.2 write
paths, the V0.3 deletion path, the V0.4 app context (bundle trees in
temp directories, `mdfind` scripted — including the "wedged index must
not manufacture a gone-verdict" property) and the guarded `resetbtm`
path, driven by four test doubles: a stateful `FakeLaunchd` (its
`print`/`print-disabled` output reflects its current state, so before/after
a mutation can be asserted), a copy-runner that implements the `sudo cp`
seam inside a temp directory, a removal-runner that makes `rm`/`sudo rm`
really delete inside the temp tree — because file-system verification
reads the real world, so a silent `rm` (exit 0, nothing deleted) must be
catchable in tests — and a stateful in-memory BTM store for the reset.
End-to-end tests run the full engine — scan, resolve, gate, plan,
apply, verify — against temporary homes only; live mutation against real
system state is a separate, deliberate step. The guarded `resetbtm` is
tested against a stateful in-memory BTM store behind the same runner seam
(`dumpbtm` renders, `resetbtm` empties; snapshots land in a temp root),
covering dry-run executes nothing, no snapshot → no reset, unreadable
database → refused, and failed/timed-out post-dump → appliedFailed.

BTM scan timeout: one `sfltool dumpbtm` attempt with a 45 s budget
(`BTMCTL_BTM_TIMEOUT` to override). A healthy dump completes in seconds.
A timeout has two typical causes the tool cannot tell apart: the first run
after a macOS upgrade (the BTM daemon migrates its store — seen live on the
26 → 27 upgrade: 45 s timeout, 3 s on the next run) or a blocked call
(sandbox/permissions). The report names both and does not retry into a
longer dead wait; running again is the user's call.

BTM URL formats: macOS 26 writes `URL:` as a percent-encoded file URL
(`file:///Applications/My%20App.app/`), macOS 27 as a plain path. Both are
normalized to the on-disk path before any existence probe (V0.4.1 — before
that, two installed plug-ins with spaces in their names were reported as
orphans).

## Roadmap

- **V0.2** ✅ — disable/enable (launchctl-state only) + snapshot backup
  (`~/Library/Application Support/btmctl/backups`) + restore, dry-run by
  default, single gate, audit log
- **V0.3** ✅ — `remove`: one orphaned launch plist at a time, four-lock
  gate (plist shape, allowlisted dir, no symlink escape, orphaned only),
  mandatory pre-delete snapshot, file-system verification after `rm`
- **V0.4** ✅ — app correlation via bundle IDs/Team IDs/Spotlight (read-only,
  degrades to `unknown` when the index is unavailable) + guarded
  `sfltool resetbtm`: dry-run default, mandatory pre-reset audit snapshot
  (no snapshot, no reset), post-dump verification — with the command
  stating in words that the snapshot is an audit artifact, not a backup
  (`sfltool` has no import)
- **V0.4.1** ✅ — percent-encoded BTM URLs decoded before file probes (fixes
  two false-positive orphans on macOS 26), honest BTM-timeout message (cold
  start after an OS upgrade vs. blocked call), warning-free build, release
  script + installation guide for the multi-device test round
- **V0.4.2** ✅ — sudo seam via `posix_spawn` in btmctl's own process group
  (the Foundation `Process` child was a background job: clear-text echo, no
  input); launchd domain derived from the job, not the plist directory
  (`/Library/LaunchAgents` agents are `gui/<uid>` jobs, no sudo for
  `launchctl`, sudo only for the file); 180 s budget for password prompts;
  `remove` refusals name the working command for jobs whose plist is gone
- **V0.4.3** ✅ — remediation resolves against the same full inventory `list`
  prints (BTM layer included — a smaller scan renumbered the ids, so
  `remove 54` could have hit a different entry); `--user`/`--system` filter
  rows instead of narrowing the scan; unloaded agents with a disable override
  count as disabled (so `remove` drops the override); BTM-only leftovers
  resolve and are refused honestly instead of "no match"

All destructive features keep the rules in the spec: no `/System`
writes ever, no implicit wildcards, explicit target identity required,
audit log of every operation.