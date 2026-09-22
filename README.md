# launchkeeper — macOS Background Service Inventory + Gated Remediation (V0.5.5)

> Formerly **btmctl** (releases up to v0.5.0 were published under that name). Same core, same
> guarantees; data moved from `~/Library/Logs/btmctl` and `~/Library/Application Support/btmctl`
> to the `launchkeeper` equivalents — the old audit log is carried over once, old backups still restore.

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
via `disable` (reversible). This is the rule that keeps launchkeeper out of
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
  `~/Library/Logs/launchkeeper/operations.log`.
- **System scope runs interactively.** Commands that need root go through
  one `sudo` seam with inherited stdio *in launchkeeper's own process group*, so
  the password prompt is visible, echo is off, and sudo actually receives
  what you type (V0.4.2 — Foundation's `Process` had put the child into a
  background process group, which showed the password in clear text and
  never accepted it). Root is needed only where it is needed: `launchctl`
  for jobs in the `system` domain, `rm`/`cp` for files under `/Library`.
  A `/Library/LaunchAgents` agent is a *user-session* job with a
  root-owned file — launchkeeper unloads it as you and deletes it via sudo.
  launchkeeper never asks for blanket sudo and never uses a shell.
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

launchkeeper is one universal CLI binary (Apple silicon + Intel), signed with
a Developer ID and notarized by Apple. Releases are built by GitHub Actions
from the tag and published at
<https://github.com/tietjen/launchkeeper/releases>. (Releases up to v0.4.5
were published under the former name btmctl on the author's Gitea.)

### Homebrew

```
brew trust tietjen/tap          # Homebrew 7+: third-party taps must be trusted once
brew install tietjen/tap/launchkeeper
```

The formula installs the prebuilt universal binary from the GitHub release,
pinned by its SHA-256; `brew upgrade launchkeeper` follows new releases.

### Option A — prebuilt release (no Xcode needed)

1. **Download** `launchkeeper-vX.Y.Z-macos-universal.tar.gz` and `SHA256SUMS`
   from the release page. Prefer `curl` over the browser: files fetched by
   curl carry no quarantine flag, so Gatekeeper never gets involved.
   ```
   BASE=https://github.com/tietjen/launchkeeper/releases/download/v0.5.0
   curl -fsSLO "$BASE/launchkeeper-v0.5.0-macos-universal.tar.gz"
   curl -fsSLO "$BASE/SHA256SUMS"
   ```
   (Copying the tarball over AirDrop, scp or a NAS share works just as well.)
2. **Verify** the checksum, then unpack:
   ```
   shasum -a 256 -c SHA256SUMS
   tar -xzf launchkeeper-v0.5.0-macos-universal.tar.gz
   ```
3. **Install** into your PATH (`/usr/local/bin` needs sudo once):
   ```
   sudo install -m 755 launchkeeper-v0.5.0-macos-universal/launchkeeper /usr/local/bin/launchkeeper
   ```
4. **Check the signature and run the first scan:**
   ```
   codesign -dv --verbose=2 /usr/local/bin/launchkeeper   # Authority=Developer ID Application: Jan Tietjen (Y2LTPLFG6D)
   launchkeeper --version                                   # 0.5.0
   launchkeeper doctor                                      # read-only health check
   ```
   The first `doctor` after a macOS upgrade may report the BTM layer as
   timed out — the BTM daemon is migrating its store; run it again.

**Downloaded with a browser** (Safari, Finder)? The file carries the
quarantine flag, and Gatekeeper then checks Apple's notarization ticket
online — release binaries are notarized (since v0.4.1), so it passes. A bare CLI binary cannot carry a stapled ticket, so an
offline first run, or a copy made before the notarization run, may still
be refused; clear the flag before installing in that case:
```
xattr -d com.apple.quarantine launchkeeper-v0.5.0-macos-universal/launchkeeper
```

**Uninstall:** `sudo rm /usr/local/bin/launchkeeper`. launchkeeper keeps its data in
`~/Library/Logs/launchkeeper/operations.log` (audit log) and
`~/Library/Application Support/launchkeeper/` (backups, BTM snapshots) — delete
those only if you no longer need the undo history.

### Option B — build from source (Xcode 16+ / Swift 6)

```
git clone https://github.com/tietjen/launchkeeper.git
cd launchkeeper
swift build -c release
sudo install -m 755 .build/release/launchkeeper /usr/local/bin/launchkeeper
```

### Cutting a release (maintainer)

Push a tag `v<version>` — `.github/workflows/release.yml` runs the tests,
builds the universal binary, signs and notarizes it with the repository
secrets and publishes the GitHub release with `SHA256SUMS`. `ci.yml` builds
and tests every push. The same steps run locally:

```
scripts/release.sh 0.5.0                  # tests, universal build, codesign, dist/*.tar.gz + SHA256SUMS
scripts/release.sh 0.5.0 --notarize       # + Apple notarization (keychain profile, see script header)
# Notarize an already-shipped binary later (same bytes → same ticket, no re-release):
#   tar -xzf dist/launchkeeper-v0.5.0-macos-universal.tar.gz && ditto -c -k --keepParent launchkeeper-v0.5.0-macos-universal/launchkeeper n.zip
#   xcrun notarytool submit n.zip --keychain-profile SparkMenu --wait
scripts/release.sh 0.5.0 --upload         # + tag v0.5.0, Gitea release with assets (rbw must be unlocked)
```

## Usage

```
launchkeeper list                    # the inventory table (default command)
launchkeeper list --orphans          # only provably broken entries, with reasons
launchkeeper list --running          # only entries with a live process
launchkeeper list --user / --system  # restrict to one launchd domain
launchkeeper list --disabled         # entries flagged disabled (BTM/launchd)
launchkeeper list --all              # include Apple-internal bookkeeping entries
launchkeeper list --json             # machine-readable (audit/SIEM/Ansible)
launchkeeper inspect <id|name>       # one entry in full detail (by id or fragment)
                               # ids are positional per scan but IDENTICAL across
                               # list/inspect/disable/enable/remove: every command
                               # numbers the same full inventory (V0.4.3). If a
                               # layer failed (e.g. BTM timed out), the run is
                               # marked incomplete and numbers are REFUSED for
                               # disable/enable/remove — use the label (V0.4.5)
launchkeeper doctor                  # health of the scan itself + orphan summary
launchkeeper doctor --json           # machine-readable health report

# V0.5 — the Autoruns-style dimensions
launchkeeper list --category <name>  # one category: launch-items, login-items, app-extensions, …
launchkeeper list --category app-extensions   # pluginkit: QuickLook, Share, Widgets, Finder Sync, …
                                     # with the user election (use / ignore / none) and the host app
launchkeeper list --category system-extensions  # systemextensionsctl + kexts: network filters, drivers,
                                     # camera extensions, legacy kernel extensions — state and host app
launchkeeper list --category privileged-helpers # /Library/PrivilegedHelperTools: SMJobBless helpers with
                                     # their LaunchDaemon and authorized client apps; leftovers flagged
launchkeeper background              # System Settings › Login Items & Extensions, rebuilt from
                                     # the inventory: "Open at Login" + "Allow in the Background",
                                     # one row per app/developer with its switch and components
launchkeeper background --json       # the same view, machine-readable

# V0.2+ — remediation (all dry-run unless --apply)
launchkeeper disable <id|name>       # show the disable plan (override + unload)
launchkeeper disable <id|name> --apply   # execute it, then verify against launchd
launchkeeper enable <id|name> [--now] [--apply]  # undo; --now reloads the job
launchkeeper backup [--label <tag>]  # snapshot launch plists + disabled-override
                               # state (read-only, always safe)
launchkeeper restore <snapshot> [--apply]  # copy files back from a snapshot

# V0.3 — deletion, deliberately narrow
launchkeeper remove <id|name>        # plan: backup snapshot, unload, delete ONE
                               # orphaned launch plist (gated, dry-run)
launchkeeper remove <id|name> --apply  # execute — but only after the pre-delete
                               # snapshot is written; verified afterwards
                               # a job launchd still holds from a plist that is
                               # already gone is REFUSED here — the refusal names
                               # the working command (launchkeeper disable … --apply)

# V0.4 — the BTM database reset (the one non-restorable command)
launchkeeper resetbtm                # dry-run: shows the record count, names the
                               # audit snapshot that would be written,
                               # executes NOTHING
launchkeeper resetbtm --apply        # audit snapshot (full dumpbtm + sfltool
                               # archive), then sfltool resetbtm, then a
                               # post-dump: the reset is only "applied" if
                               # the database can be read afterwards
                               # NOT RESTORABLE: sfltool has no import — the
                               # snapshot is an audit artifact, not a backup
```

Note: `remove` refuses working components — they leave via `disable`
(reversible), never via deletion. Undo for a deletion is two steps:
`launchkeeper restore <snapshot> && launchkeeper enable <label> --now`. `resetbtm` has
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
$ launchkeeper disable 07
DRY-RUN — nothing executed (dry-run is the default).
plan:
  1. /bin/launchctl disable gui/501/com.example.script
      persistent disable override (survives reboot, visible in print-disabled)
  2. /bin/launchctl bootout gui/501/com.example.script
      unload the running job

undo later with: launchkeeper enable 07
execute for real with: --apply

$ launchkeeper disable com.apple.Finder
REFUSED — Apple system component (com.apple.*) — read-only by policy
  this is a hard gate — no flag bypasses it

$ launchkeeper remove com.leftover.tool
DRY-RUN — nothing executed (dry-run is the default).
plan:
  1. /bin/launchctl bootout gui/501/com.leftover.tool
      unload the job before its file goes
  2. /bin/rm -- /Users/joe/Library/LaunchAgents/com.leftover.tool.plist
      delete the orphaned backing plist (--apply always snapshots the launch dirs first)

undo later with: launchkeeper restore <pre-remove backup> && launchkeeper enable com.leftover.tool --now
execute for real with: --apply
```

More examples:

```
$ launchkeeper doctor
macOS 26.6.2
  . plist sources: 3 dirs, 34 jobs read
  . launchctl print gui/501: ok (463 service lines)
  . launchctl print-disabled gui/501: ok
  . launchctl print system: ok (454 service lines)
  . launchctl print-disabled system: ok
  . sfltool dumpbtm: ok (127 records)
  . 69 items, 9 orphaned, 0 BTM entries uncorrelated
  no warnings

$ launchkeeper list --orphans
ID  NAME                    STATE    CONF  REASON
03  old-adobe-helper        -        high  executable missing: …
```

`doctor` checks the *tool's* view, not your system: if a data source
failed, it says so instead of pretending the inventory is complete.

## Categories, control matrix, provenance (V0.5)

Every item carries three more dimensions, visible in `inspect` and `--json`:

- **category** — the Autoruns-style tab it belongs to (`launch-items`,
  `login-items`, `app-extensions`, `system-extensions`,
  `privileged-helpers`; more scanners follow in V0.5.x).
  `list --category <name>` filters by it.
- **control** — what launchkeeper can do with it, computed from the *same*
  gate the mutating commands consult: `reversible` (disable/enable),
  `removable` (an orphaned launch plist that passes all four `remove`
  locks) or `display-only` with the reason and where the switch lives
  instead (Apple/System territory, Background Task Management leftovers,
  extensions managed by System Settings).
- **origin** — where it came from, from evidence already in hand: Apple,
  Homebrew, Mac App Store receipt; package receipts arrive with V0.6.
  Unknown stays unknown.

`background` rebuilds the System Settings › General › Login Items &
Extensions pane, verified against the pane itself (V0.5.2):

- **Open at Login** lists apps registered by themselves — BTM `app` records
  whose own bit is `enabled` (a login item added in the pane). SMAppService
  helpers of type `login item` are *not* listed there; they are components
  under their app's row below.
- **Allow in the Background**: one row per app or developer; the switch is
  the components' BTM disposition bit — exactly what the pane shows. A
  launchd override (`launchctl disable`) is invisible to the pane, so it is
  a separate `LAUNCHD` column, never folded into the switch: an app can read
  ON there while launchd keeps its job disabled.
- A container's own bit is not the switch (48 of 49 read `disabled` on a
  healthy Mac) — except for app-level registrations without components.
  Unnamed rows are named after their component's executable, as the pane
  does.

launchkeeper never writes to Background Task Management; the switch stays
in System Settings.

## App extensions (V0.5.4)

`pluginkit -mAvv` lists every registered app extension — QuickLook and
Spotlight plug-ins, Share and Action extensions, widgets, Finder Sync,
notification services, Safari app extensions — with the user's election
(`+` use, `-` ignore, no tag = default). launchkeeper turns them into items
of category `app-extensions`: extensions that Background Task Management
also lists (QuickLook, Spotlight, dock tiles) merge with their BTM record by
bundle path, the rest become their own entries; `inspect` shows the
extension point (`ext-sdk`), election and host app. Apple's own extensions
are hidden from the default `list` like other Apple internals (`--all`).
The election itself is read-only here (`pluginkit -e use|ignore -i <id>`);
launchkeeper control follows in V0.7. A failed `pluginkit` call marks the
inventory incomplete, like a failed BTM dump.

## System extensions, kexts, privileged helpers (V0.5.5)

`systemextensionsctl list` is the source for **system extensions** — network
filters and VPNs, endpoint security agents, DriverKit drivers, camera
(CMIO) extensions — with their enabled/active bits, state (`[activated
enabled]`, `[activated waiting for user]`, …), team ID, version and the
System Settings pane that owns the switch. launchkeeper locates the
installed copy under `/Library/SystemExtensions/<uuid>/` and the host app
that ships it (`<App>.app/Contents/Library/SystemExtensions/`, then
Spotlight). Apple requires that app to live in `/Applications`, so a
missing host app is a real signal: the extension outlives its app and is
flagged as an orphan (medium confidence). **Kernel extensions** come from
`kmutil showloaded` (third-party only) plus the bundles installed in
`/Library/Extensions`; both are category `system-extensions`, signed as
bundles, display-only: the control text names the `systemextensionsctl
uninstall <teamID> <bundleID>` route and the pane.

`/Library/PrivilegedHelperTools` holds the **SMJobBless helpers** — root
daemons that apps install to do privileged work. Each helper's embedded
Info.plist (`launchctl plist __TEXT,__info_plist <binary>`) names its
`SMAuthorizedClients`; launchkeeper merges the helper with the LaunchDaemon
whose `Program` points at it (category `privileged-helpers`, the daemon
keeps its launchd control) and resolves the client app via Spotlight. A
helper no LaunchDaemon points at is its own item and an orphan: nothing can
start it — the leftover of an uninstalled app (medium confidence,
display-only until V0.8 cleanup). A Spotlight miss on the client app is
*not* evidence — Spotlight does not index `/Library/Application Support`
and clients are often nested bundles — so the client is named for display
and nothing more. Helpers without an embedded Info.plist (some vendors skip
it) are listed with the fact.

## How it works

    LaunchAgent/Daemon plists ─┐
    launchctl print (live)   ──┤→ Correlation ──→ Orphan + Risk analysis
    sfltool dumpbtm (BTM)    ──┤     ↓                    ↓
    pluginkit -mAvv          ──┤
    systemextensionsctl list ──┤
    kmutil + /Library/Extensions┤
    PrivilegedHelperTools    ──┤
    codesign -dvvv           ──┘  BackgroundItem ──→ table / JSON
    .app Info.plist + mdfind ────┘  (V0.4 app context: parent app,
                                     Spotlight confirmation)

Key model rule: **a BTM entry is not one plist.** macOS aggregates
launchd jobs, SMAppService/login-item helpers and legacy services into
BTM records. launchkeeper therefore correlates sources into normalized
`BackgroundItem`s (many evidence sources → one component) and reports a
correlation confidence instead of pretending precision it does not have.

Orphan detection is deliberately conservative: an item is flagged only
when a referenced on-disk target is *provably* missing (executable gone,
parent app bundle gone, broken symlink). A **BTM leftover** — a Background
Task Management record whose plist is already gone and that no launchd job
backs — is reported separately (`LEFTOVER`, confidence low, one reason):
it is the trail of a component already removed, nothing to act on, and
BTM prunes it itself within minutes (V0.4.4). Unknown stays unknown —
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
macOS 26.6.2 without sudo). The 200-test suite includes the V0.2 write
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

BTM scan timeout: one `sfltool dumpbtm` attempt with a 150 s budget
(`LAUNCHKEEPER_BTM_TIMEOUT` to override). A warm dump completes in seconds;
the first call after the BTM daemon sat idle (or after a macOS upgrade) can
take a minute or two — seen live: 76 s and 97 s, then 1–5 s (BTM re-validates
every registered bundle; large apps dominate) — and the scan says so on stderr
after five seconds. A timeout kills only the client; the daemon keeps working,
so the next run is fast. A timeout has two typical causes the tool cannot
tell apart: that cold start, or a blocked call (sandbox/permissions). The report names both and does not retry into a
longer dead wait; running again is the user's call.

BTM URL formats: macOS 26 writes `URL:` as a percent-encoded file URL
(`file:///Applications/My%20App.app/`), macOS 27 as a plain path. Both are
normalized to the on-disk path before any existence probe (V0.4.1 — before
that, two installed plug-ins with spaces in their names were reported as
orphans).

## Roadmap

- **V0.2** ✅ — disable/enable (launchctl-state only) + snapshot backup
  (`~/Library/Application Support/launchkeeper/backups`) + restore, dry-run by
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
- **V0.4.2** ✅ — sudo seam via `posix_spawn` in launchkeeper's own process group
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
- **V0.4.4** ✅ — BTM leftovers (record only, plist gone, no launchd job)
  get their own orphan reason, low confidence and a `LEFTOVER` flag instead
  of posing as open "executable missing" work items right after a clean
  `remove`
- **V0.5.5** ✅ — system extensions (`systemextensionsctl list`), kernel
  extensions (`kmutil showloaded` + `/Library/Extensions`) and privileged
  helper tools (`/Library/PrivilegedHelperTools` + embedded Info.plist) as
  categories `system-extensions` / `privileged-helpers`; helpers merge
  with their LaunchDaemon, a host app or daemon that is gone is an orphan
- **V0.5.4** ✅ — app extensions via `pluginkit -mAvv` as category
  `app-extensions`, merged with the BTM extension records by bundle path,
  election and extension point on every item, incomplete-marking on failure
- **V0.5.3** ✅ — `background` keeps developer row names, unnamed
  registrations one row per component
- **V0.5.2** ✅ — `background` verified against the System Settings pane:
  the switch is the components' BTM bit, launchd overrides get their own
  column, app-level registrations are the Open-at-Login entries, unnamed
  rows take their component's executable name
- **V0.5.1** ✅ — the Autoruns-style dimensions on every item (category,
  control matrix as data, provenance), `list --category`, and `background`:
  the Login Items & Extensions pane rebuilt from the inventory with the
  switch state derived from the components; BTM budget 150 s with a
  cold-start hint
- **V0.4.5** ✅ — numeric ids are accepted only against a complete
  inventory: when an item source did not answer (`sfltool dumpbtm` timeout,
  `launchctl print` failure) the run is marked incomplete, `list` says so,
  and `disable`/`enable`/`remove` refuse numbers (labels still work) — a
  number typed from an earlier, complete `list` would have hit a different
  entry

All destructive features keep the rules in the spec: no `/System`
writes ever, no implicit wildcards, explicit target identity required,
audit log of every operation.