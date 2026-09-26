# launchkeeper — macOS Background Service Inventory + Gated Remediation (V0.9.4)

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

Since V0.8 it can also take away what an installer package put on disk —
**only files that provably still are what the package installed, moved
into a quarantine, never deleted** — see [Cleanup](#cleanup-uninstall-by-receipt-v08).

Think "Sysinternals Autoruns for macOS, as a CLI". **It is not** a malware
scanner, antivirus or one-click system cleaner.

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

V0.8 cleanup keeps the same line with a stronger tool: `uninstall` takes
away only files that still match the package's bill of materials (size +
checksum), and it **moves** them into a quarantine instead of deleting
them — `quarantine restore` puts everything back. The one real deletion in
launchkeeper is `quarantine purge`, explicitly, one entry at a time.

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
launchkeeper list --category scheduled          # everything on a timer: launchd StartInterval/StartCalendarInterval,
                                     # cron, at, periodic(8), pmset power events (Apple's alarms with --all)
launchkeeper list --category legacy             # loginwindow hooks, /Library/StartupItems, rc.local, emond rules
launchkeeper list --category plugin-directories # authorization plugins (with their login wiring), HAL audio,
                                     # Spotlight, QuickLook, input methods, screen savers, prefpanes, …
launchkeeper list --category shell-startup      # ~/.zshrc & co., /etc/zshrc & co., what they source, launch hints
                                     # (line numbers + keywords, never a line), /etc/paths.d entries
launchkeeper list --category network            # listening processes (lsof) linked to the entry that starts them,
                                     # Application Firewall rules; Apple's daemons with --all

# V0.6 — provenance
launchkeeper list --origin receipt    # only entries a package receipt accounts for (apple, homebrew,
                                     # app-store, receipt, manual, unknown)
launchkeeper list --origin manual     # apps dragged out of a disk image: no receipt, no App Store
launchkeeper receipts                 # the installer packages behind the inventory: version, install
                                     # date, files still on disk, the entries they run (--missing, --all)

# V0.6 — export, snapshots, diff
launchkeeper list --csv > inventory.csv       # spreadsheet export (all columns, orphan reasons, origin)
launchkeeper list --markdown                  # Markdown table for a report
launchkeeper snapshot --name before-upgrade   # save the whole inventory (~/Library/Application Support/
launchkeeper snapshot list                    #   launchkeeper/inventory/<timestamp>[-name].json)
launchkeeper diff                             # what changed since the latest snapshot: added, removed,
launchkeeper diff before-upgrade --exit-code  #   changed configuration; exit 1 on differences (scripts)
launchkeeper diff <older> <newer> --json      # two snapshots against each other
launchkeeper inspect 07 --verify              # signature in depth: seal (codesign --verify --strict), authority
                                              #   chain, hardened runtime, Gatekeeper/notarization (spctl), SHA-256
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

# V0.7 — the same two verbs beyond launchd (dry-run unless --apply)
launchkeeper disable <extension>     # pluginkit election → ignore   (enable → use)
launchkeeper disable <cron entry>    # comment the crontab line out behind a marker
launchkeeper disable hook:LoginHook:user  # park the hook in the loginwindow plist
launchkeeper disable <firewall rule> # block incoming connections (enable → allow; sudo)

# V0.8 — cleanup by package receipt (dry-run unless --apply; moves, never deletes)
launchkeeper uninstall <package-id>                  # what would move, what stays and why
launchkeeper uninstall <package-id> --verify-as-root # also prove root-only files now (sudo)
launchkeeper uninstall <package-id> --list           # every file, not only the move roots
launchkeeper uninstall <package-id> --apply          # move into the quarantine (sudo), forget the receipt if nothing stays
launchkeeper quarantine [list]                       # what cleanup took away
launchkeeper quarantine restore <name> [--apply]     # move it all back (never overwrites)
launchkeeper quarantine purge <name> [--apply]       # delete one entry for good — the only real deletion
launchkeeper remove <leftover>                       # V0.8.1: helper without a job, StartupItem,
                                                     # dead paths.d file → into the quarantine
launchkeeper leftovers [--all] [--json]              # V0.8.2: what gone apps left behind (read-only)
launchkeeper leftovers <bundle-id> [--apply]         # move one gone app's leftovers into the quarantine

# V0.9 — observe (read-only)
launchkeeper watch                                   # report new / removed / changed autostart entries live
launchkeeper watch --notify --interval 300           # + macOS notifications; full rescan every 5 min
launchkeeper watch --json                            # JSON lines (also logged to ~/Library/Logs/launchkeeper/watch.log)
launchkeeper list --root "<backup>/… - Data"         # V0.9.1: offline analysis of another system's files
launchkeeper snapshot save --root <root> --name old  # … and snapshot it for `diff`

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
  `privileged-helpers`, `scheduled`, `legacy`, `plugin-directories`,
  `shell-startup`, `network`).
  `list --category <name>` filters by it.
- **control** — what launchkeeper can do with it, computed from the *same*
  gate the mutating commands consult: `reversible` (disable/enable),
  `removable` (an orphaned launch plist that passes all four `remove`
  locks) or `display-only` with the reason and where the switch lives
  instead (Apple/System territory, Background Task Management leftovers,
  system extensions). Since V0.7 it also names the **mechanism** — the
  switch the actions flip (`launchd`, `pluginkit`, `cron`, `login-hook`,
  `firewall`); see [Control beyond launchd](#control-beyond-launchd-v07).
- **origin** — where it came from: Apple, Homebrew, Mac App Store receipt,
  an installer package receipt (`pkgutil`, with package id, version and
  install date), or `manual` for an app on disk that no receipt knows.
  Unknown stays unknown. `list --origin <kind>` filters by it.

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
Since V0.7 `disable`/`enable` set the election (`pluginkit -e ignore|use`)
through the gate — Apple's extensions stay read-only. A failed `pluginkit`
call marks the inventory incomplete, like a failed BTM dump.

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

## Scheduled, legacy, plugin directories (V0.5.6)

**Scheduled** is everything that runs on a timer. launchd jobs with
`StartInterval` or `StartCalendarInterval` stay launch items but carry a
`schedule` in their metadata, and `list --category scheduled` includes
them. The rest are their own items: the user's crontab (`crontab -l`) and
`/etc/crontab` if present, `atq` jobs, `periodic(8)` scripts under
`/etc/periodic` and `/usr/local/etc/periodic`, and `pmset -g sched` power
events (Apple's own alarms hide like other Apple internals; `--all` shows
them). A cron command with an absolute path is the item's executable, so a
missing one is an orphan like a missing launchd program. All of it is
read-only for now; the control text names the manual route.

**Legacy** covers persistence mechanisms macOS no longer runs or that are
unusual enough to deserve a look: `LoginHook`/`LogoutHook` in the
loginwindow preferences, `/Library/StartupItems` (SystemStarter left with
OS X 10.10 — every entry there is a leftover and flagged as such),
`/etc/rc.local`, `/etc/rc.shutdown.local`, `/etc/launchd.conf` and
non-Apple emond rules.

**Plugin directories** lists the bundles the OS loads by location:
authorization plugins (`/Library/Security/SecurityAgentPlugins`, checked
against the `system.login.console` mechanism chain from `security
authorizationdb read` — a plugin wired into login shows as loaded), HAL
audio drivers, Spotlight importers, QuickLook generators, input methods,
Internet plug-ins, screen savers, preference panes, scripting additions and
color pickers, system-wide and per user, each with bundle id, version and
code signature. Display-only until V0.8 cleanup.

## Shell startup and network (V0.5.7)

**Shell startup** lists the files every interactive shell runs — the
user's `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.bash_profile`,
`.bashrc`, `.profile` and friends, the system's `/etc/zshrc`, `/etc/profile`
and the rest — plus what they `source` (depth 1, resolved through `~` and
`$HOME`; targets with other variables are listed as unresolved) and the
`/etc/paths.d` and `/etc/manpaths.d` PATH additions. Each file carries its
size, modification time and **launch hints**: line numbers with a keyword
(`launchctl`, `nohup`, a background job, `osascript`, `open -a`, `curl …
| sh`, `eval "$(…)"`, `crontab`, `defaults write`). launchkeeper never
prints a line of a shell file — that is where people export tokens — and
never edits one. A `source` line whose target is gone, or a PATH entry
pointing at a missing directory, is a low-confidence orphan: the leftover
of an uninstalled tool.

**Network** ties listening sockets to the inventory. `lsof` lists every
TCP listener and bound UDP socket, `ps` resolves the process's executable,
and the process becomes an item of category `network` with its ports
(loopback-only marked) — linked by executable path or app bundle to the
entry that starts it, which in turn gets a `listening` metadata and a
`LISTEN` flag in the table. Application Firewall rules
(`socketfilterfw --listapps`) merge into the process they name or stand
alone; the global firewall state is in `doctor`. Apple's own daemons hide
like other Apple internals (`--all`). Read-only: the control text names the
entry to act on and the `socketfilterfw --blockapp` route. A failed `lsof`
or `socketfilterfw` marks the inventory incomplete.

## Provenance and receipts (V0.6)

Every scan indexes the non-Apple installer receipts `pkgutil --pkgs`
knows — each package's file list (`pkgutil --files`), version and install
time (`pkgutil --pkg-info-plist`) — about a second for a typical machine.
An item whose plist, executable, bundle or app a receipt lists gets
`origin: receipt` with the package id, version and install date (visible
in `inspect` and `--json`). An app on disk that no receipt lists and that
carries no App Store receipt is `manual`: dragged out of a disk image or a
zip — the origin that leaves no uninstaller behind. Apple and Homebrew
still win by label and path, so a Homebrew formula that also ran an
installer stays Homebrew. If `pkgutil` does not answer, provenance falls
back to what the paths say; nothing is marked incomplete, because receipts
enrich the inventory rather than contribute entries.

`launchkeeper receipts` turns the index around: one row per package with
version, install date, how many of its files are still on disk (`MISSING`
counts the ones that are gone) and the inventory entries attributed to it.
`--missing` keeps only half-removed packages, `--all` includes Apple's.
This is the ground for V0.8's receipt-based uninstall: what a package put
where, and how much of it a manual deletion left behind.

Signature details that `codesign -dvvv` already reports — identifier,
Team ID and the leaf authority — are now metadata on every checked item.

## Snapshots, diff, export (V0.6.1)

`launchkeeper snapshot` saves the whole inventory of one scan as JSON under
`~/Library/Application Support/launchkeeper/inventory/`, optionally with a
`--name`; `snapshot list` shows what is there. `launchkeeper diff` compares
the latest snapshot (or the one you name, or any `list --json` file) with a
fresh scan — or two snapshots with each other — **by entry key**: entries
that appeared, entries that vanished, and entries whose configuration
changed, field by field (enabled, path, executable, signature, Team ID,
orphan verdict, origin, control level, schedule, listening ports, firewall
rule, helper clients, extension state, shell launch hints …). Whether a
job happens to be running is not a configuration change; `--state` adds
loaded/running. Apple internals stay hidden unless `--all`. `--exit-code`
returns 1 on differences, so a cron job or a login script can notice a new
autostart entry; `--json` gives the diff as data. Keys are stable across
scans on purpose: a listening process is `net:<executable>`, a power event
`pmset:<owner>:<kind>`, a cron line `cron:<user>:<source>:<command>`
(twins get `#2`, `#3` …), never a pid, an index or a line number.

`list --csv` writes every row with all columns (key, category, type,
domain, state, enabled, signature, Team ID, name, app, path, executable,
origin, package, install date, flags, orphan reasons, control), quoted
where needed; `list --markdown` renders a table for a report. Both honour
the usual filters.

## Signature in depth (V0.6.2)

`inspect <entry> --verify` looks at one executable (or bundle) the way a
reviewer would: `codesign --verify --strict` says whether the seal still
holds — a modified app reports "a sealed resource is missing or invalid" —
then the identifier, Team ID, format, timestamp, CDHash, whether the
hardened runtime is on, whether the signature is ad-hoc, and the whole
authority chain leaf first. `spctl --assess` gives Gatekeeper's verdict
with its source ("Notarized Developer ID", "no usable signature" …);
bundles are assessed for execution, bare binaries against the install
policy, because the execute policy calls a binary "not an app". Last the
SHA-256 of the executable (a bundle's main executable), for checking
against a vendor's published hash or a scanner of your choice — nothing is
uploaded anywhere. The whole block is in `--json` too. This stays per
entry on purpose: `spctl` costs a third of a second per path and its
verdicts are worth reading, not summarizing.

## Control beyond launchd (V0.7)

`disable` and `enable` reach every switch macOS offers outside launchd —
through the same gate, with the same guarantees: dry-run by default, the
plan shown before anything runs, a snapshot of the whole source before the
first write where there is a file to lose, verify-after-mutate, an audit
line for every path. `remove` stays what it was: one orphaned launch plist.

| mechanism | items | disable | enable | snapshot | verified by | never |
|---|---|---|---|---|---|---|
| `launchd` | launch agents/daemons | override + unload | drop override (`--now` reloads) | — (override is state) | `print` / `print-disabled` | `com.apple.*`, `/System` |
| `pluginkit` | app extensions | `pluginkit -e ignore -i <id>` | `-e use` | — (previous election in plan + undo hint) | `pluginkit -mAvv -i <id>`, every version | Apple extensions, `/System` |
| `cron` | lines in *your* crontab | comment out behind `#launchkeeper-disabled ` | take the marker off | whole table (`crontab -l`) | `crontab -l` reads back the edited table byte for byte | `/etc/crontab`, root tables, deleting lines |
| `login-hook` | `LoginHook` / `LogoutHook` | park the path under `LaunchKeeperDisabled<kind>`, then delete the key | put it back, delete the parked key | the loginwindow plist | `defaults read` of both keys | overwriting a parked value |
| `firewall` | existing Application Firewall rules | `socketfilterfw --blockapp` (sudo) | `--unblockapp` | — (previous action in plan + undo hint) | `socketfilterfw --listapps` | Apple binaries, adding or removing rules |

- **Disabled stays visible.** A commented-out cron line and a parked hook
  remain in the inventory as disabled entries — `enable` finds them again,
  `diff` shows the change.
- **Undo is exact.** Every plan prints the way back. An extension that had
  no election at all returns with `pluginkit -e default -i <id>` (`enable`
  would elect `use` — a different state); cron and hooks add a full rollback
  from their snapshot (`crontab <file>`, `defaults import`).
- **Tokens stay out of the log.** The audit target for cron is
  `crontab:<user>:line<N>`, never the command line.
- **The source is re-read at run time.** cron and hooks build the plan from
  the table/plist as it reads *now*; if the entry moved or vanished since
  the scan, the command refuses instead of guessing. The same schedule and
  command twice, or a hook that is live *and* parked, are refused — resolve
  by hand.
- System plists and firewall rules go through the interactive sudo seam;
  `crontab` and `pluginkit` run as you. Snapshots live under
  `~/Library/Application Support/launchkeeper/config-snapshots/` with a
  sha256 manifest.
- The control matrix is data: `inspect` and `--json` show level, actions,
  mechanism and reason, and a test holds the invariant that no item
  promises an action the gate would refuse.

## Cleanup: uninstall by receipt (V0.8)

`launchkeeper uninstall <package-id>` takes away what an installer package
put on disk — addressed by the exact id `pkgutil` knows (`launchkeeper
receipts`), never by a fragment. Expert tool; you have been warned. The
rules, enforced in code:

- **Proof, not trust.** Every path in the package's bill of materials
  (`/var/db/receipts/<id>.bom`) is checked against the disk: a file must
  still have its size and 32-bit checksum (the POSIX `cksum` CRC the BOM
  records), a symlink its target. Only that is *intact*. An edited file is
  *modified* and stays; a root-only file is *unreadable* and stays unless
  `--verify-as-root` (or `--apply`, which always does it) proves it with
  `sudo -n cksum` after one `sudo -v`.
- **Nobody else's.** A path another receipt lists — Apple's included, asked
  per directory with `pkgutil --file-info` — is *shared* and stays. Live
  lesson: Apple's data template lists `/Library/Printers/PPDs`, which a
  printer driver's receipt lists too. Top-level locations two levels deep
  (`/Library/<Vendor>`, `/opt/<tool>`) never move; if one would be left
  empty, the plan says so. `/System`, `/usr` (except `/usr/local`),
  `/bin`, `/sbin` and the receipts database are protected whatever a BOM
  claims, and a path behind a symlinked parent is never followed.
- **Directories move whole — bundles all or nothing.** A directory moves
  as one when everything in it on disk is intact package content. A bundle
  (`.app`, `.framework`, `.jdk`, …) that changed since install — typical
  after a self-update — stays *completely*: taking out the unchanged half
  would leave a broken app (live: AusweisApp, Ziti Desktop Edge, both
  updated through the App Store — nothing moves).
- **Moved, not deleted.** `--apply` moves the roots with `sudo mv` into
  `~/Library/Application Support/launchkeeper/quarantine/<stamp>-uninstall-<id>/files/<original path>`
  — a rename on the same volume: instant, no extra space, owner and mode
  preserved. The manifest is written before the first move.
- **The receipt goes last, and only when nothing stays.** `pkgutil --forget`
  runs only when no exclusive file of the package remains on disk; its
  `.bom` and `.plist` are copied into the quarantine first, so `quarantine
  restore` brings the receipt back too.
- **Verified.** After `--apply` every root must be gone from its place and
  present in the quarantine, and `pkgutil` must no longer know a forgotten
  receipt — otherwise the run reports failure, and whatever moved comes
  back with `quarantine restore`.
- **Restore never overwrites.** Something new at an original place is
  skipped and named. **Purge** (`sudo rm -rf` of one quarantine entry, after
  checking it resolves inside the quarantine root) is the only deletion.

Receipts whose files are all gone (`receipts --missing`) are the simple
case: the plan is just the forget step. macOS may refuse to move an app
bundle from `/Applications` unless your terminal has *App Management* (or
Full Disk Access) permission — the verification then reports what did not
move.

### Leftover entries (V0.8.1)

`remove` takes more than orphaned launch plists now. Three kinds of
provable leftovers are **moved into the same quarantine** (never deleted),
one entry per call, dry-run first:

| leftover | where | proof |
|---|---|---|
| privileged helper | direct entry of `/Library/PrivilegedHelperTools` | no LaunchDaemon starts it (no job, no plist) |
| StartupItem | direct folder of `/Library/StartupItems` | nothing runs StartupItems since OS X 10.10 |
| PATH / MANPATH file | direct entry of `/etc/paths.d` or `/etc/manpaths.d` | *every* line points at a missing directory — re-read at run time |

The gate allows only direct entries of these locations, never `/System` or
Apple platform paths; at run time the entry must still be on disk with the
expected type (a helper is a file, a StartupItem a folder), and an entry an
Apple receipt lists is refused. If a third-party receipt lists it, the plan
says so — `uninstall <package>` would take the rest of that package too.
Shell profiles (`.zshrc` …) stay untouched: launchkeeper never edits shell
files. System extensions are not files launchkeeper takes: macOS removes
one itself when its host app goes to the Trash **in the Finder** (or through
the vendor's uninstaller) — if the app is already gone, reinstall it first.
`systemextensionsctl uninstall` refuses while System Integrity Protection is
on, and switching SIP off for that is not worth it. An extension stuck at
`[activated waiting for user]` was never approved and is not active.

### App leftovers (V0.8.2)

`launchkeeper leftovers` lists what apps left behind after they were
deleted — preferences, caches, Application Support, saved state, HTTP
storage, WebKit data, logs, cookies, sandbox containers and application
scripts in `~/Library`, plus Application Support, caches, preferences and
logs in `/Library`. This is user data, so the bar is the highest in the tool:

- **Named by a bundle id** (three or more parts). Never: anything with
  `com.apple` in it, `group.`/`systemgroup.` and Team-ID-scoped app groups
  (`ABCDE12345.vendor.group` — shared by a vendor's apps; live: Ziti, Things),
  `org.cups.*` (live: the first report listed `org.cups.printers`, the
  system's printer setup), shared framework helpers (`org.sparkle-project.*`),
  and file-name debris (`warp.log.old.0`, `…compiled.cache`).
- **The app is gone** only when the application folders (two levels deep,
  with login items and helpers inside apps), LaunchServices and Spotlight
  all find nothing, it is not running and no registered extension has the
  id. A Spotlight that does not answer means *unknown*, never gone.
  Helper domains of an installed app (`com.vendor.app.helper`) are present;
  another app of the same vendor still installed makes it *unknown* — vendor
  data may be shared (`com.microsoft.office` next to Word).
- **It was an app**: a sandbox container, an application scripts folder,
  saved window state, WebKit data, or preferences with keys only GUI apps
  write (window frames, status item positions, Sparkle). Without that the
  verdict is *no-app-evidence* — a CLI tool's cache or a framework's
  defaults domain stays.

`leftovers <bundle-id>` re-checks that one id and moves every path into the
quarantine — as you for `~/Library`, via sudo for `/Library`. Containers of
other apps can need *App Data* or Full Disk Access for your terminal; the
verification names what did not move.

## Watch (V0.9)

`launchkeeper watch` says it when something new may start automatically —
the part BlockBlock/KnockKnock cover and Autoruns does not. Read-only.

- **Baseline, then differences.** The first complete scan is the reference;
  every rescan is compared with the previous one by stable entry key (the
  `diff` of V0.6.1): `NEW`, `GONE`, `CHANGED` with the fields that moved.
- **Triggers.** FSEvents on the autostart locations — launch directories,
  PrivilegedHelperTools, StartupItems, SystemExtensions,
  SecurityAgentPlugins, `/etc/paths.d`, the loginwindow plists, shell
  profiles and the top level of `/Applications` — start a rescan after a
  5-second quiet period; writes deep inside app bundles or other
  preference files are ignored. A full rescan also runs every `--interval`
  seconds (default 300) for what has no file to watch: Background Task
  Management, app extensions, crontab, the firewall.
- **Cold BTM dumps.** A rescan set off by a file reuses the last
  `sfltool dumpbtm` of the session (a cold one can take minutes); the
  interval rescan refreshes it.
- **No false "gone".** An incomplete scan (BTM timeout, pluginkit failure)
  is reported as `skipped` and never compared — the baseline stays.
- **Configuration, not runtime.** A process that starts listening is not a
  new autostart entry; listeners appear only with `--state` (which also
  adds loaded/running changes). Apple internals only with `--all`.
- **Where it goes.** Terminal lines (or `--json`), JSON lines appended to
  `~/Library/Logs/launchkeeper/watch.log`, and with `--notify` a macOS
  notification per change (the text is passed to `osascript` as an
  argument, never as script source).

Live check (2026-09-26): an empty `~/.zlogin` was reported `NEW` one
second after it appeared and `GONE` after it was removed.

To keep it running, write a LaunchAgent yourself (launchkeeper never
installs one on its own) — e.g. `~/Library/LaunchAgents/local.launchkeeper.watch.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.launchkeeper.watch</string>
  <key>ProgramArguments</key><array>
    <string>/opt/homebrew/bin/launchkeeper</string><string>watch</string><string>--notify</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/launchkeeper-watch.out</string>
  <key>StandardErrorPath</key><string>/tmp/launchkeeper-watch.err</string>
</dict></plist>
```

then `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.launchkeeper.watch.plist`.
It will, of course, show up in its own inventory.

## Offline analysis: `--root` (V0.9.1)

`launchkeeper list --root <folder>` inventories **another system from its
files** — a Time Machine backup (the `… - Data` folder of a backup), a Mac
in target disk mode, a mounted disk image. `snapshot save --root` stores
it for `diff`.

- **Every path below the root.** A file manager maps each absolute path
  into the root (`/Applications/X.app` is read as `<root>/Applications/X.app`;
  `/etc`, `/var`, `/tmp` fall back to `<root>/private/…` on a Data volume),
  so orphan detection, app context and symlinks are judged against *that*
  system, not this one.
- **Every user.** All homes under `<root>/Users` (not Shared) — their
  LaunchAgents, loginwindow hooks, plugin folders and shell profiles.
- **Files only.** What runs: launch plists, privileged helpers (their
  embedded Info.plist via `launchctl plist <file>`), StartupItems, hooks,
  rc/emond files, plugin directories, shell profiles and `paths.d`, code
  signatures (`codesign` on the file below the root). What only a running
  system can answer is listed as *not available offline* and never taken
  from this machine — launchd state, Background Task Management,
  app-extension elections, system extensions, crontab/at/pmset, network,
  receipts, Spotlight. A runner allowlist enforces that: only `codesign`
  (never signing) and `launchctl plist` reach the system.
- **Nothing is switchable** — every entry is display-only; launchkeeper
  controls the running system only.
- Reading Time Machine backups needs **Full Disk Access** for your
  terminal; without it `--root` says so.

Cross-check on the maintainer's Mac: `list --root /` found the same 23
launch plists and the same orphans as the live scan, in 4 seconds.
A `diff` between an offline snapshot and a live one shows the live-only
layers as added — compare offline with offline (two backups), or read the
launch-item rows.

## How it works

    LaunchAgent/Daemon plists ─┐
    launchctl print (live)   ──┤→ Correlation ──→ Orphan + Risk analysis
    sfltool dumpbtm (BTM)    ──┤     ↓                    ↓
    pluginkit -mAvv          ──┤
    systemextensionsctl list ──┤
    kmutil + /Library/Extensions┤
    PrivilegedHelperTools    ──┤
    crontab/atq/pmset/periodic┤
    loginwindow/StartupItems ──┤
    plugin directories       ──┤
    shell startup files      ──┤
    lsof + socketfilterfw    ──┤
    pkgutil receipts (V0.6)  ──┤
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

- **V0.9.1** ✅ — `--root` offline analysis (Time Machine backup, target
  disk mode, disk image): files only, every user home, paths mapped below
  the root, live tools refused by an allowlist — V0.9 is complete
- **V0.9.0** ✅ — `watch`: FSEvents on the autostart locations + interval
  rescans, stable-key comparison against a baseline, incomplete scans
  skipped, BTM dump reused for file-triggered rescans, notifications and a
  JSON-lines log
- **V0.8.2** ✅ — `leftovers`: what gone apps left in `~/Library` and
  `/Library`, gone only on three negative sources plus positive app
  evidence, hard exclusions for Apple, app groups, CUPS and framework
  helpers; `leftovers <bundle-id>` into the quarantine — V0.8 is complete
- **V0.8.1** ✅ — `remove` quarantines provable leftovers: privileged
  helpers without a job, StartupItems, paths.d/manpaths.d files whose every
  entry is gone (control mechanism `quarantine`, `removable` in the matrix)
- **V0.8.0** ✅ — `uninstall <package-id>` by bill of materials (size +
  checksum, root-only files proven via sudo, claims of every receipt
  including Apple's, bundles all or nothing), moved into a quarantine with
  manifest; `quarantine list / restore / purge`; receipt forgotten only when
  nothing stays, with a copy
- **V0.7.0** ✅ — control beyond launchd: pluginkit elections, user-crontab
  lines (marker, snapshot), loginwindow hooks (parked, snapshot), Application
  Firewall rules (block/allow via sudo); the control matrix names its
  mechanism, one gate for all of it
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
- **V0.6.2** ✅ — `inspect --verify`: seal check, authority chain,
  hardened runtime, Gatekeeper/notarization verdict, SHA-256 — V0.6 is
  complete
- **V0.6.1** ✅ — `snapshot` / `snapshot list`, `diff` by stable entry
  key (added, removed, changed fields; `--state`, `--exit-code`, `--json`,
  two snapshots), `list --csv` and `list --markdown`
- **V0.6.0** ✅ — provenance from package receipts (`pkgutil` index per
  scan: package id, version, install date on every attributed item;
  `manual` for drag-installed apps), `list --origin`, `receipts` with
  files-still-on-disk counts, signature identifier/Team ID/authority as
  metadata
- **V0.5.7** ✅ — shell startup files with sourced files, PATH additions
  and launch hints (never a line's content), and network: listening
  processes linked to the entry that starts them, Application Firewall
  rules, `LISTEN` flag — categories `shell-startup` / `network`; the V0.5
  breadth is complete
- **V0.5.6** ✅ — scheduled work (launchd timers as metadata, cron, at,
  periodic, pmset), legacy persistence (loginwindow hooks, StartupItems,
  rc.local, emond) and plugin directories (authorization plugins with their
  login wiring, HAL, Spotlight, QuickLook, input methods, screen savers,
  prefpanes, scripting additions) as categories `scheduled` / `legacy` /
  `plugin-directories`
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