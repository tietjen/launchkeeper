# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning once 1.0 is reached. Releases up to 0.4.5 were published
under the former name **btmctl**.

## [0.12.1] — 2026-09-27

### Security
- `RemediationEnvironment.systemScopeOnly` (set by the app's privileged
  helper): entries that belong to one user — user domain, per-user app
  extension elections, a config file in the user's home — are refused for
  root. A system daemon whose *program* lives in a home (a common adware
  pattern) stays changeable: only the file root writes counts.
- `CleanupEnvironment.forbiddenMovePrefixes` and `requireRootOwnedParents`
  (set by the helper): `uninstall` refuses packages that would move files
  out of places a non-root user can change — `/Users/`, temp directories,
  `/Volumes/`, `/opt/homebrew/`, and any path whose parent chain is not
  root-owned or is world-writable (`PathUtils.userWritableAncestor`; covers
  `/usr/local` on Intel Homebrew Macs and `/Library/Caches`). Checked before
  anything is read as root.

3 new tests (354 total).

## [0.12.0] — 2026-09-27

### Security
- **Root keeps its bookkeeping out of the user's home.** Found by
  independent reviews of the LaunchKeeper app's privileged helper: root
  worked with paths inside `~/Library/Application Support/launchkeeper`,
  where any process of the user can rename directories or plant symlinks
  between root's check and root's write — enough to redirect a chown, a
  restore or a snapshot onto system files. The kit now knows a root-owned
  tree, `/Library/Application Support/launchkeeper/{quarantine,backups,
  config-snapshots}`, written only by the privileged helper; the CLI keeps
  writing into the user's own quarantine and only reads the helper's tree
  (`quarantine list`, `restore`, `purge` see both; `restore` finds the
  helper's snapshots too).
- Launch-dir snapshots never follow symlinks, copy regular files only, and
  a copy is never more readable than its original — as root, a link or a
  0600 daemon plist could otherwise end up readable in a snapshot.
- A CLI restore of a helper entry says when its status could not be
  recorded (the helper's entries are read-only for the user) and how to.

### Changed
- `CleanupEnvironment`/`RemediationEnvironment.systemQuarantineRoot`,
  `CleanupEngine.systemStore`, `locate(_:)`, `listAll()`.

2 new tests (351 total).

## [0.11.1] — 2026-09-27

Findings of an independent review (Fable) of the 0.11 batches.

### Fixed
- **Batch removals kept their way back.** Snapshot names have one-second
  resolution; two `remove`s of one batch in the same second shared one
  snapshot, and the second overwrote its manifest without the first file —
  the first removal could no longer be restored. Every snapshot now gets a
  directory of its own (a suffix when the name is taken).
- `disable`, `enable` and `remove` without a target are a usage error again
  (0.11.0 scanned and reported "0 of 0" with exit 0).
- Entries a batch skips (stopped, or the same entry twice) get an audit line.

2 new tests (349 total).

## [0.11.0] — 2026-09-27

### Added
- Batches: `disable`, `enable` and `remove` take several targets
  (`launchkeeper disable a b c [--apply]`) and run them against ONE scan —
  the scan (with a cold Background Task Management dump up to a minute) used
  to run once per target. Every entry still goes through its own gate, plan,
  audit line and verification; results print as they come, a summary line
  follows, and `--json` prints an array. A failure does not stop the batch;
  the same entry twice in one batch is refused (the shared scan would be
  stale for the second action).
- Kit: `RemediationEngine.runBatch(_:apply:…)` with `RemediationRequest`,
  progress callback and a stop check between entries; `scan(options:)` and
  `run(…, in: report)` for callers that hold a scan; results carry the
  resolved `key`. Used by the app's queue.

2 new tests (347 total).

## [0.10.2] — 2026-09-26

### Fixed
- `SignatureVerification` is `Sendable` (value type of strings and flags).
  Swift 6.1 (Xcode 16.4, the GitHub macOS runners) refused to hand it out of
  a background task in the app; Swift 6.3 had accepted it.

## [0.10.1] — 2026-09-26

### Fixed
- Origin "apple" is no longer given for an Apple executable alone. A
  third-party plist that starts one of macOS's own programs (`/bin/bash`,
  `osascript`, `curl`, `/usr/bin/true` …) was shown as "Apple system
  component" — the classic way persistence hides. Apple now means: an Apple
  label, a file under /System, or an Apple binary without a third-party
  backing file. Such entries read "unknown — third-party entry running a
  macOS program". `/usr/local` is no longer taken for Apple's either
  (Homebrew/vendor tools there were "apple"). Live: 7 entries on the dev Mac
  changed origin.

### Added
- Risk hint `third-party-plist-runs-system-binary` for such entries, unless
  a launcher (`arch`, `env` …) starts a third-party program that is judged on
  its own.

2 new tests (345 total).

## [0.10.0] — 2026-09-26

### Added
- `remove --working`: take away a working launch plist — the way to get rid
  of an unwanted or malicious agent, which is never orphaned (its program is
  there). It never deletes: `disable` first (override, then unload), then the
  plist is moved into the quarantine, restorable with
  `launchkeeper quarantine restore`. The disable override stays, so an app or
  updater that writes the plist again cannot start it. Locks 1–3 of `remove`
  still apply, plus lock 5: entries Background Task Management marks as
  managed (configuration profile / MDM) are refused. Plain `remove` stays
  orphans-only.
- `Controllability.removeWorking` (`remove-working`) in the actions of
  working launch plists that would pass those locks.

### Changed
- Quarantine moves of files in the user's own home run without sudo.

4 new tests (343 total).

## [0.9.5] — 2026-09-26

### Changed
- An exact entry key resolves uniquely before any fragment match
  (`disable com.vendor.agent` no longer collides with
  `com.vendor.agent.helper`). The app addresses entries only by key.
- `RemediationEnvironment.btmCache` passes a Background Task Management dump
  cache to the resolution scan, so a caller that already holds a dump (the
  app) does not pay a cold one per action.
- `quarantine restore` moves paths in the user's own home back without sudo
  when the user may move them (app leftovers); everything else still goes
  through the sudo seam.

1 new test (339 total).

## [0.9.4] — 2026-09-26

### Added
- `EffectiveProgram`: what an entry really runs when its executable is an
  interpreter or launcher — shells (script, `-c`), Python (script, `-m`,
  `-c`), Perl/Ruby/PHP/Node/osascript (script or inline code), `open` (app),
  and launcher chains (`arch`, `env`, `nohup`, `nice`, `caffeinate`). Every
  entry carries it as metadata (`runs`, `runs-target`, `runs-kind`), visible
  in `inspect` and `--json`. Live: "arch" entries are Brother's print
  servers, "bash" entries the scripts they run.
- Package receipts count their **own** files too (`ownFileCount`,
  `ownMissingFiles`): without shared folders like `/Applications`, paths
  other receipts list, and AppleDouble entries. Live: a receipt with 15,245
  paths had "1 present" — `/Applications` itself; by its own files the
  package is gone.

### Changed
- Orphan rule "script missing" now checks only the payload the interpreter
  actually runs (and the binary behind `arch`/`env` …) — an output file
  among the arguments no longer marks an entry as orphaned. Reason text:
  `script missing: <path> (run by bash)` / `program missing: <path> (run by arch)`.

### Fixed
- A launchd plist with both `Program` and `ProgramArguments` runs `Program`;
  the inventory used `ProgramArguments[0]` as the executable.

8 new tests (338 total).

## [0.9.3] — 2026-09-26

### Changed
- For the SwiftUI app (`launchkeeper-app`): the model types a scan returns
  (`BackgroundItem`, `ScanReport`, `SourceEvidence`, `BTMContainer` …) are
  `Sendable`; `ListFilter.isAppleInternal` is public; `AppLeftoverCandidate`,
  `LeftoverPath`, `QuarantineManifest` and `QuarantineMove` have public
  initializers.

### Fixed
- `RootedFileManager` no longer claims a `Sendable` conformance its
  `FileManager` superclass rules out (warning in release builds).

## [0.9.2] — 2026-09-26

### Added
- `LaunchKeeperKit` is a library product now, so other packages can depend
  on it — the SwiftUI app (`launchkeeper-app`) builds on the same core.

## [0.9.1] — 2026-09-26

### Added
- `list --root <folder>` and `snapshot save --root <folder>`: offline
  analysis of another system from its files (Time Machine backup's
  "… - Data" folder, target disk mode, disk image). `RootedFileManager`
  maps every absolute path below the root (with `/private` fallbacks for
  `/etc`, `/var`, `/tmp`); all homes under `<root>/Users` are scanned;
  launch plists, helpers, StartupItems, loginwindow hooks, rc/emond,
  plugin directories, shell profiles, paths.d and code signatures. Live
  layers are listed as not available offline; `OfflineRunner` lets only
  `codesign` (never signing) and `launchctl plist` run, with mapped paths.
  Everything is display-only. Unreadable roots name Full Disk Access.

### Changed
- Shell startup and `/etc/crontab` are read through the injected file
  manager (no more `String(contentsOfFile:)` past it).

4 new tests (330 total).

## [0.9.0] — 2026-09-26

### Added
- `launchkeeper watch` — live report of new, removed and changed autostart
  entries. First complete scan = baseline, comparison by stable entry key.
  FSEvents on the autostart locations (launch dirs, helpers, StartupItems,
  system extensions, authorization plugins, paths.d, loginwindow plists,
  shell profiles, top level of /Applications) trigger a rescan after a
  5-second quiet period; a full rescan runs every `--interval` seconds
  (default 300). Incomplete scans are `skipped`, never reported as removed.
  `--notify` (macOS notification, text as argv), `--json`, `--all`,
  `--state` (listeners, loaded/running), `--verbose`, `--no-fsevents`.
  Events are appended as JSON lines to `~/Library/Logs/launchkeeper/watch.log`.
- In-process BTM dump cache (`BTMDumpCache`): rescans set off by files
  reuse the last `sfltool dumpbtm`, the interval rescan refreshes it.

### Fixed
- The control hint for system extensions no longer offers
  `systemextensionsctl uninstall` as the way out — it refuses while System
  Integrity Protection is on (found live). The hint now names the Finder
  route (host app to the Trash, or the vendor's uninstaller; reinstall the
  app first when it is gone) and says when an extension waiting for user
  approval was never active.

9 new tests (326 total).

## [0.8.2] — 2026-09-26

### Added
- `launchkeeper leftovers` — read-only report of what gone apps left in
  `~/Library` (Application Support, Caches, Preferences, Saved Application
  State, HTTPStorages, WebKit, Logs, Cookies, Containers, Application
  Scripts) and `/Library` (Application Support, Caches, Preferences, Logs).
  An entry counts only when named by a bundle id; the app is gone only when
  the application folders, LaunchServices (`NSWorkspace`) and Spotlight find
  nothing and nothing running or registered claims the id (Spotlight silent
  = unknown); same-vendor apps still installed = unknown; and something must
  show it was an app (container, application scripts, saved state, WebKit
  data, GUI preference keys) — otherwise `no-app-evidence`. `--all` shows
  every verdict with its reason, `--json` for scripts.
- `launchkeeper leftovers <bundle-id> [--apply]` moves one gone app's
  leftovers into the quarantine (sudo only for `/Library`).

### Found live
- The first report listed `org.cups.printers` (`/Library/Preferences`, the
  printer setup), `systemgroup.com.apple.*`, Team-ID app groups of installed
  apps (Ziti, Things, Telegram), CLI-tool caches and log-file names — hence
  the hard exclusions and the app-evidence requirement. On the
  maintainer's Mac: 247 bundle-id entries, 38 gone apps with leftovers.

5 new tests (317 total).

## [0.8.1] — 2026-09-26

### Added
- `remove` takes provable leftover files into the quarantine (control
  mechanism `quarantine`): privileged helpers no LaunchDaemon starts,
  StartupItems, and `/etc/paths.d` / `/etc/manpaths.d` files whose every
  entry points at a missing directory (re-read at run time). Only direct
  entries of those locations, never Apple platform paths, refused when an
  Apple receipt lists the file, the expected on-disk type is checked (no
  following). `quarantine restore` brings them back.
- The `remove` dry-run prints the plan's notes (e.g. which receipt lists
  the file).

### Changed
- Control matrix: those leftovers are `removable` now (were display-only
  "comes with V0.8").

5 new tests (312 total).

## [0.8.0] — 2026-09-26

### Added
- `launchkeeper uninstall <package-id>`: receipt-based uninstall, dry-run by
  default. Every BOM path is classified against the disk — intact (size +
  POSIX `cksum` CRC, or symlink target), missing, modified, unreadable
  (root-only), shared (listed by another receipt, Apple's included via
  `pkgutil --file-info`, or a top-level location), protected (`/System`,
  `/usr`, receipts DB, symlinked parent), foreign content, kept with a
  changed bundle. Only intact exclusive content moves; directories move
  whole when all their content does; bundles move all or nothing.
  `--verify-as-root` proves root-only files in the dry-run; `--apply`
  always does. `--list` prints every file, `--json` every classified path.
- Quarantine instead of deletion: `--apply` moves the roots via `sudo mv`
  into `~/Library/Application Support/launchkeeper/quarantine/<name>/files/`
  with a manifest written first; `pkgutil --forget` only when nothing of the
  package stays, after copying `.bom`/`.plist` into the quarantine.
- `launchkeeper quarantine list | restore <name> | purge <name>` — restore
  moves everything back and never overwrites; purge is the only real
  deletion (`sudo rm -rf` of one entry inside the quarantine root).
- `receipts` points at `uninstall` when receipts have missing files.

### Found live (dry-runs on the maintainer's Mac)
- Apple's `com.apple.files.data-template` lists `/Library/Printers/PPDs`;
  the non-Apple index alone would have moved that standard folder with a
  printer driver.
- Self-updated apps (AusweisApp, Ziti Desktop Edge via the App Store)
  differ from their receipts in hundreds of files — hence bundles all or
  nothing.
- A package that installs INTO a bundle (`com.oracle.jdk-27` → `jdk-27.jdk`)
  has the BOM root `.` as its own directory.

15 new tests (307 total).

## [0.7.0] — 2026-09-25

### Added
- `disable` / `enable` beyond launchd, through the same gate, dry-run by
  default, verified after every change:
  - **app extensions** — the pluginkit election (`-e ignore` / `-e use`),
    verified on every registered version; undo returns to the exact previous
    election (`-e default` when there was none). Apple and `/System`
    extensions stay read-only.
  - **user crontab lines** — commented out behind `#launchkeeper-disabled `
    and back; the whole table is snapshotted first, the edited copy is
    installed with `crontab <file>` and must read back byte for byte.
    Disabled lines stay in the inventory. `/etc/crontab` stays read-only.
  - **LoginHook / LogoutHook** — the script path is parked under
    `LaunchKeeperDisabled<kind>` in the same loginwindow plist (park first,
    delete second), and put back by `enable`; plist snapshot first, system
    plist via sudo, `defaults import` as full rollback.
  - **Application Firewall rules** — an existing rule flips to block
    (`disable`) or allow (`enable`) via `socketfilterfw` and sudo, verified
    through `--listapps`; rules are never added or removed, Apple binaries
    stay read-only; a switched-off firewall is said out loud.
- `Controllability.mechanism` (`launchd`, `pluginkit`, `cron`, `login-hook`,
  `firewall`) in `inspect` and `--json`; config snapshots under
  `~/Library/Application Support/launchkeeper/config-snapshots/` with a
  sha256 manifest.

### Changed
- The control matrix: app extensions, user crontab lines, loginwindow hooks
  and third-party firewall rules are `reversible` now (were display-only).
  A `diff` against an older snapshot shows that as a control change.
- Audit targets for the new mechanisms: `pluginkit/<id>`,
  `crontab:<user>:line<N>` (never the command), `loginwindow:<domain>:<kind>`,
  `firewall:<path>`.
- Entries can be addressed by an extension's pluginkit identifier.

35 new tests (292 total).

## [0.6.2] — 2026-09-23

### Added
- `inspect <entry> --verify`: the signature in depth for one entry —
  `codesign --verify --strict` (seal), identifier, Team ID, format,
  timestamp, CDHash, hardened runtime, ad-hoc flag, the full authority
  chain, Gatekeeper's verdict and source via `spctl --assess` (execute
  policy for bundles, install policy for bare binaries), and the SHA-256
  of the executable (a bundle's main executable). Text block under the
  inspect output; `--json` wraps item and verification. 3 tests.

## [0.6.1] — 2026-09-23

### Added
- `launchkeeper snapshot [save] [--name]` saves the whole inventory as
  JSON under `~/Library/Application Support/launchkeeper/inventory/`;
  `snapshot list` lists them newest first.
- `launchkeeper diff [<before>] [<after>]` compares a snapshot (default:
  the latest; a name, file name or path; any `list --json` file works)
  with a fresh scan or a second snapshot, by entry key: added, removed,
  and changed configuration fields (enabled, path, executable, signature,
  Team ID, orphaned, origin, control, schedule, listening, firewall,
  helper clients, extension state, election, shell hints …). `--state`
  adds loaded/running, `--all` includes Apple internals, `--json` and
  `--exit-code` for scripts.
- `list --csv` (all columns, RFC-style quoting) and `list --markdown`.

### Changed
- Entry keys carry no volatile parts any more: listening processes are
  `net:<executable>`, power events `pmset:<owner>:<kind>`, cron lines
  `cron:<user>:<source>:<command>`; twins get `#2`, `#3` …. The pid, index
  and line number stay in the metadata. 8 tests.

## [0.6.0] — 2026-09-23

### Added
- Provenance from package receipts: every scan indexes the non-Apple
  receipts (`pkgutil --pkgs`, `--pkg-info-plist`, `--files`) and attributes
  items to packages by plist, executable, bundle or app path. Attributed
  items carry `origin: receipt` with package id, version and install date
  (`inspect`, `--json`). Apps on disk that no receipt lists and that have
  no App Store receipt are `manual` (drag-installed). Apple and Homebrew
  keep precedence. A failed `pkgutil` is a warning, not incompleteness.
- `list --origin <kind>` filters by provenance (apple, homebrew, app-store,
  receipt, manual, unknown).
- `launchkeeper receipts`: one row per installer package with version,
  install date, files still on disk vs. missing, and the inventory entries
  it accounts for; `--missing`, `--all`, `--json`.
- Signature identifier, Team ID and leaf authority from `codesign -dvvv`
  are metadata on every checked item. 9 tests.

## [0.5.7] — 2026-09-22

### Added
- Shell startup: the user's and the system's shell startup files, the
  files they source (depth 1, `~`/`$HOME` resolved, other variables listed
  as unresolved) and `/etc/paths.d` / `/etc/manpaths.d` entries become
  items of category `shell-startup` with size, modification time and
  launch hints (line number + keyword: `launchctl`, `nohup`, background
  job, `osascript`, `open -a`, `curl | sh`, `eval "$(…)"`, `crontab`,
  `defaults write`). No line of a shell file is ever printed. A missing
  `source` target or PATH directory is a low-confidence orphan. `--user-only`
  scans keep to `$HOME`.
- Network: `lsof` listeners (TCP LISTEN, bound UDP) grouped per process
  with the executable from `ps`, as items of category `network` linked to
  the inventory entry that starts them (by executable or app bundle); the
  entry gets `listening` metadata and a `LISTEN` flag. Application
  Firewall rules (`socketfilterfw --listapps`) merge into their process or
  stand alone; the global state is a `doctor` line. Apple's daemons hide
  by default. A failed `lsof` or `socketfilterfw` marks the inventory
  incomplete. 9 tests.

## [0.5.6] — 2026-09-22

### Added
- Scheduled: launchd `StartInterval` / `StartCalendarInterval` are rendered
  as `schedule` metadata on launch items and `list --category scheduled`
  includes them. The user's crontab, `/etc/crontab`, `atq`, `periodic(8)`
  scripts and `pmset -g sched` power events become items of category
  `scheduled`; a cron command with an absolute path is the item's
  executable, so a missing one is an orphan. Apple's own power alarms hide
  in the default view. A failed `crontab`, `atq` or `pmset` call marks the
  inventory incomplete.
- Legacy: `LoginHook`/`LogoutHook` from the loginwindow preferences,
  `/Library/StartupItems` (each entry flagged as a leftover — SystemStarter
  is gone since OS X 10.10), `/etc/rc.local`, `/etc/rc.shutdown.local`,
  `/etc/launchd.conf` and non-Apple emond rules as category `legacy`.
- Plugin directories: authorization plugins (checked against the
  `system.login.console` mechanism chain), HAL audio drivers, Spotlight
  importers, QuickLook generators, input methods, Internet plug-ins, screen
  savers, preference panes, scripting additions and color pickers, system
  and per-user, as category `plugin-directories` with bundle id, version
  and code signature. All three categories are display-only; the control
  text names the manual route. Two fixtures, 15 tests.

## [0.5.5] — 2026-09-22

### Added
- System extensions: `systemextensionsctl list` is a scan source. Network,
  endpoint-security, DriverKit and camera extensions become items of
  category `system-extensions` with enabled/active bits, state, team ID,
  version, the owning System Settings pane, the installed copy under
  `/Library/SystemExtensions` and the host app that ships it. A host app
  that is nowhere (not in `/Applications`, unknown to Spotlight) makes the
  extension an orphan of medium confidence. Kernel extensions from `kmutil
  showloaded` (third-party only) and `/Library/Extensions` join the same
  category. Both are display-only; the control text names the
  `systemextensionsctl uninstall` route. Bundles are code-signature checked.
- Privileged helper tools: `/Library/PrivilegedHelperTools` is a scan
  source. Each helper's embedded Info.plist (`launchctl plist
  __TEXT,__info_plist`) yields bundle id, version and `SMAuthorizedClients`;
  the helper merges with the LaunchDaemon whose `Program` points at it
  (category `privileged-helpers`, launchd control kept) or, without one,
  becomes its own item and an orphan of medium confidence — nothing can
  start it. The client app is resolved via Spotlight for display; a miss
  is not treated as evidence. Failed `systemextensionsctl`, `kmutil` or an
  unreadable helper directory mark the inventory incomplete. Anonymized
  fixture and 12 tests.

## [0.5.4] — 2026-09-22

### Added
- App extensions: `pluginkit -mAvv` is a scan source. Every registered
  extension (QuickLook, Spotlight, Share, widgets, Finder Sync, notification
  services, …) becomes an item of category `app-extensions` with its user
  election (`use` / `ignore` / `none`), extension point and host app;
  extensions that Background Task Management also lists merge with their
  BTM record by bundle path. A failed `pluginkit` call marks the inventory
  incomplete. The election is read-only until V0.7. Anonymized fixture
  (510 extensions, 34 elected) and 8 tests.

## [0.5.3] — 2026-09-22

### Fixed
- `background`: developer rows carry their name as their identifier
  ("Docker" / "Docker") and were renamed after a component in 0.5.2; names
  are kept. Unnamed registrations ("Unknown Developer") appear one row per
  component, named after the component's executable — as the pane does.

## [0.5.2] — 2026-09-22

### Fixed
- `background` now matches the System Settings pane (verified against it):
  the switch is the components' BTM disposition bit — a launchd override
  (`launchctl disable`) is invisible to the pane and is shown as its own
  `LAUNCHD` column instead of flipping the switch (GoogleUpdater and
  Wireshark read ON in the pane while launchd had them disabled); "Open at
  Login" lists apps registered by themselves (BTM `app` records with an
  enabled bit), not SMAppService `login item` helpers, which belong under
  their app's row; unnamed developer rows are named after their component's
  executable ("bash"), as the pane does.
- A timed-out child that ignores SIGTERM is now killed (its whole process
  group for the piped seam) and reaped; a lingering client kept our pipe
  open and, for `sfltool`, queued up behind the BTM daemon.

## [0.5.1] — 2026-09-22

### Added
- Every item carries `category` (Autoruns-style tab), `control` (what
  launchkeeper may do with it — reversible / removable / display-only with
  the reason, computed from the same gate the mutating commands use) and
  `provenance` (Apple, Homebrew, Mac App Store receipt; unknown stays
  unknown). Shown by `inspect` and in `--json`; `list --category <name>`.
- `background`: the System Settings › Login Items & Extensions pane rebuilt
  from the inventory — "Open at Login" and "Allow in the Background", one row
  per app/developer with the switch state derived from its components (the
  container's own BTM bit is not the switch, except for app-level
  registrations without components) and the components beneath. `--json`
  for scripts. Read-only; the switch stays in System Settings.
- Homebrew tap `tietjen/homebrew-tap` (`brew install tietjen/tap/launchkeeper`).

### Changed
- BTM scan budget 45 s → 150 s: the first `sfltool dumpbtm` after the daemon
  sat idle took 76 s and 97 s live (BTM re-validates every registered bundle),
  the next one seconds. After five seconds the scan says on stderr that it is
  waiting.
- Login items and other non-launchd BTM registrations no longer merge into a
  launch agent with the same bundle-id core; they are their own components
  (live: a LoginItems helper had vanished behind a LaunchAgent).

### Fixed
- `scripts/release.sh` fails unless Apple's notarization status is
  `Accepted` — `notarytool submit --wait` exits 0 even for `Invalid`.

## [0.5.0] — 2026-09-22

### Changed
- Renamed the project from btmctl to **launchkeeper**: package
  `launchkeeper`, library `LaunchKeeperKit`, binary `launchkeeper`. State moved
  to `~/Library/Logs/launchkeeper` and `~/Library/Application Support/launchkeeper`;
  the btmctl-era audit log is carried over once, btmctl-era backups still
  restore. `BTMCTL_BTM_TIMEOUT` still works as a fallback for
  `LAUNCHKEEPER_BTM_TIMEOUT`.
- Licensed under MIT; added SECURITY.md and CONTRIBUTING.md.
- Test fixtures are now synthetic (anonymized captures); real captures never
  leave the developer's machine. The git history was rewritten on 2026-09-22
  to carry the anonymized fixtures and neutral example names in every
  commit; tags v0.4.1–v0.4.5 point at the rewritten commits (the published
  release assets are unchanged).
- Public home on GitHub (`tietjen/launchkeeper`); GitHub Actions build and
  test every push (`ci.yml`) and turn a `v*` tag into a signed, notarized
  release (`release.yml`).

## [0.4.5] — 2026-09-22
### Fixed
- Numeric display ids are accepted only against a complete inventory. When an
  item source did not answer (`sfltool dumpbtm` timeout, `launchctl print`
  failure) the run is marked incomplete, `list`/`doctor` say so, and
  `disable`/`enable`/`remove` refuse a number instead of resolving it against
  a shifted numbering. Labels still work.

## [0.4.4] — 2026-09-22
### Changed
- A Background Task Management record whose plist is gone and that no launchd
  job backs is reported as a **leftover** (one reason, confidence low,
  `LEFTOVER` flag) instead of an open "executable missing" work item.

## [0.4.3] — 2026-09-22
### Fixed
- Remediation resolves targets against the same full inventory `list` prints
  (BTM layer included); a smaller scan had renumbered the ids, so
  `remove <id>` could hit a different entry. `--user`/`--system` filter rows
  instead of narrowing the scan.
- BTM-only leftovers resolve and are refused with the reason instead of
  "no match"; `enable` may drop a dangling override.
- Unloaded agents with a `print-disabled` override count as disabled, so
  `remove` drops the override as designed.

## [0.4.2] — 2026-09-22
### Fixed
- The sudo password prompt echoed the password in clear text and never
  accepted it: Foundation's `Process` had put the child into its own process
  group (a background job on the terminal). The interactive seam now uses
  `posix_spawn` in the tool's own process group.
- `/Library/LaunchAgents` agents were planned as `system/<label>` via sudo.
  The launchd domain is derived from the job (live evidence, else agent vs.
  daemon); `launchctl` runs as the user, only file operations under
  `/Library` use sudo.
- Password prompts get a 180 s budget; `remove` refusals for a loaded job
  without a file name the working command (`disable`).

## [0.4.1] — 2026-09-22
### Fixed
- Percent-encoded BTM URLs (macOS 26 `file:///…/My%20App.app/`) are decoded
  before any file probe; two installed plug-ins with spaces in their names had
  been reported as orphans. macOS 27 plain paths are handled identically.
- The BTM timeout warning names both causes (cold start after a macOS upgrade
  vs. blocked call).
### Added
- `scripts/release.sh` (universal build, Developer ID signing, notarization,
  upload) and an installation guide. Releases are notarized from here on.

## [0.4.0] — 2026-09-18
### Added
- App correlation: parent application from the deepest `.app` bundle, bundle
  `Info.plist` for id/team/name, Spotlight as an independent second source
  for "bundle gone" (degrades to unknown, never to a guess).
- Guarded `resetbtm`: dry-run default, mandatory pre-reset audit snapshot
  (no snapshot, no reset), post-dump verification; the command states that
  the snapshot is an audit artifact, not a backup.

## [0.3.0] — 2026-09-17
### Added
- `remove`: deletes one orphaned launch plist through a four-lock gate (plist
  shape, allowlisted directory, no symlink escape, orphaned only), on top of a
  mandatory pre-delete snapshot, verified against the file system afterwards.
  Undo hints address entries by label.

## [0.2.0] — 2026-09-16
### Added
- Gated remediation: `disable`/`enable` (launchctl overrides), `backup` and
  `restore` (four launch directories, SHA-256 manifest, integrity check before
  and after write), one gate without bypass, dry-run default,
  verify-after-mutate, interactive sudo seam, audit log.

## [0.1.0] — 2026-09-16
### Added
- Read-only inventory: LaunchAgents/LaunchDaemons, live launchd state,
  Background Task Management (`sfltool dumpbtm`), code signatures — correlated
  many-to-one into `BackgroundItem`s with orphan detection and risk hints.
  `list`, `inspect`, `doctor`, JSON output.
