# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning once 1.0 is reached. Releases up to 0.4.5 were published
under the former name **btmctl**.

## [Unreleased] — 0.5.6

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
