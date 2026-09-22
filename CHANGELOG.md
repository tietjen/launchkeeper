# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning once 1.0 is reached. Releases up to 0.4.5 were published
under the former name **btmctl**.

## [Unreleased]

### Added
- Homebrew tap `tietjen/homebrew-tap` (`brew install tietjen/tap/launchkeeper`).

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
