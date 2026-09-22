#!/usr/bin/env bash
# launchkeeper release build — universal binary, Developer ID signed, optionally
# notarized, packaged as a tarball with SHA-256 sums, optionally published
# as a Gitea release.
#
#   scripts/release.sh <version> [--notarize] [--upload] [--notes <file>]
#
#   <version>     e.g. 0.4.1 — must match `launchkeeper --version` (LaunchKeeper.swift)
#   --notarize    zip + `xcrun notarytool submit --wait` (keychain profile
#                 $NOTARY_PROFILE, default "SparkMenu"); a bare Mach-O cannot
#                 be stapled, Gatekeeper checks the ticket online
#   --upload      create tag v<version> (if missing), push it, create the
#                 Gitea release and attach the tarball + SHA256SUMS. Token:
#                 `rbw get PKGTOKEN` (unlock rbw first) or $GITEA_TOKEN
#   --notes FILE  release body (Markdown); default: a short generated note
#
# Rules: refuses a dirty working tree, refuses a version mismatch, and never
# prints the token. Output lands in dist/.
set -euo pipefail

VERSION="${1:-}"; shift || true
[[ -n "$VERSION" ]] || { echo "usage: $0 <version> [--notarize] [--upload] [--notes <file>]" >&2; exit 2; }
NOTARIZE=0; UPLOAD=0; NOTES_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --notarize) NOTARIZE=1 ;;
        --upload)   UPLOAD=1 ;;
        --notes)    NOTES_FILE="${2:?--notes needs a file}"; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

IDENTITY="${CODESIGN_IDENTITY:-Developer ID Application: Jan Tietjen (Y2LTPLFG6D)}"
NOTARY_PROFILE="${NOTARY_PROFILE:-SparkMenu}"
GITEA_HOST="${GITEA_HOST:-git.dev.paranoidsecurity.de}"
REPO_OWNER="${REPO_OWNER:-tj}"
REPO_NAME="${REPO_NAME:-launchkeeper}"
TAG="v$VERSION"
PKG="launchkeeper-$TAG-macos-universal"

# Read the notes NOW: dist/ is wiped below, and a notes file living there
# (as happened for v0.4.2) would vanish before the upload step needs it.
NOTES_TEXT=""
if [[ -n "$NOTES_FILE" ]]; then
    NOTES_TEXT="$(cat "$NOTES_FILE")" || { echo "cannot read notes: $NOTES_FILE" >&2; exit 2; }
fi

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"

echo "==> Preflight"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree is not clean — commit or stash first" >&2; exit 1
fi
grep -q "version: \"$VERSION\"" Sources/launchkeeper/LaunchKeeper.swift \
    || { echo "LaunchKeeper.swift does not declare version \"$VERSION\"" >&2; exit 1; }
grep -q "toolVersion: String = \"$VERSION\"" Sources/LaunchKeeperKit/Remediation/BackupService.swift \
    || { echo "BackupService.swift toolVersion is not \"$VERSION\"" >&2; exit 1; }

echo "==> Tests"
swift test 2>&1 | grep -E "Executed [0-9]+ tests" | tail -1

echo "==> Universal release build (arm64 + x86_64)"
swift build -c release --arch arm64 --arch x86_64 2>&1 | tail -1
BIN_DIR="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"
BIN="$BIN_DIR/launchkeeper"
[[ -x "$BIN" ]] || { echo "binary not found: $BIN" >&2; exit 1; }
lipo -archs "$BIN" | grep -q "x86_64 arm64\|arm64 x86_64" || { echo "not a universal binary" >&2; exit 1; }

rm -rf "$DIST"; mkdir -p "$DIST/$PKG"
cp "$BIN" "$DIST/$PKG/launchkeeper"
cp README.md "$DIST/$PKG/README.md"

echo "==> Codesign ($IDENTITY)"
codesign --force --sign "$IDENTITY" --options runtime --timestamp "$DIST/$PKG/launchkeeper"
codesign --verify --strict --verbose=2 "$DIST/$PKG/launchkeeper"

if [[ $NOTARIZE -eq 1 ]]; then
    echo "==> Notarize (profile $NOTARY_PROFILE)"
    ditto -c -k --keepParent "$DIST/$PKG/launchkeeper" "$DIST/launchkeeper-notarize.zip"
    xcrun notarytool submit "$DIST/launchkeeper-notarize.zip" --keychain-profile "$NOTARY_PROFILE" --wait
    rm -f "$DIST/launchkeeper-notarize.zip"
    NOTARIZED="notarized"
else
    NOTARIZED="NOT notarized (curl download or xattr -d com.apple.quarantine needed on other Macs)"
fi

echo "==> Package"
"$DIST/$PKG/launchkeeper" --version | grep -qx "$VERSION" || { echo "built binary reports a different version" >&2; exit 1; }
tar -C "$DIST" -czf "$DIST/$PKG.tar.gz" "$PKG"
( cd "$DIST" && shasum -a 256 "$PKG.tar.gz" > SHA256SUMS )
rm -rf "$DIST/$PKG"
echo "  $DIST/$PKG.tar.gz"
cat "$DIST/SHA256SUMS"
echo "  signed: $IDENTITY — $NOTARIZED"

if [[ $UPLOAD -eq 0 ]]; then
    echo "==> Done (no upload). Publish with: $0 $VERSION --upload"
    exit 0
fi

echo "==> Tag $TAG"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    echo "  tag exists, reusing"
else
    git tag -a "$TAG" -m "launchkeeper $TAG"
fi
git push origin HEAD          # the release commit itself, not only the tag
git push origin "$TAG"

echo "==> Gitea release"
TOKEN="${GITEA_TOKEN:-$(rbw get PKGTOKEN)}"
API="https://$GITEA_HOST/api/v1/repos/$REPO_OWNER/$REPO_NAME"
if [[ -n "$NOTES_TEXT" ]]; then
    BODY_TEXT="$NOTES_TEXT"
else
    BODY_TEXT="launchkeeper $TAG — test release (universal, Developer ID signed, $NOTARIZED). See README → Installation."
fi
PAYLOAD="$(python3 -c 'import json,sys; print(json.dumps({"tag_name": sys.argv[1], "name": "launchkeeper " + sys.argv[1], "body": sys.argv[2], "prerelease": True}))' "$TAG" "$BODY_TEXT")"
RELEASE_ID="$(curl -fsSL -X POST -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$API/releases" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
for asset in "$PKG.tar.gz" SHA256SUMS; do
    curl -fsSL -X POST -H "Authorization: token $TOKEN" -F "attachment=@$DIST/$asset" \
        "$API/releases/$RELEASE_ID/assets?name=$asset" >/dev/null
    echo "  uploaded $asset"
done
unset TOKEN
echo "==> Published: https://$GITEA_HOST/$REPO_OWNER/$REPO_NAME/releases/tag/$TAG"
