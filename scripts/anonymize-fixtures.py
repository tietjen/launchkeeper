#!/usr/bin/env python3
"""Regenerate the public test fixtures from real captures.

    scripts/anonymize-fixtures.py            # real/ -> public, prints a summary
    scripts/anonymize-fixtures.py --report   # also prints the token mapping (NEVER commit it)

Real captures live in Tests/Fixtures/real/ (git-ignored) and must never be
committed: they carry the host's user name, Team IDs and the full application
inventory. The public fixtures keep every structural quirk the parsers are
tested against (field layout, tab/space mixes, instance-service names,
"Assoc. Bundle IDs" lines, percent-encoded URLs) and replace everything that
identifies the machine:

- every non-Apple identifier token becomes a deterministic pseudo-word,
  consistently across ALL files, so labels, plist URLs, BTM identifiers and
  print-disabled keys still correlate;
- UUIDs become sequential fake UUIDs, 10-character Team IDs fake Team IDs,
  the user name becomes `alice`;
- Apple's own entries (com.apple.*) and structural vocabulary stay as they
  are — they describe macOS, not the owner;
- a few anchors the tests read by name get fixed, readable pseudonyms.

The mapping is a pure function of the input (seeded PRNG), so regenerating
from the same captures yields byte-identical fixtures.
"""
import pathlib, re, random, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "Tests" / "Fixtures"
REAL = ROOT / "real"
FILES = ["dumpbtm-nosudo.txt", "launchctl-gui.txt", "launchctl-system.txt", "disabled-gui.txt"]

# Anchors the tests reference by name (readable on purpose).
FIXED = {
    "example-domain": "example",
    "alice": "alice",
    "vendorkit": "vendorkit", "241012ess7yxs0e": "a1b2c3d4e5f6g7h", "ShipIt": "Updater",
    "vendor-a": "searchco", "vendor-b": "updater",
    "vendor-c": "whale",
}

# Structural vocabulary: format keys, dispositions, types, OS path words,
# file extensions, launchctl words, company suffixes. Never pseudonymized.
KEEP = set("""
Records for UID Items UUID Name Developer Type Flags Disposition Identifier URL Executable Path
Generation Parent Embedded Item Identifiers Assoc Bundle IDs Team ServiceManagement migrated
LaunchServices registered true false null
enabled disabled allowed notified not legacy daemon agent app developer login item quicklook
spotlight dock tile curated xpc service services domain state pid gui system unmanaged launchd
application com org net io de ch uk eu us co
file Library LaunchAgents LaunchDaemons Applications Contents MacOS PlugIns Helpers Frameworks
Resources Support Application Users usr local bin sbin opt homebrew private var tmp etc System
Versions Current Extensions XPCServices Spotlight QuickLook Internet Plug-Ins Utilities
plist appex mdimporter docktileplugin plugin framework bundle dylib sh py rb js
helper Helper Updater updater Agent Daemon Service Systems Inc LLC GmbH AG Ltd Corporation
automount-guard mxcl Unknown
""".split())

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
UUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
FAKE_UUID = re.compile(r"^[0-9A-F]{8}-0000-4000-8000-[0-9A-F]{12}$")
TEAM = re.compile(r"\b(?=[A-Z0-9]{10}\b)(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{10}\b")
FAKE_TEAM = re.compile(r"^TEAM\d{6}$")
HEXFLAG = re.compile(r"^0x[0-9A-Fa-f]+$")
# Regions that may identify the machine. Everything outside them is format.
LABEL = re.compile(r"(?<![\w./-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+(?![\w-])")   # reverse-DNS labels
PATH = re.compile(r"(?<![\w%])/(?:[^\s/]+/)*[^\s/]*")                                 # /a/b/c and file:///…
QUOTED = re.compile(r'"[^"]*"')
FIELD = re.compile(r"^(\s*)([A-Za-z][A-Za-z. ]*?):\s*(.*)$")
VALUE_FIELDS = {"Name", "Developer Name", "Identifier", "Parent Identifier", "Assoc. Bundle IDs",
                "URL", "Executable Path", "Bundle Identifier"}
CHILD = re.compile(r"^(\s*#\d+:\s+)(\S.*)$")

rng = random.Random(20260922)
SYL = ["ba","do","fi","ka","lo","me","nu","pa","ri","so","tu","va","we","zo","gan","tel","mir","sol","vex","lum","qua","dri","pon","kas"]
def pseudo(word):
    n = 2 if len(word) <= 6 else 3
    p = "".join(rng.choice(SYL) for _ in range(n))
    return p.capitalize() if word[0].isupper() else p

def main(report=False):
    texts = {f: (REAL / f).read_text() for f in FILES}
    tokens, uuids, teams = {}, {}, {}

    def map_token(m):
        w = m.group(0)
        if (w in KEEP or len(w) <= 2 or w.isdigit() or HEXFLAG.match(w)
                or FAKE_UUID.match(w) or FAKE_TEAM.match(w)):
            return w
        if w in FIXED:
            return FIXED[w]
        if w not in tokens:
            tokens[w] = pseudo(w)
        return tokens[w]

    def map_uuid(m):
        u = m.group(0).upper()
        if u not in uuids:
            i = len(uuids) + 1
            uuids[u] = f"{i:08X}-0000-4000-8000-{i:012X}"
        return uuids[u]

    def map_team(m):
        t = m.group(0)
        if t not in teams:
            teams[t] = f"TEAM{len(teams) + 1:06d}"
        return teams[t]

    def region(text):
        """Pseudonymize one identifying region; Apple's own stays verbatim."""
        if "apple" in text.lower():
            return UUID.sub(map_uuid, text)
        text = UUID.sub(map_uuid, text)
        text = TEAM.sub(map_team, text)
        return TOKEN.sub(map_token, text)

    def btm_line(line):
        m = FIELD.match(line)
        if m and m.group(2) in VALUE_FIELDS:
            return m.group(1) + m.group(2) + ": " + region(m.group(3))
        c = CHILD.match(line)
        if c:
            return c.group(1) + region(c.group(2))
        return UUID.sub(map_uuid, TEAM.sub(map_team, line) if "Team Identifier" in line else line)

    # launchctl output mixes labels without dots ("tool"), labels with
    # spaces ("Some Vendor Agent"), endpoint names glued to paths and app
    # names behind com.apple.xpc.launchd.unmanaged.<App>.<pid>. Region
    # matching misses those, so launchctl files get GLOBAL token mapping with
    # two vocabularies that stay verbatim: Apple's own label/path words and
    # the format's structural words (lines without labels, paths or quotes,
    # outside the services/endpoints listings).
    SERVICE_LINE = re.compile(r"^\s*[\d-]+\s+\S+\s+\S")
    ENDPOINT_LINE = re.compile(r"^\s*0x[0-9a-f]+\s+\S+\s+\S+\s+\S")
    APPLE_LABEL = re.compile(r"(?:application\.)?com\.apple\.[A-Za-z0-9_.-]*")
    APPLE_PATH = re.compile(r"/(?:System|usr|bin|sbin|Library/Apple)/[^\s]*")
    apple_vocab, struct_vocab = set(), set()
    for f in ("launchctl-gui.txt", "launchctl-system.txt"):
        for line in texts[f].split("\n"):
            for lab in APPLE_LABEL.findall(line):
                lab = lab.split(".unmanaged.")[0]          # the app behind unmanaged. is inventory
                apple_vocab.update(TOKEN.findall(lab))
            for path in APPLE_PATH.findall(line):
                apple_vocab.update(TOKEN.findall(path))
            if SERVICE_LINE.match(line) or ENDPOINT_LINE.match(line):
                continue
            if not any(c in line for c in "./\""):
                struct_vocab.update(TOKEN.findall(line))

    def map_launchctl_token(m):
        w = m.group(0)
        if w in apple_vocab or w in struct_vocab:
            return w
        return map_token(m)

    def launchctl_line(line):
        line = UUID.sub(map_uuid, line)
        return TOKEN.sub(map_launchctl_token, line)

    def disabled_line(line):
        return QUOTED.sub(lambda m: region(m.group(0)), line)

    handlers = {"dumpbtm-nosudo.txt": btm_line, "launchctl-gui.txt": launchctl_line,
                "launchctl-system.txt": launchctl_line, "disabled-gui.txt": disabled_line}
    for f, t in texts.items():
        h = handlers[f]
        (ROOT / f).write_text("\n".join(h(line) for line in t.split("\n")))
    print(f"regenerated {len(FILES)} fixtures: {len(tokens)} tokens, {len(uuids)} UUIDs, {len(teams)} Team IDs pseudonymized")
    if report:
        for k, v in sorted(tokens.items()): print(f"  {k} -> {v}")
        for k, v in teams.items(): print(f"  {k} -> {v}")
        print("structural vocabulary kept verbatim:", " ".join(sorted(struct_vocab)))

if __name__ == "__main__":
    main(report="--report" in sys.argv)
