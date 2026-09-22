# Fixtures

The `*.txt` files are **anonymized captures** of a real macOS 26.6.2 system
(`sfltool dumpbtm`, `launchctl print gui/501`, `launchctl print system`,
`launchctl print-disabled gui/501`, `pluginkit -mAvv`,
`systemextensionsctl list`, all taken without sudo). They keep every
structural quirk the parsers are tested against and replace everything that
identifies the machine: non-Apple identifiers become deterministic pseudo-words
(consistently across all files, so labels, plist URLs, BTM identifiers and
print-disabled keys still correlate), UUIDs and Team IDs become fake ones, the
user name becomes `alice`. Apple's own entries stay verbatim.

They are generated, not edited: `scripts/anonymize-fixtures.py` reads the real
captures from `real/` (git-ignored, never committed) and rewrites these files.
A few anchors the tests read by name are fixed pseudonyms
(`de.example.automount-guard`, `com.vendorkit.a1b2c3d4e5f6g7h.Updater`,
`com.searchco.updater.agent`, `com.whale.helper`).

To refresh after a new capture: put the raw files into `real/`, run the script,
run `swift test`.
