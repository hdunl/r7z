"""The "What's new" text of a release: what the desktop app shows before it updates.

    python scripts/release_notes.py v0.2.0             print it
    python scripts/release_notes.py v0.2.0 --summary   also write it, and the full
                                                       release notes, to the GitHub
                                                       job summary for review

The text is the "## What's new" section of docs/releases/<tag>.md, up to the next "## "
heading. package_release.py signs exactly this text into r7z-notes.txt, so the app shows
what was reviewed.
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The app reads at most 32 KiB of notes; this leaves room for the header lines.
LIMIT = 24 * 1024


def notes_file(tag: str) -> Path:
    return ROOT / "docs" / "releases" / f"{tag}.md"


def whats_new(tag: str) -> str:
    path = notes_file(tag)
    if not path.is_file():
        sys.exit(f"{path} is missing")
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index("## What's new") + 1
    except ValueError:
        sys.exit(f'{path} has no "## What\'s new" section')
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    text = "\n".join(lines[start:end]).strip("\n")
    if not text.strip():
        sys.exit(f'the "What\'s new" section of {path} is empty')
    if any(re.match(r"\s*<", line) for line in text.splitlines()):
        sys.exit(f'the "What\'s new" section of {path} contains HTML, which the app shows as text')
    if len(text.encode("utf-8")) > LIMIT:
        sys.exit(f'the "What\'s new" section of {path} is over {LIMIT} bytes')
    return text


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    tag = args[0]
    text = whats_new(tag)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if "--summary" in sys.argv and summary:
        full = notes_file(tag).read_text(encoding="utf-8")
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"# Review r7z {tag.removeprefix('v')} before approving\n\n")
            f.write("## In the app: shown before the update installs\n\n")
            f.write(text + "\n\n---\n\n")
            f.write("## On the release page\n\n")
            f.write(full + "\n")


if __name__ == "__main__":
    main()
