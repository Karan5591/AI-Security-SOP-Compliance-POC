"""Build JSON for /review/batch from changed repository files."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

EXTENSIONS = {
    ".py": "python", ".js": "nodejs", ".jsx": "nodejs", ".ts": "typescript",
    ".tsx": "typescript", ".conf": "nginx", ".nginx": "nginx",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml",
}
MAX_FILE_BYTES = 512_000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", default="")
    parser.add_argument("--actor", default="")
    args = parser.parse_args()
    names = subprocess.check_output(["git", "diff", "--name-only", "--diff-filter=ACMR", args.base, args.head], text=True).splitlines()

    files = []
    for name in (n.strip() for n in names if n.strip()):
        path = Path(name)
        technology = EXTENSIONS.get(path.suffix.lower())
        if technology is None or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            raise SystemExit(f"Changed file is too large for security review: {name}")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        files.append({"filename": name, "content": content, "technology": technology})

    print(json.dumps({"files": files, "repository": args.repository, "commit_sha": args.head, "actor": args.actor}))


if __name__ == "__main__":
    main()
