"""Build JSON for /review/batch from a target repository's tracked files.

Reviews every tracked, supported file at the target repo's current HEAD
(a full scan), rather than diffing against a previous commit. This is
what lets the pipeline point at ANY cloned repo (via --repo-dir) and
review it, independent of whatever repo Jenkins itself auto-checked-out
for the job.
"""
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
    parser.add_argument("--repo-dir", required=True, help="Path to the target repo checkout (e.g. target-repo)")
    parser.add_argument("--repository", default="")
    parser.add_argument("--actor", default="")
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir)
    head = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True
    ).strip()
    names = subprocess.check_output(
        ["git", "-C", str(repo_dir), "ls-files"], text=True
    ).splitlines()

    files = []
    for name in (n.strip() for n in names if n.strip()):
        path = repo_dir / name
        technology = EXTENSIONS.get(path.suffix.lower())
        if technology is None or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            # Skip oversized files rather than aborting the whole scan --
            # a full-repo scan can legitimately contain large generated
            # or vendored files that aren't worth reviewing anyway.
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        files.append({"filename": name, "content": content, "technology": technology})

    print(json.dumps({
        "files": files,
        "repository": args.repository,
        "commit_sha": head,
        "actor": args.actor,
    }))


if __name__ == "__main__":
    main()