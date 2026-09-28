#!/usr/bin/env python3
"""Make README links portable to Docker Hub, pinned to the published commit."""

import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repository", default="mcp-runtime/mcp-auth")
parser.add_argument("--ref", required=True, help="Published Git commit or tag")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()


def absolute_link(match: re.Match[str]) -> str:
    target = match.group(1)
    if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith(("#", "//")):
        return match.group(0)
    if Path(target).suffix.lower() in {".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp"}:
        base = f"https://raw.githubusercontent.com/{args.repository}/{args.ref}"
    else:
        base = f"https://github.com/{args.repository}/blob/{args.ref}"
    return f"]({base}/{target.removeprefix('./')})"


readme = re.sub(r"\]\(([^)\s]+)\)", absolute_link, Path("README.md").read_text())
if "```mermaid" in readme:
    raise SystemExit("Docker Hub requires rendered diagram images, not Mermaid fences")
if len(readme.encode()) > 25_000:
    raise SystemExit("README exceeds Docker Hub's 25,000-byte limit")
args.output.write_text(readme)
