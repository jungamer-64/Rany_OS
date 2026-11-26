#!/usr/bin/env python3
"""Export the repository's pinned Rust toolchain to GitHub Actions."""

import os
import tomllib
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        print(f"toolchain={toolchain['toolchain']['channel']}", file=output)


if __name__ == "__main__":
    main()
