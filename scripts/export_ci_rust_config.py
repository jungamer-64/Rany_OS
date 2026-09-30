#!/usr/bin/env python3
"""Project repository Rust inputs into GitHub Actions outputs and environment.

RUSTFLAGS overrides Cargo's target configuration. When CI supplies that override,
retain the flags shared by every target so dependency backend requirements still
apply. Target-specific flags remain the responsibility of the selected build.
"""

import os
import tomllib
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    config = tomllib.loads((root / ".cargo/config.toml").read_text(encoding="utf-8"))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        print(f"toolchain={toolchain['toolchain']['channel']}", file=output)

    if "RUSTFLAGS" in os.environ:
        flags = config["target"]["cfg(all())"]["rustflags"]
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as env:
            print("RUSTFLAGS=" + " ".join([os.environ["RUSTFLAGS"], *flags]), file=env)


if __name__ == "__main__":
    main()
