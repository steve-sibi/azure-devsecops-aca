from __future__ import annotations

import sys

from . import cli


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "az":
        return cli.main(["--context", "az", *argv[1:]])
    if argv and argv[0] == "env":
        return cli.main(["--context", "az", *argv])
    return cli.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

