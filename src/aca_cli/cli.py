#!/usr/bin/env python3
"""ACA CLI entrypoint and help routing."""

from __future__ import annotations

import argparse
import sys

from . import commands, config, parser
from .core import die


def _print_help_topic(
    parser_obj: argparse.ArgumentParser,
    cmd_parsers: dict[str, argparse.ArgumentParser],
    args,
) -> int:
    topic_tokens = [str(t).strip() for t in (getattr(args, "topic", None) or []) if str(t).strip()]
    topic = " ".join(topic_tokens)
    if topic:
        if topic not in cmd_parsers:
            die(
                f"Unknown help topic: {topic}. Try one of: {', '.join(sorted(cmd_parsers.keys()))}"
            )
        print(cmd_parsers[topic].format_help().rstrip())
        return 0

    print(parser_obj.format_help().rstrip())
    print("\n---\n")
    for name in sorted(k for k in cmd_parsers.keys() if k != "help"):
        print(cmd_parsers[name].format_help().rstrip())
        print("\n---\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser_obj, cmd_parsers = parser.build_parser()
    args = parser_obj.parse_args(argv)

    if args.command == "help":
        return _print_help_topic(parser_obj, cmd_parsers, args)

    cfg = config.Config(args)
    return commands._dispatch_command(cfg, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
