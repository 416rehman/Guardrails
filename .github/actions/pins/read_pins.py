"""Print the named pins of one tool in a build-tools file as key=value lines for GITHUB_OUTPUT.

Usage: python3 -I read_pins.py <build-tools.toml> <tool> "<key> [<key> ...]"

Nothing is printed unless every string value of the tool is one line and every named key holds a
value of its form. A refusal exits 1 with a GRDR-SUPPLY code on stderr, naming the tool and key
but never the value.
"""

import re
import sys
import tomllib

FORMS = {
    "version": re.compile(r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?"),
    "image": re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}"),
    "config": re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"),
    "repository": re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9._-]*"),
    "commit": re.compile(r"[0-9a-f]{40}"),
    "severities": re.compile(r"(?:INFO|WARNING|ERROR)(?: (?:INFO|WARNING|ERROR))*"),
}


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code} {message}")


def read_tool(path, tool):
    try:
        with open(path, "rb") as pins:
            tools = tomllib.load(pins).get("tool")
    except (OSError, ValueError, RecursionError) as error:
        raise Refusal("GRDR-SUPPLY-0004", f"cannot read {path}: {type(error).__name__}") from None
    table = tools.get(tool) if isinstance(tools, dict) else None
    if not isinstance(table, dict):
        raise Refusal("GRDR-SUPPLY-0003", f"{path} has no [tool.{tool}] table")
    return table


def check_one_line(tool, table):
    for key, value in table.items():
        if isinstance(value, str) and value.splitlines() != [value]:
            raise Refusal("GRDR-SUPPLY-0001", f"[tool.{tool}] {key!a} is not one line of text")


def pin_lines(tool, table, keys):
    lines = []
    for key in keys:
        form = FORMS.get(key)
        value = table.get(key)
        if form is None or not isinstance(value, str):
            raise Refusal("GRDR-SUPPLY-0003", f"[tool.{tool}] has no readable pin {key!a}")
        if not form.fullmatch(value):
            raise Refusal("GRDR-SUPPLY-0002", f"[tool.{tool}] {key} is not of the {key} form")
        lines.append(f"{key}={value}")
    return lines


def main(argv):
    if len(argv) != 4 or not argv[3].split():
        raise Refusal("GRDR-SUPPLY-0003", "usage: read_pins.py <build-tools.toml> <tool> <keys>")
    _, path, tool, keys = argv
    table = read_tool(path, tool)
    check_one_line(tool, table)
    print("\n".join(pin_lines(tool, table, keys.split())))


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Refusal as refusal:
        print(f"::error::{refusal}", file=sys.stderr)
        sys.exit(1)
