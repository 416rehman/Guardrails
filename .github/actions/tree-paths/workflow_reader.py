"""The workflow test is WorkflowTest in test_pinned_toolchain.py, with its reader workflow_reader.py and its rules
pin_rules.py. It reads the working-tree copies of the files in WORKFLOWS and ACTION_FILES, and PIN_ACTION_FILE, and
each of its rules is a text match. For a workflow or action in a form GitHub runs, whose working-tree copy is the
committed file byte for byte, it fails when, and claims to fail only when:
1. a job in a file in WORKFLOWS has an actions/checkout step, and the two steps after its first checkout are not
   the pin step and the write step;
2. a file in WORKFLOWS or ACTION_DEFINITIONS holds a layout, a character or a key the reader does not read, or
   PIN_ACTION_FILE, read as text with CR and CRLF taken as line breaks, holds one;
3. a file in WORKFLOWS or ACTION_DEFINITIONS holds a step, job, action or runs key outside the key sets in
   pin_rules.py, or a job's first checkout takes an input outside CHECKOUT_INPUTS;
4. a file it reads holds a form that a fixture of the test expects it to refuse, in the place that fixture holds
   it, outside the declared allowlists.
The fixtures are the list. The test claims nothing about a form no fixture expects it to refuse, even one of the
same kind as a fixture's. It claims nothing about a committed file whose working-tree copy differs from it. It is
a tripwire for drift and mistakes in workflow edits. Every file it reads is under .github/**, which is trust core,
and review of an edit there by the trust-core evaluator set is the control against a hostile edit (design/02
TB-11, D-63).
"""

import dataclasses
import re

BLOCK_SCALAR = "<block scalar>"
PRINTABLE = re.compile(r"[ -~]*")
WORD_KEY = r"[A-Za-z_][A-Za-z0-9_-]*"
KEY_LINE = re.compile(rf"(?P<key>{WORD_KEY}|\"{WORD_KEY}\"|'{WORD_KEY}') *:(?: +(?P<rest>.*))?")
BLOCK_INDICATOR = re.compile(r"[|>][+-]?(?: +#.*)?")
SINGLE_QUOTED = re.compile(r"'((?:[^']|'')*)'(?: +#.*)?")
DOUBLE_QUOTED = re.compile(r'"([^"\\]*)"(?: +#.*)?')
FLOW_OF_WORDS = re.compile(r"\[[A-Za-z0-9_., -]*\]|\{\}")
PLAIN_START = re.compile(r"[^-?:,\[\]{}#&*!|>'\"%@`]|[-?:][^ ]")


@dataclasses.dataclass
class ItemStart:
    number: int
    indent: int


@dataclasses.dataclass
class Line:
    number: int
    indent: int
    text: str


@dataclasses.dataclass
class Value:
    number: int
    data: str | dict | list


class Unreadable(Exception):
    pass


def lines_of(text):
    text_deeper_than = None
    for number, line in enumerate(text.split("\n"), 1):
        if not PRINTABLE.fullmatch(line):
            raise Unreadable(f"line {number}: a character outside printable ASCII")
        content = line.lstrip(" ")
        indent = len(line) - len(content)
        if text_deeper_than is not None and (not content or indent > text_deeper_than):
            continue
        text_deeper_than = None
        if not content or content.startswith("#"):
            continue
        if content.startswith("- "):
            yield ItemStart(number, indent)
            content, indent = content[2:], indent + 2
        key_line = KEY_LINE.fullmatch(content)
        if key_line and key_line["rest"] and BLOCK_INDICATOR.fullmatch(key_line["rest"]):
            text_deeper_than = indent
        yield Line(number, indent, content)


def scalar(text, number):
    if BLOCK_INDICATOR.fullmatch(text):
        return BLOCK_SCALAR
    single = SINGLE_QUOTED.fullmatch(text)
    if single:
        return single[1].replace("''", "'")
    double = DOUBLE_QUOTED.fullmatch(text)
    if double:
        return double[1]
    value = text.split(" #", 1)[0].rstrip()
    if FLOW_OF_WORDS.fullmatch(value):
        return value
    if not PLAIN_START.match(value) or ": " in value or value.endswith(":"):
        raise Unreadable(f"line {number}: a value the reader does not read")
    return value


def parse_block(lines, at, indent):
    number = lines[at].number
    entries, items = {}, []
    while at < len(lines) and lines[at].indent == indent:
        if isinstance(lines[at], ItemStart):
            item, at = parse_item(lines, at + 1, indent + 2, lines[at].number)
            items.append(item)
            continue
        key, value, at = parse_entry(lines, at, indent)
        if key in entries:
            raise Unreadable(f"line {value.number}: {key} repeated in one mapping")
        entries[key] = value
    if entries and items:
        raise Unreadable(f"line {number}: sequence items and keys in one block")
    return Value(number, items or entries), at


def parse_item(lines, at, indent, number):
    first = lines[at]
    if KEY_LINE.fullmatch(first.text) is None:
        return Value(number, scalar(first.text, first.number)), at + 1
    block, at = parse_block(lines, at, indent)
    return Value(number, block.data), at


def parse_entry(lines, at, indent):
    line = lines[at]
    key_line = KEY_LINE.fullmatch(line.text) if isinstance(line, Line) else None
    if key_line is None:
        raise Unreadable(f"line {line.number}: not a key the reader reads")
    key, rest = key_line["key"].strip("'\""), key_line["rest"]
    at += 1
    if rest and not rest.startswith("#"):
        return key, Value(line.number, scalar(rest, line.number)), at
    if at < len(lines) and lines[at].indent > indent:
        block, at = parse_block(lines, at, lines[at].indent)
        return key, Value(line.number, block.data), at
    return key, Value(line.number, ""), at


def parse(text):
    lines = list(lines_of(text))
    if not lines:
        raise Unreadable("an empty file")
    root, at = parse_block(lines, 0, 0)
    if at != len(lines):
        raise Unreadable(f"line {lines[at].number}: indented out of place")
    return root


def as_mapping(value, what):
    if not isinstance(value.data, dict):
        raise Unreadable(f"line {value.number}: {what} is not a mapping")
    return value.data


def as_sequence(value, what):
    if not isinstance(value.data, list):
        raise Unreadable(f"line {value.number}: {what} is not a sequence")
    return value.data


def text_of(value):
    return value.data if value is not None and isinstance(value.data, str) else None


def values_of(value, what):
    return {} if value is None else {key: text_of(child) for key, child in as_mapping(value, what).items()}


def jobs_of(root):
    workflow = as_mapping(root, "the workflow")
    if "jobs" not in workflow:
        raise Unreadable("no jobs at the top level")
    for job_id, job in as_mapping(workflow["jobs"], "jobs").items():
        keys = as_mapping(job, job_id)
        steps = as_sequence(keys["steps"], f"the steps of {job_id}") if "steps" in keys else []
        yield job_id, keys, [as_mapping(step, f"a step of {job_id}") for step in steps]

