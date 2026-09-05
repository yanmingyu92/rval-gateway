"""miniyaml.py — tiny YAML-subset parser (stdlib has no YAML support).

The gateway's decision-rule config (`config/decision_rules.yml`) needs YAML,
but the hard environment constraint is Python stdlib only — no PyYAML. This
module implements exactly the subset the config files use, and nothing more.

Supported subset
----------------
- Nested mappings by 2-or-more-space indentation: ``key: value`` or ``key:``
  followed by an indented block. Keys are bare identifiers or quoted strings.
- Sequences: items start with ``- `` at some indent level; an item may be a
  scalar, a mapping (``- key: value`` with continuation lines), or a nested
  block on following lines.
- Scalars: integers, floats, booleans (``true``/``false``, case-insensitive),
  ``null``/``~``, single- and double-quoted strings (with ``\\`` and ``\"``
  escapes in double quotes), and plain (unquoted) strings. Plain scalars are
  trimmed; inline trailing comments (``  # ...``) are stripped *only* when the
  ``#`` is preceded by whitespace.
- Comments: full-line ``# ...`` and blank lines are ignored.

Not supported (will raise ``MiniYamlError``): anchors/aliases, flow
collections (``[a, b]`` / ``{a: 1}``), block scalars (``|``, ``>``), tags,
multi-document streams, tabs in indentation.

API: ``load(text) -> python object`` (dict/list/scalars), ``load_file(path)``.
"""

from __future__ import annotations


class MiniYamlError(ValueError):
    """Raised when input is outside the supported YAML subset."""


def _strip_inline_comment(text: str) -> str:
    """Strip a trailing `` # comment`` from a plain-scalar line.

    Only strips when '#' is preceded by whitespace, and never inside quotes.
    """
    in_s = in_d = False
    prev = ""
    out = []
    for ch in text:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s and prev != "\\":
            in_d = not in_d
        if ch == "#" and not in_s and not in_d and prev in (" ", "\t"):
            break
        out.append(ch)
        prev = ch
    return "".join(out).rstrip()


def _parse_scalar(token: str):
    token = token.strip()
    if token == "":
        return ""
    if token[0] in "[{":
        raise MiniYamlError(f"flow collections not supported: {token!r}")
    if token[0] in "|>":
        raise MiniYamlError(f"block scalars not supported: {token!r}")
    if token[0] in "&*":
        raise MiniYamlError(f"anchors/aliases not supported: {token!r}")
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        body = token[1:-1]
        out = []
        i = 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'")
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


class _Line:
    __slots__ = ("indent", "content", "lineno")

    def __init__(self, indent: int, content: str, lineno: int):
        self.indent = indent
        self.content = content
        self.lineno = lineno


def _tokenize(text: str) -> list[_Line]:
    lines = []
    for i, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise MiniYamlError(f"line {i}: tabs in indentation not supported")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append(_Line(indent, stripped, i))
    return lines


_KEY_SPLIT_RE_MSG = "line {lineno}: expected 'key: value' mapping entry, got {content!r}"


def _split_key(content: str, lineno: int) -> tuple[str, str]:
    """Split 'key: value' respecting quoted keys. Returns (key, rest)."""
    if content.startswith(('"', "'")):
        q = content[0]
        end = content.find(q, 1)
        if end == -1 or not content[end + 1 :].startswith(":"):
            raise MiniYamlError(_KEY_SPLIT_RE_MSG.format(lineno=lineno, content=content))
        key = _parse_scalar(content[: end + 1])
        rest = content[end + 2 :]
    else:
        idx = content.find(":")
        if idx == -1 or (idx + 1 < len(content) and content[idx + 1] not in (" ", "")):
            raise MiniYamlError(_KEY_SPLIT_RE_MSG.format(lineno=lineno, content=content))
        key = content[:idx].strip()
        if not key:
            raise MiniYamlError(f"line {lineno}: empty mapping key")
        rest = content[idx + 1 :]
    return str(key), rest.strip()


def load(text: str):
    """Parse YAML-subset text into Python dicts/lists/scalars."""
    lines = _tokenize(text)
    if not lines:
        return None
    value, pos = _parse_block(lines, 0, lines[0].indent)
    if pos != len(lines):
        ln = lines[pos]
        raise MiniYamlError(f"line {ln.lineno}: unexpected dedent: {ln.content!r}")
    return value


def load_file(path) -> object:
    with open(path, encoding="utf-8") as fh:
        return load(fh.read())


def _parse_block(lines: list[_Line], pos: int, indent: int):
    """Parse a block at the given indent. Returns (value, next_pos)."""
    if pos >= len(lines):
        return None, pos
    first = lines[pos]
    if first.indent < indent:
        return None, pos
    if first.content.startswith("- ") or first.content == "-":
        return _parse_seq(lines, pos, first.indent)
    return _parse_map(lines, pos, first.indent)


def _parse_map(lines: list[_Line], pos: int, indent: int):
    out = {}
    while pos < len(lines):
        ln = lines[pos]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            raise MiniYamlError(f"line {ln.lineno}: unexpected indent: {ln.content!r}")
        if ln.content.startswith("- ") or ln.content == "-":
            break  # sequence belongs to the parent key, handled by caller
        key, rest = _split_key(ln.content, ln.lineno)
        if key in out:
            raise MiniYamlError(f"line {ln.lineno}: duplicate key {key!r}")
        pos += 1
        if rest:
            out[key] = _parse_scalar(_strip_inline_comment(rest))
        else:
            if pos < len(lines) and lines[pos].indent > indent:
                out[key], pos = _parse_block(lines, pos, lines[pos].indent)
            elif pos < len(lines) and lines[pos].indent == indent and (
                lines[pos].content.startswith("- ") or lines[pos].content == "-"
            ):
                # sequence at same indent as the key (common YAML style)
                out[key], pos = _parse_seq(lines, pos, indent)
            else:
                out[key] = None
    return out, pos


def _parse_seq(lines: list[_Line], pos: int, indent: int):
    out = []
    while pos < len(lines):
        ln = lines[pos]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            raise MiniYamlError(f"line {ln.lineno}: unexpected indent in sequence")
        if not (ln.content.startswith("- ") or ln.content == "-"):
            break
        item_text = ln.content[1:].strip() if ln.content != "-" else ""
        pos += 1
        if not item_text:
            # nested block on following lines
            if pos < len(lines) and lines[pos].indent > indent:
                item, pos = _parse_block(lines, pos, lines[pos].indent)
                out.append(item)
            else:
                out.append(None)
            continue
        if ":" in item_text and not item_text.startswith(('"', "'")):
            # inline mapping start: "- key: value" with possible continuation
            key, rest = _split_key(item_text, ln.lineno)
            item = {}
            if rest:
                item[key] = _parse_scalar(_strip_inline_comment(rest))
            elif pos < len(lines) and lines[pos].indent > indent:
                item[key], pos = _parse_block(lines, pos, lines[pos].indent)
            else:
                item[key] = None
            # continuation mapping lines deeper than the dash indent
            while pos < len(lines) and lines[pos].indent > indent and not (
                lines[pos].content.startswith("- ")
            ):
                sub = lines[pos]
                k2, r2 = _split_key(sub.content, sub.lineno)
                pos += 1
                if r2:
                    item[k2] = _parse_scalar(_strip_inline_comment(r2))
                elif pos < len(lines) and lines[pos].indent > sub.indent:
                    item[k2], pos = _parse_block(lines, pos, lines[pos].indent)
                else:
                    item[k2] = None
            out.append(item)
        else:
            out.append(_parse_scalar(_strip_inline_comment(item_text)))
    return out, pos
