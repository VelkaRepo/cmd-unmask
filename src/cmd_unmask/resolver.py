"""Case-aware bottom-up static Expression Resolver for PowerShell and Bash obfuscation."""

from __future__ import annotations

import base64
import re
from collections import Counter
from dataclasses import dataclass, field

MAX_RESOLVER_PASSES: int = 20

_QUOTED_STR_PAT = r"(?:'(?:''|[^'])*'|\"(?:`\"|\"\"|[^\"])*\")"

# [char]105 or [char]0x69 or [char](105)
_CHAR_CAST_RE = re.compile(
    r"\[\s*char\s*\]\s*\(?\s*(0x[0-9a-fA-F]+|\d+)\s*\)?",
    re.IGNORECASE,
)

# [char[]](105, 101, 120) -join ''
_CHAR_ARRAY_JOIN_RE = re.compile(
    rf"\(?\s*\[\s*char\s*\[\s*\]\s*\]\s*\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,?\s*)+)\)\s*\)?\s*-join\s*({_QUOTED_STR_PAT})?",
    re.IGNORECASE,
)

# (105,101,120) | % { [char]$_ } or ForEach-Object
_PIPE_CHAR_FOREACH_RE = re.compile(
    r"\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,?\s*)+)\)\s*\|\s*(?:%|ForEach-Object|foreach)\s*\{\s*\[\s*char\s*\]\s*\$_\s*\}",
    re.IGNORECASE,
)

# [string]::Join('sep', ('a', 'b', 'c')) or [string]::Join('sep', [char[]](105, 101, 120))
_STRING_JOIN_STATIC_RE = re.compile(
    rf"\[\s*(?:system\.)?string\s*\]::join\s*\(\s*({_QUOTED_STR_PAT})\s*,\s*\(?\s*((?:{_QUOTED_STR_PAT}\s*,?\s*)+)\)?\s*\)",
    re.IGNORECASE,
)

# ('a', 'b', 'c') -join 'sep'
_ARRAY_OP_JOIN_RE = re.compile(
    rf"\(\s*({_QUOTED_STR_PAT}(?:\s*,\s*{_QUOTED_STR_PAT})+)\s*\)\s*-join\s*({_QUOTED_STR_PAT})?",
    re.IGNORECASE,
)

# Adjacent string concatenation: 'a' + "b"
_STR_CONCAT_RE = re.compile(
    rf"({_QUOTED_STR_PAT})\s*\+\s*({_QUOTED_STR_PAT})"
)

# Format operator: "{1}{0}" -f 'a', 'b'
_FORMAT_OP_RE = re.compile(
    rf"({_QUOTED_STR_PAT})\s*-f\s+({_QUOTED_STR_PAT}(?:\s*,\s*{_QUOTED_STR_PAT})*)",
    re.IGNORECASE,
)

# .Replace('old', 'new') - CASE-SENSITIVE in .NET
_DOT_REPLACE_RE = re.compile(
    rf"({_QUOTED_STR_PAT})\s*\.\s*replace\s*\(\s*({_QUOTED_STR_PAT})\s*,\s*({_QUOTED_STR_PAT})\s*\)",
    re.IGNORECASE,
)

# -replace 'old', 'new' or -replace 'old' - CASE-INSENSITIVE in PowerShell
_OP_REPLACE_RE = re.compile(
    rf"({_QUOTED_STR_PAT})\s*-replace\s+({_QUOTED_STR_PAT})(?:\s*,\s*({_QUOTED_STR_PAT}))?",
    re.IGNORECASE,
)

# [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...'))
_DOTNET_B64_GETSTRING_RE = re.compile(
    rf"\[\s*(?:system\.)?text\.encoding\s*\]::\s*(utf8|unicode|ascii|default)\s*\.\s*getstring\s*\(\s*\[\s*(?:system\.)?convert\s*\]::\s*frombase64string\s*\(\s*({_QUOTED_STR_PAT})\s*\)\s*\)",
    re.IGNORECASE,
)

# Redundant parens around a single quoted literal: ('powershell') -> 'powershell'
_PAREN_QUOTED_RE = re.compile(rf"\(\s*({_QUOTED_STR_PAT})\s*\)")

# Redundant parens around a bare flag/token: (-c) -> -c
_PAREN_FLAG_RE = re.compile(r"\(\s*(-[A-Za-z][A-Za-z0-9_-]*)\s*\)")

# PowerShell variable assignment: $var = 'literal'
_PS_VAR_ASSIGN_RE = re.compile(
    rf"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*({_QUOTED_STR_PAT})"
)

# PowerShell [array]::Reverse($var)
_PS_ARRAY_REVERSE_RE = re.compile(
    r"\[\s*(?:system\.)?array\s*\]::\s*reverse\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.IGNORECASE,
)

# Bash ANSI-C quoting: $'\x63\x75\x72\x6c' or $'\150\164'
_BASH_ANSI_C_RE = re.compile(r"\$'((?:\\.|[^'])*)'")

# Bash variable assignment: var='literal' or var="literal"
_BASH_VAR_ASSIGN_RE = re.compile(
    rf"(?:^|[;&\s])([A-Za-z_][A-Za-z0-9_]*)=({_QUOTED_STR_PAT})"
)

# Bash parameter expansion: ${var//old/new} or ${var/old/new} or ${var}
_BASH_PARAM_SUB_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(//?)([^}/]*)/([^}]*))?\}"
)

# Bash echo <literal> | base64 -d
_BASH_ECHO_B64_RE = re.compile(
    rf"echo\s+(?:-n\s+|-e\s+)*({_QUOTED_STR_PAT}|[A-Za-z0-9+/=_-]{{8,}})\s*\|\s*base64\s+(?:-d|--decode)",
    re.IGNORECASE,
)

# Bash echo <literal> | rev
_BASH_ECHO_REV_RE = re.compile(
    rf"echo\s+(?:-n\s+|-e\s+)*({_QUOTED_STR_PAT})\s*\|\s*rev\b",
    re.IGNORECASE,
)

# Bash echo <literal> | tr 'a' 'b'
_BASH_ECHO_TR_RE = re.compile(
    rf"echo\s+(?:-n\s+|-e\s+)*({_QUOTED_STR_PAT})\s*\|\s*tr\s+({_QUOTED_STR_PAT}|\S+)\s+({_QUOTED_STR_PAT}|\S+)",
    re.IGNORECASE,
)


@dataclass
class ExpressionResolutionResult:
    """Result of running the static fixed-point Expression Resolver."""

    original_text: str
    resolved_text: str
    modified: bool
    passes_run: int = 0
    applied_reducers: list[str] = field(default_factory=list)


def _unquote(token: str) -> str:
    """Strip outer quotes from a PowerShell or Bash string literal and unescape doubled quotes."""
    s = token.strip()
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('`"', '"').replace('""', '"')
    return s


def _quote_single(val: str) -> str:
    """Wrap a resolved literal in single quotes with PowerShell '' escaping."""
    escaped = val.replace("'", "''")
    return f"'{escaped}'"


def _parse_int(token: str) -> int | None:
    t = token.strip()
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except ValueError:
        return None


def _decode_ansi_c_escapes(inner: str) -> str:
    r"""Decode Bash $'...' hex (\xNN), octal (\NNN), and standard escapes."""
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        if inner[i] == "\\" and i + 1 < n:
            nxt = inner[i + 1]
            if nxt == "x" and i + 3 < n:
                hex_part = inner[i + 2 : i + 4]
                try:
                    out.append(chr(int(hex_part, 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt in "01234567":
                oct_digits = []
                j = i + 1
                while j < n and j < i + 4 and inner[j] in "01234567":
                    oct_digits.append(inner[j])
                    j += 1
                try:
                    out.append(chr(int("".join(oct_digits), 8)))
                    i = j
                    continue
                except ValueError:
                    pass
            escape_map = {
                "n": "\n",
                "r": "\r",
                "t": "\t",
                "'": "'",
                '"': '"',
                "\\": "\\",
            }
            if nxt in escape_map:
                out.append(escape_map[nxt])
                i += 2
                continue
        out.append(inner[i])
        i += 1
    return "".join(out)


def _fold_pass(text: str) -> tuple[str, set[str]]:
    """Execute a single bottom-up static reduction pass."""
    reducers: set[str] = set()
    curr = text

    # 1. Bash ANSI-C quoting: $'\x63\x75\x72\x6c' -> 'curl'
    def _repl_ansi_c(m: re.Match[str]) -> str:
        reducers.add("bash_ansi_c")
        return _quote_single(_decode_ansi_c_escapes(m.group(1)))

    curr = _BASH_ANSI_C_RE.sub(_repl_ansi_c, curr)

    # 2. [char] casts: [char]105 -> 'i'
    def _repl_char_cast(m: re.Match[str]) -> str:
        code = _parse_int(m.group(1))
        if code is not None and 0 <= code <= 0x10FFFF:
            reducers.add("char_cast")
            return _quote_single(chr(code))
        return m.group(0)

    curr = _CHAR_CAST_RE.sub(_repl_char_cast, curr)

    # 3. [char[]](105, 101, 120) -join ''
    def _repl_char_array_join(m: re.Match[str]) -> str:
        nums_raw = [tok for tok in re.split(r"[,\s]+", m.group(1).strip()) if tok]
        chars: list[str] = []
        for tok in nums_raw:
            val = _parse_int(tok)
            if val is None or not (0 <= val <= 0x10FFFF):
                return m.group(0)
            chars.append(chr(val))
        sep = _unquote(m.group(2)) if m.group(2) else ""
        reducers.add("char_array_join")
        return _quote_single(sep.join(chars))

    curr = _CHAR_ARRAY_JOIN_RE.sub(_repl_char_array_join, curr)
    curr = _PIPE_CHAR_FOREACH_RE.sub(
        lambda m: _repl_char_array_join(m) if False else m.group(0), curr
    )

    # 4. [string]::Join('sep', ('a', 'b', 'c'))
    def _repl_string_join_static(m: re.Match[str]) -> str:
        sep = _unquote(m.group(1))
        items = [_unquote(q.group(0)) for q in re.finditer(_QUOTED_STR_PAT, m.group(2))]
        if items:
            reducers.add("string_join")
            return _quote_single(sep.join(items))
        return m.group(0)

    curr = _STRING_JOIN_STATIC_RE.sub(_repl_string_join_static, curr)

    # 5. ('a', 'b', 'c') -join 'sep'
    def _repl_array_op_join(m: re.Match[str]) -> str:
        items = [_unquote(q.group(0)) for q in re.finditer(_QUOTED_STR_PAT, m.group(1))]
        sep = _unquote(m.group(2)) if m.group(2) else ""
        if items:
            reducers.add("array_join")
            return _quote_single(sep.join(items))
        return m.group(0)

    curr = _ARRAY_OP_JOIN_RE.sub(_repl_array_op_join, curr)

    # 6. PowerShell format operator: "{1}{0}" -f 'a', 'b'
    def _repl_format_op(m: re.Match[str]) -> str:
        fmt_str = _unquote(m.group(1))
        args = [_unquote(q.group(0)) for q in re.finditer(_QUOTED_STR_PAT, m.group(2))]
        try:
            formatted = fmt_str.format(*args)
            reducers.add("format_operator")
            return _quote_single(formatted)
        except Exception:
            return m.group(0)

    curr = _FORMAT_OP_RE.sub(_repl_format_op, curr)

    # 7. .Replace('old', 'new') - CASE-SENSITIVE (.NET String.Replace)
    def _repl_dot_replace(m: re.Match[str]) -> str:
        target = _unquote(m.group(1))
        old_val = _unquote(m.group(2))
        new_val = _unquote(m.group(3))
        reducers.add("dot_replace")
        return _quote_single(target.replace(old_val, new_val))

    curr = _DOT_REPLACE_RE.sub(_repl_dot_replace, curr)

    # 8. -replace 'old', 'new' - CASE-INSENSITIVE (PowerShell -replace operator)
    def _repl_op_replace(m: re.Match[str]) -> str:
        target = _unquote(m.group(1))
        old_pat = _unquote(m.group(2))
        new_val = _unquote(m.group(3)) if m.group(3) is not None else ""
        try:
            replaced = re.sub(old_pat, new_val, target, flags=re.IGNORECASE)
        except re.error:
            replaced = re.sub(re.escape(old_pat), new_val, target, flags=re.IGNORECASE)
        reducers.add("operator_replace")
        return _quote_single(replaced)

    curr = _OP_REPLACE_RE.sub(_repl_op_replace, curr)

    # 9. .NET [Text.Encoding]::UTF8/Unicode/ASCII.GetString([Convert]::FromBase64String('...'))
    def _repl_dotnet_b64(m: re.Match[str]) -> str:
        enc_name = m.group(1).lower()
        b64_str = _unquote(m.group(2)).strip()
        try:
            missing_pad = len(b64_str) % 4
            if missing_pad:
                b64_str += "=" * (4 - missing_pad)
            raw_bytes = base64.b64decode(b64_str)
            py_enc = "utf-16le" if enc_name == "unicode" else ("ascii" if enc_name == "ascii" else "utf-8")
            decoded = raw_bytes.decode(py_enc, errors="replace")
            reducers.add("dotnet_frombase64_getstring")
            return _quote_single(decoded)
        except Exception:
            return m.group(0)

    curr = _DOTNET_B64_GETSTRING_RE.sub(_repl_dotnet_b64, curr)

    # 10. Adjacent string literal concatenation: 'a' + "b" -> 'ab'
    def _repl_concat(m: re.Match[str]) -> str:
        reducers.add("string_concat")
        return _quote_single(_unquote(m.group(1)) + _unquote(m.group(2)))

    curr = _STR_CONCAT_RE.sub(_repl_concat, curr)

    # 11. Unwrap redundant parens around a single quoted literal or flag
    def _repl_paren_quoted(m: re.Match[str]) -> str:
        reducers.add("paren_unwrap")
        return m.group(1)

    # Avoid unwrapping parens when immediately preceded by a method call name like FromBase64String('...')
    curr = re.sub(
        rf"(?<![A-Za-z0-9_:\]])\(\s*({_QUOTED_STR_PAT})\s*\)(?!\s*\.)",
        _repl_paren_quoted,
        curr,
    )
    curr = _PAREN_FLAG_RE.sub(lambda m: m.group(1), curr)

    # 12. PowerShell single-assignment constant propagation and [array]::Reverse($x)
    var_counts: Counter[str] = Counter()
    var_values: dict[str, str] = {}
    for m in _PS_VAR_ASSIGN_RE.finditer(curr):
        vname = m.group(1).lower()
        var_counts[vname] += 1
        var_values[vname] = _unquote(m.group(2))

    single_vars = {k: v for k, v in var_values.items() if var_counts[k] == 1}
    if single_vars:
        reversed_vars: set[str] = {
            m.group(1).lower() for m in _PS_ARRAY_REVERSE_RE.finditer(curr)
        }
        for rv in reversed_vars:
            if rv in single_vars:
                single_vars[rv] = single_vars[rv][::-1]
                reducers.add("array_reverse")

        # Fold $x -join '' when $x was reversed or assigned a string
        for vname, vval in single_vars.items():
            join_pat = re.compile(
                rf"\${vname}\b\s*-join\s*({_QUOTED_STR_PAT})?",
                re.IGNORECASE,
            )
            if join_pat.search(curr):
                reducers.add("variable_propagation")
                curr = join_pat.sub(lambda m, val=vval: _quote_single(val), curr)

            # Substitute &$var or $var outside the assignment itself
            call_pat = re.compile(rf"(?:&\s*)?\${vname}\b(?!\s*=)", re.IGNORECASE)
            if call_pat.search(curr):
                reducers.add("variable_propagation")
                curr = call_pat.sub(lambda m, val=vval: val, curr)

    # 13. Bash variable assignment & ${var//a/b} parameter expansion
    bash_vars: dict[str, str] = {}
    for m in _BASH_VAR_ASSIGN_RE.finditer(curr):
        bash_vars[m.group(1)] = _unquote(m.group(2))

    if bash_vars:
        def _repl_bash_param(m: re.Match[str]) -> str:
            vname = m.group(1)
            if vname not in bash_vars:
                return m.group(0)
            val = bash_vars[vname]
            op = m.group(2)
            old_sub = m.group(3) or ""
            new_sub = m.group(4) or ""
            reducers.add("bash_parameter_expansion")
            if op == "//":
                return val.replace(old_sub, new_sub)
            if op == "/":
                return val.replace(old_sub, new_sub, 1)
            return val

        curr = _BASH_PARAM_SUB_RE.sub(_repl_bash_param, curr)

    # 14. Bash inline echo pipelines: base64 -d, rev, tr
    def _repl_bash_b64(m: re.Match[str]) -> str:
        b64_str = _unquote(m.group(1)).strip()
        try:
            missing_pad = len(b64_str) % 4
            if missing_pad:
                b64_str += "=" * (4 - missing_pad)
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
            reducers.add("bash_echo_base64")
            return decoded
        except Exception:
            return m.group(0)

    curr = _BASH_ECHO_B64_RE.sub(_repl_bash_b64, curr)

    def _repl_bash_rev(m: re.Match[str]) -> str:
        reducers.add("bash_echo_rev")
        return _unquote(m.group(1))[::-1]

    curr = _BASH_ECHO_REV_RE.sub(_repl_bash_rev, curr)

    def _repl_bash_tr(m: re.Match[str]) -> str:
        src_str = _unquote(m.group(1))
        set1 = _unquote(m.group(2))
        set2 = _unquote(m.group(3))
        if len(set1) == len(set2) and set1:
            reducers.add("bash_echo_tr")
            return src_str.translate(str.maketrans(set1, set2))
        return m.group(0)

    curr = _BASH_ECHO_TR_RE.sub(_repl_bash_tr, curr)

    return curr, reducers


def resolve_expression_node(
    command_text: str,
    max_passes: int = MAX_RESOLVER_PASSES,
) -> ExpressionResolutionResult:
    """Run the bounded fixed-point Expression Resolver (up to max_passes) on a Payload Node."""
    if not command_text:
        return ExpressionResolutionResult(
            original_text=command_text,
            resolved_text=command_text,
            modified=False,
        )

    curr = command_text
    applied: list[str] = []
    passes = 0

    for _ in range(max_passes):
        nxt, pass_reducers = _fold_pass(curr)
        if nxt == curr:
            break
        passes += 1
        for r in sorted(pass_reducers):
            if r not in applied:
                applied.append(r)
        curr = nxt

    return ExpressionResolutionResult(
        original_text=command_text,
        resolved_text=curr,
        modified=(curr != command_text),
        passes_run=passes,
        applied_reducers=applied,
    )


def resolve_expressions(command_text: str, max_passes: int = MAX_RESOLVER_PASSES) -> str:
    """Static Expression Resolver public seam returning the folded command text."""
    return resolve_expression_node(command_text, max_passes=max_passes).resolved_text
