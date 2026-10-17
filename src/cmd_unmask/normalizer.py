"""Quote-aware two-pass Shell Normalizer for cmd.exe and PowerShell DOSfuscation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Canonical Windows 11 environment variables (lowercased keys for case-insensitive lookup)
CANONICAL_WIN11_ENV: dict[str, str] = {
    "comspec": r"C:\Windows\System32\cmd.exe",
    "windir": r"C:\Windows",
    "systemroot": r"C:\Windows",
    "systemdrive": "C:",
    "public": r"C:\Users\Public",
    "appdata": r"C:\Users\Default\AppData\Roaming",
    "localappdata": r"C:\Users\Default\AppData\Local",
    "programdata": r"C:\ProgramData",
    "programfiles": r"C:\Program Files",
    "programfiles(x86)": r"C:\Program Files (x86)",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "temp": r"C:\Users\Default\AppData\Local\Temp",
    "tmp": r"C:\Users\Default\AppData\Local\Temp",
    "userprofile": r"C:\Users\Default",
    "allusersprofile": r"C:\ProgramData",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL",
}

VALID_PS_ESCAPES: frozenset[str] = frozenset({"n", "r", "t", "0", "a", "b", "f", "v"})

KNOWN_SHELL_TOKENS: frozenset[str] = frozenset(
    {
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "cmd",
        "cmd.exe",
        "iex",
        "invoke-expression",
        "invoke-webrequest",
        "invoke-restmethod",
        "new-object",
        "start-process",
        "downloadstring",
        "downloadfile",
        "downloaddata",
        "webclient",
        "net.webclient",
        "system.net.webclient",
        "frombase64string",
        "tobase64string",
        "getstring",
        "utf8",
        "unicode",
        "ascii",
        "encoding",
        "text.encoding",
        "system.text.encoding",
        "convert",
        "system.convert",
        "io.compression.gzipstream",
        "io.compression.deflatestream",
        "io.memorystream",
        "io.streamreader",
        "gzipstream",
        "deflatestream",
        "memorystream",
        "streamreader",
        "readtoend",
        "windowstyle",
        "hidden",
        "noprofile",
        "noninteractive",
        "executionpolicy",
        "bypass",
        "unrestricted",
        "encodedcommand",
        "enc",
        "command",
        "certutil",
        "mshta",
        "rundll32",
        "regsvr32",
        "bitsadmin",
        "msiexec",
        "wscript",
        "cscript",
        "schtasks",
        "reg",
    }
)

_SET_ASSIGN_RE = re.compile(
    r'''(?:^|[;&|\s"'])set\s+(?:"([^"=]+)=([^"]*)"|([A-Za-z_][A-Za-z0-9_]*)=([^;&|"\r\n]+))''',
    re.IGNORECASE,
)

_ENV_EXPR_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*(?::[^%]+)?)%")


@dataclass
class NormalizationResult:
    """Result of running the two-pass Shell Normalizer."""

    original_text: str
    normalized_text: str
    modified: bool
    applied_passes: list[str] = field(default_factory=list)
    resolved_env_vars: dict[str, str] = field(default_factory=dict)


def _resolve_env_token(expr: str, env_map: dict[str, str]) -> str | None:
    """Resolve a cmd.exe %VAR%, %VAR:~offset[,len]%, or %VAR:old=new% expression."""
    if ":" not in expr:
        val = env_map.get(expr.lower())
        return val

    var_name, modifier = expr.split(":", 1)
    base_val = env_map.get(var_name.lower())
    if base_val is None:
        return None

    if modifier.startswith("~"):
        slice_spec = modifier[1:].strip()
        parts = [p.strip() for p in slice_spec.split(",", 1)]
        try:
            offset = int(parts[0])
            length = int(parts[1]) if len(parts) > 1 and parts[1] != "" else None
        except ValueError:
            return None

        str_len = len(base_val)
        start = max(0, str_len + offset) if offset < 0 else offset
        if length is None:
            return base_val[start:]
        if length < 0:
            end = max(start, str_len + length)
            return base_val[start:end]
        return base_val[start : start + length]

    if "=" in modifier:
        old_sub, new_sub = modifier.split("=", 1)
        if not old_sub:
            return base_val
        pattern = re.compile(re.escape(old_sub), re.IGNORECASE)
        return pattern.sub(new_sub, base_val)

    return None


def _extract_inline_set_vars(text: str, env_map: dict[str, str]) -> dict[str, str]:
    """Extract inline cmd.exe 'set VAR=val' definitions and strip redundant set clauses when expanded."""
    discovered: dict[str, str] = {}
    for match in _SET_ASSIGN_RE.finditer(text):
        var_name = match.group(1) or match.group(3)
        var_val = match.group(2) if match.group(1) is not None else match.group(4)
        if var_name and var_val is not None:
            clean_val = var_val.strip()
            env_map[var_name.strip().lower()] = clean_val
            discovered[var_name.strip()] = clean_val
    return discovered


def _normalize_cmd_pass(text: str) -> tuple[str, bool, dict[str, str]]:
    """Pass 1: cmd.exe quote-aware caret stripping, empty-quote collapsing, and env var slicing."""
    env_map = dict(CANONICAL_WIN11_ENV)
    discovered_vars = _extract_inline_set_vars(text, env_map)

    # First, strip unquoted ^ escapes and collapse adjacent empty double quotes embedded in tokens
    out: list[str] = []
    in_single = False
    n = len(text)
    i = 0

    while i < n:
        ch = text[i]

        if ch == "'":
            in_single = not in_single
            out.append(ch)
            i += 1
            continue

        if not in_single:
            # Collapse adjacent empty double quotes when attached to word characters (e.g. po""wershell)
            if ch == '"' and i + 1 < n and text[i + 1] == '"':
                prev_ch = out[-1] if out else ""
                next_ch = text[i + 2] if i + 2 < n else ""
                prev_is_word = bool(prev_ch) and (prev_ch.isalnum() or prev_ch in "_-/.")
                next_is_word = bool(next_ch) and (next_ch.isalnum() or next_ch in "_-/.")
                if prev_is_word and next_is_word:
                    i += 2
                    continue

            # Strip cmd.exe caret escape ^ when outside single quotes and attached to a token
            if ch == "^" and i + 1 < n:
                next_ch = text[i + 1]
                prev_ch = out[-1] if out else ""
                # Do not strip ^ if it is spaced as a binary operator (e.g. 'a ^ b')
                if not (prev_ch.isspace() and next_ch.isspace()):
                    out.append(next_ch)
                    i += 2
                    continue

        out.append(ch)
        i += 1

    stage1 = "".join(out)

    # Expand %VAR% and %VAR:~offset,len% outside single-quoted segments
    def _replace_env_outside_single_quotes(src: str) -> str:
        segments: list[str] = []
        in_sq = False
        seg_start = 0
        for idx, c in enumerate(src):
            if c == "'":
                if in_sq:
                    # closing single quote: keep [seg_start, idx+1] untouched
                    segments.append(src[seg_start : idx + 1])
                    seg_start = idx + 1
                    in_sq = False
                else:
                    # opening single quote: process [seg_start, idx] for env vars
                    chunk = src[seg_start:idx]
                    segments.append(
                        _ENV_EXPR_RE.sub(
                            lambda m: (
                                resolved
                                if (resolved := _resolve_env_token(m.group(1), env_map)) is not None
                                else m.group(0)
                            ),
                            chunk,
                        )
                    )
                    seg_start = idx
                    in_sq = True
        tail = src[seg_start:]
        if in_sq:
            segments.append(tail)
        else:
            segments.append(
                _ENV_EXPR_RE.sub(
                    lambda m: (
                        resolved
                        if (resolved := _resolve_env_token(m.group(1), env_map)) is not None
                        else m.group(0)
                    ),
                    tail,
                )
            )
        return "".join(segments)

    # Re-extract inline set vars after caret stripping in case 's^e^t' was obfuscated
    more_vars = _extract_inline_set_vars(stage1, env_map)
    discovered_vars.update(more_vars)

    stage2 = _replace_env_outside_single_quotes(stage1)
    return stage2, (stage2 != text), discovered_vars


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch in ("_", "-", ".")


def _normalize_powershell_pass(text: str) -> tuple[str, bool]:
    """Pass 2: PowerShell quote-aware backtick obfuscation stripping."""
    out: list[str] = []
    in_single = False
    n = len(text)
    i = 0

    while i < n:
        ch = text[i]

        if ch == "'":
            # Handle PowerShell doubled single-quote '' inside single-quoted string
            if in_single and i + 1 < n and text[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_single = not in_single
            out.append(ch)
            i += 1
            continue

        if not in_single and ch == "`" and i + 1 < n:
            next_ch = text[i + 1]
            # Check if next_ch could be a valid lowercase PowerShell escape sequence
            if next_ch in VALID_PS_ESCAPES:
                # Determine if this `x is actually mid-word backtick obfuscation (e.g., -e`n`c or h`i`d`d`e`n)
                followed_by_backtick = (i + 2 < n and text[i + 2] == "`")
                # Extract surrounding contiguous word+backtick token to check against known keywords
                tok_start = i
                while tok_start > 0 and (_is_word_char(text[tok_start - 1]) or text[tok_start - 1] == "`"):
                    tok_start -= 1
                tok_end = i + 2
                while tok_end < n and (_is_word_char(text[tok_end]) or text[tok_end] == "`"):
                    tok_end += 1
                raw_token = text[tok_start:tok_end]
                stripped_token = raw_token.replace("`", "").lstrip("-").lower()

                if followed_by_backtick or stripped_token in KNOWN_SHELL_TOKENS:
                    out.append(next_ch)
                    i += 2
                    continue
                # Preserve valid PowerShell escape sequence (`n, `r, `t, `0, etc.)
                out.append("`")
                out.append(next_ch)
                i += 2
                continue
            else:
                # Strip obfuscation backtick before non-escape character (e.g., `E, `X, `p, `s, etc.)
                out.append(next_ch)
                i += 2
                continue

        out.append(ch)
        i += 1

    result = "".join(out)
    return result, (result != text)


def normalize_shell(command_text: str) -> NormalizationResult:
    """Execute the two-pass quote-aware Shell Normalizer (cmd.exe + PowerShell)."""
    if not command_text:
        return NormalizationResult(
            original_text=command_text,
            normalized_text=command_text,
            modified=False,
        )

    applied: list[str] = []
    after_cmd, cmd_mod, env_vars = _normalize_cmd_pass(command_text)
    if cmd_mod:
        applied.append("cmd_normalizer")

    after_ps, ps_mod = _normalize_powershell_pass(after_cmd)
    if ps_mod:
        applied.append("powershell_normalizer")

    return NormalizationResult(
        original_text=command_text,
        normalized_text=after_ps,
        modified=(after_ps != command_text),
        applied_passes=applied,
        resolved_env_vars=env_vars,
    )


normalize = normalize_shell
