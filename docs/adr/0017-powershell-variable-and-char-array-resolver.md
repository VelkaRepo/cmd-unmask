# PowerShell Multi-Line Variable, `[char]` Array, and Sub-Expression Resolver

Event ID 4104 (PowerShell Script Block Logging) and AMSI payloads frequently obfuscate stagers across multiple lines using:
- `[char[]]` array subexpressions (`[char[]]@(73,69,88) -join ''` or `[char]73 + [char]69 + [char]88`)
- Multi-line `$var = ...` assignments built from concatenated chunks, `[char]` casts, or `-f` format expressions
- Sub-expression interpolation (`$($a)`, `"$a$b"`) and indirect call-operator invocations (`&($cmd)`, `. ($cmd)`)

While `cmd-unmask`'s existing Expression Resolver ([ADR-0004](0004-case-aware-static-expression-resolver.md)) handles single-line literal reductions (`'a' + 'b'`, `[char[]](...) -join ''`, `$var = 'literal'`), it misses `@(...)` array subexpressions, backtick/quote-split concatenations across expressions, multi-line symbol-table dependencies, and `&($var)` / `$($var)` invocation patterns.

To reconstruct Event ID 4104 and AMSI script blocks statically using 100% Python standard library with zero `eval()`/`exec()` or child-shell execution ([ADR-0001](0001-static-stdlib-only-analysis.md)):

1. **Deterministic `[char]` Array & String Concatenation Evaluator (`resolver.py`):**
   - Extend `[char[]]` / `[int[]]` array reduction to support PowerShell `@(...)` array subexpressions (`[char[]]@(73, 69, 88) -join ''` and `([char[]]@(73,69,88) -join '')`) as well as `[char]73 + [char]69 + [char]88` chains (including hex `0x49` and parenthesized ordinals `[char](0x49)`).
   - Extend `-f` format operator and quote/backtick-split concatenation reduction to evaluate mixed literal + `[char]` expressions cleanly inside bounded fixed-point passes (`MAX_RESOLVER_PASSES = 20`).
   - Enforce strict ordinal bounds (`0 <= codepoint <= 0x10FFFF`, printable/whitespace guard for auto-folding) so malformed or non-ASCII integers never raise `ValueError` or produce binary noise.

2. **Bounded Multi-Line Variable Symbol-Table Reconstruction (`resolver.py` / `unpacker.py`):**
   - Track sequential `$var = <expr>` assignments line-by-line (and semicolon-delimited statements) across multi-line script blocks using a bounded **Symbol Table** (`max_vars = 128`, `max_value_bytes = 32_768` per variable, `max_total_bytes = 262_144`).
   - Fold right-hand-side expressions (concatenation, `[char]` arrays, `-f` formatting, already-bound `$var` references) before storing the resolved string in the symbol table.
   - Substitute `$var`, `$($var)`, `"$a$b"` double-quoted interpolation, and `&($cmd)` / `. ($cmd)` indirect call-operator invocations safely, while leaving PowerShell automatic/environment variables (`$_`, `$PSItem`, `$env:*`, `$true`, `$false`, `$null`, `$args`, `$PSScriptRoot`) untouched.
   - Guard against self-referential or cyclic assignments (`$a = $a + 'x'` bounded by `max_value_bytes` and sequential single-pass / bounded-pass evaluation).

3. **Detection Rigidity:**
   - Benign administrative PowerShell scripts using normal `$var` paths, `$env:SystemRoot`, or `Write-Output` loops must never trigger False Positives (`FPR=0.0000` on the Regression Corpus).
