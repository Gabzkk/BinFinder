# BinIdentifier

**Static binary vulnerability classifier** — upload or pass an ELF binary and instantly identify potential exploitation techniques, security mitigations, and difficulty ratings.

## Features

- **13 vulnerability classifiers** covering the full spectrum from Easy to Super Hard:

| # | Technique | Difficulty |
|---|-----------|-----------|
| 1 | Stack Buffer Overflow (ret2win) | Easy |
| 2 | Format String (Basic Info Leak) | Easy |
| 3 | Shellcode Injection (no NX) | Beginner–Intermediate |
| 4 | Integer Overflow / Underflow | Beginner–Intermediate |
| 5 | Return-Oriented Programming (ROP) | Intermediate |
| 6 | Heap Overflow | Intermediate |
| 7 | Format String (Arbitrary Write) | Intermediate |
| 8 | Use-After-Free (UAF) | Hard |
| 9 | Heap Exploitation (tcache/fastbin) | Hard |
| 10 | ASLR + PIE Bypass (Info Leak Chaining) | Hard |
| 11 | Kernel Exploitation | Super Hard |
| 12 | Browser / JIT Exploitation | Super Hard |
| 13 | Side-Channel Attacks (Spectre/Meltdown) | Super Hard |

- **Checksec-equivalent** security mitigation detection (NX, PIE, RELRO, Canary, FORTIFY)
- **Confidence scoring** — each detection includes a 0–100% confidence rating
- **Actionable evidence** — shows exactly what triggered each detection
- **Exploitation recommendations** — step-by-step guidance and tool suggestions
- **Dual interface** — beautiful web UI + coloured CLI output

## Quick Start

### CLI Mode

```bash
# Analyze any ELF binary
python3 cli.py ./your_binary

# JSON output for scripting
python3 cli.py ./your_binary --json
```

### Web UI Mode

```bash
# Start the web server
python3 app.py

# Open http://localhost:5000 in your browser
# Drag & drop a binary to analyze
```

## Installation

```bash
# Dependencies (likely already installed on a CTF/security machine)
pip install flask pyelftools capstone

# Or use the venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Project Structure

```
BinIdentifier/
├── app.py                          # Flask web application
├── cli.py                          # Command-line interface
├── requirements.txt
├── bin_identifier/
│   ├── __init__.py
│   ├── analyzer.py                 # Main analysis orchestrator
│   ├── protections.py              # Security mitigation checks
│   ├── elf_utils.py                # ELF parsing utilities
│   ├── models.py                   # Data models (dataclasses)
│   └── classifiers/
│       ├── __init__.py             # Classifier registry
│       ├── stack_overflow.py       # #1 — Stack BOF / ret2win
│       ├── format_string.py        # #2,7 — Format string (basic + write)
│       ├── shellcode.py            # #3 — Shellcode injection
│       ├── integer_overflow.py     # #4 — Integer overflow
│       ├── rop.py                  # #5 — ROP
│       ├── heap.py                 # #6,8,9 — Heap overflow, UAF, advanced
│       ├── aslr_pie.py             # #10 — ASLR/PIE bypass
│       └── advanced.py             # #11,12,13 — Kernel, JIT, side-channel
├── templates/
│   └── index.html                  # Web UI template
├── static/
│   ├── css/style.css               # Design system
│   └── js/app.js                   # Frontend logic
└── samples/
    ├── vuln_demo.c                 # Intentionally vulnerable source
    └── vuln_demo                   # Compiled test binary
```

## How It Works

1. **ELF Parsing** — Reads headers, segments, and sections via `pyelftools`
2. **Protection Check** — Determines NX, PIE, RELRO, Canary, FORTIFY status
3. **Symbol Analysis** — Extracts imports, exports, and all symbols
4. **String Extraction** — Finds printable strings for pattern matching
5. **Classification** — Runs all 13 classifiers against the collected context
6. **Scoring** — Each classifier produces a confidence score based on evidence

## Sample Output

```
  ╔══════════════════════════════════════════════╗
  ║        B i n I d e n t i f i e r             ║
  ╚══════════════════════════════════════════════╝

  Binary:  vuln_demo
  Type:    ELF 64-bit LE Executable (EM_X86_64)

  ─── Security Mitigations ──────────────────────
    ●  NX/DEP     Disabled
    ●  PIE        Disabled
    ●  RELRO      Partial
    ●  Canary     Disabled
    ●  FORTIFY    Disabled

  ─── Detected Vulnerabilities (4) ──────────────

  [1]  Stack Buffer Overflow (ret2win)
       Difficulty:  Easy
       Confidence:  ████████████████████ 100%
       Evidence:
         ● Dangerous input functions imported: read
         ● Stack canary is DISABLED
         ● Potential 'win' / target functions found: win
         ● Interesting strings: FLAG{you_found_the_win_function}
         ● PIE is DISABLED — static addresses

  [2]  Shellcode Injection (no NX)
       Difficulty:  Beginner–Intermediate
       Confidence:  █████████████████░░░ 85%

  [3]  Format String (Basic Info Leak)
       Difficulty:  Easy
       Confidence:  ██████████████░░░░░░ 70%

  [4]  Format String (Arbitrary Write)
       Difficulty:  Intermediate
       Confidence:  █████████████░░░░░░░ 65%
```

## Adding Custom Classifiers

Create a new file in `bin_identifier/classifiers/` following this pattern:

```python
from ..models import VulnerabilityMatch, Difficulty

def classify_my_vuln(ctx: dict) -> list[VulnerabilityMatch]:
    # ctx contains: protections, imported_functions, exported_functions,
    #               all_symbols, sections, dynamic_libs, strings, has_rwx_segment
    evidence, confidence = [], 0.0

    # ... your detection logic ...

    if confidence < 0.25:
        return []

    return [VulnerabilityMatch(
        id=14,
        name="My Custom Vulnerability",
        category="Custom",
        difficulty=Difficulty.INTERMEDIATE,
        confidence=min(confidence, 1.0),
        description="...",
        tags=["custom"],
        evidence=evidence,
        recommendations=["..."],
    )]
```

Then register it in `classifiers/__init__.py`:
```python
from .my_module import classify_my_vuln
ALL_CLASSIFIERS.append(classify_my_vuln)
```

## License

MIT — built for CTF players and security researchers.

## Author

SunBurnz
