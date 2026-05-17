#!/usr/bin/env python3
"""
cli.py — Command-line interface for BinIdentifier.

Usage:
    python3 cli.py <binary_file> [--json]

Performs a full static vulnerability analysis and prints results
to the terminal with coloured output.
"""

from __future__ import annotations

import argparse
import json
import sys

from bin_identifier.analyzer import analyze_binary


# ── ANSI colours ─────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"

DIFF_COLOURS = {
    "Easy":                    GREEN,
    "Beginner–Intermediate":  CYAN,
    "Intermediate":            YELLOW,
    "Hard":                    RED,
    "Super Hard":              MAGENTA,
}


def prot_colour(status: str) -> str:
    if status == "Enabled":  return GREEN
    if status == "Partial":  return YELLOW
    if status == "Disabled": return RED
    return DIM


def confidence_bar(conf: float, width: int = 20) -> str:
    filled = int(conf * width)
    bar = "█" * filled + "░" * (width - filled)
    if conf >= 0.7:   colour = GREEN
    elif conf >= 0.4: colour = YELLOW
    else:             colour = RED
    return f"{colour}{bar}{RESET} {conf:.0%}"


def print_results(data: dict) -> None:
    """Pretty-print analysis results to the terminal."""
    p = data["protections"]

    print()
    print(f"  {BOLD}{MAGENTA}╔══════════════════════════════════════════════╗{RESET}")
    print(f"  {BOLD}{MAGENTA}║        B i n I d e n t i f i e r             ║{RESET}")
    print(f"  {BOLD}{MAGENTA}╚══════════════════════════════════════════════╝{RESET}")
    print()

    # ── Summary ──────────────────────────────────────────────
    print(f"  {BOLD}Binary:{RESET}  {CYAN}{data['filename']}{RESET}")
    print(f"  {BOLD}Type:{RESET}    {data['file_type']}")
    print(f"  {BOLD}Arch:{RESET}    {p['arch']}  ({p['bits']}-bit {p['endian']})")
    print(f"  {BOLD}Stripped:{RESET} {'Yes' if p['stripped'] else 'No'}")
    print()

    # ── Protections ──────────────────────────────────────────
    print(f"  {BOLD}{WHITE}─── Security Mitigations ──────────────────────{RESET}")
    for name, key in [("NX/DEP", "nx"), ("PIE", "pie"), ("RELRO", "relro"),
                       ("Canary", "canary"), ("FORTIFY", "fortify")]:
        val = p[key]
        colour = prot_colour(val)
        dot = f"{colour}●{RESET}"
        print(f"    {dot}  {name:<10} {colour}{val}{RESET}")
    print()

    # ── Vulnerabilities ──────────────────────────────────────
    vulns = data["vulnerabilities"]
    print(f"  {BOLD}{WHITE}─── Detected Vulnerabilities ({len(vulns)}) ──────────────{RESET}")
    if not vulns:
        print(f"    {DIM}No vulnerabilities detected.{RESET}")
        print()
        return

    # ── Auto-detected values banner ──────────────────
    ad = data.get("auto_detected", {})
    has_probes = any(ad.get(k) is not None for k in ["bof_offset", "fmt_offset", "prompt"])
    if has_probes:
        print()
        print(f"  {BOLD}{GREEN}⚙  Probe Results:{RESET}")
        if ad.get("bof_offset") is not None:
            print(f"    {GREEN}✓{RESET} BOF Offset:       {BOLD}{CYAN}{ad['bof_offset']}{RESET} bytes  {DIM}(cyclic + GDB){RESET}")
        else:
            print(f"    {DIM}○ BOF Offset:       not detected{RESET}")
        if ad.get("fmt_offset") is not None:
            print(f"    {GREEN}✓{RESET} Fmt Str Offset:   {BOLD}{CYAN}%{ad['fmt_offset']}$p{RESET}  {DIM}(sequential probe){RESET}")
        else:
            print(f"    {DIM}○ Fmt Str Offset:   not detected{RESET}")
        if ad.get("prompt"):
            print(f"    {GREEN}✓{RESET} Input Prompt:     {BOLD}{CYAN}\"{ad['prompt']}\"{RESET}  {DIM}(live detection){RESET}")
        if ad.get("libc_path"):
            print(f"    {GREEN}✓{RESET} Libc Path:        {CYAN}{ad['libc_path']}{RESET}")
        if ad.get("one_gadgets"):
            for g in ad['one_gadgets'][:3]:
                print(f"    {GREEN}✓{RESET} one_gadget:       {CYAN}{g['addr']}{RESET}")

    for i, v in enumerate(vulns, 1):
        diff = v["difficulty"]
        dc = DIFF_COLOURS.get(diff, WHITE)
        is_rec = v.get("recommended", False)
        vr = v.get("validation_result")
        badge = f" {GREEN}★ RECOMMENDED{RESET}" if is_rec else ""
        confirmed = v.get("confirmed_offset") or v.get("confirmed_fmt_offset")
        status_tag = ""
        if confirmed:
            status_tag = f"  {GREEN}CONFIRMED{RESET}"
        elif vr:
            status_tag = f"  {_validation_colour(vr)}{vr.upper()}{RESET}"

        print()
        print(f"  {BOLD}{WHITE}[{i}]{RESET}  {BOLD}{v['name']}{RESET}{badge}{status_tag}")
        print(f"       Difficulty:  {dc}{diff}{RESET}")
        print(f"       Confidence:  {confidence_bar(v['confidence'])}")
        print(f"       Category:    {v['category']}")
        print(f"       Tags:        {DIM}{', '.join(v['tags'])}{RESET}")
        print()
        print(f"       {DIM}{v['description']}{RESET}")
        print()

        if v["evidence"]:
            print(f"       {BOLD}Evidence:{RESET}")
            for e in v["evidence"]:
                print(f"         {CYAN}●{RESET} {e}")

        # ── Quick Steps Checklist ─────────────────────────────
        if is_rec or confirmed:
            print()
            print(f"       {BOLD}{GREEN}Quick Steps{RESET}")
            print(f"       {DIM}{'─' * 40}{RESET}")
            _print_checklist(v, data)

        if v.get("exploit_steps"):
            print()
            print(f"       {BOLD}{YELLOW}⚡ Exploitation Steps:{RESET}")
            for idx, step in enumerate(v["exploit_steps"], 1):
                lines = step.split("\n")
                print(f"         {YELLOW}{idx}.{RESET} {lines[0]}")
                for code_line in lines[1:]:
                    print(f"            {DIM}{code_line}{RESET}")

        if v.get("payload_script"):
            print()
            label = "🔧 Payload Crafter"
            if vr == "shell" or vr == "flag_leaked":
                label += f"  {GREEN}✅ VALIDATED — WORKING{RESET}"
            elif vr == "crash":
                label += f"  {YELLOW}⚠ Crashed — offset may need adjustment{RESET}"
            print(f"       {BOLD}{MAGENTA}{label}{RESET}")
            print(f"       {DIM}{'─' * 50}{RESET}")
            for line in v["payload_script"].rstrip().split("\n"):
                print(f"       {CYAN}│{RESET} {DIM}{line}{RESET}")
            print(f"       {DIM}{'─' * 50}{RESET}")
            print(f"       {DIM}Copy → save as exploit.py → python3 exploit.py{RESET}")

        if v.get("gdb_script"):
            print()
            print(f"       {BOLD}{YELLOW}🐛 GDB Debug Script:{RESET}")
            print(f"       {DIM}{'─' * 50}{RESET}")
            for line in v["gdb_script"].rstrip().split("\n"):
                print(f"       {YELLOW}│{RESET} {DIM}{line}{RESET}")
            print(f"       {DIM}{'─' * 50}{RESET}")
            print(f"       {DIM}Save as debug.gdb → gdb -x debug.gdb ./<binary>{RESET}")

        if v["recommendations"]:
            print(f"       {BOLD}Recommendations:{RESET}")
            for r in v["recommendations"]:
                print(f"         {GREEN}→{RESET} {r}")

    print()
    print(f"  {DIM}Imports: {len(data['imported_functions'])}  |  "
          f"Exports: {len(data['exported_functions'])}  |  "
          f"Strings: {len(data['raw_strings_sample'])}{RESET}")
    print()


def _validation_colour(status: str) -> str:
    return {
        "shell": GREEN, "flag_leaked": GREEN, "clean_exit": YELLOW,
        "crash": RED, "abort": RED, "timeout": DIM, "confirmed": GREEN,
    }.get(status, DIM)


def _print_checklist(v: dict, data: dict) -> None:
    """Print a step-by-step exploit checklist for a confirmed vuln."""
    p = data["protections"]
    ad = data.get("auto_detected", {})
    prompt = v.get("input_prompt") or ad.get("prompt")
    bof = v.get("confirmed_offset")
    fmt = v.get("confirmed_fmt_offset")
    vr = v.get("validation_result")

    print(f"       {GREEN}1. ✅{RESET} Binary loaded")
    print(f"       {GREEN}2. ✅{RESET} Arch: {p['arch']} {p['bits']}-bit  |  Canary: {p['canary']}  |  NX: {p['nx']}  |  PIE: {p['pie']}")

    # Win function
    win_syms = [s for s in data.get("exported_functions", [])
                if s.lower() in {"win", "flag", "shell", "backdoor", "get_flag", "ret2win"}]
    if win_syms:
        print(f"       {GREEN}3. ✅{RESET} win() found: {CYAN}{', '.join(win_syms)}{RESET}")
    else:
        print(f"       {YELLOW}3. ☐{RESET} No win() — will need ret2libc or shellcode")

    # Offset
    if bof is not None:
        print(f"       {GREEN}4. ✅{RESET} Offset confirmed: {BOLD}{CYAN}{bof}{RESET}")
    elif fmt is not None:
        print(f"       {GREEN}4. ✅{RESET} Fmt offset confirmed: {BOLD}{CYAN}%{fmt}$p{RESET}")
    else:
        print(f"       {YELLOW}4. ☐{RESET} Offset not auto-detected — use cyclic in GDB")

    # Prompt
    if prompt:
        print(f"       {GREEN}5. ✅{RESET} Prompt detected: {CYAN}\"{prompt}\"{RESET}")
    else:
        print(f"       {YELLOW}5. ☐{RESET} Prompt unknown — check binary output")

    # Validation
    if vr in ("shell", "flag_leaked"):
        print(f"       {GREEN}6. ✅{RESET} {BOLD}Payload validated — WORKING locally!{RESET}")
    elif vr == "clean_exit":
        print(f"       {YELLOW}6. ⚠{RESET}  Payload ran but exited cleanly — may need tweaking")
    elif vr == "crash":
        print(f"       {RED}6. ✗{RESET}  Payload crashed — offset may be wrong")
    else:
        print(f"       {DIM}6. ▶{RESET}  Run: {CYAN}python3 exploit.py{RESET}")

    print(f"       {DIM}7. ☐  If local works → change to remote(){RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BinIdentifier — Static binary vulnerability classifier."
    )
    parser.add_argument("binary", help="Path to the ELF binary to analyse.")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of formatted text.")
    args = parser.parse_args()

    try:
        with open(args.binary, "rb") as f:
            result = analyze_binary(f, args.binary, binary_path=args.binary)
    except FileNotFoundError:
        print(f"Error: file not found: {args.binary}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {args.binary}", file=sys.stderr)
        sys.exit(1)

    data = result.to_dict()

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_results(data)


if __name__ == "__main__":
    main()
