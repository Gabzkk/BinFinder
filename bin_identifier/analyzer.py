"""
analyzer.py — Main analysis orchestrator.

Coordinates ELF parsing, protection checks, and all vulnerability
classifiers to produce a complete ``AnalysisResult``.
"""

from __future__ import annotations

import io
import os
from typing import IO

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from .models import AnalysisResult, BinaryProtections
from .protections import check_protections
from .elf_utils import (
    get_imported_functions,
    get_exported_functions,
    get_all_symbols,
    get_sections_info,
    get_dynamic_libs,
    extract_strings,
    has_rwx_segment,
)
from .classifiers import ALL_CLASSIFIERS
from .payload_crafter import craft_payload, post_process_payload
from .auto_detect import run_auto_detect, generate_gdb_script
from .validator import validate_payload, validate_ret2win


def analyze_binary(stream: IO[bytes], filename: str,
                   binary_path: str | None = None) -> AnalysisResult:
    """Perform full static + dynamic analysis on the binary."""
    try:
        elf = ELFFile(stream)
    except ELFError as exc:
        return AnalysisResult(
            filename=filename,
            file_type="Unknown / Not ELF",
            protections=BinaryProtections(),
            vulnerabilities=[],
            raw_strings_sample=extract_strings(stream),
            imported_functions=[],
            exported_functions=[],
            sections=[],
            error=f"Not a valid ELF binary: {exc}",
        )

    # ── gather static data ───────────────────────────────────────
    protections = check_protections(elf)
    imported = get_imported_functions(elf)
    exported = get_exported_functions(elf)
    all_syms = get_all_symbols(elf)
    sections = get_sections_info(elf)
    dyn_libs = get_dynamic_libs(elf)
    rwx = has_rwx_segment(elf)
    strings = extract_strings(stream)
    file_type = _describe_elf(elf)

    # ── dynamic probes ───────────────────────────────────────────
    auto_detected = {}
    if binary_path and os.path.isfile(binary_path):
        try:
            auto_detected = run_auto_detect(
                binary_path, bits=protections.bits, strings=strings
            )
        except Exception:
            pass

    # ── build classifier context ─────────────────────────────────
    ctx = {
        "elf": elf,
        "protections": protections,
        "imported_functions": imported,
        "exported_functions": exported,
        "all_symbols": all_syms,
        "sections": sections,
        "dynamic_libs": dyn_libs,
        "has_rwx_segment": rwx,
        "strings": strings,
        "_filename": filename,
        "_binary_path": binary_path,
        "auto_detected": auto_detected,
    }

    # ── run classifiers ──────────────────────────────────────────
    vulnerabilities = []
    for classifier in ALL_CLASSIFIERS:
        try:
            vulnerabilities.extend(classifier(ctx))
        except Exception:
            pass

    # ── inject confirmed values + rank ───────────────────────────
    prompt = auto_detected.get("prompt")
    bof_offset = auto_detected.get("bof_offset")
    fmt_offset = auto_detected.get("fmt_offset")
    no_canary = protections.canary.value != "Enabled"

    # Determine the win functions
    win_names = {"win", "flag", "shell", "secret", "get_flag", "print_flag",
                 "give_shell", "backdoor", "ret2win", "cat_flag", "read_flag"}
    has_win = bool(set(all_syms) & win_names)

    for vuln in vulnerabilities:
        vuln.auto_detected = auto_detected
        vuln.input_prompt = prompt
        vuln.confirmed_offset = bof_offset
        vuln.confirmed_fmt_offset = fmt_offset

        # ── Smart ranking rule ───────────────────────────────
        # win() + no canary + BOF = ret2win is THE path
        if vuln.id == 1 and has_win and no_canary:
            vuln.recommended = True
            if bof_offset is not None:
                vuln.confidence = 1.0  # confirmed
        elif vuln.id in (2, 7) and fmt_offset is not None:
            vuln.confidence = max(vuln.confidence, 0.90)
            if not (has_win and no_canary):
                vuln.recommended = True  # fmt is top if no ret2win

    # ── generate payloads with confirmed values ──────────────────
    for vuln in vulnerabilities:
        try:
            script = craft_payload(vuln.id, ctx)
            vuln.payload_script = post_process_payload(script, auto_detected)
        except Exception:
            pass
        try:
            vuln.gdb_script = generate_gdb_script(
                binary_path or filename, all_syms,
                bof_offset=bof_offset,
            )
        except Exception:
            pass

    # ── validate the recommended payload ─────────────────────────
    if binary_path:
        for vuln in vulnerabilities:
            if not vuln.recommended:
                continue
            try:
                if vuln.id == 1 and bof_offset and has_win:
                    # Find the actual win address
                    win_sym = next(
                        (s for s in all_syms if s.lower() in win_names), None
                    )
                    if win_sym:
                        from elftools.elf.elffile import ELFFile as _EF
                        stream.seek(0)
                        _e = _EF(stream)
                        from .elf_utils import get_all_symbols as _gas
                        # Get symbol address from symtab
                        for section in _e.iter_sections():
                            if section.header['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                                for sym in section.iter_symbols():
                                    if sym.name == win_sym and sym.entry['st_value']:
                                        vr = validate_ret2win(
                                            binary_path, bof_offset,
                                            sym.entry['st_value'],
                                            bits=protections.bits,
                                            prompt=prompt,
                                        )
                                        vuln.validation_result = vr.get("status")
                                        if vr.get("adjusted_offset"):
                                            vuln.confirmed_offset = vr["adjusted_offset"]
                                        break
            except Exception:
                pass

    return AnalysisResult(
        filename=filename,
        file_type=file_type,
        protections=protections,
        vulnerabilities=vulnerabilities,
        raw_strings_sample=strings,
        imported_functions=imported,
        exported_functions=exported,
        sections=sections,
        auto_detected=auto_detected,
    )


def _describe_elf(elf: ELFFile) -> str:
    """Human-readable one-liner about the ELF."""
    kind = {
        "ET_EXEC": "Executable",
        "ET_DYN": "Shared Object / PIE Executable",
        "ET_REL": "Relocatable Object",
        "ET_CORE": "Core Dump",
    }.get(elf.header.e_type, elf.header.e_type)

    arch = elf.header.e_machine
    bits = elf.elfclass
    endian = "LE" if elf.little_endian else "BE"

    return f"ELF {bits}-bit {endian} {kind} ({arch})"
