"""
protections.py — Detect binary security mitigations (checksec equivalent).

Reads ELF headers, segments, and dynamic tags to determine NX, PIE, RELRO,
stack canary, and FORTIFY status without shelling out to external tools.
"""

from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection

from .models import BinaryProtections, ProtectionStatus


def check_protections(elf: ELFFile) -> BinaryProtections:
    """Inspect *elf* and return a populated ``BinaryProtections``."""
    prot = BinaryProtections()

    # ── Architecture ──────────────────────────────────────────────
    _arch_map = {
        "EM_386": "x86",
        "EM_X86_64": "x86_64",
        "EM_ARM": "ARM",
        "EM_AARCH64": "AArch64",
        "EM_MIPS": "MIPS",
        "EM_PPC": "PowerPC",
        "EM_PPC64": "PowerPC64",
    }
    prot.arch = _arch_map.get(elf.header.e_machine, elf.header.e_machine)
    prot.bits = elf.elfclass  # 32 or 64
    prot.endian = "big" if not elf.little_endian else "little"

    # ── NX (non-executable stack) ─────────────────────────────────
    prot.nx = _check_nx(elf)

    # ── PIE (position-independent executable) ─────────────────────
    prot.pie = _check_pie(elf)

    # ── RELRO ─────────────────────────────────────────────────────
    prot.relro = _check_relro(elf)

    # ── Stack canary ──────────────────────────────────────────────
    prot.canary = _check_canary(elf)

    # ── FORTIFY ───────────────────────────────────────────────────
    prot.fortify = _check_fortify(elf)

    # ── Stripped? ─────────────────────────────────────────────────
    prot.stripped = _check_stripped(elf)

    return prot


# ── helpers ──────────────────────────────────────────────────────────

def _check_nx(elf: ELFFile) -> ProtectionStatus:
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            # PF_X = 0x1
            if seg.header.p_flags & 0x1:
                return ProtectionStatus.DISABLED
            return ProtectionStatus.ENABLED
    # No GNU_STACK segment → behaviour is arch-dependent; assume enabled.
    return ProtectionStatus.ENABLED


def _check_pie(elf: ELFFile) -> ProtectionStatus:
    if elf.header.e_type == "ET_DYN":
        # Shared objects are always position-independent, but we
        # distinguish PIE executables from plain shared libs by
        # looking for a PT_INTERP segment.
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_INTERP":
                return ProtectionStatus.ENABLED
        # Likely a shared library rather than a PIE binary.
        return ProtectionStatus.ENABLED
    return ProtectionStatus.DISABLED


def _check_relro(elf: ELFFile) -> ProtectionStatus:
    has_relro_segment = False
    has_bind_now = False

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_RELRO":
            has_relro_segment = True

    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    has_bind_now = True
                if tag.entry.d_tag == "DT_FLAGS":
                    if tag.entry.d_val & 0x8:  # DF_BIND_NOW
                        has_bind_now = True
                if tag.entry.d_tag == "DT_FLAGS_1":
                    if tag.entry.d_val & 0x1:  # DF_1_NOW
                        has_bind_now = True

    if has_relro_segment and has_bind_now:
        return ProtectionStatus.ENABLED      # Full RELRO
    if has_relro_segment:
        return ProtectionStatus.PARTIAL      # Partial RELRO
    return ProtectionStatus.DISABLED


def _check_canary(elf: ELFFile) -> ProtectionStatus:
    """Look for __stack_chk_fail in symbol tables and dynamic imports."""
    canary_syms = {"__stack_chk_fail", "__stack_chk_guard",
                   "__intel_security_cookie"}
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for sym in section.iter_symbols():
                if sym.name in canary_syms:
                    return ProtectionStatus.ENABLED
    return ProtectionStatus.DISABLED


def _check_fortify(elf: ELFFile) -> ProtectionStatus:
    """Check for FORTIFY_SOURCE by looking for __*_chk symbols."""
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for sym in section.iter_symbols():
                if "_chk" in sym.name and sym.name.startswith("__"):
                    # e.g. __printf_chk, __memcpy_chk
                    return ProtectionStatus.ENABLED
    return ProtectionStatus.DISABLED


def _check_stripped(elf: ELFFile) -> bool:
    """A binary is stripped if it has no .symtab section."""
    for section in elf.iter_sections():
        if section.name == ".symtab":
            return False
    return True
