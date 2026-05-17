"""
elf_utils.py — ELF parsing utilities.

Extracts sections, symbols, imported/exported functions, and printable
strings from an ELF binary.
"""

from __future__ import annotations

import re
from typing import IO

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection


# Minimum length for a printable string to be considered interesting.
_MIN_STRING_LEN = 4
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LEN)


def get_imported_functions(elf: ELFFile) -> list[str]:
    """Return names of dynamically imported (undefined) symbols."""
    imports: list[str] = []
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            if (sym.name
                    and sym.entry.st_info.type in ("STT_FUNC", "STT_NOTYPE")
                    and sym.entry.st_shndx == "SHN_UNDEF"):
                imports.append(sym.name)
    return sorted(set(imports))


def get_exported_functions(elf: ELFFile) -> list[str]:
    """Return names of globally-visible defined function symbols."""
    exports: list[str] = []
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            if (sym.name
                    and sym.entry.st_info.type == "STT_FUNC"
                    and sym.entry.st_info.bind == "STB_GLOBAL"
                    and sym.entry.st_shndx != "SHN_UNDEF"):
                exports.append(sym.name)
    return sorted(set(exports))


def get_all_symbols(elf: ELFFile) -> list[str]:
    """Return every symbol name found in the binary."""
    names: list[str] = []
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for sym in section.iter_symbols():
                if sym.name:
                    names.append(sym.name)
    return names


def get_sections_info(elf: ELFFile) -> list[dict]:
    """Return metadata about each section."""
    results: list[dict] = []
    for section in elf.iter_sections():
        flags = section.header.sh_flags
        results.append({
            "name": section.name,
            "type": section.header.sh_type,
            "address": hex(section.header.sh_addr),
            "size": section.header.sh_size,
            "flags": {
                "write": bool(flags & 0x1),
                "alloc": bool(flags & 0x2),
                "exec": bool(flags & 0x4),
            },
        })
    return results


def get_dynamic_libs(elf: ELFFile) -> list[str]:
    """Return NEEDED shared library names."""
    libs: list[str] = []
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    libs.append(tag.needed)
    return libs


def extract_strings(stream: IO[bytes], min_len: int = _MIN_STRING_LEN,
                    max_count: int = 500) -> list[str]:
    """Extract printable ASCII strings from the raw binary stream."""
    stream.seek(0)
    data = stream.read()
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    strings: list[str] = []
    for match in pattern.finditer(data):
        strings.append(match.group().decode("ascii", errors="replace"))
        if len(strings) >= max_count:
            break
    return strings


def get_got_entries(elf: ELFFile) -> list[str]:
    """Return symbol names referenced by the GOT/PLT relocation sections."""
    names: list[str] = []
    for section in elf.iter_sections():
        if section.header.sh_type in ("SHT_REL", "SHT_RELA"):
            symtab = elf.get_section(section.header.sh_link)
            if not isinstance(symtab, SymbolTableSection):
                continue
            for rel in section.iter_relocations():
                sym_idx = rel.entry.r_info_sym
                if sym_idx:
                    sym = symtab.get_symbol(sym_idx)
                    if sym and sym.name:
                        names.append(sym.name)
    return sorted(set(names))


def has_rwx_segment(elf: ELFFile) -> bool:
    """Check if any LOAD segment has Read+Write+Execute permissions."""
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD":
            flags = seg.header.p_flags
            # PF_X=1, PF_W=2, PF_R=4
            if (flags & 0x1) and (flags & 0x2) and (flags & 0x4):
                return True
    return False
