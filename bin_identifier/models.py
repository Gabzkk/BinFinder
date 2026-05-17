"""
Data models for binary analysis results.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Optional


class Difficulty(Enum):
    """Exploit difficulty tier."""
    EASY = "Easy"
    BEGINNER_INTERMEDIATE = "Beginner–Intermediate"
    INTERMEDIATE = "Intermediate"
    HARD = "Hard"
    SUPER_HARD = "Super Hard"

    @property
    def rank(self) -> int:
        _MAP = {
            "Easy": 1,
            "Beginner–Intermediate": 2,
            "Intermediate": 3,
            "Hard": 4,
            "Super Hard": 5,
        }
        return _MAP[self.value]


class ProtectionStatus(Enum):
    """Whether a binary protection is enabled."""
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PARTIAL = "Partial"
    UNKNOWN = "Unknown"


@dataclasses.dataclass
class BinaryProtections:
    """Security mitigations present in the binary."""
    nx: ProtectionStatus = ProtectionStatus.UNKNOWN
    pie: ProtectionStatus = ProtectionStatus.UNKNOWN
    relro: ProtectionStatus = ProtectionStatus.UNKNOWN
    canary: ProtectionStatus = ProtectionStatus.UNKNOWN
    fortify: ProtectionStatus = ProtectionStatus.UNKNOWN
    stripped: bool = False
    arch: str = "unknown"
    bits: int = 0
    endian: str = "little"

    def to_dict(self) -> dict:
        return {
            "nx": self.nx.value,
            "pie": self.pie.value,
            "relro": self.relro.value,
            "canary": self.canary.value,
            "fortify": self.fortify.value,
            "stripped": self.stripped,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
        }


@dataclasses.dataclass
class VulnerabilityMatch:
    """A single detected vulnerability / exploit technique."""
    id: int
    name: str
    category: str
    difficulty: Difficulty
    confidence: float          # 0.0 – 1.0
    description: str
    tags: list[str]
    evidence: list[str]        # human-readable evidence strings
    recommendations: list[str] # suggested next steps / tools
    exploit_steps: list[str] = dataclasses.field(default_factory=list)
    payload_script: str = ""
    gdb_script: str = ""
    auto_detected: dict = dataclasses.field(default_factory=dict)
    # ── Confirmed probe fields ───────────────────────────────────
    confirmed_offset: int | None = None      # BOF offset from cyclic probe
    confirmed_fmt_offset: int | None = None  # fmt offset from %p probe
    input_prompt: str | None = None          # detected input prompt
    validation_result: str | None = None     # shell / crash / clean_exit
    recommended: bool = False                # True = top-ranked exploit path

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty.value,
            "difficulty_rank": self.difficulty.rank,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "tags": self.tags,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "exploit_steps": self.exploit_steps,
            "payload_script": self.payload_script,
            "gdb_script": self.gdb_script,
            "auto_detected": self.auto_detected,
            "confirmed_offset": self.confirmed_offset,
            "confirmed_fmt_offset": self.confirmed_fmt_offset,
            "input_prompt": self.input_prompt,
            "validation_result": self.validation_result,
            "recommended": self.recommended,
        }


@dataclasses.dataclass
class AnalysisResult:
    """Complete analysis output for a binary."""
    filename: str
    file_type: str
    protections: BinaryProtections
    vulnerabilities: list[VulnerabilityMatch]
    raw_strings_sample: list[str]
    imported_functions: list[str]
    exported_functions: list[str]
    sections: list[dict]
    error: Optional[str] = None
    auto_detected: dict = dataclasses.field(default_factory=dict)
    # ^ Binary-level auto-detected values

    def to_dict(self) -> dict:
        vulns = sorted(self.vulnerabilities,
                       key=lambda v: (-v.confidence, v.difficulty.rank))
        return {
            "filename": self.filename,
            "file_type": self.file_type,
            "protections": self.protections.to_dict(),
            "vulnerabilities": [v.to_dict() for v in vulns],
            "raw_strings_sample": self.raw_strings_sample[:50],
            "imported_functions": self.imported_functions,
            "exported_functions": self.exported_functions,
            "sections": self.sections,
            "error": self.error,
            "auto_detected": self.auto_detected,
        }
