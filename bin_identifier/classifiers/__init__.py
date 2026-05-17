"""
classifiers — Pluggable vulnerability detection modules.

Each classifier is a callable that receives analysis context and returns
zero or more ``VulnerabilityMatch`` instances.
"""

from .stack_overflow import classify_stack_overflow
from .format_string import classify_format_string_basic, classify_format_string_write
from .shellcode import classify_shellcode_injection
from .integer_overflow import classify_integer_overflow
from .rop import classify_rop
from .heap import classify_heap_overflow, classify_uaf, classify_heap_advanced
from .aslr_pie import classify_aslr_pie_bypass
from .advanced import classify_kernel, classify_browser_jit, classify_side_channel

ALL_CLASSIFIERS = [
    classify_stack_overflow,
    classify_format_string_basic,
    classify_format_string_write,
    classify_shellcode_injection,
    classify_integer_overflow,
    classify_rop,
    classify_heap_overflow,
    classify_uaf,
    classify_heap_advanced,
    classify_aslr_pie_bypass,
    classify_kernel,
    classify_browser_jit,
    classify_side_channel,
]
