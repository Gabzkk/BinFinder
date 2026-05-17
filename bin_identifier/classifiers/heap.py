"""
heap.py — Heap overflow, Use-After-Free, and advanced heap exploitation classifiers.
"""

from __future__ import annotations
from ..models import VulnerabilityMatch, Difficulty

HEAP_ALLOC = {"malloc", "calloc", "realloc", "free", "reallocarray"}
HEAP_OPS = {"memcpy", "memmove", "strcpy", "strcat", "strncpy", "memset"}
INPUT_FUNCS = {"read", "recv", "fgets", "scanf", "__isoc99_scanf", "gets", "fread"}


def classify_heap_overflow(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    evidence, confidence = [], 0.0

    alloc = imports & HEAP_ALLOC
    ops = imports & HEAP_OPS
    inp = imports & INPUT_FUNCS

    if not alloc:
        return []

    evidence.append(f"Heap allocators: {', '.join(sorted(alloc))}")
    confidence += 0.20

    if ops:
        evidence.append(f"Heap-copy functions: {', '.join(sorted(ops))}")
        confidence += 0.20
    if inp:
        evidence.append(f"Input functions: {', '.join(sorted(inp))}")
        confidence += 0.15
    if "free" in imports:
        evidence.append("free() imported — metadata corruption possible")
        confidence += 0.10

    if confidence < 0.30:
        return []

    return [VulnerabilityMatch(
        id=6, name="Heap Overflow", category="Heap",
        difficulty=Difficulty.INTERMEDIATE, confidence=min(confidence, 1.0),
        description="Overflow a heap allocation to corrupt adjacent heap metadata or object pointers.",
        tags=["heap", "overflow", "allocator"], evidence=evidence,
        recommendations=[
            "Map object layout with gdb + heap-analysis plugins (pwndbg/GEF).",
            "Overflow into adjacent chunk metadata or vtable pointers.",
            "Target: tcache fd pointer, fastbin fd, or adjacent object fields.",
        ],
        exploit_steps=[
            "Step 1 — Understand the allocator: Determine the glibc version (strings <binary> | grep GLIBC). This dictates which heap structures (tcache, fastbin, unsorted bin) are available.",
            "Step 2 — Map the heap layout: In gdb with pwndbg, allocate objects and examine their positions:\n    heap  # Show heap overview\n    vis_heap_chunks  # Visualise chunk layout\n    Identify which chunks are adjacent to your controlled buffer.",
            "Step 3 — Find the overflow: Look for a write operation (memcpy, strcpy, read) that doesn't check if the data exceeds the allocated chunk size.",
            "Step 4 — Corrupt adjacent chunk metadata: Overflow into the next chunk's header to modify:\n    - size field → create overlapping chunks\n    - fd/bk pointers → arbitrary allocation (after free)\n    - Application data → overwrite function pointers or vtables",
            "Step 5 — Trigger the corruption: Free the corrupted chunk, then allocate again. The allocator will follow the corrupted pointers, giving you an allocation at an arbitrary address.",
            "Step 6 — Achieve code execution: Write to the arbitrary allocation to overwrite __malloc_hook, __free_hook (glibc < 2.34), GOT entry, or a return address. Then trigger the overwritten pointer to get shell.",
        ],
    )]


def classify_uaf(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    all_syms = set(ctx["all_symbols"])
    evidence, confidence = [], 0.0

    if "free" not in imports and "free" not in all_syms:
        return []

    alloc = imports & HEAP_ALLOC
    if not alloc:
        return []

    evidence.append("malloc/free both present — allocation lifecycle exists")
    confidence += 0.25

    if "free" in imports and "malloc" in imports:
        confidence += 0.15
        evidence.append("Both malloc and free imported — potential dangling pointer")

    inp = imports & INPUT_FUNCS
    if inp:
        evidence.append(f"Input after free possible: {', '.join(sorted(inp))}")
        confidence += 0.15

    strings = ctx["strings"]
    menu_kw = [s for s in strings if any(k in s.lower() for k in ("delete", "remove", "free", "edit", "view", "show"))]
    if menu_kw:
        evidence.append(f"Menu-like strings suggest allocate/free/use pattern: {', '.join(menu_kw[:5])}")
        confidence += 0.15

    if confidence < 0.30:
        return []

    return [VulnerabilityMatch(
        id=8, name="Use-After-Free (UAF)", category="Heap",
        difficulty=Difficulty.HARD, confidence=min(confidence, 1.0),
        description="Trigger a dangling pointer by freeing memory that's still referenced, then allocate controlled data in the same region.",
        tags=["heap", "UAF", "dangling pointer"], evidence=evidence,
        recommendations=[
            "Identify the free → realloc → use sequence in the binary.",
            "Allocate a same-size chunk to land in the freed slot.",
            "Overwrite function pointers or vtable entries in the reclaimed chunk.",
            "Use gdb with pwndbg to track tcache/fastbin state.",
        ],
        exploit_steps=[
            "Step 1 — Identify the lifecycle: Map the menu/API options. Look for: Allocate (create), Edit (write), Delete (free), View (read). The UAF occurs when Delete doesn't clear the pointer, and View/Edit still work.",
            "Step 2 — Trigger the free: Use the Delete option on an object. Verify the pointer is still accessible by trying View — if it shows freed chunk data (or crashes), the dangling pointer exists.",
            "Step 3 — Reclaim the freed slot: Allocate a new object of the SAME SIZE as the freed one. The allocator reuses the freed chunk. Your new data now occupies the same memory as the dangling pointer.\n    # In gdb: check that the new allocation address matches the old one.",
            "Step 4 — Overwrite critical data: Write controlled data through the new allocation. If the old object had a function pointer, vtable, or fd pointer at a known offset, your data overwrites it.",
            "Step 5 — Trigger the stale reference: Use the original (dangling) pointer via View or another operation. It now reads/calls your controlled data → code execution.\n    # Example: if the old object had a function pointer at offset 0, write the address of system() there.",
            "Step 6 — Get shell: If the function pointer is called with a user-controlled argument, point it to system() with '/bin/sh' as the argument. Otherwise, chain with a ROP gadget or one_gadget.",
        ],
    )]


def classify_heap_advanced(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    libs = ctx.get("dynamic_libs", [])
    evidence, confidence = [], 0.0

    alloc = imports & HEAP_ALLOC
    if len(alloc) < 2:
        return []

    evidence.append(f"Multiple heap primitives: {', '.join(sorted(alloc))}")
    confidence += 0.20

    if any("libc" in lib for lib in libs):
        evidence.append("glibc linked — tcache / fastbin / unsorted bin attacks apply")
        confidence += 0.20

    if "free" in imports and "malloc" in imports:
        evidence.append("malloc + free = full lifecycle for tcache poisoning / fastbin dup")
        confidence += 0.15

    strings = ctx["strings"]
    menu_kw = [s for s in strings if any(k in s.lower() for k in ("add", "delete", "edit", "show", "alloc", "free"))]
    if len(menu_kw) >= 3:
        evidence.append(f"Rich menu interface ({len(menu_kw)} keywords) — typical heap challenge pattern")
        confidence += 0.15

    if confidence < 0.35:
        return []

    return [VulnerabilityMatch(
        id=9, name="Heap Exploitation (Advanced — tcache/fastbin)", category="Heap",
        difficulty=Difficulty.HARD, confidence=min(confidence, 1.0),
        description="Abuse glibc malloc internals like tcache poisoning, fastbin dup, or house-of-force to gain arbitrary allocation primitives.",
        tags=["tcache", "fastbin", "house-of-*"], evidence=evidence,
        recommendations=[
            "Determine glibc version (strings + libc-database / nix-shell).",
            "Identify which bins are used (tcache for size < 0x410 in glibc ≥ 2.26).",
            "Classic attacks: tcache poisoning, fastbin dup, unsorted bin attack.",
            "Use pwndbg heap commands to visualise allocator state.",
        ],
        exploit_steps=[
            "Step 1 — Determine glibc version: This is critical — techniques differ per version:\n    strings <binary> | grep GLIBC\n    # Or: ldd <binary>  then: strings libc.so.6 | head -1",
            "Step 2 — Identify available primitives: Map what the binary lets you do:\n    - Allocate: malloc(size) with controlled size?\n    - Write: can you write to allocated chunks?\n    - Free: can you free chunks? Double-free possible?\n    - Read: can you leak heap/libc addresses?",
            "Step 3 — Tcache poisoning (glibc ≥ 2.26): Free a chunk, then overwrite its fd pointer to point to your target address. Next allocation returns a chunk at that target:\n    free(chunk_A)\n    # Overwrite chunk_A->fd = target_addr  (via UAF or overflow)\n    malloc(same_size)  # returns chunk_A\n    malloc(same_size)  # returns target_addr!",
            "Step 4 — Fastbin dup (glibc < 2.32): Double-free the same chunk with a different chunk in between:\n    free(A); free(B); free(A)  # A appears twice in fastbin\n    malloc() → A; write(A->fd = target)\n    malloc() → B\n    malloc() → target!",
            "Step 5 — Leak libc base: Use an unsorted bin attack or tcache read to leak a libc address:\n    # Free a chunk > 0x410 bytes (goes to unsorted bin)\n    # Its fd/bk point to main_arena in libc\n    # Read the freed chunk to leak the address\n    libc_base = leaked - main_arena_offset",
            "Step 6 — Write to target: With arbitrary allocation, overwrite:\n    - __free_hook (glibc < 2.34) → system, then free(chunk_containing_'/bin/sh')\n    - __malloc_hook → one_gadget\n    - GOT entry (if Partial RELRO)\n    - Stack return address (if you can get a stack leak)",
            "Step 7 — Trigger shell: Call the overwritten hook/function to execute system('/bin/sh') or the one_gadget.",
        ],
    )]
