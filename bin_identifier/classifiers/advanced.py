"""
advanced.py — Kernel, Browser/JIT, and Side-channel classifiers.

These are heuristic-only since static analysis of a user-space binary
can only hint at kernel / browser / side-channel relevance.
"""

from __future__ import annotations
from ..models import VulnerabilityMatch, Difficulty


def classify_kernel(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    all_syms = set(ctx["all_symbols"])
    strings = ctx["strings"]
    evidence, confidence = [], 0.0

    kmod_hints = {"init_module", "delete_module", "finit_module",
                  "create_module", "query_module"}
    # Only match /dev/ paths that look like driver nodes, not /dev/null etc.
    dev_strings = [s for s in strings if (s.startswith("/dev/") and s not in ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd"))
                   or "kmod" in s.lower() or "kmalloc" in s.lower()]

    km = all_syms & kmod_hints
    if km:
        evidence.append(f"Kernel module symbols: {', '.join(sorted(km))}")
        confidence += 0.35

    if dev_strings:
        evidence.append(f"Device / kernel strings: {', '.join(dev_strings[:5])}")
        confidence += 0.15

    if "ioctl" in imports:
        evidence.append("ioctl() imported — kernel driver interaction")
        confidence += 0.20

    if confidence < 0.35:
        return []

    return [VulnerabilityMatch(
        id=11, name="Kernel Exploitation", category="Kernel",
        difficulty=Difficulty.SUPER_HARD, confidence=min(confidence, 1.0),
        description="Exploit vulnerabilities in the OS kernel itself to escalate privileges.",
        tags=["kernel", "privilege escalation", "race condition"], evidence=evidence,
        recommendations=[
            "Identify the target kernel module / driver.",
            "Look for race conditions, UAF, or OOB in ioctl handlers.",
            "Use QEMU + gdb for safe kernel debugging.",
            "Tools: kROP, kernel-exploit-factory, syzkaller.",
        ],
        exploit_steps=[
            "Step 1 — Identify the attack surface: Find the kernel module or driver being targeted. Check /dev/ entries, lsmod output, and dmesg for loaded modules.",
            "Step 2 — Reverse the ioctl handler: Decompile the kernel module (.ko file) in Ghidra. Map the ioctl command numbers to their handler functions. Look for missing bounds checks, UAF, or race conditions.",
            "Step 3 — Set up a safe environment: Use QEMU + a debug kernel (KASAN/KASLR disabled) for testing:\n    qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio \\\n        -append 'console=ttyS0 nokaslr' -s -S",
            "Step 4 — Trigger the vulnerability: Write a user-space program that opens the /dev/ node and sends crafted ioctl requests to trigger the bug (OOB write, UAF, race condition).",
            "Step 5 — Achieve kernel RIP control: Overwrite a function pointer in kernel memory (ops struct, RCU callback, workqueue function) to redirect execution.",
            "Step 6 — Escalate privileges: Execute commit_creds(prepare_kernel_cred(0)) to set the current process's credentials to root, then return to user-space.",
            "Step 7 — Return cleanly: Use KPTI trampoline (swapgs + iretq) to return to user-space without crashing the kernel, then execve('/bin/sh') as root.",
        ],
    )]


def classify_browser_jit(ctx: dict) -> list[VulnerabilityMatch]:
    strings = ctx["strings"]
    libs = ctx.get("dynamic_libs", [])
    evidence, confidence = [], 0.0

    js_hints = [s for s in strings if any(k in s.lower() for k in
                ("v8", "spidermonkey", "javascriptcore", "jit", "wasm", "turbofan"))]
    browser_libs = [l for l in libs if any(k in l.lower() for k in
                    ("v8", "mozjs", "webkit", "chromium", "jsc"))]

    if js_hints:
        evidence.append(f"JIT/browser engine strings: {', '.join(js_hints[:5])}")
        confidence += 0.40
    if browser_libs:
        evidence.append(f"Browser engine libraries: {', '.join(browser_libs[:5])}")
        confidence += 0.30

    if confidence < 0.25:
        return []

    return [VulnerabilityMatch(
        id=12, name="Browser / JIT Exploitation", category="Browser",
        difficulty=Difficulty.SUPER_HARD, confidence=min(confidence, 1.0),
        description="Exploit JIT compilers or JavaScript engine internals — type confusion, OOB in optimised code.",
        tags=["JIT", "browser", "type confusion", "sandbox escape"], evidence=evidence,
        recommendations=[
            "Identify the JS engine version (d8 --version, about:version).",
            "Search for known CVEs for that version.",
            "Type confusion and OOB in optimised JIT code are common entry points.",
            "Sandbox escape is typically a separate exploit chain.",
        ],
        exploit_steps=[
            "Step 1 — Identify the engine version: Determine the exact V8/SpiderMonkey/JSC version. Search for known CVEs or 0-days that affect it.",
            "Step 2 — Trigger the bug in JS: Write JavaScript that exploits the specific bug (type confusion, bounds check elimination, incorrect optimisation). The goal is to get an out-of-bounds read/write on a JS ArrayBuffer.",
            "Step 3 — Build addrof/fakeobj primitives: Use the OOB access to:\n    - addrof(obj): leak the memory address of a JS object\n    - fakeobj(addr): create a fake JS object at an arbitrary address",
            "Step 4 — Achieve arbitrary read/write: Use fakeobj to create a fake ArrayBuffer with a controlled backing store pointer. Reading/writing through this ArrayBuffer gives arbitrary memory access.",
            "Step 5 — Bypass mitigations: Defeat pointer compression, V8 sandbox (if present), and CFI. Techniques vary by engine version.",
            "Step 6 — Execute shellcode: Overwrite JIT-compiled code (RWX JIT page) or use WebAssembly to get executable memory. Write shellcode into the RWX region and jump to it.",
            "Step 7 — Sandbox escape (if sandboxed): Chain a second exploit targeting the browser's IPC/sandbox boundary (Mojo, etc.) to break out of the renderer sandbox and achieve full system compromise.",
        ],
    )]


def classify_side_channel(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    strings = ctx["strings"]
    all_syms = set(ctx["all_symbols"])
    evidence, confidence = [], 0.0

    # Exclude common timing functions that appear in almost every binary
    timing_funcs = {"rdtsc", "rdtscp", "nanosleep", "usleep"}
    cache_hints = {"clflush", "mfence", "lfence", "_mm_clflush",
                   "_mm_mfence", "_mm_lfence"}

    tf = imports & timing_funcs | all_syms & timing_funcs
    cf = all_syms & cache_hints

    spectre_strings = [s for s in strings if any(k in s.lower() for k in
                       ("spectre", "meltdown", "flush+reload", "cache", "side.channel"))]

    if tf:
        evidence.append(f"Timing functions: {', '.join(sorted(tf))}")
        confidence += 0.25
    if cf:
        evidence.append(f"Cache manipulation intrinsics: {', '.join(sorted(cf))}")
        confidence += 0.30
    if spectre_strings:
        evidence.append(f"Side-channel keywords in strings: {', '.join(spectre_strings[:5])}")
        confidence += 0.30

    if confidence < 0.30:
        return []

    return [VulnerabilityMatch(
        id=13, name="Side-Channel Attacks (Spectre / Meltdown class)", category="Side Channel",
        difficulty=Difficulty.SUPER_HARD, confidence=min(confidence, 1.0),
        description="Infer secret data by measuring timing, cache state, or speculative execution side effects.",
        tags=["spectre", "cache timing", "microarchitecture"], evidence=evidence,
        recommendations=[
            "Identify the covert channel (cache timing, branch prediction, etc.).",
            "Implement Flush+Reload or Prime+Probe to measure cache sets.",
            "Statistical analysis over many samples to extract signal from noise.",
            "Tools: Mastik, CacheOut PoCs, perf stat for HW counters.",
        ],
        exploit_steps=[
            "Step 1 — Identify the secret: Determine what data you're trying to extract (encryption key, password in kernel memory, another process's data) and where it resides.",
            "Step 2 — Choose the side channel: Select the appropriate technique:\n    - Flush+Reload: attacker and victim share memory (shared libraries)\n    - Prime+Probe: no shared memory needed, works cross-process\n    - Spectre v1: exploit branch misprediction to read out-of-bounds\n    - Spectre v2: poison the branch target buffer",
            "Step 3 — Set up the covert channel: Allocate a 256×cache_line_size probe array. Each element maps to one possible byte value of the secret.",
            "Step 4 — Train the branch predictor (Spectre): Repeatedly call the victim function with in-bounds values to train the branch predictor, then call with an out-of-bounds index that accesses the secret.",
            "Step 5 — Trigger speculative access: The CPU speculatively reads secret_byte, then accesses probe_array[secret_byte * 256]. Even though the speculation is rolled back, the cache state is changed.",
            "Step 6 — Measure cache timing: Time access to each element of the probe array. The element corresponding to the secret byte will be cached (fast access, ~5-20 cycles), while others are uncached (~100+ cycles):\n    for i in range(256):\n        t = rdtsc(); tmp = probe[i * 256]; dt = rdtsc() - t\n        if dt < threshold: secret_byte = i",
            "Step 7 — Repeat and accumulate: Run the attack thousands of times and use statistical analysis (majority voting) to extract the secret byte-by-byte. Cache timing is noisy — many samples improve accuracy.",
        ],
    )]
