"""
auto_detect.py — Dynamic probing for confirmed exploit parameters.

Runs the binary with controlled inputs to discover:
  - BOF offset  (cyclic + GDB x/gx $rsp)
  - Fmt offset  (sequential %N$p probes)
  - Input prompt (strings analysis + live probe)
  - Libc path   (ldd)
  - one_gadget  (subprocess)
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════

def run_auto_detect(binary_path: str, bits: int = 64,
                    strings: list[str] | None = None) -> dict:
    """Run all probes. Returns dict of confirmed values."""
    results = {
        "bof_offset": None,
        "fmt_offset": None,
        "prompt": None,
        "prompts": [],
        "one_gadgets": [],
        "libc_path": None,
        "validation": None,
    }

    if not os.path.isfile(binary_path):
        return results

    _make_executable(binary_path)

    # 1. Detect input prompt first — needed by other probers
    results["prompts"] = detect_prompts(strings or [])
    results["prompt"] = detect_input_prompt(binary_path, strings or [])

    # 2. Probe BOF offset (GDB + cyclic)
    results["bof_offset"] = probe_bof_offset(
        binary_path, bits, prompt=results["prompt"]
    )

    # 3. Probe fmt offset (sequential %p)
    results["fmt_offset"] = probe_fmt_offset(
        binary_path, bits, prompt=results["prompt"]
    )

    # 4. Libc + one_gadget
    results["libc_path"] = detect_libc_path(binary_path)
    if results["libc_path"]:
        results["one_gadgets"] = find_one_gadgets(results["libc_path"])

    return results


# ═══════════════════════════════════════════════════════════════════
# 1. Input Prompt Detection
# ═══════════════════════════════════════════════════════════════════

def detect_input_prompt(binary_path: str,
                        strings: list[str] | None = None) -> str | None:
    """Find the prompt the binary shows before reading input.

    Strategy: run the binary, read what it prints before blocking,
    fallback to string analysis.
    """
    # Try live detection first — run binary, see what it prints
    try:
        proc = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        import select
        import time
        time.sleep(0.3)  # let it print the prompt
        # Read whatever is available
        import fcntl
        fd = proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        try:
            output = proc.stdout.read(4096)
        except (BlockingIOError, OSError):
            output = b""
        proc.kill()
        proc.wait()

        if output:
            text = output.decode("utf-8", errors="replace").strip()
            # Take the last line — that's usually the prompt
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            if lines:
                return lines[-1]
    except Exception:
        pass

    # Fallback: string table analysis
    if strings:
        hints = [":", "> ", "? ", "enter", "input", "name", "pass",
                 "traveler", ">>"]
        candidates = [
            s.strip() for s in strings
            if any(h in s.lower() for h in hints)
            and 2 < len(s.strip()) < 80
        ]
        if candidates:
            return candidates[-1]

    # Last resort: run `strings` on the binary
    try:
        proc = subprocess.run(
            ["strings", binary_path], capture_output=True, text=True, timeout=5
        )
        hints = [":", "> ", "? "]
        for line in reversed(proc.stdout.splitlines()):
            line = line.strip()
            if any(line.endswith(h) for h in hints) and 2 < len(line) < 80:
                return line
    except Exception:
        pass

    return None


def detect_prompts(strings: list[str]) -> list[str]:
    """Find all likely input prompt strings."""
    prompts = []
    hints = [":", "> ", "? ", ">>>", "enter", "input"]
    for s in strings:
        s = s.strip()
        if not s or len(s) > 100 or len(s) < 2:
            continue
        if any(s.lower().endswith(h) for h in [":", ": ", "> ", ">>> ", "? "]):
            prompts.append(s)
    return prompts[:10]


# ═══════════════════════════════════════════════════════════════════
# 2. BOF Offset Detection  (GDB + cyclic + x/gx $rsp)
# ═══════════════════════════════════════════════════════════════════

def _cyclic(length: int = 300) -> bytes:
    """Generate cyclic pattern (pwntools or fallback)."""
    try:
        from pwn import cyclic
        return cyclic(length)
    except ImportError:
        # Simple de Bruijn fallback
        cs = b"abcdefghijklmnopqrstuvwxyz"
        out = bytearray()
        for a in cs:
            for b in cs:
                for c in cs:
                    for d in cs:
                        out.extend([a, b, c, d])
                        if len(out) >= length:
                            return bytes(out[:length])
        return bytes(out[:length])


def _cyclic_find(value: int, bits: int = 64) -> int | None:
    """Find offset of a value in the cyclic pattern."""
    try:
        from pwn import cyclic_find
        # Try 4-byte subpattern first (works for both 32 and 64)
        offset = cyclic_find(value & 0xffffffff)
        if offset >= 0:
            return offset
        # Try 8-byte for 64-bit
        if bits == 64:
            offset = cyclic_find(value, n=8)
            if offset >= 0:
                return offset
    except (ImportError, Exception):
        pass

    # Manual search fallback
    import struct
    pattern = _cyclic(600)
    needle4 = struct.pack("<I", value & 0xffffffff)
    idx = pattern.find(needle4)
    return idx if idx >= 0 else None


def probe_bof_offset(binary_path: str, bits: int = 64,
                     prompt: str | None = None) -> int | None:
    """Send cyclic pattern via GDB, read $rsp to find exact overflow offset.

    Uses: gdb -batch -x script.gdb ./binary
    The GDB script feeds cyclic input and reads the stack after crash.
    """
    gdb = shutil.which("gdb")
    if not gdb:
        return None

    pattern = _cyclic(300)

    try:
        # Write pattern to a temp file for GDB input
        pat_file = tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False, mode="wb"
        )
        pat_file.write(pattern)
        pat_file.close()

        # Write GDB script
        reg = "rsp" if bits == 64 else "esp"
        gdb_cmds = (
            f"set disable-randomization on\n"
            f"run < {pat_file.name}\n"
            f"x/gx ${reg}\n"
            f"quit\n"
        )
        gdb_file = tempfile.NamedTemporaryFile(
            suffix=".gdb", delete=False, mode="w"
        )
        gdb_file.write(gdb_cmds)
        gdb_file.close()

        result = subprocess.run(
            [gdb, "-batch", "-q", "-nx", "-x", gdb_file.name, binary_path],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr

        # Parse x/gx output:  0x7fffffffe4f8: 0x6161616161616166
        match = re.search(r'0x[0-9a-f]+:\s+0x([0-9a-f]+)', output)
        if match:
            rsp_val = int(match.group(1), 16)
            offset = _cyclic_find(rsp_val, bits)
            if offset is not None and 0 < offset < 500:
                return offset

        # Fallback: try parsing register dump if x/gx failed
        for reg_name in (["rip", "eip"] if bits == 64 else ["eip"]):
            m = re.search(rf'{reg_name}\s+0x([0-9a-f]+)', output, re.I)
            if m:
                val = int(m.group(1), 16)
                off = _cyclic_find(val, bits)
                if off is not None and 0 < off < 500:
                    return off

    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        for f in [pat_file.name, gdb_file.name]:
            try:
                os.unlink(f)
            except Exception:
                pass

    return None


# ═══════════════════════════════════════════════════════════════════
# 3. Format String Offset Detection  (sequential %N$p probes)
# ═══════════════════════════════════════════════════════════════════

def probe_fmt_offset(binary_path: str, bits: int = 64,
                     prompt: str | None = None) -> int | None:
    """Send AAAA%N$p for N=1..24, look for 0x41414141 in output."""
    marker = b"AAAAAAAA" if bits == 64 else b"AAAA"
    needle = "4141414141414141" if bits == 64 else "41414141"

    for offset in range(1, 25):
        payload = marker + f"%{offset}$p\n".encode()
        try:
            proc = subprocess.run(
                [binary_path], input=payload,
                capture_output=True, timeout=3,
            )
            out = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
            if needle.lower() in out.lower():
                return offset
        except (subprocess.TimeoutExpired, OSError):
            continue
        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════════
# 4. Libc + one_gadget
# ═══════════════════════════════════════════════════════════════════

def detect_libc_path(binary_path: str) -> str | None:
    """Find libc path via ldd."""
    ldd = shutil.which("ldd")
    if not ldd:
        return None
    try:
        proc = subprocess.run(
            [ldd, binary_path], capture_output=True, text=True, timeout=5
        )
        for line in proc.stdout.splitlines():
            if "libc.so" in line or "libc-" in line:
                m = re.search(r'=> (\S+)', line)
                if m and os.path.isfile(m.group(1)):
                    return m.group(1)
                parts = line.strip().split()
                for p in parts:
                    if ("libc" in p) and os.path.isfile(p):
                        return p
    except Exception:
        pass
    return None


def find_one_gadgets(libc_path: str) -> list[dict]:
    """Run one_gadget on libc, parse addresses + constraints."""
    og = shutil.which("one_gadget")
    if not og or not os.path.isfile(libc_path):
        return []
    try:
        proc = subprocess.run(
            [og, libc_path], capture_output=True, text=True, timeout=15
        )
        gadgets, current = [], None
        for line in proc.stdout.splitlines():
            m = re.match(r'^(0x[0-9a-f]+)', line)
            if m:
                if current:
                    gadgets.append(current)
                current = {"addr": m.group(1), "constraints": []}
            elif current and line.strip().startswith("["):
                current["constraints"].append(line.strip())
        if current:
            gadgets.append(current)
        return gadgets[:5]
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════
# 5. GDB Script Generation
# ═══════════════════════════════════════════════════════════════════

def generate_gdb_script(binary_path: str, symbols: list[str],
                        bof_offset: int | None = None) -> str:
    """Generate a ready-to-use GDB debug script."""
    b = os.path.basename(binary_path)
    bp_names = ["main", "vuln", "vulnerable", "win", "flag", "shell",
                "backdoor", "secret", "get_flag", "read_flag"]
    found = [s for s in bp_names if s in symbols]

    lines = [
        f"# GDB debug script for {b}",
        f"# Usage: gdb -x debug.gdb ./{b}",
        "",
        f"file ./{b}",
        "set disable-randomization on",
        "set follow-fork-mode child",
        "",
        "# ── Breakpoints ──────────────────────────",
    ]
    for fn in (found or ["main"]):
        lines.append(f"break {fn}")

    lines += [
        "",
        "# ── Display on break ─────────────────────",
        "define hook-stop",
        "  info registers",
        "  x/4gx $rsp",
        "end",
        "",
    ]

    if bof_offset:
        lines += [
            "# ── BOF offset check ─────────────────────",
            f"# Auto-detected offset: {bof_offset}",
            f"# Verify: run <<< $(python3 -c "
            f"\"import sys; sys.stdout.buffer.write(b'A'*{bof_offset}+b'BBBBBBBB')\")",
            f"# RSP should show 0x4242424242424242",
            "",
        ]

    lines.append("run")
    return "\n".join(lines)


def _make_executable(path: str):
    """chmod +x the binary."""
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
