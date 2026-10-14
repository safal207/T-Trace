"""Measurement arithmetic and process-memory units; no protocol decisions."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import sys

MEMORY_METHODS = {
    "Windows": {"python": "GetProcessMemoryInfo.PeakWorkingSetSize (bytes)",
                "node": "Node process.resourceUsage().maxRSS (KiB multiplied by 1024)"},
    "Linux": {"python": "Linux getrusage(RUSAGE_SELF).ru_maxrss (KiB multiplied by 1024)",
              "node": "Node process.resourceUsage().maxRSS (KiB multiplied by 1024)"},
}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def summarize(samples: list[int]) -> dict:
    if not samples or any(type(value) is not int or value <= 0 for value in samples):
        raise ValueError("measurement samples must be nonempty positive integer nanoseconds")
    ordered = sorted(samples)
    return {"count": len(samples), "min": ordered[0], "median": statistics.median(ordered),
            "p95": ordered[math.ceil(0.95 * len(ordered)) - 1], "max": ordered[-1]}


def checked_report(report: dict) -> str:
    if (report.get("handoff_at_cutoff") != "supported-under-receiver-context"
            or report.get("global_capture_completeness") != "unproven"
            or report.get("cross_source", {}).get("status") != "consistent-in-supplied-snapshots"):
        raise ValueError("benchmark input did not produce the required bounded handoff decision")
    for role in ("sender", "receiver"):
        item = report["receipts"][role]
        if (item["signature"] != "valid" or item["claim_binding"] != "matches-expected-handoff"
                or item["historical_authority"] != "authorized-at-observation"
                or item["current_authority"] != "authorized-for-current-policy"):
            raise ValueError("benchmark must not time failed or incomplete verification as success")
    return digest(report)


def process_peak_memory() -> dict:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        value = int(counters.PeakWorkingSetSize)
        method = "GetProcessMemoryInfo.PeakWorkingSetSize (bytes)"
    elif sys.platform.startswith("linux"):
        import resource
        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        method = "Linux getrusage(RUSAGE_SELF).ru_maxrss (KiB multiplied by 1024)"
    else:
        raise RuntimeError("whole-process memory measurement is supported only on Windows and Linux")
    if value <= 0:
        raise RuntimeError("process peak memory was unavailable; do not substitute zero")
    return {"bytes": value, "method": method}
