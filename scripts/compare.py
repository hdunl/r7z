"""Compare r7z with 7-Zip on real directories.

    python scripts/compare.py --r7z target/release/r7z --7z 7z [--levels 1,5,9] DIR [DIR...]

For each directory and level it measures `a` (create), `t` (test) and `x` (extract) for
both tools and prints a Markdown table: wall time, CPU time, peak memory, archive size.
Runs are cold for `a` (fresh archive) and warm for `t`/`x` (the archive is in the page
cache). Peak memory is the process peak working set on Windows and max RSS elsewhere.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time


def run(cmd):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t)
                for n in ("Peak", "WS", "QPP", "QP", "QPNP", "QNP", "PF", "PPF")
            ]

        class FT(ctypes.Structure):
            _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0400 | 0x0010, False, p.pid)
        p.wait()
        wall = time.perf_counter() - t0
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
        c, e, k, u = FT(), FT(), FT(), FT()
        ctypes.windll.kernel32.GetProcessTimes(h, *(ctypes.byref(x) for x in (c, e, k, u)))
        cpu = sum(((x.hi << 32) | x.lo) / 1e7 for x in (k, u))
        return wall, cpu, pmc.Peak / 2**20, p.returncode
    import resource

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wall = time.perf_counter() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    scale = 1 if sys.platform == "darwin" else 1024
    return wall, cpu, after.ru_maxrss * scale / 2**20, rc


def best(cmd, n, before=None):
    results = []
    for _ in range(n):
        if before:
            before()
        results.append(run(cmd))
    r = min(results, key=lambda x: x[0])
    if r[3] != 0:
        raise SystemExit(f"command failed ({r[3]}): {' '.join(cmd)}")
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r7z", default="target/release/r7z")
    ap.add_argument("--7z", dest="sevenzip", default="7z")
    ap.add_argument("--levels", default="1,5,9")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix="r7z-compare-")
    tools = [("r7z", a.r7z), ("7-Zip", a.sevenzip)]
    print("| Input | Level | Tool | Create | CPU | Peak mem | Size | Test | Extract |")
    print("|---|---|---|---|---|---|---|---|---|")
    try:
        for d in a.dirs:
            d = os.path.abspath(d)
            for level in a.levels.split(","):
                for name, exe in tools:
                    arc = os.path.join(work, f"{name}.7z")
                    out = os.path.join(work, "out")

                    def clean_arc():
                        if os.path.exists(arc):
                            os.remove(arc)

                    def clean_out():
                        shutil.rmtree(out, ignore_errors=True)

                    c = best([exe, "a", "-bd", f"-mx{level}", arc, d], 1, clean_arc)
                    size = os.path.getsize(arc)
                    t = best([exe, "t", "-bd", arc], a.repeat)
                    x = best([exe, "x", "-bd", "-y", f"-o{out}", arc], a.repeat, clean_out)
                    clean_out()
                    print(
                        f"| {os.path.basename(d)} | mx{level} | {name} | {c[0]:.2f} s | {c[1]:.1f} s "
                        f"| {c[2]:.0f} MiB | {size / 1e6:.2f} MB | {t[0]:.2f} s | {x[0]:.2f} s |",
                        flush=True,
                    )
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
