"""Run the RED-AI capability range and write the report.

    python -m redai_range            # run the ladder, print the matrix
    python -m redai_range --write    # also write docs/RANGE_REPORT.md
"""
from __future__ import annotations

import sys
from pathlib import Path

from redai_range.harness import run_all, render_report, frontier


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    print("RED-AI capability range: running the ladder against the live engage pipeline...\n",
          flush=True)
    results = run_all()
    for r in sorted(results, key=lambda r: r.box.difficulty):
        val = f"  -> {r.value}" if r.value else ""
        print(f"  L{r.box.difficulty} {r.box.id:<28} {r.verdict:<16}{val}", flush=True)
    cleared, gap = frontier(results)
    print(f"\nFrontier: clears L1-L{cleared}.", flush=True)
    if gap is not None:
        print(f"First gap: {gap.box.id} ({gap.box.archetype}) -> needs {gap.box.capability}.",
              flush=True)
    fp = [r for r in results if r.verdict == "FALSE-POSITIVE"]
    reg = [r for r in results if r.verdict == "REGRESSION"]
    if fp:
        print(f"\n!! {len(fp)} FALSE POSITIVE(S) -- must be zero:", flush=True)
        for r in fp:
            print(f"   {r.box.id}: claimed {r.value!r}, real flag {r.box.flag!r}", flush=True)
    if reg:
        print(f"\n!! {len(reg)} REGRESSION(S):", flush=True)
        for r in reg:
            print(f"   {r.box.id}: expected capture, got none", flush=True)

    if "--write" in argv:
        out = Path(__file__).resolve().parent.parent / "docs" / "RANGE_REPORT.md"
        out.write_text(render_report(results), encoding="utf-8")
        print(f"\nReport written: {out}", flush=True)

    # non-zero exit on a real problem (false positive or regression), for CI
    return 1 if (fp or reg) else 0


if __name__ == "__main__":
    sys.exit(main())
