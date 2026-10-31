"""Print per-function line coverage of the module from a gcovr JSON report.

Functions are listed from least to most covered, so the gaps come first.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict


def main(path: str) -> None:
    with open(path) as report:
        data = json.load(report)

    for entry in data["files"]:
        functions = sorted(entry.get("functions", []), key=lambda f: f["lineno"])
        if not functions:
            continue
        starts = [f["lineno"] for f in functions]

        # Attribute every instrumented line to the function that starts
        # closest above it; gcovr reports functions by first line only.
        totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for line in entry["lines"]:
            if line.get("gcovr/noncode"):
                continue
            owner = None
            for function, start in zip(functions, starts):
                if start > line["line_number"]:
                    break
                owner = function
            if owner is None:
                continue
            counts = totals[owner["name"]]
            counts[1] += 1
            if line["count"] > 0:
                counts[0] += 1

        rows = []
        for function in functions:
            covered, total = totals[function["name"]]
            share = covered / total if total else 1.0
            rows.append((share, function["execution_count"], function["name"], covered, total))

        print(f"{entry['file']}: per-function line coverage (least covered first)")
        print(f"{'lines':>11}  {'share':>6}  {'calls':>7}  function")
        for share, calls, name, covered, total in sorted(rows):
            print(f"{covered:>5}/{total:<5}  {share:>6.0%}  {calls:>7}  {name}")


if __name__ == "__main__":
    main(sys.argv[1])
