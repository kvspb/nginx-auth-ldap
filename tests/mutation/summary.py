"""Print a Markdown summary of a Mull report (mutation.json) for CI."""

import json
import sys
from pathlib import Path


def main(report_path: str) -> None:
    report = json.loads(Path(report_path).read_text())
    mutants = [(path, mutant) for path, entry in report["files"].items() for mutant in entry["mutants"]]
    survivors = [(path, m) for path, m in mutants if m["status"] != "Killed"]
    killed = len(mutants) - len(survivors)

    print(f"### Mutation testing: {killed} of {len(mutants)} mutants killed\n")
    if not survivors:
        return
    print("Kill each survivor with a test or explain it in the pull request.\n")
    print("| Location | Mutator | Replacement | Status |")
    print("|---|---|---|---|")
    for path, m in survivors:
        line = m["location"]["start"]["line"]
        where = f"{path.removeprefix('/src/')}:{line}"
        replacement = m.get("replacement", "")
        print(f"| `{where}` | {m['mutatorName']} | `{replacement}` | {m['status']} |")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/reports/mutation/mutation.json")
