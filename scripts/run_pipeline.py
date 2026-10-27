"""Run the whole analysis: XML -> model -> pseudocode -> index -> checks -> HTML reports.

Usage: python scripts/run_pipeline.py [--force]   (--force re-extracts every module, ignoring the cache)
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STEPS = [
    ["extract_model.py"],
    ["decompile_actions.py"],
    ["build_index.py"],
    ["checks/security.py"],
    ["generate_reports.py"],
]

if __name__ == "__main__":
    for step in STEPS:
        args = [sys.executable, os.path.join(HERE, step[0])] + step[1:]
        if step[0] == "extract_model.py" and "--force" in sys.argv:
            args.append("--force")
        t = time.time()
        print("== %s" % step[0], flush=True)
        if subprocess.call(args) != 0:
            sys.exit("Step %s failed" % step[0])
        print("   %.1fs" % (time.time() - t), flush=True)
