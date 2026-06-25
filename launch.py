#!/usr/bin/env python3
"""
Mobile App Analyzer — Launcher
Checks dependencies and starts the application.
"""

import sys
import subprocess
import importlib.util

REQUIRED = ["flask", "werkzeug"]
OPTIONAL = []  # future: androguard, frida, yara-python

def check_deps():
    missing = []
    for pkg in REQUIRED:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)
    return missing

def install(pkgs):
    print(f"Installing: {', '.join(pkgs)}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", *pkgs])

def main():
    print("=" * 50)
    print("  Mobile App Analyzer")
    print("=" * 50)

    missing = check_deps()
    if missing:
        print(f"Installing dependencies: {missing}")
        try:
            install(missing)
        except Exception as e:
            print(f"Error installing deps: {e}")
            print(f"Please run: pip install {' '.join(missing)}")
            sys.exit(1)

    print("Starting… browser will open automatically.")
    print("Press Ctrl+C to quit.\n")

    import runpy
    import os
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    runpy.run_path("analyzerr.py", run_name="__main__")

if __name__ == "__main__":
    main()
