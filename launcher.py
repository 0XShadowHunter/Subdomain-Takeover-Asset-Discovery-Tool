"""PyInstaller entry point — keeps one copy of src.cli in the frozen bundle.

Build (from the project root, with the venv active):
    pyinstaller --onefile --name subtake --console --paths . ^
        --add-data "config;config" ^
        --add-data "data\\wordlists;data\\wordlists" ^
        --add-data "src\\reporting\\templates;src\\reporting\\templates" ^
        launcher.py

Double-clicking the resulting dist\\subtake.exe opens the GUI; running it from
a terminal with arguments uses the CLI (see scripts\\install.ps1 for the
automated "install as a program" flow).
"""

import sys

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
