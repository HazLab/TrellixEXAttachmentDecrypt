# PyInstaller spec — one-file executable for the service.
# Build:  pyinstaller trellix_decrypt.spec
# Produces dist/trellix-decrypt (or trellix-decrypt.exe on Windows).
# Bundles the Jinja templates + static assets and uvicorn's dynamically-imported
# submodules. At runtime the executable still needs a writable DATA_DIR for the
# secret.key and SQLite DB (default: the working directory).

import os
import sys

from PyInstaller.utils.hooks import collect_submodules

# The package is NOT pip-installed in the build environment (CI installs only the
# requirements), so it must be made importable for collect_submodules, and its data
# files are listed by PATH rather than discovered by import: collect_data_files()
# silently returns nothing for a package it cannot import, which shipped executables
# with no templates/static and crashed them at startup.
sys.path.insert(0, SPECPATH)
_PKG = os.path.join(SPECPATH, "trellix_decrypt")
datas = [
    (os.path.join(_PKG, "templates"), "trellix_decrypt/templates"),
    (os.path.join(_PKG, "static"), "trellix_decrypt/static"),
]
for _src, _ in datas:
    if not os.path.isdir(_src):
        raise SystemExit(f"build aborted: data directory missing: {_src}")
hiddenimports = (
    collect_submodules("uvicorn")       # loops, protocols, lifespan (dynamic imports)
    + collect_submodules("trellix_decrypt")
    + ["anyio", "sqlalchemy.dialects.sqlite"]
)

a = Analysis(
    ["pyinstaller_entry.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="trellix-decrypt",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
