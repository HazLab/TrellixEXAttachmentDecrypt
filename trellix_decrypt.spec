# PyInstaller spec — one-file executable for the service.
# Build:  pyinstaller trellix_decrypt.spec
# Produces dist/trellix-decrypt (or trellix-decrypt.exe on Windows).
# Bundles the Jinja templates + static assets and uvicorn's dynamically-imported
# submodules. At runtime the executable still needs a writable DATA_DIR for the
# secret.key and SQLite DB (default: the working directory).

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("trellix_decrypt")  # templates/*, static/*
hiddenimports = (
    collect_submodules("uvicorn")       # loops, protocols, lifespan (dynamic imports)
    + collect_submodules("trellix_decrypt")
    + ["anyio", "sqlalchemy.dialects.sqlite"]
)

a = Analysis(
    ["pyinstaller_entry.py"],
    pathex=[],
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
