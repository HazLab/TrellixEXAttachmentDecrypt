"""PyInstaller entry point.

Importing ``trellix_decrypt.__main__`` as a package module (rather than running
``__main__.py`` directly, which PyInstaller would execute as top-level ``__main__``
and break its ``from .app import build`` relative import) keeps package-relative
imports working inside the frozen executable.
"""

from trellix_decrypt.__main__ import main

if __name__ == "__main__":
    main()
