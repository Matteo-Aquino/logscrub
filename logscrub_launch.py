"""
Standalone entry point for the PyInstaller-built logscrub executable.

Delegates to the same main() used by the installed console script so there
is a single code path and the two entry points cannot diverge.
"""
import os
os.environ.setdefault("PYTHONUTF8", "1")

from logscrub.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()
