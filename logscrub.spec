# logscrub.spec — PyInstaller build spec
# Build with: pyinstaller logscrub.spec --clean

from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT
from PyInstaller.utils.hooks import collect_data_files
import sys as _sys

block_cipher = None

# PySide6 ships Qt plugins and binaries that must be bundled
_pyside6_datas = collect_data_files("PySide6")

a = Analysis(
    ["logscrub_launch.py"],
    pathex=["."],
    binaries=[],
    datas=_pyside6_datas,
    hiddenimports=[
        "PySide6",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        # logscrub modules
        "logscrub",
        "logscrub.engine",
        "logscrub.patterns",
        "logscrub.handlers",
        "logscrub.gui",
        "logscrub.gui.app",
        "logscrub.audit",
        "logscrub.profiles",
        "logscrub.cli",
        "platformdirs",
        "yaml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["customtkinter", "tkinter", "textual"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="logscrub",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # GUI app — no terminal window on Windows; on Linux console=False is fine too
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    **({"version": None} if _sys.platform == "win32" else {}),
)
