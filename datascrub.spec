# datascrub.spec — PyInstaller build spec
# Build with: pyinstaller datascrub.spec --clean

from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT
from PyInstaller.utils.hooks import collect_data_files
import sys as _sys

block_cipher = None

# CustomTkinter ships JSON theme files that must be bundled
_ctk_datas = collect_data_files("customtkinter")

a = Analysis(
    ["datascrub_launch.py"],
    pathex=["."],
    binaries=[],
    datas=_ctk_datas,
    hiddenimports=[
        "customtkinter",
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
        # pyyaml (used by config.py for custom patterns)
        "yaml",
        "_yaml",
        # datascrub modules
        "datascrub",
        "datascrub.engine",
        "datascrub.patterns",
        "datascrub.handlers",
        "datascrub.config",
        "datascrub.gui",
        "datascrub.gui.app",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["textual"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

import sys as _sys

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="datascrub",
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
