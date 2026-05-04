"""
Standalone entry point for the PyInstaller-built datascrub executable.
"""
import os
os.environ.setdefault("PYTHONUTF8", "1")

from datascrub.gui.app import DataScrubApp

if __name__ == "__main__":
    DataScrubApp().mainloop()
