import os
os.environ.setdefault("PYTHONUTF8", "1")

from datascrub.gui.app import DataScrubApp


def main() -> None:
    DataScrubApp().mainloop()


if __name__ == "__main__":
    main()
