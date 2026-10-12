"""GUI application entry point (install with ``pip install .[gui]``)."""
from __future__ import annotations

import sys


def main() -> int:
    if "--reload" in sys.argv[1:]:
        from seclab.gui.dev import main as dev_main
        return dev_main()
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        raise SystemExit("GUI dependencies are missing. Install the optional extra: pip install .[gui]") from exc
    from seclab.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
