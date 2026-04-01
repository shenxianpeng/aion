import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from aion.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
