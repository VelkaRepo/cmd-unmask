"""Allow invoking cmd-unmask via `python -m cmd_unmask`."""

import sys
from cmd_unmask.cli import main

if __name__ == "__main__":
    sys.exit(main())
