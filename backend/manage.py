#!/usr/bin/env python
"""Django management entry point for the forensic backend."""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")
    if sys.argv[1:2] != ["runserver"]:
        import api.apps

        # a command run beside a live server leaves its staging area alone
        api.apps.SERVING = False
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
