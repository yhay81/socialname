#! /usr/bin/env python3

"""
SocialName: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import sys


if __name__ == "__main__":
    # Checking if the user is using the correct version of Python
    # Reference:
    #  If Python version is 3.6.5
    #               major --^
    #               minor ----^
    #               micro ------^
    (major, minor, micro, _, __) = sys.version_info

    PYTHON_VERSION = f"{major}.{minor}.{micro}"

    if major != 3 or major == 3 and minor < 6:
        print(
            (
                f"SocialName requires Python 3.6+\nYou are using Python {PYTHON_VERSION}, "
                "which is not supported by SocialName"
            )
        )
        sys.exit(1)

    from socialname.cli import command

    command.execute()
