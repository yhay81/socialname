#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import os
import re
import sys

import requests

from socialname.notify import QueryNotifyPrint
from socialname.sites import SitesInformation
from socialname.sherlock import sherlock
from socialname.args import get_args, check_args
from socialname.output import write_csv, write_csv_singleoutput, open_browser
from socialname.__version__ import __version__


def check_newer_version() -> None:
    # Check for newer version of Sherlock. If it exists, let the user know about it
    try:
        res = requests.get(
            "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock/sherlock.py"
        )

        remote_version = str(re.findall('__version__ = "(.*)"', res.text)[0])
        local_version = __version__

        if remote_version != local_version:
            print(
                "Update Available!\n"
                + f"You are running version {local_version}. "
                + f"Version {remote_version} is available at https://git.io/sherlock"
            )

    except Exception as error:
        print(f"A problem occurred while checking for an update: {error}")


def run() -> None:  # noqa
    check_newer_version()
    args = get_args()
    check_args(args)

    # Create object with all information about sites we are aware of.
    data_file_path = (
        os.path.join(os.path.dirname(__file__), "resources/data.json")
        if args.local
        else args.json_file
    )
    try:
        sites = SitesInformation(
            data_file_path=data_file_path, filter_list=args.site_list
        )
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    # Create notify object for query results.
    query_notify = QueryNotifyPrint(
        result=None,
        verbose=args.verbose,
        print_all=args.print_all,
        color=not args.no_color,
    )

    # Run report on all specified users.
    results = {
        username: sherlock(
            username,
            sites.get_dict(),
            query_notify,
            tor=args.tor,
            unique_tor=args.unique_tor,
            proxy=args.proxy,
            timeout=args.timeout,
            workers=args.workers,
        )
        for username in args.username
    }

    if args.csv:
        if args.singleoutput:
            write_csv_singleoutput(results)
        else:
            write_csv(results)

    if args.browse:
        open_browser(results)


if __name__ == "__main__":
    run()
