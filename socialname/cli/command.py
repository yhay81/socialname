import re
import sys
import pathlib

import requests

from socialname.notify import QueryNotifyPrint
from socialname.sites import create_sites_info
from socialname.socialname import socialname
from socialname.output import write_csv, write_csv_singleoutput, open_browser
from socialname.__version__ import __version__

from .args import get_args, check_args


def check_newer_version() -> None:
    # Check for newer version of SocialName. If it exists, let the user know about it
    try:
        res = requests.get(
            "https://raw.githubusercontent.com/yhay81/socialname/master/socialname/__version__.py"
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


def execute() -> None:
    check_newer_version()
    args = get_args()
    check_args(args)

    # Create object with all information about sites we are aware of.
    data_file_path = (
        str(
            pathlib.Path(__file__)
            .parent.parent.joinpath("resources/data.json")
            .resolve()
        )
        if args.local
        else args.json_file
    )
    try:
        sites_info = create_sites_info(
            data_file_path=data_file_path, filter_list=args.site_list
        )
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    # Create notify object for query results.
    query_notify = QueryNotifyPrint(
        verbose=args.verbose,
        print_all=args.print_all,
        color=not args.no_color,
    )

    # Run report on all specified users.
    total_results = {
        username: socialname(
            username=username,
            sites_info=sites_info,
            query_notify=query_notify,
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
            write_csv_singleoutput(total_results)
        else:
            write_csv(total_results)

    if args.browse:
        open_browser(total_results)


if __name__ == "__main__":
    execute()
