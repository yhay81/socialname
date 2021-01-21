#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import csv
import os
import platform
import re
import sys
import webbrowser
from argparse import ArgumentParser, RawDescriptionHelpFormatter

import requests

from socialname.notify import QueryNotifyPrint
from socialname.result import QueryStatus
from socialname.sites import SitesInformation
from socialname.sherlock import sherlock, timeout_check

MODULE_NAME = "Sherlock: Find Usernames Across Social Networks"
__version__ = "0.14.0"


def main() -> None:  # noqa

    version_string = (
        f"%(prog)s {__version__}\n"
        + f"{requests.__title__}:  {requests.__version__}\n"
        + f"Python:  {platform.python_version()}"
    )

    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{MODULE_NAME} (Version {__version__})",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=version_string,
        help="Display version information and dependencies.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        "-d",
        "--debug",
        action="store_true",
        dest="verbose",
        default=False,
        help="Display extra debugging information and metrics.",
    )
    parser.add_argument(
        "--folderoutput",
        "-fo",
        dest="folderoutput",
        help=(
            "If using multiple usernames, "
            "the output of the results will be saved to this folder."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output",
        help=(
            "If using single username, "
            "the output of the result will be saved to this file."
        ),
    )
    parser.add_argument(
        "--tor",
        "-t",
        action="store_true",
        dest="tor",
        default=False,
        help=(
            "Make requests over Tor; increases runtime; "
            "requires Tor to be installed and in system path."
        ),
    )
    parser.add_argument(
        "--unique-tor",
        "-u",
        action="store_true",
        dest="unique_tor",
        default=False,
        help=(
            "Make requests over Tor with new Tor circuit after each request;"
            " increases runtime; requires Tor to be installed and in system path."
        ),
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        dest="csv",
        default=False,
        help="Create Comma-Separated Values (CSV) File.",
    )
    parser.add_argument(
        "--site",
        action="append",
        metavar="SITE_NAME",
        dest="site_list",
        default=None,
        help=(
            "Limit analysis to just the listed sites. "
            "Add multiple options to specify more than one site."
        ),
    )
    parser.add_argument(
        "--proxy",
        "-p",
        metavar="PROXY_URL",
        action="store",
        dest="proxy",
        default=None,
        help="Make requests over a proxy. e.g. socks5://127.0.0.1:1080",
    )
    parser.add_argument(
        "--json",
        "-j",
        metavar="JSON_FILE",
        dest="json_file",
        default=None,
        help="Load data from a JSON file or an online, valid, JSON file.",
    )
    parser.add_argument(
        "--timeout",
        action="store",
        metavar="TIMEOUT",
        dest="timeout",
        type=timeout_check,
        default=None,
        help="Time (in seconds) to wait for response to requests. "
        "Default timeout is infinity. "
        "A longer timeout will be more likely to get results from slow sites. "
        "On the other hand, this may cause a long delay to gather all results.",
    )
    parser.add_argument(
        "--print-all",
        action="store_true",
        dest="print_all",
        help="Output sites where the username was not found.",
    )
    parser.add_argument(
        "--print-found",
        action="store_false",
        dest="print_all",
        default=False,
        help="Output sites where the username was found.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        default=False,
        help="Don't color terminal output",
    )
    parser.add_argument(
        "username",
        nargs="+",
        metavar="USERNAMES",
        action="store",
        help="One or more usernames to check with social networks.",
    )
    parser.add_argument(
        "--browse",
        "-b",
        action="store_true",
        dest="browse",
        default=False,
        help="Browse to all results on default browser.",
    )

    parser.add_argument(
        "--local",
        "-l",
        action="store_true",
        default=False,
        help="Force the use of the local data.json file.",
    )

    parser.add_argument(
        "--singleoutput",
        "-s",
        action="store_true",
        default=False,
        help="Store all the outputs into 1 single file",
    )

    parser.add_argument(
        "--workers", "-w", type=int, default=20, help="Number of workers"
    )

    args = parser.parse_args()

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
        print(f"A problem occured while checking for an update: {error}")

    # Argument check
    # TODO(yhay81) regex check on args.proxy
    if args.tor and (args.proxy is not None):
        raise ValueError("Tor and Proxy cannot be set at the same time.")

    # Make prompts
    if args.proxy is not None:
        print("Using the proxy: " + args.proxy)

    if args.tor or args.unique_tor:
        print("Using Tor to make requests")
        print(
            (
                "Warning: some websites might refuse connecting over Tor, "
                "so note that using this option might increase connection errors."
            )
        )

    # Check if both output methods are entered as input.
    if args.output is not None and args.folderoutput is not None:
        print("You can only use one of the output methods.")
        sys.exit(1)

    # Check validity for single username output.
    if args.output is not None and len(args.username) != 1:
        print("You can only use --output with a single username")
        sys.exit(1)

    if args.singleoutput:
        with open("master.csv", "w", newline="", encoding="utf-8") as csv_report:
            writer = csv.writer(csv_report)
            writer.writerow(["username", "name", "url_user", "account_count"])

    # Create object with all information about sites we are aware of.
    try:
        if args.local:
            sites = SitesInformation(
                data_file_path=os.path.join(
                    os.path.dirname(__file__), "resources/data.json"
                )
            )
        else:
            sites = SitesInformation(data_file_path=args.json_file)
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    # Create original dictionary from SitesInformation() object.
    # Eventually, the rest of the code will be updated to use the new object
    # directly, but this will glue the two pieces together.
    site_data_all = {}
    for site in sites:
        site_data_all[site.name] = site.information

    if args.site_list is None:
        # Not desired to look at a sub-set of sites
        site_data = site_data_all
    else:
        # User desires to selectively run queries on a sub-set of the site list.

        # Make sure that the sites are supported & build up pruned site database.
        site_data = {}
        site_missing = []
        for site_name in args.site_list:
            counter = 0
            for existing_site in site_data_all:
                if site_name.lower() == existing_site.lower():
                    site_data[existing_site] = site_data_all[existing_site]
                    counter += 1
            if counter == 0:
                # Build up list of sites not supported for future error message.
                site_missing.append(f"'{site_name}'")

        if site_missing:
            print(f"Error: Desired sites not found: {', '.join(site_missing)}.")

        if not site_data:
            sys.exit(1)

    # Create notify object for query results.
    query_notify = QueryNotifyPrint(
        result=None,
        verbose=args.verbose,
        print_all=args.print_all,
        color=not args.no_color,
    )

    # Run report on all specified users.
    for username in args.username:
        results = sherlock(
            username,
            site_data,
            query_notify,
            tor=args.tor,
            unique_tor=args.unique_tor,
            proxy=args.proxy,
            timeout=args.timeout,
            workers=args.workers,
        )

        if args.output:
            result_file = args.output
        elif args.folderoutput:
            # The usernames results should be stored in a targeted folder.
            # If the folder doesn't exist, create it first
            os.makedirs(args.folderoutput, exist_ok=True)
            result_file = os.path.join(args.folderoutput, f"{username}.txt")
        else:
            result_file = f"{username}.txt"

        if args.singleoutput:
            with open("master.csv", "a", newline="", encoding="utf-8") as csv_report:
                writer = csv.writer(csv_report)
                exists_counter = 0
                csvdata = []
                for name, info in results.items():
                    if info["status"].status == QueryStatus.CLAIMED:
                        exists_counter += 1
                        csvdata.append({"site": name, "url": info["url_user"]})

                for data in csvdata:
                    writer.writerow(
                        [username, data["site"], data["url"], exists_counter]
                    )
        else:
            with open(result_file, "w", encoding="utf-8") as file:
                exists_counter = 0
                for website_name in results:
                    dictionary = results[website_name]
                    if (
                        "status" in dictionary
                        and dictionary["status"].status == QueryStatus.CLAIMED
                    ):
                        exists_counter += 1
                        file.write(dictionary["url_user"] + "\n")
                file.write(f"Total Websites Username Detected On : {exists_counter}\n")

            if args.csv:
                with open(
                    username + ".csv", "w", newline="", encoding="utf-8"
                ) as csv_report:
                    writer = csv.writer(csv_report)
                    writer.writerow(
                        [
                            "username",
                            "name",
                            "url_main",
                            "url_user",
                            "exists",
                            "http_status",
                            "response_time_s",
                        ]
                    )
                    for site_ in results:
                        response_time_s = results[site_]["status"].query_time
                        if response_time_s is None:
                            response_time_s = ""
                        writer.writerow(
                            [
                                username,
                                site_,
                                results[site_]["url_main"],
                                results[site_]["url_user"],
                                str(results[site_]["status"].status),
                                results[site_]["http_status"],
                                response_time_s,
                            ]
                        )
        print()

        # opening web browser after results are computed
        if args.browse:
            with open(result_file, "r", encoding="utf-8") as file:
                for website_name in results:
                    dictionary = results[website_name]
                    if (
                        "status" in dictionary
                        and dictionary["status"].status == QueryStatus.CLAIMED
                    ):
                        webbrowser.open_new_tab(dictionary["url_user"])


if __name__ == "__main__":
    main()
