from typing import Union
import argparse
import platform
import sys

import requests
from socialname.__version__ import __version__, __title__


def timeout_check(value: Union[float, int, str]) -> float:
    """Check Timeout Argument.

    Checks timeout for validity.

    Keyword Arguments:
    value                  -- Time in seconds to wait before timing out request.

    Return Value:
    Floating point number representing the time (in seconds) that should be
    used for the timeout.

    NOTE:  Will raise an exception if the timeout in invalid.
    """

    try:
        timeout = float(value)
    except Exception:
        raise argparse.ArgumentTypeError(f"Timeout '{value}' must be a number.")
    if timeout <= 0:
        raise argparse.ArgumentTypeError(
            f"Timeout '{value}' must be greater than 0.0s."
        )
    return timeout


def get_args() -> argparse.Namespace:
    version_string = (
        f"%(prog)s {__version__}\n"
        + f"{requests.__title__}:  {requests.__version__}\n"
        + f"Python:  {platform.python_version()}"
    )

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{__title__} (Version {__version__})",
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
        default=True,
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

    return parser.parse_args()


def check_args(args: argparse.Namespace) -> None:
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
