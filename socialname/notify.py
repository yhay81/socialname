"""SocialName Notify Module

This module defines the objects for notifying the caller about the
results of queries.
"""
import dataclasses
from typing import Optional, Union

from colorama import Fore, Style, init

from socialname.result import SocialNameResult, SocialNameStatus


class QueryNotify:
    """Query Notify Object.

    Base class that describes methods available to notify the results of
    a query.
    It is intended that other classes inherit from this base class and
    override the methods to implement specific functionality.
    """

    def __init__(self, result: Optional[SocialNameResult] = None) -> None:
        """Create Query Notify Object.

        Contains information about a specific method of notifying the results
        of a query.

        Keyword Arguments:
        self                 -- This object.
        result               -- Object of type QueryResult() containing
                                results for this query.

        Return Value:
        Nothing.
        """

        self.result = result

    def start(self, message: Optional[str] = None) -> None:
        """Notify Start.

        Notify method for start of query.  This method will be called before
        any queries are performed.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                 -- This object.
        message              -- Object that is used to give context to start
                                of query.
                                Default is None.

        Return Value:
        Nothing.
        """

    def update(self, result: SocialNameResult) -> None:
        """Notify Update.

        Notify method for query result.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                 -- This object.
        result               -- Object of type QueryResult() containing
                                results for this query.

        Return Value:
        Nothing.
        """

        self.result = result

    def finish(self, message: Optional[str] = None) -> None:
        """Notify Finish.

        Notify method for finish of query.  This method will be called after
        all queries have been performed.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                 -- This object.
        message              -- Object that is used to give context to start
                                of query.
                                Default is None.

        Return Value:
        Nothing.
        """

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """
        return str(self.result)


@dataclasses.dataclass
class PrintStyle:
    bright: Union[str, int] = ""
    reset_all: Union[str, int] = ""
    white: Union[str, int] = ""
    green: Union[str, int] = ""
    yellow: Union[str, int] = ""
    red: Union[str, int] = ""
    color: dataclasses.InitVar[bool] = False

    def __post_init__(self, color: bool) -> None:
        if color is True:
            self.bright = Style.BRIGHT
            self.reset_all = Style.RESET_ALL
            self.white = Fore.WHITE
            self.green = Fore.GREEN
            self.yellow = Fore.YELLOW
            self.red = Fore.RED


class QueryNotifyPrint(QueryNotify):
    """Query Notify Print Object.

    Query notify class that prints results.
    """

    def __init__(
        self,
        result: Optional[SocialNameResult] = None,
        verbose: bool = False,
        color: bool = True,
        print_all: bool = False,
    ) -> None:
        """Create Query Notify Print Object.

        Contains information about a specific method of notifying the results
        of a query.

        Keyword Arguments:
        self                 -- This object.
        result               -- Object of type QueryResult() containing
                                results for this query.
        verbose              -- Boolean indicating whether to give verbose output.
        print_all            -- Boolean indicating whether to only print all sites,
                                including not found.
        color                -- Boolean indicating whether to color terminal output

        Return Value:
        Nothing.
        """

        # Colorama module's initialization.
        init(autoreset=True)

        super().__init__(result)
        self.verbose = verbose
        self.print_all = print_all
        self.sty = PrintStyle(color=color)

    def start(self, message: Optional[str] = None) -> None:
        """Notify Start.

        Will print the title to the standard output.

        Keyword Arguments:
        self                 -- This object.
        message              -- String containing username that the series
                                of queries are about.

        Return Value:
        Nothing.
        """

        title = "Checking username"
        print(
            f"{self.sty.bright}{self.sty.green}[{self.sty.yellow}*{self.sty.green}] {title}"
            f"{self.sty.white} {message}{self.sty.green} on:"
        )

    def update(self, result: SocialNameResult) -> None:
        """Notify Update.

        Will print the query result to the standard output.

        Keyword Arguments:
        self                 -- This object.
        result               -- Object of type QueryResult() containing
                                results for this query.

        Return Value:
        Nothing.
        """
        self.result = result

        if self.verbose is False or result.elapsed_time is None:
            response_time_text = ""
        else:
            response_time_text = f" [{round(result.elapsed_time * 1000)} ms]"

        # Output to the terminal is desired.
        if result.status == SocialNameStatus.CLAIMED:
            print(
                (
                    f"{self.sty.bright}{self.sty.white}[{self.sty.green}+{self.sty.white}]{response_time_text} "
                    f"{self.sty.green}{result.site_name}: "
                    f"{self.sty.reset_all}{result.url_user}"
                )
            )

        elif result.status == SocialNameStatus.AVAILABLE:
            if self.print_all:
                print(
                    f"{self.sty.bright}{self.sty.white}[{self.sty.red}-{self.sty.white}]{response_time_text} "
                    f"{self.sty.green}{result.site_name}: "
                    f"{self.sty.yellow}Not Found!"
                )

        elif result.status == SocialNameStatus.UNKNOWN:
            if self.print_all:
                print(
                    f"{self.sty.bright}{self.sty.white}[{self.sty.red}-{self.sty.white}] "
                    f"{self.sty.green}{result.site_name}: "
                    f"{self.sty.red}{result.context}{self.sty.yellow} "
                )

        elif result.status == SocialNameStatus.ILLEGAL:
            if self.print_all:
                msg = "Illegal Username Format For This Site!"
                print(
                    f"{self.sty.bright}{self.sty.white}[{self.sty.red}-{self.sty.white}] "
                    f"{self.sty.green}{result.site_name} {self.sty.yellow}{msg}"
                )

        else:
            # It should be impossible to ever get here...
            raise ValueError(
                f"Unknown Query Status '{str(result.status)}' for "
                f"site '{result.site_name}'"
            )
