"""Sherlock Sites Information Module

This module supports storing information about web sites.
This is the raw data that will be used to search for usernames.
"""
import dataclasses
from typing import Any, Dict, List, Optional, Iterator, Tuple, Union
import urllib.parse

from socialname import load_sites


@dataclasses.dataclass
class SiteInformation:  # noqa
    """Site Information Object.

    Contains information about a specific web site.

    Keyword Arguments:
    name                 -- String which identifies site.
    url_main             -- String containing URL for home of site.
    url_user  -- String containing URL for Username format on site.
                            NOTE:  The string should contain the token "{}"
                            where the username should be substituted.
                            For example, a string of "https://somesite.com/users/{}"
                            indicates that the individual usernames would show up
                            under the "https://somesite.com/users/" area of the web site.
    username_claimed     -- String containing username which is known
                            to be claimed on web site.
    username_unclaimed   -- String containing username which is known
                            to be unclaimed on web site.
    information          -- Dictionary containing all known information
                            about web site.
                            NOTE:  Custom information about how to actually detect
                            the existence of the username will be included in this dictionary.
                            This information will be needed by the detection method,
                            but it is only recorded in this object for future use.
    """

    name: str
    url_main: str = dataclasses.field(init=False, repr=False)
    url_user: str = dataclasses.field(init=False, repr=False)
    username_claimed: str = dataclasses.field(init=False, repr=False)
    username_unclaimed: str = dataclasses.field(init=False, repr=False)
    headers: Dict[str, str] = dataclasses.field(init=False, repr=False)
    request_method: str = dataclasses.field(init=False, repr=False)
    request_head_only: bool = dataclasses.field(init=False, repr=False)
    error_type: Optional[str] = dataclasses.field(init=False, repr=False)
    error_message: Optional[Union[str, List[str]]] = dataclasses.field(
        init=False, repr=False
    )
    regex_check: Optional[str] = dataclasses.field(init=False, repr=False)
    url_probe: Optional[str] = dataclasses.field(init=False, repr=False)
    information: Dict[str, Any] = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        self.headers = self.information.get("headers", {})
        self.error_type = self.information.get("errorType")
        self.error_message = self.information.get("errorMsg")
        self.regex_check = self.information.get("regexCheck")
        self.request_head_only = self.information.get("request_head_only", False)
        self.request_method = self.information.get("request_method", "GET")
        self.url_main = self.information["urlMain"]
        self.url_probe = self.information.get("urlProbe")
        self.url_user = self.information["url"]
        self.username_claimed = self.information["username_claimed"]
        self.username_unclaimed = self.information["username_unclaimed"]

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """

        return f"{self.name} ({self.url_main})"


class SitesInformation:
    """Sites Information Object.

    Contains information about all supported web sites.

    Keyword Arguments:
    data_file_path   -- String which indicates path to data file.
                        The file name must end in ".json".

                        There are 3 possible formats:
                        * Absolute File Format
                            For example, "c:/stuff/data.json".
                        * Relative File Format
                            The current working directory is used as the context.
                            For example, "data.json".
                        * URL Format
                            For example,
                            "https://example.com/data.json", or
                            "http://example.com/data.json".

                            An exception will be thrown if the path to the data file is not
                            in the expected format, or if there was any problem loading the file.

                            If this option is not specified, then a default site list will be used.
    """

    sites: Dict[str, SiteInformation]
    data_file_path: Optional[str] = None
    filter_list: Optional[List[str]] = None

    def __init__(
        self, data_file_path: Optional[str] = None, filter_list: Optional[str] = None
    ) -> None:
        self.sites: Dict[str, SiteInformation] = {}
        if data_file_path is None:
            # The default data file is the live data.json which is in the GitHub repo.
            # The reason why we are using this instead of the local one is so that
            # the user has the most up to date data. This prevents users from creating
            # issue about false positives which has already been fixed or having outdated data
            data_file_path = (
                "https://raw.githubusercontent.com"
                "/sherlock-project/sherlock/master/sherlock/resources/data.json"
            )
        # Ensure that specified data file has correct extension.
        if not data_file_path.lower().endswith(".json"):
            raise FileNotFoundError(
                f"Incorrect JSON file extension for data file '{data_file_path}'."
            )

        if urllib.parse.urlparse(data_file_path).scheme in ["http", "https"]:
            site_data = load_sites.from_url(data_file_path)
        else:
            site_data = load_sites.from_file(data_file_path)

        # Add all of site information from the json file to internal site list.
        if filter_list is None:
            for site_name, information in site_data.items():
                self.sites[site_name] = SiteInformation(
                    name=site_name, information=information
                )
        else:
            for site_name in filter_list:
                if site_name in site_data:
                    information = site_data[site_name]
                    self.sites[site_name] = SiteInformation(
                        name=site_name, information=information
                    )
                else:
                    print(f"Error: Desired sites not found: {site_name}.")

    def get_dict(self) -> Dict[str, Dict[str, Any]]:
        return {
            site_name: site_info.information
            for site_name, site_info in self.sites.items()
        }

    def __iter__(self) -> Iterator[Tuple[str, SiteInformation]]:
        """Iterator For Object.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Iterator for sites object.
        """

        for site_name, site_info in self.sites.items():
            yield site_name, site_info

    def __len__(self) -> int:
        """Length Of Object.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        length of sites object.
        """

        return len(self.sites)
