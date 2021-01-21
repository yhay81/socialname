"""Sherlock Sites Information Module

This module supports storing information about web sites.
This is the raw data that will be used to search for usernames.
"""
import dataclasses
from typing import Any, Dict, List, Optional, Iterator
import urllib.parse

from socialname import load_sites


@dataclasses.dataclass
class SiteInformation:
    """Site Information Object.

    Contains information about a specific web site.

    Keyword Arguments:
    name                 -- String which identifies site.
    url_home             -- String containing URL for home of site.
    url_username_format  -- String containing URL for Username format on site.
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
    url_home: str
    url_username_format: str
    username_claimed: str
    username_unclaimed: str
    information: Dict[str, Any]

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """

        return f"{self.name} ({self.url_home})"


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
            for name, data in site_data.items():
                self.sites[name] = SiteInformation(
                    name=name,
                    url_home=data["urlMain"],
                    url_username_format=data["url"],
                    username_claimed=data["username_claimed"],
                    username_unclaimed=data["username_unclaimed"],
                    information=data,
                )
        else:
            for name in filter_list:
                if name in site_data:
                    self.sites[name] = SiteInformation(
                        name=name,
                        url_home=site_data[name]["urlMain"],
                        url_username_format=site_data[name]["url"],
                        username_claimed=site_data[name]["username_claimed"],
                        username_unclaimed=site_data[name]["username_unclaimed"],
                        information=site_data[name],
                    )
                else:
                    print(f"Error: Desired sites not found: {name}.")

    def get_dict(self) -> Dict[str, Dict[str, Any]]:
        return {name: site_info.information for name, site_info in self.sites.items()}

    def __iter__(self) -> Iterator[SiteInformation]:
        """Iterator For Object.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Iterator for sites object.
        """

        for info in self.sites.values():
            yield info
