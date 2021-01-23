"""SocialName Sites Information Module

This module supports storing information about web sites.
This is the raw data that will be used to search for usernames.
"""
import dataclasses
from typing import Any, Dict, Optional
import urllib.parse

from socialname import sites_load


@dataclasses.dataclass
class SiteInformation:
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

    site_name: str
    logic: str = dataclasses.field(init=False, repr=False)
    url_main: str = dataclasses.field(init=False, repr=False)
    url_user: str = dataclasses.field(init=False, repr=False)
    url_probe: Optional[str] = dataclasses.field(init=False, repr=False)
    regex_check: Optional[str] = dataclasses.field(init=False, repr=False)
    username_claimed: str = dataclasses.field(init=False, repr=False)
    username_unclaimed: str = dataclasses.field(init=False, repr=False)
    options: Dict[str, Any] = dataclasses.field(init=False, repr=False)
    information: dataclasses.InitVar[Dict[str, Any]] = dataclasses.field(repr=False)

    def __post_init__(self, information: Dict[str, Any]) -> None:
        self.logic = information["logic"]
        self.url_main = information["urlMain"]
        self.url_user = information["urlUser"]
        self.url_probe = information.get("urlProbe", None)
        self.regex_check = information.get("regexCheck", None)
        self.username_claimed = information["usernameClaimed"]
        self.username_unclaimed = information["usernameUnclaimed"]
        self.options = information.get("options", {})

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """

        return f"{self.site_name} ({self.url_main})"


def create_sites_info(
    data_file_path: Optional[str] = None, filter_list: Optional[str] = None
) -> Dict[str, SiteInformation]:

    sites_info: Dict[str, SiteInformation] = {}

    if data_file_path is None:
        # The default data file is the live data.json which is in the GitHub repo.
        # The reason why we are using this instead of the local one is so that
        # the user has the most up to date data. This prevents users from creating
        # issue about false positives which has already been fixed or having outdated data
        data_file_path = (
            "https://raw.githubusercontent.com"
            "/yhay81/socialname/master/socialname/resources/data.json"
        )
    # Ensure that specified data file has correct extension.
    if not data_file_path.lower().endswith(".json"):
        raise FileNotFoundError(
            f"Incorrect JSON file extension for data file '{data_file_path}'."
        )

    if urllib.parse.urlparse(data_file_path).scheme in ["http", "https"]:
        site_data = sites_load.from_url(data_file_path)
    else:
        site_data = sites_load.from_file(data_file_path)

    # Add all of site information from the json file to internal site list.
    if filter_list is None:
        for site_name, information in site_data.items():
            sites_info[site_name] = SiteInformation(
                site_name=site_name, information=information
            )
    else:
        for site_name in filter_list:
            if site_name in site_data:
                information = site_data[site_name]
                sites_info[site_name] = SiteInformation(
                    site_name=site_name, information=information
                )
            else:
                print(f"Error: Desired sites not found: {site_name}.")
    return sites_info
