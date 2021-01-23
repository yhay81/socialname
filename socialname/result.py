"""SocialName Result Module

This module defines various objects for recording the results of queries.
"""
import dataclasses
from enum import Enum
from typing import Optional, Dict, Any


class SocialNameStatus(Enum):
    """Query Status Enumeration.

    Describes status of query about a given username.
    """

    CLAIMED: str = "Claimed"  # Username Detected
    AVAILABLE: str = "Available"  # Username Not Detected
    UNKNOWN: str = "Unknown"  # Error Occurred While Trying To Detect Username
    ILLEGAL: str = "Illegal"  # Username Not Allowable For This Site

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """
        return str(self.value)


@dataclasses.dataclass
class SocialNameResult:
    """Query Result Object.

    Describes result of query about a given username.
    Contains information about a specific method of detecting usernames on
    a given type of web sites.

    Keyword Arguments:
    username             -- String indicating username that query result
                            was about.
    site_name            -- String which identifies site.
    url_user        -- String containing URL for username on site.
                            NOTE:   The site may or may not exist:  this
                                    just indicates what the name would
                                    be, if it existed.
    status               -- Enumeration of type QueryStatus() indicating
                            the status of the query.
    query_time           -- Time (in seconds) required to perform query.
                            Default of None.
    context              -- String indicating any additional context
                            about the query.  For example, if there was
                            an error, this might indicate the type of
                            error that occurred.
                            Default of None.
    """

    username: str
    site_name: str
    url_main: str
    url_user: str
    status: SocialNameStatus
    elapsed_time: Optional[int]
    context: Dict[str, Any]

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        There is extra context information available about the results.
        Append it to the normal response text.
        """
        if not self.context:
            return str(self.status)
        return f"{str(self.status)} ({self.context})"
