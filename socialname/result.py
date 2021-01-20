"""Sherlock Result Module

This module defines various objects for recording the results of queries.
"""
from enum import Enum
from typing import Optional


class QueryStatus(Enum):
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


class QueryResult:
    """Query Result Object.

    Describes result of query about a given username.
    """

    def __init__(
        self,
        username: str,
        site_name: str,
        site_url_user: str,
        status: QueryStatus,
        query_time: Optional[int] = None,
        context: Optional[str] = None,
    ) -> None:
        """Create Query Result Object.

        Contains information about a specific method of detecting usernames on
        a given type of web sites.

        Keyword Arguments:
        self                 -- This object.
        username             -- String indicating username that query result
                                was about.
        site_name            -- String which identifies site.
        site_url_user        -- String containing URL for username on site.
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

        Return Value:
        Nothing.
        """

        self.username = username
        self.site_name = site_name
        self.site_url_user = site_url_user
        self.status = status
        self.query_time = query_time
        self.context = context

    def __str__(self) -> str:
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """
        status = str(self.status)
        if self.context is not None:
            # There is extra context information available about the results.
            # Append it to the normal response text.
            status += f" ({self.context})"

        return status
