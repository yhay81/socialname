#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

from typing import Any, Dict, Optional, Tuple, Union

import psutil
import requests
import torrequest

from socialname.notify import QueryNotify
from socialname.sites import SitesInformation
from socialname.result import QueryResult, QueryStatus, Result
from socialname.get_result import get_result
from socialname.session import SherlockFuturesSession
from socialname.future import get_future


def get_methodology(
    via_tor: bool,
) -> Tuple[Union[requests.Request, torrequest.TorRequest], requests.Session]:
    # Create session based on request methodology
    if via_tor:
        # Requests using Tor obfuscation
        underlying_request = torrequest.TorRequest()
        underlying_session = underlying_request.session
    else:
        # Normal requests
        underlying_request = requests.Request()
        underlying_session = requests.session()
    return underlying_request, underlying_session


def get_max_workers(site_count: int, workers: int) -> int:
    # Limit number of workers to same as number of CPU.
    # Found on StackOverflow
    # https://stackoverflow.com/questions/1006289/how-to-find-out-the-number-of-cpus-using-python
    no_cpus = psutil.cpu_count(logical=True)
    if isinstance(no_cpus, int):
        # this will make sure number of worker will be same as logical CPU, so prevent overload/timeouts
        return min(site_count, no_cpus, workers)
    return min(site_count, workers)


def sherlock(  # noqa
    username: str,
    site_data: SitesInformation,
    query_notify: QueryNotify,
    tor: bool = False,
    unique_tor: bool = False,
    proxy: Optional[str] = None,
    timeout: Optional[int] = None,
    workers: int = 20,
) -> Dict[str, Dict[str, Any]]:
    """Run Sherlock Analysis.

    Checks for existence of username on various social media sites.

    Keyword Arguments:
    username               -- String indicating username that report
                            should be created against.
    site_data              -- Dictionary containing all of the site data.
    query_notify           -- Object with base type of QueryNotify().
                            This will be used to notify the caller about
                            query results.
    tor                    -- Boolean indicating whether to use a tor circuit for the requests.
    unique_tor             -- Boolean indicating whether to use a new tor circuit for each request.
    proxy                  -- String indicating the proxy URL
    timeout                -- Time in seconds to wait before timing out request.
                            Default is no timeout.

    Return Value:
    Dictionary containing results from report. Key of dictionary is the name
    of the social network site, and the value is another dictionary with
    the following keys:
        url_main:       URL of main site.
        url_user:       URL of user on site (if account exists).
        status:         QueryResult() object indicating results of test for
                        account existence.
        http_status:    HTTP status code of query which checked for existence on
                        site.
        response_text:  Text that came back from request.  May be None if
                        there was an HTTP error when checking for existence.
    """

    # Notify caller that we are starting the query.
    query_notify.start(username)

    underlying_request, underlying_session = get_methodology(
        via_tor=(tor or unique_tor)
    )
    # Create multi-threaded session for all requests.
    session = SherlockFuturesSession(
        max_workers=get_max_workers(len(site_data), workers), session=underlying_session
    )

    # Results from analysis of all sites
    results: Dict[str, Any] = {}
    futures: Dict[str, Any] = {}

    # First create futures for all requests. This allows for the requests to run in parallel
    for site_name, site_info in site_data:
        # Add this site's results into final dictionary with all of the other results.
        futures[site_name] = get_future(site_info, username, session, proxy, timeout)
        # Reset identify for tor (if needed)
        if unique_tor and isinstance(underlying_request, torrequest.TorRequest):
            underlying_request.reset_identity()

    # Open the file containing account links
    # Core logic: If tor requests, make them here. If multi-threaded requests, wait for responses
    for site_name, future in futures.items():
        if future is None:
            # Results from analysis of this specific site
            # Record URL of main site
            url_user = site_data.sites[site_name].url_user.format(username)
            query_result = QueryResult(
                username, site_name, url_user, QueryStatus.ILLEGAL
            )
            results[site_name] = Result(
                url_main=site_data.sites[site_name].url_main,
                status=query_result,
                url_user=url_user,
                http_status="",
                response_text="",
            )
            # URL of user on site (if it exists)
            query_notify.update(query_result)
            # Add this site's results into final dictionary with all of the other results.
            continue
        result = get_result(future, site_data.sites[site_name], username, query_notify)
        if result is not None:
            results[site_name] = result

    # Notify caller that all queries are finished.
    query_notify.finish()

    return results
