#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import re
from concurrent.futures import Future  # noqa
from typing import Optional, Callable

import requests  # noqa

from socialname.sites import SiteInformation
from socialname.session import SherlockFuturesSession


def get_future(
    site_info: SiteInformation,
    username: str,
    session: SherlockFuturesSession,
    proxy: Optional[str],
    timeout: Optional[int],
) -> "Optional[Future[requests.Response]]":

    # A user agent is needed because some sites don't return the correct
    # information since they think that we are bots (Which we actually are...)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) "
            "Gecko/20100101 Firefox/55.0"
        ),
        # Override/append any extra headers required by a given site.
        **site_info.headers,
    }

    # URL of user on site (if it exists)
    url_user = site_info.url_user.format(username)

    # Don't make request if username is invalid for the site
    if (
        site_info.regex_check is not None
        and re.search(site_info.regex_check, username) is None
    ):
        # No need to do the check at the site: this user name is not allowed.
        return None

    # Probe URL is normal one seen by people out on the web.
    # There is a special URL for probing existence separate
    # from where the user profile normally can be found.
    url_probe = (
        site_info.url_probe.format(username)
        if site_info.url_probe is not None
        else url_user
    )
    request_method: Callable[..., "Future[requests.Response]"]
    if site_info.error_type == "status_code" and site_info.request_head_only is True:
        # In most cases when we are detecting by status code,
        # it is not necessary to get the entire body:  we can
        # detect fine with just the HEAD response.
        request_method = session.head
    else:
        # Either this detect method needs the content associated
        # with the GET response, or this specific website will
        # not respond properly unless we request the whole page.
        request_method = session.get

    if site_info.error_type == "response_url":
        # Site forwards request to a different URL if username not
        # found.  Disallow the redirect so we can capture the
        # http status from the original URL request.
        allow_redirects = False
    else:
        # Allow whatever redirect that the site wants to do.
        # The final result of the request will be what is available.
        allow_redirects = True

    # This future starts running the request in a new thread, doesn't block the main thread
    future = request_method(
        url=url_probe,
        headers=headers,
        proxies={"http": proxy, "https": proxy} if proxy is not None else None,
        allow_redirects=allow_redirects,
        timeout=timeout,
    )

    return future
