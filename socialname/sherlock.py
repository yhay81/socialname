#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import re
from argparse import ArgumentTypeError
from concurrent.futures import Future  # noqa
from typing import Any, Dict, Optional, Tuple, Union

import psutil
import requests
from torrequest import TorRequest

from socialname.notify import QueryNotify
from socialname.result import QueryResult, QueryStatus
from socialname.session import SherlockFuturesSession


def get_response(
    request_future: "Future[requests.Response]",
) -> Tuple[Optional[requests.Response], Optional[str], Optional[str]]:

    # Default for Response object if some failure occurs.
    response: Optional[requests.Response] = None

    error_context: Optional[str] = "General Unknown Error"
    expection_text = None
    try:
        response = request_future.result()
        if response is not None and response.status_code:
            # Status code exists in response object
            error_context = None
    except requests.exceptions.HTTPError as errh:
        error_context = "HTTP Error"
        expection_text = str(errh)
    except requests.exceptions.ProxyError as errp:
        error_context = "Proxy Error"
        expection_text = str(errp)
    except requests.exceptions.ConnectionError as errc:
        error_context = "Error Connecting"
        expection_text = str(errc)
    except requests.exceptions.Timeout as errt:
        error_context = "Timeout Error"
        expection_text = str(errt)
    except requests.exceptions.RequestException as err:
        error_context = "Unknown Error"
        expection_text = str(err)

    return response, error_context, expection_text


def sherlock(  # noqa
    username: str,
    site_data: Dict[str, Any],
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

    # Create session based on request methodology
    if tor or unique_tor:
        # Requests using Tor obfuscation
        underlying_request = TorRequest()
        underlying_session = underlying_request.session
    else:
        # Normal requests
        underlying_session = requests.session()
        underlying_request = requests.Request()

    # Limit number of workers to same as number of CPU.
    # Found on StackOverflow
    # https://stackoverflow.com/questions/1006289/how-to-find-out-the-number-of-cpus-using-python
    no_cpus = psutil.cpu_count(logical=True)
    # this will make sure number of worker will be same as logical CPU, so prevent overload/timeouts
    max_workers = min(len(site_data), no_cpus, workers)
    # Create multi-threaded session for all requests.
    session = SherlockFuturesSession(
        max_workers=max_workers, session=underlying_session
    )

    # Results from analysis of all sites
    results_total: Dict[str, Any] = {}

    # First create futures for all requests. This allows for the requests to run in parallel
    for social_network, net_info in site_data.items():

        # Results from analysis of this specific site
        results_site: Dict[str, Any] = {}

        # Record URL of main site
        results_site["url_main"] = net_info.get("urlMain")

        # A user agent is needed because some sites don't return the correct
        # information since they think that we are bots (Which we actually are...)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) "
                "Gecko/20100101 Firefox/55.0"
            ),
        }

        if "headers" in net_info:
            # Override/append any extra headers required by a given site.
            headers.update(net_info["headers"])

        # URL of user on site (if it exists)
        url = net_info["url"].format(username)

        # Don't make request if username is invalid for the site
        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            # No need to do the check at the site: this user name is not allowed.
            results_site["status"] = QueryResult(
                username, social_network, url, QueryStatus.ILLEGAL
            )
            results_site["url_user"] = ""
            results_site["http_status"] = ""
            results_site["response_text"] = ""
            query_notify.update(results_site["status"])
        else:
            # URL of user on site (if it exists)
            results_site["url_user"] = url
            url_probe = net_info.get("urlProbe")
            if url_probe is None:
                # Probe URL is normal one seen by people out on the web.
                url_probe = url
            else:
                # There is a special URL for probing existence separate
                # from where the user profile normally can be found.
                url_probe = url_probe.format(username)

            request_method_property = net_info.get("request_method", "GET")

            if request_method_property == "POST":
                request_method = session.post
            elif request_method_property == "HEAD":
                # In most cases when we are detecting by status code,
                # it is not necessary to get the entire body:  we can
                # detect fine with just the HEAD response.
                request_method = session.head
            else:
                # Either this detect method needs the content associated
                # with the GET response, or this specific website will
                # not respond properly unless we request the whole page.
                request_method = session.get

            if net_info["errorType"] == "response_url":
                # Site forwards request to a different URL if username not
                # found.  Disallow the redirect so we can capture the
                # http status from the original URL request.
                allow_redirects = False
            else:
                # Allow whatever redirect that the site wants to do.
                # The final result of the request will be what is available.
                allow_redirects = True

            # This future starts running the request in a new thread, doesn't block the main thread
            if proxy is not None:
                proxies = {"http": proxy, "https": proxy}
                future = request_method(
                    url=url_probe,
                    headers=headers,
                    proxies=proxies,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                )
            else:
                data = None
                if request_method_property == "POST":
                    data = net_info.get("request_payload", None)

                if data is not None:
                    data = data.format(username)

                future = request_method(
                    url=url_probe,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    data=data,
                )

            # Store future in data for access later
            net_info["request_future"] = future

            # Reset identify for tor (if needed)
            if unique_tor:
                underlying_request.reset_identity()

        # Add this site's results into final dictionary with all of the other results.
        results_total[social_network] = results_site

    # Open the file containing account links
    # Core logic: If tor requests, make them here. If multi-threaded requests, wait for responses
    for social_network, net_info in site_data.items():
        if social_network not in results_total:
            continue
        # Retrieve results again
        results_site_: Dict[str, Any] = results_total[social_network]

        # Retrieve other site information again
        url = results_site_.get("url_user")
        status = results_site_.get("status")
        if status is not None:
            # We have already determined the user doesn't exist here
            continue

        # Get the expected error type
        error_type = net_info["errorType"]

        # Retrieve future and ensure it has finished
        future = net_info["request_future"]
        res, error_text, _ = get_response(request_future=future)

        if res is None:
            response_time: Optional[int] = None
            http_status: Union[str, int] = "?"
            response_text: str = ""
        else:
            # Get response time for response of our request.
            try:
                response_time = res.elapsed.seconds
            except AttributeError:
                response_time = None

            # Attempt to get request information
            try:
                http_status = res.status_code
            except Exception:
                http_status = "?"
            try:
                response_text = str(res.text.encode(res.encoding))
            except Exception:
                response_text = ""

        if res is None or error_text is not None:
            result = QueryResult(
                username,
                social_network,
                url,
                QueryStatus.UNKNOWN,
                query_time=response_time,
                context=error_text,
            )
        elif error_type == "message":
            # error_flag True denotes no error found in the HTML
            # error_flag False denotes error found in the HTML
            error_flag = True
            errors = net_info.get("errorMsg")
            # errors will hold the error message
            # it can be string or list
            # by insinstance method we can detect that
            # and handle the case for strings as normal procedure
            # and if its list we can iterate the errors
            if isinstance(errors, str):
                # Checks if the error message is in the HTML
                # if error is present we will set flag to False
                if errors in res.text:
                    error_flag = False
            else:
                # If it's list, it will iterate all the error message
                for error in errors:
                    if res is not None and error in res.text:
                        error_flag = False
                        break
            if error_flag:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.CLAIMED,
                    query_time=response_time,
                )
            else:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.AVAILABLE,
                    query_time=response_time,
                )
        elif error_type == "status_code":
            # Checks if the status code of the response is 2XX
            if not res.status_code >= 300 or res.status_code < 200:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.CLAIMED,
                    query_time=response_time,
                )
            else:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.AVAILABLE,
                    query_time=response_time,
                )
        elif error_type == "response_url":
            # For this detection method, we have turned off the redirect.
            # So, there is no need to check the response URL: it will always
            # match the request.  Instead, we will ensure that the response
            # code indicates that the request was successful (i.e. no 404, or
            # forward to some odd redirect).
            if 200 <= res.status_code < 300:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.CLAIMED,
                    query_time=response_time,
                )
            else:
                result = QueryResult(
                    username,
                    social_network,
                    url,
                    QueryStatus.AVAILABLE,
                    query_time=response_time,
                )
        else:
            # It should be impossible to ever get here...
            raise ValueError(
                f"Unknown Error Type '{error_type}' for " f"site '{social_network}'"
            )

        # Notify caller about results of query.
        query_notify.update(result)

        # Save status of request
        results_site_["status"] = result

        # Save results from request
        results_site_["http_status"] = http_status
        results_site_["response_text"] = response_text

        # Add this site's results into final dictionary with all of the other results.
        results_total[social_network] = results_site_

    # Notify caller that all queries are finished.
    query_notify.finish()

    return results_total


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
        raise ArgumentTypeError(f"Timeout '{value}' must be a number.")
    if timeout <= 0:
        raise ArgumentTypeError(f"Timeout '{value}' must be greater than 0.0s.")
    return timeout
