"""Sherlock Result Module

This module defines various objects for recording the results of queries.
"""
from concurrent.futures import Future  # noqa
from typing import List, Optional, Union, Tuple

import requests

from socialname.notify import QueryNotify
from socialname.sites import SiteInformation
from socialname.result import Result, QueryStatus, QueryResult


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


def status_from_message(
    res: requests.Response, error_message: Optional[Union[str, List[str]]]
) -> QueryStatus:
    # error_flag True denotes no error found in the HTML
    # error_flag False denotes error found in the HTML
    error_flag = True
    # errors will hold the error message
    # it can be string or list
    # by insinstance method we can detect that
    # and handle the case for strings as normal procedure
    # and if its list we can iterate the errors
    if isinstance(error_message, str):
        # Checks if the error message is in the HTML
        # if error is present we will set flag to False
        if error_message in res.text:
            error_flag = False
    elif isinstance(error_message, list):
        # If it's list, it will iterate all the error message
        for error in error_message:
            if res is not None and error in res.text:
                error_flag = False
                break
    return QueryStatus.CLAIMED if error_flag else QueryStatus.AVAILABLE


def status_from_status_code(res: requests.Response) -> QueryStatus:
    # Checks if the status code of the response is 2XX
    return (
        QueryStatus.CLAIMED
        if not res.status_code >= 300 or res.status_code < 200
        else QueryStatus.AVAILABLE
    )


def status_from_response_url(res: requests.Response) -> QueryStatus:
    # For this detection method, we have turned off the redirect.
    # So, there is no need to check the response URL: it will always
    # match the request.  Instead, we will ensure that the response
    # code indicates that the request was successful (i.e. no 404, or
    # forward to some odd redirect).
    return (
        QueryStatus.CLAIMED if 200 <= res.status_code < 300 else QueryStatus.AVAILABLE
    )


def get_context(
    res: Optional[requests.Response],
) -> Tuple[Optional[int], Union[str, int], str]:
    response_time: Optional[int] = None
    http_status: Union[str, int] = "?"
    response_text: str = ""
    if res is not None:
        # Get response time for response of our request.
        try:
            response_time = res.elapsed.seconds
        except AttributeError:
            pass
        # Attempt to get request information
        try:
            http_status = res.status_code
        except Exception:  # nosec
            pass
        try:
            response_text = str(res.text.encode(res.encoding))
        except Exception:  # nosec
            pass
    return response_time, http_status, response_text


def get_status(
    res: Optional[requests.Response],
    error_text: Optional[str],
    site_info: SiteInformation,
) -> Tuple[QueryStatus, Optional[str]]:
    if res is None or error_text is not None:
        return QueryStatus.UNKNOWN, error_text
    if site_info.error_type == "message":
        return status_from_message(res, site_info.error_message), None
    if site_info.error_type == "status_code":
        return status_from_status_code(res), None
    if site_info.error_type == "response_url":
        return status_from_response_url(res), None
    # It should be impossible to ever get here...
    raise ValueError(
        f"Unknown Error Type '{site_info.error_type}' for site '{site_info.name}'"
    )


def get_result(
    future: "Future[requests.Response]",
    site_info: SiteInformation,
    username: str,
    query_notify: QueryNotify,
) -> Result:
    url_user = site_info.url_user.format(username)
    result = Result(url_main=site_info.url_main, url_user=url_user)
    res, error_text, _ = get_response(request_future=future)

    response_time, http_status, response_text = get_context(res)
    status, context = get_status(res, error_text, site_info)
    query_result = QueryResult(
        site_name=site_info.name,
        status=status,
        username=username,
        url_user=url_user,
        query_time=response_time,
        context=context,
    )

    # Notify caller about results of query.
    query_notify.update(query_result)

    # Save status of request
    result.status = query_result

    # Save results from request
    result.http_status = http_status
    result.response_text = response_text

    return result
