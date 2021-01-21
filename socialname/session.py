#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import datetime
from concurrent.futures import Future  # noqa
from time import monotonic
from typing import Any, Dict, Optional

import requests
from requests_futures.sessions import FuturesSession


class SherlockFuturesSession(FuturesSession):  # type: ignore
    def request(  # noqa
        self,
        method: str,
        url: str,
        *args: Any,
        hooks: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> "Future[requests.Response]":
        """Request URL.

        This extends the FuturesSession request method to calculate a response
        time metric to each request.

        It is taken (almost) directly from the following StackOverflow answer:
        https://github.com/ross/requests-futures#working-in-the-background

        Keyword Arguments:
        self                 -- This object.
        method               -- String containing method desired for request.
        url                  -- String containing URL for request.
        hooks                -- Dictionary containing hooks to execute after
                                request finishes.
        args                 -- Arguments.
        kwargs               -- Keyword arguments.

        Return Value:
        Request object.
        """
        # Record the start time for the request.
        hooks = {} if hooks is None else hooks
        start = monotonic()

        def response_time(resp: requests.Response, *_args: Any, **_kwargs: Any) -> None:
            """Response Time Hook.

            Keyword Arguments:
            resp                   -- Response object.
            args                   -- Arguments.
            kwargs                 -- Keyword arguments.

            Return Value:
            N/A
            """
            resp.elapsed = datetime.timedelta(seconds=monotonic() - start)

        # Install hook to execute when response completes.
        # Make sure that the time measurement hook is first, so we will not
        # track any later hook's execution time.
        try:
            if isinstance(hooks["response"], list):
                hooks["response"].insert(0, response_time)
            elif isinstance(hooks["response"], tuple):
                # Convert tuple to list and insert time measurement hook first.
                hooks["response"] = list(hooks["response"])
                hooks["response"].insert(0, response_time)  # type: ignore
            else:
                # Must have previously contained a single hook function,
                # so convert to list.
                hooks["response"] = [response_time, hooks["response"]]
        except KeyError:
            # No response hook was already defined, so install it ourselves.
            hooks["response"] = [response_time]

        result: "Future[requests.Response]" = super(
            SherlockFuturesSession, self
        ).request(method, url, hooks=hooks, *args, **kwargs)
        return result
