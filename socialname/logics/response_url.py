from typing import Callable

import requests

import cerberus
from socialname.result import SocialNameStatus

from ._base_simple_request import BaseSimpleRequestLogic

OPTIONS_VALIDATOR = cerberus.Validator(
    {
        "errorUrl": {"type": "string", "required": True},
    }
)
OPTIONS_VALIDATOR.allow_unknown = True


class Logic(BaseSimpleRequestLogic):
    def get_status(self, response: requests.Response) -> SocialNameStatus:
        # For this detection method, we have turned off the redirect.
        # So, there is no need to check the response URL: it will always
        # match the request.  Instead, we will ensure that the response
        # code indicates that the request was successful (i.e. no 404, or
        # forward to some odd redirect).
        return (
            SocialNameStatus.CLAIMED
            if 200 <= response.status_code < 300
            else SocialNameStatus.AVAILABLE
        )

    @property
    def request_method(self) -> Callable[..., requests.Response]:
        return self.underlying_session.get

    @property
    def allow_redirects(self) -> bool:
        return False
