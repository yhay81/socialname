from typing import Callable

import cerberus
import requests

from socialname.result import SocialNameStatus

from ._base_simple_request import BaseSimpleRequestLogic

OPTIONS_VALIDATOR = cerberus.Validator({})
OPTIONS_VALIDATOR.allow_unknown = True


class Logic(BaseSimpleRequestLogic):
    def get_status(self, response: requests.Response) -> SocialNameStatus:
        # Checks if the status code of the response is 2XX
        return (
            SocialNameStatus.CLAIMED
            if not response.status_code >= 300 or response.status_code < 200
            else SocialNameStatus.AVAILABLE
        )

    @property
    def request_method(self) -> Callable[..., requests.Response]:
        if self.site_info.options.get("requestHeadOnly", None) is True:
            # In most cases when we are detecting by status code,
            # it is not necessary to get the entire body:  we can
            # detect fine with just the HEAD response.
            return self.underlying_session.head
        # Either this detect method needs the content associated
        # with the GET response, or this specific website will
        # not respond properly unless we request the whole page.
        return self.underlying_session.get

    @property
    def allow_redirects(self) -> bool:
        return True
