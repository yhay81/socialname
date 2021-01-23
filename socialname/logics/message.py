from typing import Callable

import cerberus
import requests

from socialname.result import SocialNameStatus

from ._base_simple_request import BaseSimpleRequestLogic

OPTIONS_VALIDATOR = cerberus.Validator(
    {
        "errorMessage": {
            "anyof": [
                {"type": "string"},
                {"type": "list", "schema": {"type": "string"}},
            ],
            "required": True,
        },
    }
)
OPTIONS_VALIDATOR.allow_unknown = True


class Logic(BaseSimpleRequestLogic):
    def get_status(self, response: requests.Response) -> SocialNameStatus:
        error_message = self.site_info.options.get("errorMessage", None)
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
            if error_message in response.text:
                error_flag = False
        elif isinstance(error_message, list):
            # If it's list, it will iterate all the error message
            for error in error_message:
                if response is not None and error in response.text:
                    error_flag = False
                    break
        return SocialNameStatus.CLAIMED if error_flag else SocialNameStatus.AVAILABLE

    @property
    def request_method(self) -> Callable[..., requests.Response]:
        return self.underlying_session.get

    @property
    def allow_redirects(self) -> bool:
        return True
