from typing import Any
import re

from socialname.notify import QueryNotify
from socialname.result import SocialNameResult
from socialname.sites import SiteInformation

# Also need OPTIONS_VALIDATOR when implementing new logic
#
# import cerberus
# OPTIONS_VALIDATOR = cerberus.Validator({})
#


class BaseLogic:
    def __init__(
        self,
        site_name: str,
        site_info: SiteInformation,
        query_notify: QueryNotify,
        **kwargs: Any,
    ) -> None:
        self.site_name = site_name
        self.site_info = site_info
        self.query_notify = query_notify
        self.kwargs = kwargs

    def get_result(self, username: str) -> SocialNameResult:
        raise NotImplementedError

    def is_illegal(self, username: str) -> bool:
        regex_check = self.site_info.regex_check
        if regex_check is not None and re.search(regex_check, username) is None:
            return True
        return False
