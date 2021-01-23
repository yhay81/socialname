"""SocialName Module

This module contains the main logic to search for usernames at social
networks.
"""

from socialname.__version__ import (
    __author__,
    __author_email__,
    __license__,
    __title__,
    __version__,
)
from socialname.notify import QueryNotify, QueryNotifyPrint
from socialname.result import SocialNameResult, SocialNameStatus
from socialname.sites import SiteInformation, create_sites_info
from socialname.socialname import socialname

__all__ = [
    "__author__",
    "__author_email__",
    "__license__",
    "__title__",
    "__version__",
    "QueryNotify",
    "QueryNotifyPrint",
    "SiteInformation",
    "SocialNameResult",
    "SocialNameStatus",
    "create_sites_info",
    "socialname",
]
