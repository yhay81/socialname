from typing import Any, Callable, Optional, Tuple, Union, Dict
import dataclasses

import requests
import torrequest

from socialname.notify import QueryNotify
from socialname.result import SocialNameResult, SocialNameStatus
from socialname.sites import SiteInformation

from ._base import BaseLogic


@dataclasses.dataclass
class SimpleRequestContext:
    http_status: Union[str, int]
    elapsed_time: Optional[int]
    response_text: str
    error_context: Optional[str]
    expection_text: Optional[str]


def get_context(
    response: Optional[requests.Response],
    error_context: Optional[str],
    expection_text: Optional[str],
) -> SimpleRequestContext:
    elapsed_time: Optional[int] = None
    http_status: Union[str, int] = "?"
    response_text: str = ""
    if response is not None:
        # Get response time for response of our request.
        try:
            elapsed_time = response.elapsed.seconds
        except AttributeError:
            pass
        # Attempt to get request information
        try:
            http_status = response.status_code
        except Exception:  # nosec
            pass
        try:
            response_text = str(response.text.encode(response.encoding))
        except Exception:  # nosec
            pass
    return SimpleRequestContext(
        http_status=http_status,
        elapsed_time=elapsed_time,
        response_text=response_text,
        error_context=error_context,
        expection_text=expection_text,
    )


def get_response(
    url: str,
    request_method: Callable[..., requests.Response],
    allow_redirects: bool,
    headers: Dict[str, Any],
    proxy: Optional[str],
    timeout: Optional[int],
) -> Tuple[Optional[requests.Response], SimpleRequestContext]:
    response: Optional[requests.Response] = None
    error_context: Optional[str] = "General Unknown Error"
    expection_text = None
    try:
        response = request_method(
            url=url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) "
                    "Gecko/20100101 Firefox/55.0"
                ),
                # Override/append any extra headers required by a given site.
                **headers,
            },
            proxies={"http": proxy, "https": proxy} if proxy is not None else None,
            allow_redirects=allow_redirects,
            timeout=timeout,
        )

        if response is not None and response.status_code:
            # Status code exists in response object
            error_context = None
    except requests.exceptions.HTTPError as http_error:
        error_context = "HTTP Error"
        expection_text = str(http_error)
    except requests.exceptions.ProxyError as proxy_error:
        error_context = "Proxy Error"
        expection_text = str(proxy_error)
    except requests.exceptions.ConnectionError as connection_error:
        error_context = "Error Connecting"
        expection_text = str(connection_error)
    except requests.exceptions.Timeout as timeout_error:
        error_context = "Timeout Error"
        expection_text = str(timeout_error)
    except requests.exceptions.RequestException as error:
        error_context = "Unknown Error"
        expection_text = str(error)

    return response, get_context(response, error_context, expection_text)


class BaseSimpleRequestLogic(BaseLogic):
    underlying_request: Union[requests.Request, torrequest.TorRequest]
    underlying_session: requests.Session

    def __init__(
        self,
        site_name: str,
        site_info: SiteInformation,
        query_notify: QueryNotify,
        **kwargs: Any,
    ) -> None:
        super().__init__(site_name, site_info, query_notify, **kwargs)
        if kwargs.get("tor") is True or kwargs.get("unique_tor") is True:
            # Requests using Tor obfuscation
            self.underlying_request = torrequest.TorRequest()
            self.underlying_session = self.underlying_request.session
        else:
            # Normal requests
            self.underlying_request = requests.Request()
            self.underlying_session = requests.session()

    def get_result(self, username: str) -> SocialNameResult:
        site_name = self.site_info.site_name
        url_main = self.site_info.url_main
        url_user = self.site_info.url_user.format(username)
        url_probe = (
            self.site_info.url_probe.format(username)
            if self.site_info.url_probe is not None
            else None
        )

        # Don't make request if username is invalid for the site
        if self.is_illegal(username):
            # No need to do the check at the site: this user name is not allowed.
            return SocialNameResult(
                username=username,
                site_name=site_name,
                url_user=url_user,
                url_main=url_main,
                status=SocialNameStatus.ILLEGAL,
                elapsed_time=None,
                context={},
            )

        response, context = get_response(
            url=url_probe or url_user,
            request_method=self.request_method,
            allow_redirects=self.allow_redirects,
            headers=self.site_info.options.get("headers", {}),
            proxy=self.kwargs.get("proxy", None),
            timeout=self.kwargs.get("timeout", None),
        )

        if self.kwargs.get("unique_tor") is True and isinstance(
            self.underlying_request, torrequest.TorRequest
        ):
            self.underlying_request.reset_identity()

        if response is None or context.error_context is not None:
            status = SocialNameStatus.UNKNOWN
        else:
            status = self.get_status(response)

        result = SocialNameResult(
            username=username,
            site_name=site_name,
            url_user=url_user,
            url_main=url_main,
            status=status,
            elapsed_time=context.elapsed_time,
            context=dataclasses.asdict(context),
        )
        # Notify caller about results of query.
        self.query_notify.update(result)
        return result

    def get_status(self, response: requests.Response) -> SocialNameStatus:
        raise NotImplementedError

    @property
    def request_method(self) -> Callable[..., requests.Response]:
        raise NotImplementedError

    @property
    def allow_redirects(self) -> bool:
        raise NotImplementedError
