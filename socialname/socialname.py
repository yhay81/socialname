import concurrent.futures
import importlib
from typing import Any, Dict, List, Tuple, Optional

import psutil

from socialname.logics import BaseLogic, run_logic
from socialname.notify import QueryNotify, QueryNotifyPrint
from socialname.result import SocialNameResult
from socialname.sites import SiteInformation, create_sites_info


def get_max_workers(site_count: int, workers: int) -> int:
    # Limit number of workers to same as number of CPU.
    # Found on StackOverflow
    # https://stackoverflow.com/questions/1006289/how-to-find-out-the-number-of-cpus-using-python
    no_cpus = psutil.cpu_count(logical=True)
    if isinstance(no_cpus, int):
        # this will make sure number of worker will be same as logical CPU, so prevent overload/timeouts
        return min(site_count, no_cpus, workers)
    return min(site_count, workers)


def socialname(
    username: str,
    sites_info: Optional[Dict[str, SiteInformation]] = None,
    query_notify: Optional[QueryNotify] = None,
    *,
    workers: int = 20,
    **kwargs: Any,
) -> Dict[str, SocialNameResult]:
    if sites_info is None:
        sites_info = create_sites_info()
    if query_notify is None:
        query_notify = QueryNotifyPrint()

    query_notify.start(username)

    logic_usernames: List[Tuple[BaseLogic, str]] = []
    for site_name, site_info in sites_info.items():
        module = importlib.import_module(f"socialname.logics.{site_info.logic}")
        logic_usernames.append(
            (
                module.Logic(site_name, site_info, query_notify, **kwargs),  # type: ignore
                username,
            )
        )

    results: Dict[str, SocialNameResult] = {}
    max_workers = get_max_workers(len(sites_info), workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(run_logic, logic_usernames):
            results[result.site_name] = result

    query_notify.finish()
    return results
