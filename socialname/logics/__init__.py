from typing import Tuple

from socialname.result import SocialNameResult

from ._base import BaseLogic


def run_logic(logic_username: Tuple[BaseLogic, str]) -> SocialNameResult:
    logic, username = logic_username
    return logic.get_result(username)


__all__ = [
    "BaseLogic",
    "run_logic",
]
