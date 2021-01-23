import csv
import os
import webbrowser
from typing import Dict, List, Tuple, Optional

from socialname.result import SocialNameStatus, SocialNameResult


def write_txt(
    total_results: Dict[str, Dict[str, SocialNameResult]],
    output: Optional[str] = None,
    folderoutput: Optional[str] = None,
) -> None:
    for username, results in total_results.items():
        if output is not None:
            result_file = output
        elif folderoutput is not None:
            # The usernames results should be stored in a targeted folder.
            # If the folder doesn't exist, create it first
            os.makedirs(folderoutput, exist_ok=True)
            result_file = os.path.join(folderoutput, f"{username}.txt")
        else:
            result_file = f"{username}.txt"

        with open(result_file, "w", encoding="utf-8") as file:
            exists_counter = 0
            for result in results.values():
                if result.status is SocialNameStatus.CLAIMED:
                    exists_counter += 1
                    file.write(result.url_user + "\n")
            file.write(f"Total Websites Username Detected On : {exists_counter}\n")


def write_csv_singleoutput(
    total_results: Dict[str, Dict[str, SocialNameResult]]
) -> None:
    csv_data: List[Tuple[str, str, str, str, str, str]] = [
        ("username", "site_name", "url_main", "url_user", "status", "response_time_s"),
    ]
    for username, results in total_results.items():
        for site_name, result in results.items():
            if result.status is SocialNameStatus.CLAIMED:
                csv_data.append(
                    (
                        username,
                        site_name,
                        result.url_main,
                        result.url_user,
                        str(result.status),
                        str(result.elapsed_time) or "",
                    )
                )
    with open("master.csv", "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_data)


def write_csv(total_results: Dict[str, Dict[str, SocialNameResult]]) -> None:
    for username, results in total_results.items():
        csv_data: List[Tuple[str, str, str, str, str, str]] = [
            (
                "username",
                "site_name",
                "url_main",
                "url_user",
                "status",
                "response_time_s",
            ),
        ]
        for site_name, result in results.items():
            csv_data.append(
                (
                    username,
                    site_name,
                    result.url_main,
                    result.url_user,
                    str(result.status),
                    str(result.elapsed_time) or "",
                )
            )
        with open(username + ".csv", "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerows(csv_data)


def open_browser(total_results: Dict[str, Dict[str, SocialNameResult]]) -> None:
    # opening web browser after results are computed
    for results in total_results.values():
        for result in results.values():
            if result.status is SocialNameStatus.CLAIMED:
                webbrowser.open_new_tab(result.url_user)
