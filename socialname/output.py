#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import csv
import os
import webbrowser
from typing import Any, Dict, List, Tuple, Optional

from socialname.result import QueryStatus


def write_txt(
    results: Dict[str, Dict[str, Any]],
    output: Optional[str] = None,
    folderoutput: Optional[str] = None,
) -> None:
    for username, result in results.items():
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
            for info in result.values():
                if "status" in info and info["status"].status == QueryStatus.CLAIMED:
                    exists_counter += 1
                    file.write(info["url_user"] + "\n")
            file.write(f"Total Websites Username Detected On : {exists_counter}\n")


def write_csv_singleoutput(results: Dict[str, Dict[str, Any]]) -> None:
    csv_data: List[Tuple[str, str, str, str]] = [
        ("username", "name", "url_user", "account_count"),
    ]
    for username, result in results.items():
        exists_counter = 0
        for name, info in result.items():
            if info["status"].status == QueryStatus.CLAIMED:
                exists_counter += 1
                csv_data.append((username, name, info["url_user"], str(exists_counter)))
    with open("master.csv", "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_data)


def write_csv(results: Dict[str, Dict[str, Any]]) -> None:
    for username, result in results.items():
        csv_data: List[Tuple[str, str, str, str, str, str, str]] = [
            (
                "username",
                "name",
                "url_main",
                "url_user",
                "exists",
                "http_status",
                "response_time_s",
            ),
        ]
        for name, info in result.items():
            csv_data.append(
                (
                    username,
                    name,
                    info["url_main"],
                    info["url_user"],
                    str(info["status"].status),
                    info["http_status"],
                    info["status"].query_time or "",
                )
            )
        with open(username + ".csv", "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerows(csv_data)


def open_browser(results: Dict[str, Dict[str, Any]]) -> None:
    # opening web browser after results are computed
    for result in results.values():
        for site_info in result.values():
            if site_info["status"].status == QueryStatus.CLAIMED:
                webbrowser.open_new_tab(site_info["url_user"])
