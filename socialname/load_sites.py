"""Sherlock Sites Information Module

This module supports storing information about web sites.
This is the raw data that will be used to search for usernames.
"""
import json
from typing import Any, Dict

import requests
import cerberus


VALIDATOR = cerberus.Validator(
    {
        "errorMsg": {
            "anyof": [
                {"type": "string"},
                {"type": "list", "schema": {"type": "string"}},
            ]
        },
        "errorType": {"type": "string", "required": True},
        "errorUrl": {"type": "string"},
        "headers": {"type": "dict"},
        "noPeriod": {"type": "string"},
        "regexCheck": {"type": "string"},
        "request_head_only": {"type": "boolean"},
        "url": {"type": "string", "required": True},
        "urlMain": {"type": "string", "required": True},
        "urlProbe": {"type": "string"},
        "username_claimed": {"type": "string", "required": True},
        "username_unclaimed": {"type": "string", "required": True},
    }
)


def validate(data: Dict[str, Any]) -> None:
    errors: Dict[str, str] = {}
    for key, value in data.items():
        if not VALIDATOR.validate(value):
            errors[key] = VALIDATOR.errors
    if len(errors) > 0:
        raise ValueError(f"Loaded data is not valid. {errors}")


def from_url(data_file_path: str) -> Dict[str, Any]:
    # Reference is to a URL.
    try:
        response = requests.get(url=data_file_path)
    except Exception as error:
        raise FileNotFoundError(
            f"Problem while attempting to access "
            f"data file URL '{data_file_path}':  {str(error)}"
        )
    if response.status_code == 200:
        try:
            result: Dict[str, Any] = response.json()
        except Exception as error:
            raise ValueError(
                f"Problem parsing json contents at "
                f"'{data_file_path}':  {str(error)}."
            )
        validate(result)
        return result
    raise FileNotFoundError(
        f"Bad response while accessing data file URL '{data_file_path}'."
    )


def from_file(data_file_path: str) -> Dict[str, Any]:
    # Reference is to a file.
    try:
        with open(data_file_path, "r", encoding="utf-8") as file:
            try:
                result: Dict[str, Any] = json.load(file)
            except Exception as error:
                raise ValueError(
                    f"Problem parsing json contents at "
                    f"'{data_file_path}':  {str(error)}."
                )
            validate(result)
            return result
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Problem while attempting to access data file '{data_file_path}'."
        )
