import json
from typing import Any, Dict
import importlib

import requests
import cerberus


VALIDATOR = cerberus.Validator(
    {
        "logic": {"type": "string", "required": True},
        "urlMain": {"type": "string", "required": True},
        "urlUser": {"type": "string", "required": True},
        "urlProbe": {"type": "string"},
        "regexCheck": {"type": "string"},
        "usernameClaimed": {"type": "string", "required": True},
        "usernameUnclaimed": {"type": "string", "required": True},
        "options": {"type": "dict", "allow_unknown": True},
    }
)


def validate(data: Dict[str, Any]) -> None:
    errors: Dict[str, str] = {}
    for key, value in data.items():
        is_valid = VALIDATOR.validate(value)
        if not is_valid:
            errors[key] = VALIDATOR.errors
            continue
        logic: str = value["logic"]
        module = importlib.import_module(f"socialname.logics.{logic}")
        options_validator: cerberus.Validator = module.OPTIONS_VALIDATOR  # type: ignore
        is_options_valid = options_validator.validate(value.get("options", {}))
        if not is_options_valid:
            errors[key] = options_validator.errors
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
