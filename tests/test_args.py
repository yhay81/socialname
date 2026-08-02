import argparse
from types import SimpleNamespace

import pytest

from socialname.cli.args import check_args, proxy_check


@pytest.mark.parametrize(
    "proxy_url",
    [
        "http://127.0.0.1:8080",
        "https://proxy.example:443",
        "socks4://localhost:9050",
        "socks5h://user:secret@[::1]:1080",
    ],
)
def test_proxy_check_accepts_supported_urls(proxy_url):
    assert proxy_check(proxy_url) == proxy_url


@pytest.mark.parametrize(
    "proxy_url",
    [
        "",
        "proxy.example:8080",
        "ftp://proxy.example:21",
        "http://proxy.example",
        "http://proxy.example:not-a-port",
        "http://proxy.example:8080/path",
        "http://proxy example:8080",
    ],
)
def test_proxy_check_rejects_invalid_urls(proxy_url):
    with pytest.raises(argparse.ArgumentTypeError):
        proxy_check(proxy_url)


def test_check_args_does_not_print_proxy_credentials(capsys):
    secret = "do-not-log-this"
    args = SimpleNamespace(
        tor=False,
        unique_tor=False,
        proxy=f"http://user:{secret}@proxy.example:8080",
        output=None,
        folderoutput=None,
        username=["example"],
    )

    check_args(args)

    output = capsys.readouterr().out
    assert output == "Using the configured proxy\n"
    assert secret not in output
