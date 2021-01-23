#!/usr/bin/env python
import codecs
from typing import Dict

import setuptools

__version__: Dict[str, str] = {}
with codecs.open("socialname/__version__.py", "r", "utf-8") as version_file:
    exec(version_file.read(), __version__)  # noqa

with codecs.open("README.md", "r", "utf-8") as f:
    readme = f.read()

install_requires = [
    "bs4",
    "cerberus",
    "colorama",
    "dataclasses",
    "lxml",
    "requests",
    "torrequest",
    "psutil",
]

setuptools.setup(
    name=__version__["__title__"],
    version=__version__["__version__"],
    description=__version__["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    keywords=["sns"],
    url=__version__["__url__"],
    author=__version__["__author__"],
    author_email=__version__["__author_email__"],
    license=__version__["__license__"],
    install_requires=install_requires,
    packages=["socialname"],
    package_data={"": ["LICENSE"]},
    package_dir={"socialname": "socialname"},
    include_package_data=True,
    python_requires=">=3.7",
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    project_urls={"Source": "https://github.com/yhay81/socialname"},
)
