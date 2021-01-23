#!/usr/bin/env python
import codecs
import sys
from typing import Dict

import setuptools

__version__: Dict[str, str] = {}
with codecs.open("socialname/__version__.py", "r") as version_file:
    exec(version_file.read(), __version__)  # noqa


install_requires = [
    "Cerberus>=1.3.2",
    "colorama>=0.4.4",
    "requests>=2.25.1",
    "torrequest>=0.1.0",
    "psutil>=5.8.0",
]

if sys.version_info[:2] == (3, 6):
    install_requires.append("dataclasses")

setuptools.setup(
    name=__version__["__title__"],
    version=__version__["__version__"],
    description=__version__["__description__"],
    long_description=codecs.open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    keywords=["sns"],
    url=__version__["__url__"],
    author=__version__["__author__"],
    author_email=__version__["__author_email__"],
    license=__version__["__license__"],
    install_requires=install_requires,
    packages=setuptools.find_packages(exclude=["tests*"]),
    package_data={"": ["LICENSE"]},
    package_dir={"socialname": "socialname"},
    include_package_data=True,
    python_requires=">=3.6",
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
    extras_require={},
    entry_points={
        "console_scripts": [
            "socialname = socialname.cli.command:execute",
        ],
    },
)
