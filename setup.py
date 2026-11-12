#!/usr/bin/env python
import codecs
from typing import Dict

import setuptools

__version__: Dict[str, str] = {}
with codecs.open("socialname/__version__.py", "r") as version_file:
    exec(version_file.read(), __version__)  # noqa


install_requires = [
    "Cerberus>=1.3.5; python_version < '3.7'",
    "Cerberus>=1.3.8; python_version >= '3.7'",
    "colorama>=0.4.5; python_version < '3.7'",
    "colorama>=0.4.6; python_version >= '3.7'",
    "requests>=2.27.1; python_version < '3.7'",
    "requests>=2.31.0; python_version == '3.7'",
    "requests>=2.32.4; python_version == '3.8'",
    "requests>=2.32.5; python_version == '3.9'",
    "requests>=2.34.2; python_version >= '3.10'",
    "torrequest>=0.1.0",
    "psutil>=7.2.2",
    "dataclasses>=0.8; python_version == '3.6'",
]

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
