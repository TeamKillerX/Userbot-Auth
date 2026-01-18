import os
import re

import setuptools


def read(fname, version=False):
    text = open(
        os.path.join(
            os.path.dirname(__file__),
            fname),
        encoding="utf8").read()
    return re.search(r'__version__ = "(.*?)"', text)[1] if version else text


setuptools.setup(
    name="userbot_auth",
    packages=setuptools.find_packages(),
    version=read("userbot-auth/__version__.py", version=True),
    license="MIT",
    description="Ryzenth UBT | Enterprise Security Framework.",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="TeamKillerX",
    project_urls={
        "Source": "https://github.com/TeamKillerX/Userbot-Auth/",
        "Issues": "https://github.com/TeamKillerX/Userbot-Auth/issue",
    },
    keywords=[
        "Userbot-Auth-API",
        "Ryzenth-SDK"
    ],
    install_requires=[
        "requests",
        "typing",
        "aiohttp"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Natural Language :: English",
    ],
    python_requires="~=3.7",
)
