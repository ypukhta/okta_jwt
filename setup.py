#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import async_okta_jwt
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, '__init__.py'))
    ]


extras_require = {}

setup(
    name="async_okta_jwt",
    version=async_okta_jwt.__version__,
    author="Adithya Sampatoor, Yevgen Pukhta",
    author_email="adithya.sampatoor@gmail.com, eugene.pukhta@gmail.com",
    description="Okta JWT Access Token verifier",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ypukhta/okta_jwt",
    packages=get_packages('async_okta_jwt'),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Utilities'
    ],
    extras_require=extras_require,
    tests_require=['mock', 'ddt', 'asynctest'],
    install_requires=['six <2.0', 'httpx', 'python-jose']
)
