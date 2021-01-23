# -*- coding:utf-8 -*-
# created by Toons on 01/05/2017
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open("VERSION") as f1, open("README.md") as f2:
    VERSION = f1.read().strip()
    LONG_DESCRIPTION = f2.read()

kw = {
    "version": VERSION,
    "name": "pySecp256k1",
    "keywords": ["elliptic", "curve", "bitcoin"],
    "author": "Toons",
    "author_email": "moustikitos@gmail.com",
    "maintainer": "Toons",
    "maintainer_email": "moustikitos@gmail.com",
    "url": "https://github.com/Moustikitos/elliptic-curve",
    "download_url":
        "https://github.com/Moustikitos/elliptic-curve/archive/master.zip",
    "include_package_data": True,
    "description": "Pure python implementation for bitcoin curve",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["pySecp256k1"],
    "install_requires": ["future"],
    "dependecy_list": [],
    "license": "Copyright 2021, MIT licence",
    "classifiers": [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
}

setup(**kw)
