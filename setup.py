#!/usr/bin/env python 
# -*- coding: utf-8 -*-
#Copyright 2019 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

from setuptools import setup

setup(
    name = 'KitHack',
    version = "1.0",
    description = "Kit de herramientas hacking",
    author = 'AdrMXR',
    author_email = 'memo923849j@gmail.com',
    download_url = 'https://github.com/AdrMXR/KitHack',
    scripts = ['KitHack.py', 'lib/kitools.py,'],
    install_requires=['py-getch'],
    license = "MIT", 
    classifiers=[
        "Programming Language :: Python :: 2.7",
    ],
)
