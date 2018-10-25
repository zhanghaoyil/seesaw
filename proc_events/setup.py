#!/usr/bin/env python
from setuptools import setup, find_packages


kwargs = {
    "name": "proc_events",
    "version": "0.1b0.dev1",
    "description": "Interface to the process event connector in linux kernels.",
    "author": "Daniel Brandt",
    "author_email": "me@dbrandt.se",
    "url": "http://dbrandt.se/proc_events",
    "scripts": ["bin/pec_listener.py"],
    "packages": find_packages(),
}

if __name__ == "__main__":
    setup(**kwargs)
