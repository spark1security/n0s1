"""A setuptools based setup module.

See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
"""

import pathlib
import re

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

here = pathlib.Path(__file__).parent.resolve()  # current path
long_description = (here / "README.md").read_text(encoding="utf-8")
with open(here / "requirements.txt") as fp:
    install_reqs = [r.rstrip() for r in fp.readlines() if not r.startswith("#")]


def get_version():
    file = here / "src/n0s1/__init__.py"
    return re.search(
        r'^__version__ = [\'"]([^\'"]*)[\'"]', file.read_text(), re.M
    )[1]


setup(
    name="n0s1",
    version=get_version(),
    description="Secret Scanner for Slack, Jira, Confluence, Asana, Wrike, Linear, Zendesk, GitHub and GitLab. Prevent credential leaks with n0s1.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://spark1.us/n0s1",
    author="Spark 1",
    author_email="contact@spark1.us",
    classifiers=["Development Status :: 3 - Alpha",
                 "Intended Audience :: Developers",
                 "Intended Audience :: Information Technology",
                 "Operating System :: OS Independent",
                 "Topic :: Security",
                 "Topic :: Software Development",
                 "Topic :: System :: Monitoring",
                 "Topic :: Utilities",
                 "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
                 "Programming Language :: Python :: 3.9",
                 "Programming Language :: Python :: 3.10",
                 "Programming Language :: Python :: 3.11",
                 "Programming Language :: Python :: 3.12",
                 "Programming Language :: Python :: 3.13",
                 ],  # Classifiers help users find your project by categorizing it https://pypi.org/classifiers/
    keywords="security, cybersecurity, scanner, secret scanner, secret leak, data leak, Slack, Jira, Confluence, Asana, Wrike, Linear, Zendesk, GitHub, GitLab, security scanner, data loss prevention",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9, <4",

    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=install_reqs,

    # List additional groups of dependencies here (e.g. development
    # dependencies). Users will be able to install these using the "extras"
    # syntax, for example: $ pip install sampleproject[dev]
    # Similar to `install_requires` above, these must be valid existing projects
    extras_require={"dev": ["check-manifest"],
                    "test": ["coverage"],
                    },

    include_package_data=True,
    package_data={"n0s1": ["src/n0s1/config/*"],
                  },

    # The following would provide a command called `n0s1` which
    # executes the function `main` from this package when invoked:
    entry_points={"console_scripts": ["n0s1=n0s1.n0s1:main", ],
                  },

    project_urls={"Bug Reports": "https://github.com/spark1security/n0s1/issues",
                  "Funding": "https://gofund.me/c6a0520c",
                  "Source": "https://github.com/spark1security/n0s1",
                  },
)
