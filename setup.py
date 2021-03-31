#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""
from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.md') as history_file:
    history = history_file.read()

# Installed by pip install nevermined-gateway
# or pip install -e .
install_requirements = [
    # Install squid-py and all its dependencies first
    'common-utils-py==0.4.6',
    'contracts-lib-py==0.6.2',
    'nevermined-secret-store==0.1.0',
    'Flask==1.1.2',
    'Flask-Cors==3.0.8',
    'flask-swagger==0.2.14',
    'flask-swagger-ui==3.25.0',
    'Jinja2>=2.10.1',
    'requests~=2.21.0',
    'gunicorn==19.9.0',
    'nevermined-metadata-driver-interface>=0.1.5',
    'nevermined-metadata-driver-azure>=0.1.0',
    'nevermined-metadata-driver-aws>=0.1.0',
    'nevermined-metadata-driver-onprem>=0.1.0',
    'nevermined-metadata-driver-ipfs>=0.1.0',
    'nevermined-metadata-driver-filecoin>=0.2.1',
    'Werkzeug>=0.15.3',
    'ldap3==2.8.1',
    # secp256k1 support was added recently and the latest release of authlib does not included it yet
    # we will use a fork in the meantime
    'nevermined-authlib==0.1.0',
    'cryptography==3.3.2',
    'ecdsa==0.16.1',
    'eth-keys==0.3.3',
    "pysha3==1.0.2"
]

# Required to run setup.py:
setup_requirements = ['pytest-runner', ]

test_requirements = [
    'coverage',
    'docker',
    'pylint',
    'pytest',
    'pytest-watch',
    'tox',
    'plecos'
]

# Possibly required by developers of nevermined-gateway:
dev_requirements = [
    'bumpversion',
    'pkginfo',
    'twine',
    'watchdog',
]

setup(
    author="nevermined-io",
    author_email='root@nevermined.io',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
    ],
    description="Nevermined Gateway.",
    extras_require={
        'test': test_requirements,
        'dev': dev_requirements + test_requirements,
    },
    install_requires=install_requirements,
    license="Apache Software License 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords='nevermined-gateway',
    name='nevermined-gateway',
    packages=find_packages(include=['nevermined_gateway', 'nevermined_gateway.app']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/nevermined-io/gateway',
    version='0.6.0',
    zip_safe=False,
)
