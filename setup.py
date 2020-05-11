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
    'common-utils-py==0.2.2',
    'contracts-lib-py==0.2.2',
    'ocean-secret-store-client==0.0.2',
    'Flask==1.1.2',
    'Flask-Cors==3.0.8',
    'flask-swagger==0.2.14',
    'flask-swagger-ui==3.25.0',
    'Jinja2>=2.10.1',
    'requests>=2.23.0',
    'gunicorn==19.9.0',
    'osmosis-azure-driver==0.0.4',
    'osmosis-aws-driver==0.0.4',
    'osmosis-driver-interface==0.0.7',
    'osmosis-on-premise-driver==0.0.6',
    'osmosis-ipfs-driver==0.0.1',
    'Werkzeug>=0.15.3',
    'eciespy==0.3.5',
    'eth-keys==0.3.3',
    'rsa==4.0',
]

# Required to run setup.py:
setup_requirements = ['pytest-runner', ]

test_requirements = [
    'codacy-coverage',
    'coverage',
    'docker',
    'mccabe',
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
    author="keyko-io",
    author_email='root@keyko.io',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
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
    url='https://github.com/keyko-io/nevermined-gateway',
    version='0.2.2',
    zip_safe=False,
)
