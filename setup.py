#!/usr/bin/env python
#
# Copyright © 2016 SUSE LLC, James Mason <jmason@suse.com>.
#
# This file is part of SUSE openbare.
#
# openbare is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# openbare is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with openbare. If not, see <http://www.gnu.org/licenses/>.

try:
    import setuptools
except ImportError:
    sys.stderr.write('Python setuptools required, please install.')
    sys.exit(1)

if __name__ == '__main__':
    setuptools.setup(
        name='openbare',
        description=(
            'openbare is a digital asset library system, implemented on Django.'
        ),
        url='https://github.com/openbare/openbare',
        license='GPL-3.0',
        author='James Mason, Robert Schweikert',
        author_email='jmason@suse.com, rjschwei@suse.com',
        version='0.0.2',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Web Environment',
            'Framework :: Django',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Natural Language :: English',
            'Operating System :: POSIX :: Linux',
            'Programming Language :: Python :: 3 :: Only',
            'Topic :: System :: Software Distribution',
            'Topic :: System :: Systems Administration :: Authentication/Directory'
        ],
        keywords='''
            openbare library lcms digitalassets onlineaccounts publiccloud
        ''',
        packages=find_packages(),
        install_requires=[
            'django',
            'python-social-auth',
            'django-markdown-deux',
            'django-split-settings',
            'boto3'
        ],
        include_package_data=True,
        package_data=[
            'openbare': ['LICENSE', 'README.md', 'manage.py']
        ],
        scripts=['manage.py', 'tools/user_monitor.py']
    )
