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

Name:           openbare
Version:        0.0.1
Release:        0
Summary:        a digital asset library system, implemented on Django
License:        GPL-3.0
Group:          Applications/Internet
Url:            https://github.com/openbare/openbare
Source0:        %{name}-%{version}.tar.bz2
Requires:       python3
Requires:       python3-Django
Requires:       python3-python-social-auth
Requires:       python3-django-markdown-deux
Requires:       python3-django-split-settings
Requires:       python3-boto3
BuildRequires:  python-setuptools
Recommends:     python3-django-debug-toolbar
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%if 0%{?suse_version} && 0%{?suse_version} <= 1110
%{!?python_sitelib: %global python_sitelib %(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%else
BuildArch:      noarch
%endif

%description
openbare is a digital asset library system, implemented on Django.

The system started out with the intend to provide access to Public Cloud
accounts for everyone at SUSE. At the onset of the project is was hoped that
implementation of the framework could be sufficiently generalized to provide
functionality for pretty much anything that one might keep track of that
fits the concept of a Public Library. Once the first plugin was developed
to manage AWS IAM access this hope was realized and the project moved from
a private repository to a public repository in the hopes that others will
find the system useful and will contribute back to the project.

We'd like to thank SUSE for sponsoring our work and enabling us to set up the
project in a company independent way.

%prep
%setup -q -n %{name}-%{version}

%build
python setup.py build

%install
python setup.py install --prefix=%{_prefix} --root=%{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE README.md
%dir %{python_sitelib}/openbare
%{python_sitelib}/*

%changelog
