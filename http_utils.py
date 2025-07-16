# authentic2 - versatile identity manager
# Copyright (C) 2010-2019 Entr'ouvert
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import requests
from django.conf import settings

from authentic2 import app_settings


def get_url(url):
    '''Does a simple GET on an URL, check the certificate'''
    verify = app_settings.A2_VERIFY_SSL
    if verify and app_settings.CAFILE:
        verify = app_settings.CAFILE
    return requests.get(url, verify=verify, timeout=settings.REQUESTS_TIMEOUT).text
