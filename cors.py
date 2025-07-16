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


import urllib.parse

from django.conf import settings

from . import app_settings, plugins
from .utils.cache import SessionCache


def make_origin(url):
    '''Build origin of an URL'''
    parsed = urllib.parse.urlparse(url)
    if ':' in parsed.netloc:
        host, port = parsed.netloc.split(':', 1)
        if parsed.scheme == 'http' and port == 80:
            port = None
        if parsed.scheme == 'https' and port == 443:
            port = None
    else:
        host, port = parsed.netloc, None
    result = '%s://%s' % (parsed.scheme, host)
    if port:
        result += ':%s' % port
    return result


@SessionCache(timeout=60, args=(1,))
def check_origin(request, origin):
    '''Decide if an origin is authorized to do a CORS request'''
    if settings.DEBUG:
        return True
    request_origin = make_origin(request.build_absolute_uri())
    if origin == 'null':
        return False
    if not origin:
        return False
    if origin == request_origin:
        return True
    # A2_CORS_WHITELIST must contain properly formatted origins (i.e. only
    # scheme and netloc, no path and port must be normalized)
    for whitelist_origin in app_settings.A2_CORS_WHITELIST:
        if whitelist_origin == origin:
            return True
    for plugin in plugins.get_plugins():
        if hasattr(plugin, 'check_origin'):
            if plugin.check_origin(request, origin):
                return True
    return False
