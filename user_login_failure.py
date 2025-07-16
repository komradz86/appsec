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

import hashlib
import logging

from django.core.cache import cache
from django.utils.encoding import smart_bytes

from . import app_settings


def key(identifier):
    return 'user-login-failure-%s' % hashlib.md5(smart_bytes(identifier)).hexdigest()


def user_login_success(identifier):
    cache.delete(key(identifier))


def user_login_failure(identifier):
    logger = logging.getLogger('authentic2.user_login_failure')
    logger.info('user %s failed to login', identifier)
    cache.add(key(identifier), 0)
    try:
        count = cache.incr(key(identifier))
    except ValueError:
        logger.info('Memcache seems to be down')
        return
    if (
        app_settings.A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING
        and count >= app_settings.A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING
    ):
        logger.warning('user %s failed to login more than %d times in a row', identifier, count)
