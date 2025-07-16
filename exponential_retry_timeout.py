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
import time

from django.core.cache import cache


class ExponentialRetryTimeout:
    FACTOR = 1.8
    DURATION = 0.8
    MAX_DURATION = 3600  # max 1 hour
    KEY_PREFIX = 'exp-backoff-'
    CACHE_DURATION = 86400

    def __init__(
        self,
        factor=FACTOR,
        duration=DURATION,
        max_duration=MAX_DURATION,
        key_prefix=None,
        cache_duration=CACHE_DURATION,
    ):
        self.factor = factor
        self.duration = duration
        self.max_duration = max_duration
        self.cache_duration = cache_duration
        self.logger = logging.getLogger(__name__)
        self.key_prefix = key_prefix

    def key(self, keys):
        key = '-'.join(str(key) for key in keys)
        key = key.encode('utf-8')
        return '%s%s' % (self.key_prefix or self.KEY_PREFIX, hashlib.md5(key).hexdigest())

    def seconds_to_wait(self, *keys):
        """Return the duration in seconds until the next time when an action can be
        done.
        """
        key = self.key(keys)
        if self.duration:
            now = time.time()
            what = cache.get(key)
            if what and what[1] > now:
                return what[1] - now
        return 0

    def success(self, *keys):
        """Signal an action success, delete exponential backoff cache."""
        key = self.key(keys)
        if not self.duration:
            return
        cache.delete(key)
        self.logger.debug('success for %s', keys)

    def failure(self, *keys):
        """Signal an action failure, augment the exponential backoff one level."""
        key = self.key(keys)
        if not self.duration:
            return
        what = cache.get(key)
        if not what:
            now = time.time()
            level, next_time = 0, now + self.duration
        else:
            level, next_time = what
            level += 1
            duration = min(self.duration * self.factor**level, self.max_duration)
            next_time += duration
        cache.set(key, (level, next_time), self.cache_duration)
        self.logger.debug('failure for %s, level: %s, next_time: %s', keys, level, next_time)
