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

import logging


class RequestContextFilter(logging.Filter):
    DEFAULT_USERNAME = '-'
    DEFAULT_IP = '-'
    DEFAULT_REQUEST_ID = '-'

    def filter(self, record):
        """Add username, ip and request ID to the log record.

        Inspired by django-log-request-id
        """
        from . import middleware

        request = record.request = getattr(record, 'request', middleware.StoreRequestMiddleware.get_request())
        if not hasattr(request, 'META'):
            record.request = None

        if not hasattr(record, 'request_id'):
            record.request_id = getattr(request, 'request_id', self.DEFAULT_REQUEST_ID)

        if not hasattr(record, 'ip'):
            record.ip = self.DEFAULT_IP
            if record.request:
                record.ip = request.META.get('REMOTE_ADDR', self.DEFAULT_IP)

        if not hasattr(record, 'user'):
            if hasattr(request, 'user') and request.user.is_authenticated:
                record.user = str(request.user)
            else:
                record.user = self.DEFAULT_USERNAME

        return True


class ForceDebugFilter(logging.Filter):
    def filter(self, record):
        record.levelno = logging.DEBUG
        record.levelname = 'DEBUG'
        return super().filter(record)
