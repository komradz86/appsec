# authentic2 - versatile identity manager
# Copyright (C) 2010-2022 Entr'ouvert
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
import os
from contextlib import contextmanager

from django.core.management.base import BaseCommand


@contextmanager
def log_to_console(loggername, verbosity):
    if 'TERM' not in os.environ:
        yield
    else:
        handler = logging.StreamHandler()
        # add timestamp to messages
        formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)

        if verbosity == 1:
            handler.setLevel(logging.ERROR)
        elif verbosity == 2:
            handler.setLevel(logging.INFO)
        elif verbosity == 3:
            handler.setLevel(logging.DEBUG)

        logger = logging.getLogger(loggername)
        initial_level = logger.level
        try:
            logger.propagate = False
            logger.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            yield
        finally:
            logger.propagate = True
            logger.setLevel(initial_level)
            logger.removeHandler(handler)


class LogToConsoleCommand(BaseCommand):
    loggername = None

    def core_command(self, *args, **kwargs):
        raise NotImplementedError

    def handle(self, *args, **kwargs):
        verbosity = int(kwargs['verbosity'])

        with log_to_console(self.loggername, verbosity):
            self.core_command(*args, **kwargs)
