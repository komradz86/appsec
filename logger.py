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


class SettingsLogLevel(int):
    def __new__(cls, default_log_level, debug_setting='DEBUG'):
        return super().__new__(cls, getattr(logging, default_log_level))

    def __init__(self, default_log_level, debug_setting='DEBUG'):
        self.debug_setting = debug_setting
        super().__init__()


class DjangoLogger(logging.getLoggerClass()):
    def getEffectiveLevel(self):
        level = super().getEffectiveLevel()
        if isinstance(level, SettingsLogLevel):
            from django.conf import settings

            debug = getattr(settings, level.debug_setting, False)
            if debug:
                return logging.DEBUG
        return level


logging.setLoggerClass(DjangoLogger)


class DjangoRootLogger(DjangoLogger, logging.RootLogger):
    pass


logging.root.__class__ = DjangoRootLogger
