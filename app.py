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
import re

from django.apps import AppConfig
from django.db.models import CharField, TextField
from django.views import debug

from . import plugins
from .utils.postgres_utils import TrigramStrictWordSimilar


class Authentic2Config(AppConfig):
    name = 'authentic2'
    verbose_name = 'Authentic2'

    def ready(self):
        plugins.init()
        debug.HIDDEN_SETTINGS = re.compile('API|TOKEN|KEY|SECRET|PASS|PROFANITIES_LIST|SIGNATURE|LDAP')

        # register convertes
        from authentic2.utils.converters import register_converters

        register_converters()

        # register custom postgres ORM lookup
        CharField.register_lookup(TrigramStrictWordSimilar)
        TextField.register_lookup(TrigramStrictWordSimilar)
