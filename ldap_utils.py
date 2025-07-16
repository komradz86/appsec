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


import string

import ldap.dn
import ldap.filter
from django.utils.encoding import force_str


class DnFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        value = super().get_value(key, args, kwargs)
        return value

    def get_field(self, field_name, args, kwargs):
        value, used_arg = super().get_field(field_name, args, kwargs)
        if isinstance(value, (list, tuple)) and len(value) == 1:
            value = value[0]
        return value, used_arg

    def format_field(self, value, format_spec):
        value = super().format_field(value, format_spec)
        return ldap.dn.escape_dn_chars(value)

    def convert_field(self, value, conversion):
        if conversion == 's':
            return force_str(value)
        return super().convert_field(value, conversion)


class FilterFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        value = super().get_value(key, args, kwargs)
        return value

    def get_field(self, field_name, args, kwargs):
        value, used_arg = super().get_field(field_name, args, kwargs)
        if isinstance(value, (list, tuple)) and len(value) == 1:
            value = value[0]
        return value, used_arg

    def format_field(self, value, format_spec):
        value = super().format_field(value, format_spec)
        return ldap.filter.escape_filter_chars(value)

    def convert_field(self, value, conversion):
        if conversion == 's':
            return force_str(value)
        return super().convert_field(value, conversion)
