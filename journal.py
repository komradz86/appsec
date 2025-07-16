# authentic2 - versatile identity manager
# Copyright (C) 2010-2020 Entr'ouvert
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

from authentic2.apps.journal.journal import Journal as BaseJournal
from authentic2.utils.service import get_service


class Journal(BaseJournal):
    def __init__(self, **kwargs):
        self._service = kwargs.pop('service', None)
        super().__init__(**kwargs)

    @property
    def service(self):
        return self._service or get_service(self.request) if self.request else None

    def massage_kwargs(self, record_parameters, kwargs):
        if 'service' not in kwargs and 'service' in record_parameters:
            kwargs['service'] = self.service
        return super().massage_kwargs(record_parameters, kwargs)


journal = Journal()
