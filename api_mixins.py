# authentic2 - versatile identity manager
# Copyright (C) 2010-2018 Entr'ouvert
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

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.settings import api_settings
from rest_framework.utils import model_meta


class Conflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('Cannot process request because of conflicting resources.')
    default_code = 'conflict'


class GetOrCreateMixinView:
    _lookup_object = None
    _lookable_relations = ('ou',)

    def get_object(self):
        if self._lookup_object is not None:
            return self._lookup_object
        return super().get_object()

    def _get_lookup_keys(self, name):
        return self.request.GET.getlist(name)

    def _lookup_instance(self, keys):
        kwargs = {}
        for key in keys:
            try:
                # special case for email: email should be matched case-insensitively
                if key == 'email':
                    kwargs['email__iexact'] = self.request.data[key]
                elif key in self._lookable_relations:
                    # only ou supported so far
                    if key == 'ou':
                        kwargs['ou__slug'] = self.request.data[key]
                else:
                    kwargs[key] = self.request.data[key]
            except KeyError:
                raise ValidationError({api_settings.NON_FIELD_ERRORS_KEY: ['key %r is missing' % key]})

        qs = self.get_queryset()
        try:
            return qs.get(**kwargs)
        except qs.model.DoesNotExist:
            return None
        except qs.model.MultipleObjectsReturned:
            raise Conflict(
                'retrieved several instances of model %s for key attributes %s' % (qs.model.__name__, kwargs)
            )

    def _validate_get_keys(self, keys):
        # Remove many-to-many relationships from validated_data.
        # They are not valid arguments to the default `.create()` method,
        # as they require that the instance has already been saved.
        info = model_meta.get_field_info(self.get_queryset().model)
        errors = []
        for key in keys:
            if key not in info.fields and key not in info.relations:
                errors.append('unknown key %r' % key)
            if key in info.relations and key not in self._lookable_relations:
                errors.append('relation key %r cannot be used for lookup' % key)
        if errors:
            raise ValidationError({api_settings.NON_FIELD_ERRORS_KEY: errors})

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        get_or_create_keys = self._get_lookup_keys('get_or_create')
        if get_or_create_keys:
            self._validate_get_keys(get_or_create_keys)
            self._lookup_object = self._lookup_instance(get_or_create_keys)
            if self._lookup_object is not None:
                return self.retrieve(request, *args, **kwargs)
        update_or_create_keys = self._get_lookup_keys('update_or_create')
        if update_or_create_keys:
            self._validate_get_keys(update_or_create_keys)
            self._lookup_object = self._lookup_instance(update_or_create_keys)
            if self._lookup_object is not None:
                return self.partial_update(request, *args, **kwargs)
        return super().create(request, *args, **kwargs)
