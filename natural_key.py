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

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


def get_natural_keys(model):
    if not getattr(model._meta, 'natural_key', None):
        raise ValueError('model %s has no natural key defined in its Meta' % model.__name__)
    natural_key = model._meta.natural_key
    if not hasattr(natural_key, '__iter__'):
        raise ValueError('natural_key must be an iterable')
    if hasattr(natural_key[0], 'lower'):
        natural_key = [natural_key]
    return natural_key


def natural_key_json(self):
    natural_keys = get_natural_keys(self.__class__)
    d = {}
    names = set()
    for keys in natural_keys:
        for key in keys:
            names.add(key)

    for name in names:
        if name.endswith('__isnull'):
            name = name.split('__isnull')[0]
        field = self._meta.get_field(name)
        if not (field.concrete or isinstance(field, GenericForeignKey)):
            raise ValueError('field %s is not concrete' % name)
        if field.is_relation and not field.many_to_one:
            raise ValueError('field %s is a relation but not a ForeignKey' % name)
        value = getattr(self, name)
        if isinstance(field, GenericForeignKey):
            ct_field_value = getattr(self, field.ct_field)
            d[field.ct_field] = ct_field_value and ct_field_value.natural_key_json()
            d[name] = value and value.natural_key_json()
        elif field.is_relation:
            d[name] = value and value.natural_key_json()
        else:
            d[name] = value
    return d


def get_by_natural_key_json(self, d):
    model = self.model
    natural_keys = get_natural_keys(model)
    if not isinstance(d, dict):
        raise ValueError('a natural_key must be a dictionnary')
    for natural_key in natural_keys:
        get_kwargs = {}
        for name in natural_key:
            isnull = name.endswith('__isnull')
            if isnull:
                name = name.split('__isnull')[0]
            field = model._meta.get_field(name)
            if not (field.concrete or isinstance(field, GenericForeignKey)):
                raise ValueError('field %s is not concrete' % name)
            if field.is_relation and not field.many_to_one:
                raise ValueError('field %s is a relation but not a ForeignKey' % name)
            try:
                value = d[name]
            except KeyError:
                if not isnull:
                    break
                value = None
            if isinstance(field, GenericForeignKey):
                if isnull and value:
                    break
                if not isnull:
                    if not value:
                        break
                    try:
                        ct_nk = d[field.ct_field]
                    except KeyError:
                        break
                    try:
                        ct = ContentType.objects.get_by_natural_key_json(ct_nk)
                    except ContentType.DoesNotExist:
                        break
                    related_model = ct.model_class()
                    try:
                        value = related_model._default_manager.get_by_natural_key_json(value)
                    except related_model.DoesNotExist:
                        break
                    get_kwargs[field.ct_field] = ct
                    name = field.fk_field
                    value = value.pk
            elif field.is_relation:
                if isnull and value:
                    break
                if not isnull:
                    if not value:
                        break
                    try:
                        value = field.related_model._default_manager.get_by_natural_key_json(value)
                    except field.related_model.DoesNotExist:
                        break
            if isnull:
                get_kwargs[name + '__isnull'] = True
            else:
                get_kwargs[name] = value
        else:
            try:
                return self.get(**get_kwargs)
            except model.DoesNotExist:
                pass
    raise model.DoesNotExist


models.Model.natural_key_json = natural_key_json
models.Manager.get_by_natural_key_json = get_by_natural_key_json

ContentType._meta.natural_key = ['app_label', 'model']
