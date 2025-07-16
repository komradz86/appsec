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

import json

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.base import DeserializationError
from django.core.serializers.json import Serializer as JSONSerializer
from django.core.serializers.python import _get_model
from django.db import DEFAULT_DB_ALIAS


class Serializer(JSONSerializer):
    def end_object(self, obj):
        concrete_model = obj._meta.concrete_model
        for pfield in concrete_model._meta.private_fields:
            if not isinstance(pfield, GenericForeignKey):
                continue
            ct = getattr(obj, pfield.ct_field)
            if ct is None:
                continue
            sub_obj = getattr(obj, pfield.name)
            if sub_obj is None:
                continue
            if not hasattr(sub_obj, 'natural_key'):
                # abort if no natural key
                continue
            # delete non natural keys
            del self._current[pfield.ct_field]
            del self._current[pfield.fk_field]
            self._current[pfield.name] = (ct.natural_key(), sub_obj.natural_key())
        super().end_object(obj)


def PreDeserializer(objects, **options):
    db = options.pop('using', DEFAULT_DB_ALIAS)

    for d in objects:
        Model = _get_model(d['model'])
        for pfield in Model._meta.private_fields:
            if not isinstance(pfield, GenericForeignKey):
                continue
            if pfield.name not in d['fields']:
                continue
            ct_natural_key, fk_natural_key = d['fields'][pfield.name]
            ct = ContentType.objects.get_by_natural_key(*ct_natural_key)
            obj = ct.model_class()._default_manager.db_manager(db).get_by_natural_key(*fk_natural_key)
            d['fields'][pfield.ct_field] = ct.pk
            d['fields'][pfield.fk_field] = obj.pk
            del d['fields'][pfield.name]
        yield d


def Deserializer(stream_or_string, **options):
    """
    Deserialize a stream or string of JSON data.
    """
    from django.core.serializers.python import Deserializer as PythonDeserializer

    if not isinstance(stream_or_string, (bytes, str)):
        stream_or_string = stream_or_string.read()
    if isinstance(stream_or_string, bytes):
        stream_or_string = stream_or_string.decode('utf-8')
    try:
        objects = json.loads(stream_or_string)
        objects = PreDeserializer(objects, **options)
        yield from PythonDeserializer(objects, **options)
    except GeneratorExit:  # pylint: disable=try-except-raise
        raise
    except Exception as e:
        raise DeserializationError(e)
