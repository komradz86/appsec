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
from datetime import timedelta

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models.query import QuerySet
from django.utils.timezone import now
from model_utils import managers

from authentic2.a2_rbac.models import OrganizationalUnit

logger = logging.getLogger(__name__)


class GetBySlugQuerySet(QuerySet):
    def get_by_natural_key(self, slug):
        return self.get(slug=slug)


GetBySlugManager = GetBySlugQuerySet.as_manager


class GetByNameQuerySet(QuerySet):
    def get_by_natural_key(self, name):
        return self.get(name=name)


GetByNameManager = GetByNameQuerySet.as_manager


class AuthenticationEventManager(models.Manager):
    def cleanup(self):
        # expire after one week
        expire = getattr(settings, 'AUTHENTICATION_EVENT_EXPIRATION', 3600 * 24 * 7)
        self.filter(when__lt=now() - timedelta(seconds=expire)).delete()


class ExpireManager(models.Manager):
    def cleanup(self):
        self.filter(created__lt=now() - timedelta(days=7)).delete()


class GenericQuerySet(QuerySet):
    def for_generic_object(self, model):
        content_type = ContentType.objects.get_for_model(model)
        return self.filter(content_type=content_type, object_id=model.pk)


GenericManager = models.Manager.from_queryset(GenericQuerySet)


class AttributeValueQuerySet(QuerySet):
    def with_owner(self, owner):
        content_type = ContentType.objects.get_for_model(owner)
        return self.filter(content_type=content_type, object_id=owner.pk)

    def get_by_natural_key(self, ct_nk, owner_nk, attribute_nk):
        from .models import Attribute, AttributeValue

        try:
            ct = ContentType.objects.get_by_natural_key(*ct_nk)
        except ContentType.DoesNotExist:
            raise AttributeValue.DoesNotExist
        try:
            owner_class = ct.model_class()
            owner = owner_class.objects.get_by_natural_key(*owner_nk)
        except owner_class.DoesNotExist:
            raise AttributeValue.DoesNotExist
        try:
            at = Attribute.objects.get_by_natural_key(*attribute_nk)
        except Attribute.DoesNotExist:
            raise AttributeValue.DoesNotExist
        return self.get(content_type=ct, object_id=owner.pk, attribute=at)


class ServiceQuerySet(managers.InheritanceQuerySetMixin, GetBySlugQuerySet):
    pass


class BaseServiceManager(models.Manager):
    def get_by_natural_key(self, ou_natural_key, slug):
        kwargs = {'slug': slug}
        if ou_natural_key:
            try:
                ou = OrganizationalUnit.objects.get_by_natural_key(*ou_natural_key)
            except OrganizationalUnit.DoesNotExist:
                raise self.model.DoesNotExist
            kwargs['ou'] = ou
        else:
            kwargs['ou__isnull'] = True
        return self.get(**kwargs)


class AttributeManager(managers.QueryManager.from_queryset(GetByNameQuerySet)):
    pass


class SettingManager(models.Manager):
    def filter_namespace(self, ns):
        return self.filter(key__startswith=f'{ns}:')


ServiceManager = BaseServiceManager.from_queryset(ServiceQuerySet)
AttributeValueManager = managers.QueryManager.from_queryset(AttributeValueQuerySet)
