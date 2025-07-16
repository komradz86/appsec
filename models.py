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

import datetime
import functools
import hashlib
import operator
import os
import secrets
import time
import urllib.parse
import uuid
from urllib.parse import quote

import netaddr
from django.conf import settings
from django.contrib import auth
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, models, transaction
from django.db.models import JSONField, Manager
from django.db.models.query import Q
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from model_utils.managers import QueryManager
from rest_framework import exceptions as drf_exceptions

from authentic2 import app_settings as a2_app_settings
from authentic2.a2_rbac.models import Role
from authentic2.a2_rbac.utils import get_default_ou_pk
from authentic2.custom_user.backends import DjangoRBACBackend
from authentic2.manager import user_import
from authentic2.utils.crypto import base64url_decode, base64url_encode
from authentic2.utils.misc import get_password_authenticator
from authentic2.validators import HexaColourValidator, PhoneNumberValidator

# install our natural_key implementation
from . import managers
from . import natural_key as unused_natural_key  # pylint: disable=unused-import
from .utils.misc import ServiceAccessDenied
from .utils.sms import create_sms_code


class APIClientManager(Manager):
    def create_user(self, name, identifier, password, **extra_fields):
        apiclient = self.model(name=name, identifier=identifier, **extra_fields)
        apiclient.set_password(password)
        apiclient.save(using=self.db)
        return apiclient

    def by_identifier(self, identifier):
        return self.model.objects.filter(Q(identifier=identifier) | Q(identifier_legacy=identifier)).all()


class UserExternalId(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_('user'), on_delete=models.CASCADE)
    source = models.CharField(max_length=256, verbose_name=_('source'))
    external_id = models.CharField(max_length=256, verbose_name=_('external id'), null=True)
    external_guid = models.UUIDField(verbose_name=_('External GUID'), null=True)
    created = models.DateTimeField(auto_now_add=True, verbose_name=_('creation date'))
    updated = models.DateTimeField(auto_now=True, verbose_name=_('last update date'))

    def __str__(self):
        return f'{self.user} is {self.external_id or self.external_guid} on {self.source}'

    def __repr__(self):
        return (
            f'<UserExternalId user: {self.user!r} source: {self.source!r}'
            f"{f' external_id: {self.external_id!r}' if self.external_id else ''}"
            f"{f' external_guid: {self.external_guid!r}' if self.external_guid else ''}"
            f' created: {self.created} updated: {self.updated}'
        )

    class Meta:
        verbose_name = _('user external id')
        verbose_name_plural = _('user external ids')
        unique_together = [
            ('source', 'external_id'),
            ('source', 'external_guid'),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(external_id__isnull=False) | Q(external_guid__isnull=False), name='at_least_one_id'
            ),
        ]


class AuthenticationEvent(models.Model):
    '''Record authentication events whatever the source'''

    when = models.DateTimeField(auto_now=True, verbose_name=_('when'))
    who = models.CharField(max_length=80, verbose_name=_('who'))
    how = models.CharField(max_length=32, verbose_name=_('how'))
    nonce = models.CharField(max_length=255, verbose_name=_('nonce'))

    objects = managers.AuthenticationEventManager()

    class Meta:
        verbose_name = _('authentication log')
        verbose_name_plural = _('authentication logs')

    def __str__(self):
        return _('Authentication of %(who)s by %(how)s at %(when)s') % self.__dict__


class LogoutUrlAbstract(models.Model):
    logout_url = models.URLField(
        verbose_name=_('url'),
        help_text=_(
            'you can use a {} to pass the URL of the success icon, ex.: http://example.com/logout?next={}'
        ),
        max_length=255,
        blank=True,
        null=True,
    )
    logout_use_iframe = models.BooleanField(
        verbose_name=_('use an iframe instead of an img tag for logout'), default=False
    )
    logout_use_iframe_timeout = models.PositiveIntegerField(
        verbose_name=_('iframe logout timeout (ms)'),
        help_text=_(
            'if iframe logout is used, it\'s the time between the onload event for this iframe and the moment'
            ' we consider its loading to be really finished'
        ),
        default=300,
    )

    def get_logout_url(self, request):
        ok_icon_url = (
            request.build_absolute_uri(urllib.parse.urljoin(settings.STATIC_URL, 'authentic2/images/ok.png'))
            + '?nonce=%s' % time.time()
        )
        return self.logout_url.format(quote(ok_icon_url))

    class Meta:
        abstract = True


class LogoutUrl(LogoutUrlAbstract):
    content_type = models.ForeignKey(ContentType, verbose_name=_('content type'), on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField(verbose_name=_('object identifier'))
    provider = GenericForeignKey('content_type', 'object_id')

    class Meta:
        verbose_name = _('logout URL')
        verbose_name_plural = _('logout URL')


class Attribute(models.Model):
    label = models.CharField(verbose_name=_('label'), max_length=63, unique=True)
    description = models.TextField(verbose_name=_('description'), blank=True)
    name = models.SlugField(verbose_name=_('name'), max_length=256, unique=True)
    required = models.BooleanField(verbose_name=_('required'), blank=True, default=False)
    asked_on_registration = models.BooleanField(
        verbose_name=_('asked on registration'), blank=True, default=False
    )
    user_editable = models.BooleanField(verbose_name=_('user editable'), blank=True, default=False)
    user_visible = models.BooleanField(verbose_name=_('user visible'), blank=True, default=False)
    multiple = models.BooleanField(verbose_name=_('multiple'), blank=True, default=False)
    kind = models.CharField(max_length=16, verbose_name=_('kind'))
    disabled = models.BooleanField(verbose_name=_('disabled'), blank=True, default=False)
    searchable = models.BooleanField(verbose_name=_('searchable'), blank=True, default=False)
    required_on_login = models.BooleanField(verbose_name=_('required on login'), blank=True, default=False)

    scopes = models.CharField(
        verbose_name=_('scopes'),
        help_text=_('scopes separated by spaces'),
        blank=True,
        default='',
        max_length=256,
    )

    order = models.PositiveIntegerField(verbose_name=_('order'), default=0)

    all_objects = managers.AttributeManager()
    objects = managers.AttributeManager(disabled=False)

    registration_attributes = QueryManager(asked_on_registration=True)
    user_attributes = QueryManager(user_editable=True)

    def get_form_field(self, **kwargs):
        from . import attribute_kinds

        kwargs['label'] = self.label
        kwargs['required'] = self.required
        if self.description:
            kwargs['help_text'] = self.description
        return attribute_kinds.get_form_field(self.kind, **kwargs)

    def get_drf_field(self, **kwargs):
        from rest_framework import serializers

        from authentic2.attribute_kinds import DateRestField

        kind = self.get_kind()
        field_class = kind['rest_framework_field_class']
        base_kwargs = (kind.get('rest_framework_field_kwargs') or {}).copy()
        base_kwargs.update(
            {
                'source': 'attributes.%s' % self.name,
                'required': self.required,
            }
        )
        if not self.required:
            base_kwargs['allow_null'] = True
            # if not stated otherwise by the definition of the kind, string alike fields
            # accept blank values when not required
            if issubclass(field_class, serializers.CharField) and 'allow_blank' not in base_kwargs:
                base_kwargs['allow_blank'] = True
            elif issubclass(field_class, DateRestField) and 'allow_blank' not in base_kwargs:
                base_kwargs['allow_blank'] = True
        elif issubclass(field_class, serializers.CharField):
            base_kwargs['allow_blank'] = False
        elif issubclass(field_class, DateRestField):
            base_kwargs['allow_blank'] = False
        elif issubclass(field_class, serializers.BooleanField):
            base_kwargs['allow_null'] = False

        base_kwargs.update(kwargs)
        return field_class(**base_kwargs)

    def validate_value(self, value):
        try:
            drf_field = self.get_drf_field()
            drf_field.run_validation(value)
        except drf_exceptions.ValidationError as e:
            raise ValidationError(str(e))

    def get_kind(self):
        from . import attribute_kinds

        return attribute_kinds.get_kind(self.kind)

    def contribute_to_form(self, form, **kwargs):
        form.fields[self.name] = self.get_form_field(**kwargs)

    def get_value(self, owner, verified=None):
        kind = self.get_kind()
        deserialize = kind['deserialize']
        atvs = AttributeValue.all_objects.with_owner(owner)
        if verified is True or verified is False:
            atvs = atvs.filter(verified=verified)
        if self.multiple:
            result = []
            for atv in atvs.filter(attribute=self, multiple=True):
                result.append(deserialize(atv.content))
            return result
        else:
            try:
                atv = atvs.get(attribute=self, multiple=False)
                return deserialize(atv.content)
            except AttributeValue.DoesNotExist:
                return kind['default']

    def set_value(self, owner, value, verified=False, attribute_value=None):
        serialize = self.get_kind()['serialize']
        # setting to None is to delete
        if value is None:
            AttributeValue.objects.with_owner(owner).filter(attribute=self).delete()
            return

        with transaction.atomic():
            if self.multiple:
                assert isinstance(value, (list, set, tuple))
                values = value
                avs = []
                content_list = []

                list(owner.__class__.objects.filter(pk=owner.pk).select_for_update())

                for value in values:
                    content = serialize(value)
                    av, created = AttributeValue.objects.get_or_create(
                        content_type=ContentType.objects.get_for_model(owner),
                        object_id=owner.pk,
                        attribute=self,
                        multiple=True,
                        content=content,
                        defaults={
                            'verified': verified,
                            'last_verified_on': timezone.now() if verified else None,
                        },
                    )
                    if not created:
                        av.verified = verified
                        if verified:
                            av.last_verified_on = timezone.now()
                        av.save()
                    avs.append(av)
                    content_list.append(content)

                AttributeValue.objects.filter(
                    attribute=self,
                    content_type=ContentType.objects.get_for_model(owner),
                    object_id=owner.pk,
                    multiple=True,
                ).exclude(content__in=content_list).delete()
                return avs
            else:
                content = serialize(value)
                if attribute_value:
                    av, created = attribute_value, False
                else:
                    av, created = AttributeValue.objects.get_or_create(
                        content_type=ContentType.objects.get_for_model(owner),
                        object_id=owner.pk,
                        attribute=self,
                        multiple=False,
                        defaults={
                            'content': content,
                            'verified': verified,
                            'last_verified_on': timezone.now() if verified else None,
                        },
                    )
                if not created:
                    av.content = content
                    av.verified = verified
                    if verified:
                        av.last_verified_on = timezone.now()
                    av.save()
                return av

    def natural_key(self):
        return (self.name,)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, repr(str(self)))

    def __str__(self):
        return str(self.label)

    class Meta:
        verbose_name = _('attribute definition')
        verbose_name_plural = _('attribute definitions')
        ordering = ('order', 'id')
        base_manager_name = 'all_objects'


class AttributeValue(models.Model):
    content_type = models.ForeignKey(
        'contenttypes.ContentType', verbose_name=_('content type'), on_delete=models.CASCADE
    )
    object_id = models.PositiveIntegerField(verbose_name=_('object identifier'), db_index=True)
    owner = GenericForeignKey('content_type', 'object_id')

    attribute = models.ForeignKey('Attribute', verbose_name=_('attribute'), on_delete=models.CASCADE)
    multiple = models.BooleanField(default=False, null=True)

    content = models.TextField(verbose_name=_('content'), db_index=True)
    search_vector = SearchVectorField(null=True, editable=False)
    verified = models.BooleanField(default=False)
    last_verified_on = models.DateTimeField(
        verbose_name=_('last verification timestamp'),
        null=True,
    )

    all_objects = managers.AttributeValueManager()
    objects = managers.AttributeValueManager(attribute__disabled=False)

    def to_python(self):
        deserialize = self.attribute.get_kind()['deserialize']
        return deserialize(self.content)

    def natural_key(self):
        if not hasattr(self.owner, 'natural_key'):
            return self.id
        return (self.content_type.natural_key(), self.owner.natural_key(), self.attribute.natural_key())

    class Meta:
        verbose_name = _('attribute value')
        ordering = ('attribute__order', 'id')
        verbose_name_plural = _('attribute values')
        unique_together = (('content_type', 'object_id', 'attribute', 'multiple', 'content'),)
        indexes = [
            GinIndex(fields=['search_vector'], name='authentic2_atv_tsvector_idx'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['content_type', 'object_id', 'attribute'],
                name='unique_attribute_idx',
                condition=Q(multiple=False),
            ),
        ]


class PasswordReset(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, verbose_name=_('user'), on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        if self.user_id and not self.user.has_usable_password():
            self.user.set_password(uuid.uuid4().hex)
            self.user.save()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = _('password reset')
        verbose_name_plural = _('password reset')

    def __str__(self):
        return str(self.user)


class Service(models.Model):
    name = models.CharField(verbose_name=_('name'), max_length=128)
    slug = models.SlugField(verbose_name=_('slug'), max_length=128)
    ou = models.ForeignKey(
        verbose_name=_('organizational unit'),
        to='a2_rbac.OrganizationalUnit',
        swappable=False,
        on_delete=models.CASCADE,
        default=get_default_ou_pk,
    )
    authorized_roles = models.ManyToManyField(
        'a2_rbac.Role',
        verbose_name=_('authorized services'),
        through='AuthorizedRole',
        through_fields=('service', 'role'),
        related_name='allowed_services',
        blank=True,
    )
    unauthorized_url = models.URLField(
        verbose_name=_('callback url when unauthorized'), max_length=256, null=True, blank=True
    )
    home_url = models.URLField(verbose_name=_('Home URL'), max_length=256, null=True, blank=True)
    logo = models.ImageField(verbose_name=_('Logo'), blank=True, upload_to='services/logos')
    colour = models.CharField(
        verbose_name=_('Colour'), null=True, blank=True, max_length=32, validators=[HexaColourValidator()]
    )

    profile_types = models.ManyToManyField(
        to='custom_user.ProfileType',
        verbose_name=_('allowed services for this profile type'),
        through='custom_user.ServiceProfileType',
        blank=True,
        related_name='services+',
    )

    objects = managers.ServiceManager()

    def clean(self):
        errors = {}

        if self.ou is None and self.__class__.objects.exclude(pk=self.pk).filter(
            slug=self.slug, ou__isnull=True
        ):
            errors['slug'] = ValidationError(_('The slug must be unique for this ou'), code='duplicate-slug')
        if self.ou is None and self.__class__.objects.exclude(pk=self.pk).filter(
            name=self.name, ou__isnull=True
        ):
            errors['name'] = ValidationError(_('The name must be unique for this ou'), code='duplicate-name')
        if errors:
            raise ValidationError(errors)

    class Meta:
        verbose_name = _('base service model')
        verbose_name_plural = _('base service models')
        unique_together = (('slug', 'ou'),)
        base_manager_name = 'objects'

    def natural_key(self):
        return [self.ou and self.ou.natural_key(), self.slug]

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return '<%s %r>' % (self.__class__.__name__, str(self))

    def authorize(self, user):
        if not self.authorized_roles.exists():
            return True
        if user.is_superuser:
            return True
        if user.roles_and_parents().filter(allowed_services=self).exists():
            return True
        raise ServiceAccessDenied(service=self)

    def add_authorized_role(self, role):
        authorization, dummy = AuthorizedRole.objects.get_or_create(service=self, role=role)
        return authorization

    def remove_authorized_role(self, role):
        try:
            authorization = AuthorizedRole.objects.get(service=self, role=role)
            authorization.delete()
        except AuthorizedRole.DoesNotExist:
            pass
        return True

    def to_json(self, roles=None):
        if roles is None:
            roles = Role.objects.all()
        roles = roles.filter(Q(service=self) | Q(ou=self.ou, service__isnull=True))
        return {
            'name': self.name,
            'slug': self.slug,
            'ou': self.ou.name if self.ou else None,
            'ou__uuid': self.ou.uuid if self.ou else None,
            'ou__name': self.ou.name if self.ou else None,
            'ou__slug': self.ou.slug if self.ou else None,
            'roles': [role.to_json() for role in roles],
        }

    def get_absolute_url(self):
        return reverse('a2-manager-service', kwargs={'service_pk': self.pk})

    def get_base_urls(self):
        return [self.home_url] if self.home_url else []

    @classmethod
    def all_base_urls(cls):
        urls = set()
        for service in cls.objects.select_related().select_subclasses():
            urls.update(service.get_base_urls())
        return list(urls)

    def delete(self, *args, **kwargs):
        if self.logo and os.path.exists(self.logo.path):
            os.unlink(self.logo.path)

        return super().delete(*args, **kwargs)

    @property
    def manager_form_class(self):
        from .manager.forms import ServiceForm

        return ServiceForm

    def get_manager_fields(self):
        return self.manager_form_class._meta.fields

    def get_manager_fields_values(self):
        for field_name in self.get_manager_fields():
            field_value = getattr(self, field_name)
            if not isinstance(field_value, bool) and not field_value:
                continue
            if hasattr(self, 'get_%s_display' % field_name):
                field_value = getattr(self, 'get_%s_display' % field_name)()
            yield self._meta.get_field(field_name).verbose_name, field_value

    def get_manager_context_data(self):
        return {'object_fields_values': self.get_manager_fields_values()}


Service._meta.natural_key = [['slug', 'ou']]


class AuthorizedRole(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    role = models.ForeignKey('a2_rbac.Role', on_delete=models.CASCADE)


class Token(models.Model):
    uuid = models.UUIDField(
        verbose_name=_('Identifier'), primary_key=True, default=uuid.uuid4, editable=False
    )
    kind = models.CharField(verbose_name=_('Kind'), max_length=32)
    content = JSONField(verbose_name=_('Content'), blank=True)
    created = models.DateTimeField(verbose_name=_('Creation date'), auto_now_add=True)
    expires = models.DateTimeField(verbose_name=_('Expires'))

    class Meta:
        ordering = ('-expires', 'kind', 'uuid')

    @property
    def uuid_b64url(self):
        return base64url_encode(self.uuid.bytes).decode('ascii')

    @classmethod
    def create(cls, kind, content, expires=None, duration=60):
        expires = expires or (timezone.now() + datetime.timedelta(seconds=duration))
        return cls.objects.create(kind=kind, content=content, expires=expires)

    @classmethod
    def _decode_uuid(cls, _uuid):
        try:
            _uuid = uuid.UUID(_uuid)
        except (TypeError, ValueError):
            pass
        else:
            return _uuid

        if isinstance(_uuid, str):
            _uuid = _uuid.encode('ascii')
            _uuid = base64url_decode(_uuid)
        return uuid.UUID(bytes=_uuid)

    @classmethod
    def use(cls, kind, _uuid, now=None, delete=True):
        '''Can raise TypeError, ValueError if uuid is invalid, DoesNotExist if uuid is unknown or expired.'''
        now = now or timezone.now()
        if not isinstance(_uuid, uuid.UUID):
            _uuid = cls._decode_uuid(_uuid)
        with transaction.atomic():
            token = cls.objects.get(kind=kind, uuid=_uuid, expires__gt=now)
            if delete:
                token.delete()
            return token

    @classmethod
    def cleanup(cls, now=None):
        now = now or timezone.now()
        cls.objects.filter(expires__lte=now).delete()


class Lock(models.Model):
    created = models.DateTimeField(auto_now_add=True, verbose_name=_('Creation date'))
    name = models.TextField(verbose_name=_('Name'), primary_key=True)

    class Error(Exception):
        pass

    @classmethod
    def cleanup(cls, now=None, age=None):
        age = age if age is not None else datetime.timedelta(hours=1)
        now = now or timezone.now()
        with transaction.atomic(savepoint=False):
            pks = (
                cls.objects.filter(created__lte=now - age)
                .select_for_update(skip_locked=True)
                .values_list('pk', flat=True)
            )
            cls.objects.filter(pk__in=pks).delete()

    @classmethod
    def lock(cls, *args, nowait=False):
        # force ordering to prevent deadlock
        names = sorted(args)
        for name in names:
            dummy, dummy = cls.objects.get_or_create(name=name)
            try:
                cls.objects.select_for_update(nowait=nowait).get(name=name)
            except transaction.TransactionManagementError:
                raise
            except DatabaseError:
                # happen only if nowait=True, in this case the error must be
                # intercepted with "except Lock.Error:", this error is
                # recoverable (i.e. the transaction can continue after)
                raise cls.Error

    @classmethod
    def lock_email(cls, email, nowait=False):
        cls.lock('email:%s' % email, nowait=nowait)

    @classmethod
    def lock_identifier(cls, identifier, nowait=False):
        cls.lock('identifier:%s' % identifier, nowait=nowait)

    class Meta:
        verbose_name = _('Lock')
        verbose_name_plural = _('Lock')


class APIClient(models.Model):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    description = models.TextField(verbose_name=_('Description'), blank=True)
    identifier = models.CharField(max_length=256, unique=True, verbose_name=_('Identifier'))
    identifier_legacy = models.CharField(
        max_length=256, verbose_name='Legacy identifier', null=True, default=None
    )
    password = models.CharField(max_length=256, verbose_name=_('Password'))
    restrict_to_anonymised_data = models.BooleanField(
        verbose_name=_('Restrict to anonymised data'), default=False
    )
    apiclient_roles = models.ManyToManyField(
        'a2_rbac.Role',
        verbose_name=_('roles'),
        related_name='apiclients',
        blank=True,
    )
    ou = models.ForeignKey(
        verbose_name=_('organizational unit'),
        to='a2_rbac.OrganizationalUnit',
        swappable=False,
        on_delete=models.CASCADE,
        default=get_default_ou_pk,
        null=True,
        blank=True,
    )
    allowed_user_attributes = models.ManyToManyField(
        'Attribute',
        verbose_name=_('allowed user attributes'),
        related_name='apiclients',
        blank=True,
    )
    allowed_ip = models.TextField(verbose_name=_('IP allowed'), blank=True)
    denied_ip = models.TextField(verbose_name=_('IP denied'), blank=True)
    ip_allow_deny = models.BooleanField(default=False, verbose_name=_('IP restriction order allow/deny'))

    objects = APIClientManager()

    class Meta:
        verbose_name = _('APIClient')
        verbose_name_plural = _('APIClient')

    def __str__(self):
        if self.name:
            return '%s - %s' % (self._meta.verbose_name, self.name)
        return str(self._meta.verbose_name)

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    @property
    def is_superuser(self):
        return False

    @property
    def allowed_ip_list(self):
        return [
            ip for ip in [ip.strip() for ip in self.allowed_ip.splitlines() if not ip.startswith('#')] if ip
        ]

    @property
    def denied_ip_list(self):
        return [
            ip for ip in [ip.strip() for ip in self.denied_ip.splitlines() if not ip.startswith('#')] if ip
        ]

    def set_password(self, raw_password):
        self.password = auth.hashers.make_password(raw_password)
        self.clear_password = raw_password

    def api_client_password_hash_key(self):
        return f'api-client-hash-{self.pk}'

    def check_password(self, raw_password):
        cached_hash = cache.get(self.api_client_password_hash_key())
        if cached_hash:
            try:
                algo, digest = cached_hash.split(':', 1)
                if algo != 'sha256':
                    raise ValueError
            except ValueError:
                pass
            else:
                return secrets.compare_digest(digest, hashlib.sha256(raw_password.encode()).hexdigest())

        def update_password(raw_password):
            # Will update password hash if hasher changed
            self.password = auth.hashers.make_password(raw_password)
            self.save(update_fields=['password'])

        # ensure we load self.password from db and that we do not keep
        # the value given at creation
        del self.password
        result = auth.hashers.check_password(raw_password, self.password, setter=update_password)
        if result is True:
            # we keep a simplified hash of the password for 30 seconds in order
            # to improve performance, a hardened password hashes like argon2
            # takes more than one second to compute
            cache.set(
                self.api_client_password_hash_key(),
                'sha256:' + hashlib.sha256(raw_password.encode()).hexdigest(),
                timeout=30,
            )
        return result

    def save(self, *args, **kwargs):
        cache.delete(self.api_client_password_hash_key())
        return super().save(*args, **kwargs)

    def has_perm(self, perm, obj=None):
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if not isinstance(backend, DjangoRBACBackend):
                continue
            try:
                if backend.has_perm(self, perm, obj):
                    return True
            except PermissionDenied:
                return False
        return False

    def has_perms(self, perm_list, obj=None):
        if self.is_active and self.is_superuser:
            return True

        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_perm_any(self, perm_or_perms):
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if not isinstance(backend, DjangoRBACBackend):
                continue
            if backend.has_perm_any(self, perm_or_perms):
                return True
        return False

    def has_ou_perm(self, perm, ou):
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if not isinstance(backend, DjangoRBACBackend):
                continue
            if backend.has_ou_perm(self, perm, ou):
                return True
        return False

    def filter_by_perm(self, perm_or_perms, qs):
        results = []
        for backend in auth.get_backends():
            if not isinstance(backend, DjangoRBACBackend):
                continue
            results.append(backend.filter_by_perm(self, perm_or_perms, qs))
        if results:
            return functools.reduce(operator.__or__, results)
        else:
            return qs

    def get_absolute_url(self):
        return reverse('a2-manager-api-client-detail', kwargs={'pk': self.pk})

    def ip_authorized(self, client_ip=None):
        # TODO drop temporary feature flag setting once feature is implemented
        # everywhere it's needed
        if not a2_app_settings.A2_API_USERS_ALLOW_IP_RESTRICTIONS:
            return True  # feature not enabled, all IP authorized

        if not self.allowed_ip and not self.denied_ip:  # no restriction
            return True
        elif not client_ip:  # restrictions but no client ip
            return False
        elif not self.allowed_ip:  # blacklist
            return not self._ip_in_denied_list(client_ip)
        elif not self.denied_ip:  # whitelist
            return self._ip_in_allowed_list(client_ip)
        elif self.ip_allow_deny:  # allow / deny
            return self._ip_in_allowed_list(client_ip) and not self._ip_in_denied_list(client_ip)
        # deny / allow
        return not self._ip_in_denied_list(client_ip) or self._ip_in_allowed_list(client_ip)

    def _ip_in_allowed_list(self, client_ip=None):
        return self.__ip_in_restrict_list(self.allowed_ip_list, client_ip)

    def _ip_in_denied_list(self, client_ip=None):
        return self.__ip_in_restrict_list(self.denied_ip_list, client_ip)

    def __ip_in_restrict_list(self, iplist, client_ip=None):
        for ipnet in iplist:
            if client_ip in netaddr.IPNetwork(ipnet):
                return True
        return False


class SMSCode(models.Model):
    KIND_REGISTRATION = 'registration'
    KIND_PASSWORD_LOST = 'password-reset'
    KIND_PHONE_CHANGE = 'phone-change'
    KIND_ACCOUNT_DELETION = 'account-deletion'
    CODE_TO_TOKEN_KINDS = {
        KIND_REGISTRATION: 'registration',
        KIND_PASSWORD_LOST: 'pw-reset',
        KIND_PHONE_CHANGE: 'phone-change',
        KIND_ACCOUNT_DELETION: 'account-deletion',
    }
    value = models.CharField(
        verbose_name=_('Identifier'), default=create_sms_code, editable=False, max_length=32
    )
    kind = models.CharField(verbose_name=_('Kind'), max_length=32)
    phone = models.CharField(
        _('phone number'), null=True, blank=True, max_length=64, validators=[PhoneNumberValidator]
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, verbose_name=_('user'), on_delete=models.CASCADE, null=True
    )
    url_token = models.UUIDField(
        verbose_name=_('URL token'),
        default=uuid.uuid4,
    )
    created = models.DateTimeField(verbose_name=_('Creation date'), auto_now_add=True)
    expires = models.DateTimeField(verbose_name=_('Expires'))
    sent = models.BooleanField(default=False, verbose_name=_('SMS code sent'))

    # fake codes to avoid disclosing account existence info on unjustified password reset attempts
    fake = models.BooleanField(default=False, verbose_name=_('Is a fake code'))

    @classmethod
    def cleanup(cls, now=None):
        now = now or timezone.now()
        cls.objects.filter(expires__lte=now).delete()

    @classmethod
    def create(cls, phone, user=None, kind=None, expires=None, fake=False, duration=None):
        if not kind:
            kind = cls.KIND_REGISTRATION
        if not duration:
            duration = get_password_authenticator().sms_code_duration or settings.SMS_CODE_DURATION
        expires = expires or (timezone.now() + datetime.timedelta(seconds=duration))
        return cls.objects.create(kind=kind, user=user, phone=phone, expires=expires, fake=fake)


class Setting(models.Model):
    key = models.CharField(verbose_name=_('key'), max_length=128, unique=True)
    value = JSONField(verbose_name=_('value'), blank=True)

    objects = managers.SettingManager()


class UserImport(models.Model):
    class Meta:
        ordering = ('-created',)

    uuid = models.CharField(max_length=128, verbose_name=_('uuid'), unique=True)
    ou = models.ForeignKey(
        verbose_name=_('organizational unit'),
        to='a2_rbac.OrganizationalUnit',
        blank=False,
        null=False,
        swappable=False,
        on_delete=models.CASCADE,
    )
    created = models.DateTimeField(verbose_name=_('created'), auto_now_add=True)

    @property
    def user_import(self):
        return user_import.UserImport(self.uuid)
