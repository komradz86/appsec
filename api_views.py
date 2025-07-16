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

import collections
import datetime
import logging
import smtplib
from functools import partial

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import MultipleObjectsReturned
from django.db import models, transaction
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime
from django.utils.functional import cached_property
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import cache_control
from django.views.decorators.vary import vary_on_headers
from django_filters.fields import IsoDateTimeField as BaseIsoDateTimeField
from django_filters.filters import BooleanFilter, CharFilter
from django_filters.filters import IsoDateTimeFilter as BaseIsoDateTimeFilter
from django_filters.rest_framework import FilterSet
from django_filters.utils import handle_timezone
from pytz.exceptions import AmbiguousTimeError, NonExistentTimeError
from requests.exceptions import RequestException
from rest_framework import pagination, permissions, serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import AuthenticationFailed, ErrorDetail, PermissionDenied, ValidationError
from rest_framework.fields import CreateOnlyDefault
from rest_framework.filters import BaseFilterBackend
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.routers import SimpleRouter
from rest_framework.settings import api_settings
from rest_framework.validators import UniqueTogetherValidator
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ViewSet

from authentic2.apps.journal.journal import journal
from authentic2.apps.journal.models import reference_integer
from authentic2.compat.drf import action
from authentic2.utils.api import get_boolean_flag
from authentic2.utils.text import slugify_keep_underscore

from . import api_mixins, app_settings, decorators
from .a2_rbac.models import OrganizationalUnit, Role, RoleParenting
from .a2_rbac.utils import get_default_ou
from .apps.journal.models import Event
from .custom_user.models import Profile, ProfileType, User
from .journal_event_types import (
    UserDeletionForInactivity,
    UserLogin,
    UserNotificationInactivity,
    UserRegistration,
)
from .models import APIClient, Attribute, AttributeValue, PasswordReset, Service
from .passwords import get_password_checker, get_password_strength
from .utils import hooks
from .utils import misc as utils_misc
from .utils.api import DjangoRBACPermission, NaturalKeyRelatedField

User = get_user_model()


class HookMixin:
    def get_serializer(self, *args, **kwargs):
        serializer = super().get_serializer(*args, **kwargs)
        # if the serializer is a ListSerializer, we modify the child
        if hasattr(serializer, 'child'):
            hooks.call_hooks('api_modify_serializer', self, serializer.child)
        else:
            hooks.call_hooks('api_modify_serializer', self, serializer)
        return serializer

    def get_object(self):
        hooks.call_hooks('api_modify_view_before_get_object', self)
        return super().get_object()


class DjangoPermission(permissions.BasePermission):
    def __init__(self, perm):
        self.perm = perm

    def has_permission(self, request, view):
        return request.user.has_perm(self.perm)

    def has_object_permission(self, request, view, obj):
        return request.user.has_perm(self.perm, obj=obj)

    def __call__(self):
        return self


class ExceptionHandlerMixin:
    def handle_exception(self, exc):
        if hasattr(exc, 'detail'):
            exc.detail = {
                'result': 0,
                'errors': exc.detail,
            }
            return super().handle_exception(exc)
        else:
            response = super().handle_exception(exc)
            response.data = {
                'result': 0,
                'errors': response.data,
            }
            return response


class RegistrationSerializer(serializers.Serializer):
    '''Register RPC payload'''

    email = serializers.EmailField(required=False, allow_blank=True)
    ou = serializers.SlugRelatedField(
        queryset=OrganizationalUnit.objects.all(),
        slug_field='slug',
        default=get_default_ou,
        required=False,
        allow_null=True,
    )
    username = serializers.CharField(required=False, allow_blank=True)
    first_name = serializers.CharField(required=False, allow_blank=True, default='')
    last_name = serializers.CharField(required=False, allow_blank=True, default='')
    password = serializers.CharField(required=False, allow_null=True)
    no_email_validation = serializers.BooleanField(required=False)
    return_url = serializers.URLField(required=False, allow_blank=True)

    def validate(self, attrs):
        request = self.context.get('request')
        ou = attrs.get('ou')
        if request:
            perm = 'custom_user.add_user'
            if ou:
                authorized = request.user.has_ou_perm(perm, attrs['ou'])
            else:
                authorized = request.user.has_perm(perm)
            if not authorized:
                raise serializers.ValidationError(_('you are not authorized to create users in this ou'))
        User = get_user_model()
        if ou:
            if app_settings.A2_EMAIL_IS_UNIQUE or app_settings.A2_REGISTRATION_EMAIL_IS_UNIQUE:
                if 'email' not in attrs:
                    raise serializers.ValidationError(_('Email is required'))
                if User.objects.filter(email__iexact=attrs['email']).exists():
                    raise serializers.ValidationError(_('Account already exists'))

            if ou.email_is_unique:
                if 'email' not in attrs:
                    raise serializers.ValidationError(_('Email is required in this ou'))
                if User.objects.filter(ou=ou, email__iexact=attrs['email']).exists():
                    raise serializers.ValidationError(_('Account already exists in this ou'))

            if app_settings.A2_USERNAME_IS_UNIQUE or app_settings.A2_REGISTRATION_USERNAME_IS_UNIQUE:
                if 'username' not in attrs:
                    raise serializers.ValidationError(_('Username is required'))
                if User.objects.filter(username=attrs['username']).exists():
                    raise serializers.ValidationError(_('Account already exists'))

            if ou.username_is_unique:
                if 'username' not in attrs:
                    raise serializers.ValidationError(_('Username is required in this ou'))
                if User.objects.filter(ou=ou, username=attrs['username']).exists():
                    raise serializers.ValidationError(_('Account already exists in this ou'))
        return attrs


class RpcMixin:
    def post(self, request, format=None):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            response, response_status = self.rpc(request, serializer)
            return Response(response, response_status)
        else:
            response = {'result': 0, 'errors': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)


class BaseRpcView(ExceptionHandlerMixin, RpcMixin, GenericAPIView):
    pass


class PasswordChangeSerializer(serializers.Serializer):
    '''Register RPC payload'''

    email = serializers.EmailField()
    ou = serializers.SlugRelatedField(
        queryset=OrganizationalUnit.objects.all(), slug_field='slug', required=False, allow_null=True
    )
    old_password = serializers.CharField(required=True, allow_null=True)
    new_password = serializers.CharField(required=True, allow_null=True)

    def validate(self, attrs):
        User = get_user_model()
        qs = User.objects.filter(email__iexact=attrs['email'])
        if attrs['ou']:
            qs = qs.filter(ou=attrs['ou'])
        try:
            self.user = qs.get()
        except User.DoesNotExist:
            raise serializers.ValidationError('no user found')
        except MultipleObjectsReturned:
            raise serializers.ValidationError('more than one user have this email')
        if not self.user.check_password(attrs['old_password']):
            raise serializers.ValidationError('old_password is invalid')
        return attrs


class PasswordChange(BaseRpcView):
    permission_classes = (DjangoPermission('custom_user.change_user'),)
    serializer_class = PasswordChangeSerializer

    def rpc(self, request, serializer):
        serializer.user.set_password(serializer.validated_data['new_password'])
        serializer.user.save()
        request.journal.record('manager.user.password.change', form=serializer, api=True)
        return {'result': 1}, status.HTTP_200_OK


password_change = PasswordChange.as_view()


@vary_on_headers('Cookie', 'Origin', 'Referer')
@cache_control(private=True, max_age=60)
@decorators.json
def user(request):
    if request.user.is_anonymous:
        return {}
    return request.user.to_json()


class ServiceConciseSerializer(serializers.ModelSerializer):
    ou = serializers.SlugRelatedField(
        many=False,
        required=False,
        read_only=True,
        slug_field='slug',
    )

    class Meta:
        model = Service
        fields = ('ou', 'slug', 'name')


class SlugFromNameDefault:
    requires_context = True

    def __call__(self, serializer_instance):
        name = serializer_instance.context['request'].data.get('name')
        if not isinstance(name, str):
            name = ''
        return slugify_keep_underscore(name)


class RoleSerializer(serializers.ModelSerializer):
    ou = serializers.SlugRelatedField(
        many=False,
        required=False,
        default=CreateOnlyDefault(get_default_ou),
        queryset=OrganizationalUnit.objects.all(),
        slug_field='slug',
    )
    slug = serializers.SlugField(
        required=False, allow_blank=False, max_length=256, default=SlugFromNameDefault()
    )

    @property
    def user(self):
        return self.context['request'].user

    def __init__(self, instance=None, **kwargs):
        super().__init__(instance, **kwargs)
        if self.instance:
            self.fields['ou'].read_only = True

    def create(self, validated_data):
        ou = validated_data.get('ou')
        # Creating roles also means being allowed to within the OU:
        if not self.user.has_ou_perm('a2_rbac.add_role', ou):
            raise PermissionDenied('User %s can\'t create role in OU %s' % (self.user, ou))
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Check role-updating permissions:
        if not self.user.has_perm('a2_rbac.change_role', obj=instance):
            raise PermissionDenied('User %s can\'t change role %s' % (self.user, instance))
        super().update(instance, validated_data)
        return instance

    def partial_update(self, instance, validated_data):
        # Check role-updating permissions:
        if not self.user.has_perm('a2_rbac.change_role', obj=instance):
            raise PermissionDenied('User %s can\'t change role %s' % (self.user, instance))
        super().partial_update(instance, validated_data)
        return instance

    class Meta:
        model = Role
        fields = (
            'uuid',
            'name',
            'slug',
            'ou',
        )
        extra_kwargs = {'uuid': {'read_only': True}}
        validators = [
            UniqueTogetherValidator(queryset=Role.objects.all(), fields=['name', 'ou']),
            UniqueTogetherValidator(queryset=Role.objects.all(), fields=['slug', 'ou']),
        ]


class RoleCustomField(RoleSerializer):
    service = ServiceConciseSerializer(
        many=False,
        required=False,
        read_only=True,
    )

    class Meta(RoleSerializer.Meta):
        fields = ('description', 'name', 'ou', 'service', 'slug', 'uuid')
        extra_kwargs = {'ou': {'read_only': True}}


class FastUserListSerializer(serializers.ListSerializer):
    def to_representation(self, data):
        # here data is a User queryset or a list of User objects
        # - aggregate user_ids
        # - retrieve direct role memberships
        # - retrieve indirect role memberships
        # - prefetch attribute values
        # - complete user representation with attributes and roles
        user_ids = {user.id for user in data}
        representation = super().to_representation(data)
        include_roles = self.child.include_roles

        if include_roles:
            memberships_ids = Role.members.through.objects.filter(user_id__in=user_ids).values_list(
                'user_id', 'role_id'
            )
            user_to_role_ids = collections.defaultdict(set)
            role_ids = set()
            for user_id, role_id in memberships_ids:
                user_to_role_ids[user_id].add(role_id)
                role_ids.add(role_id)

            role_parenting_ids = RoleParenting.objects.filter(
                child_id__in=[x[1] for x in memberships_ids]
            ).values_list('parent_id', 'child_id')
            role_id_to_parent_ids = collections.defaultdict(set)
            for parent_id, child_id in role_parenting_ids:
                role_id_to_parent_ids[child_id].add(parent_id)
                role_ids.add(parent_id)
            role_qs = Role.objects.filter(id__in=role_ids)
            role_qs = role_qs.values(
                'id',
                'slug',
                'uuid',
                'name',
                'description',
                'ou__slug',
                'service__name',
                'service__slug',
                'service__ou__slug',
            )
            id_to_role = {}
            for role in role_qs:
                # reproduce serialization of RoleCustomField
                serialization = {
                    'slug': role['slug'],
                    'uuid': role['uuid'],
                    'name': role['name'],
                    'ou': role['ou__slug'],
                    'service': None,
                    'description': role['description'],
                }
                if role['service__name']:
                    serialization['service'] = {
                        'ou': role['service__ou__slug'],
                        'slug': role['service__slug'],
                        'name': role['service__name'],
                    }
                id_to_role[role['id']] = serialization

        def get_attributes():
            attributes = None
            if (request := self.context.get('request')) and isinstance(request.user, APIClient):
                attributes = list(request.user.allowed_user_attributes.all())
            if attributes:
                return attributes
            return list(Attribute.objects.all())

        attributes = get_attributes()
        id_to_attribute = {at.id: at for at in attributes}
        at_to_drf = {}
        user_id_to_atvs = collections.defaultdict(list)
        for atv in AttributeValue.objects.filter(
            object_id__in=user_ids, attribute_id__in=list(id_to_attribute)
        ):
            user_id_to_atvs[atv.object_id].append(atv)

        def add_attributes_and_roles(user, user_representation):
            for at_value in user_id_to_atvs[user.id]:
                try:
                    at = id_to_attribute[at_value.attribute_id]
                except KeyError:
                    continue
                # prevent SQL query to resolve at_value.attribute_id in at_value.to_python() call
                at_value.attribute = at
                if at in at_to_drf:
                    drf_field = at_to_drf.get(at)
                else:
                    drf_field = at_to_drf[at] = at.get_drf_field()
                # reproduce serialization of attributes fields and verified field
                user_representation[at.name + '_verified'] = at_value.verified
                user_representation[at.name] = drf_field.to_representation(at_value.to_python())

            for at in attributes:
                if at.name not in user_representation:
                    user_representation[at.name] = None
                if (at.name + '_verified') not in user_representation:
                    user_representation[at.name + '_verified'] = False

            if include_roles:
                roles = user_representation['roles'] = []
                for role_id in user_to_role_ids[user.id]:
                    roles.append(id_to_role[role_id])
                    for parent_role_id in role_id_to_parent_ids.get(role_id, ()):
                        roles.append(id_to_role[parent_role_id])

        for user, user_representation in zip(data, representation):
            add_attributes_and_roles(user, user_representation)
        return representation


class BaseUserSerializer(serializers.ModelSerializer):
    ou = serializers.SlugRelatedField(
        queryset=OrganizationalUnit.objects.all(), slug_field='slug', required=False, default=get_default_ou
    )
    full_name = serializers.SerializerMethodField()
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    dist = serializers.FloatField(read_only=True)
    send_registration_email = serializers.BooleanField(write_only=True, required=False, default=False)
    send_registration_email_next_url = serializers.URLField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, max_length=128, required=False)
    force_password_reset = serializers.BooleanField(write_only=True, required=False, default=False)
    hashed_password = serializers.CharField(write_only=True, max_length=128, required=False)

    def check_perm(self, perm, ou):
        self.context['view'].check_perm(perm, ou)

    def get_full_name(self, ob):
        return ob.get_full_name()

    def create(self, validated_data):
        original_data = validated_data.copy()
        send_registration_email = validated_data.pop('send_registration_email', False)
        send_registration_email_next_url = validated_data.pop('send_registration_email_next_url', None)
        force_password_reset = validated_data.pop('force_password_reset', False)

        attributes = validated_data.pop('attributes', {})
        is_verified = validated_data.pop('is_verified', {})
        password = validated_data.pop('password', None)
        hashed_password = validated_data.pop('hashed_password', None)
        self.check_perm('custom_user.add_user', validated_data.get('ou'))
        instance = super().create(validated_data)
        # prevent update on a get_or_create
        if not getattr(instance, '_a2_created', True):
            return instance
        for key, value in attributes.items():
            verified = bool(is_verified.get(key))
            accessor = instance.verified_attributes if verified else instance.attributes
            setattr(accessor, key, value)
        instance.refresh_from_db()
        if is_verified.get('first_name'):
            instance.verified_attributes.first_name = instance.first_name
        if is_verified.get('last_name'):
            instance.verified_attributes.last_name = instance.last_name
        if password is not None:
            instance.set_password(password)
        else:
            instance.set_unusable_password()
        instance.save()
        if force_password_reset:
            PasswordReset.objects.get_or_create(user=instance)
        if hashed_password is not None:
            instance.password = hashed_password
            instance.save()
        if send_registration_email and validated_data.get('email'):
            try:
                utils_misc.send_password_reset_mail(
                    instance,
                    template_names=[
                        'authentic2/api_user_create_registration_email',
                        'authentic2/password_reset',
                    ],
                    request=self.context['request'],
                    next_url=send_registration_email_next_url,
                    context={
                        'data': original_data,
                    },
                )
            except smtplib.SMTPException as e:
                logging.getLogger(__name__).error(
                    'registration mail could not be sent to user %s created through API: %s', instance, e
                )
        return instance

    def update(self, instance, validated_data):
        force_password_reset = validated_data.pop('force_password_reset', False)
        # Remove unused fields
        validated_data.pop('send_registration_email', False)
        validated_data.pop('send_registration_email_next_url', None)
        attributes = validated_data.pop('attributes', {})
        is_verified = validated_data.pop('is_verified', {})
        password = validated_data.pop('password', None)
        hashed_password = validated_data.pop('hashed_password', None)
        # Double check: to move an user from one ou into another you must be administrator of both
        self.check_perm('custom_user.change_user', instance.ou)
        if 'ou' in validated_data:
            self.check_perm('custom_user.change_user', validated_data.get('ou'))
        if validated_data.get('email') != instance.email and not validated_data.get('email_verified'):
            instance.set_email_verified(False)
        super().update(instance, validated_data)
        for key, value in attributes.items():
            verified = bool(is_verified.get(key))
            accessor = instance.verified_attributes if verified else instance.attributes
            setattr(accessor, key, value)
        for key in is_verified:
            if key not in attributes:
                verified = bool(is_verified.get(key))
                accessor = instance.verified_attributes if verified else instance.attributes
                setattr(accessor, key, getattr(instance.attributes, key))
        instance.refresh_from_db()
        if is_verified.get('first_name'):
            instance.verified_attributes.first_name = instance.first_name
        if is_verified.get('last_name'):
            instance.verified_attributes.last_name = instance.last_name
        if password is not None:
            instance.set_password(password)
            instance.save()
        if force_password_reset:
            PasswordReset.objects.get_or_create(user=instance)
        if hashed_password is not None:
            instance.password = hashed_password
            instance.save()
        return instance

    def validate(self, attrs):
        User = get_user_model()
        qs = User.objects.all()

        ou = None

        if self.instance:
            ou = self.instance.ou
        if 'ou' in attrs and not ou:
            ou = attrs['ou']

        get_or_create_fields = self.context['view'].request.GET.getlist('get_or_create')
        update_or_create_fields = self.context['view'].request.GET.getlist('update_or_create')

        already_used = False
        if (
            'email' not in get_or_create_fields
            and 'email' not in update_or_create_fields
            and attrs.get('email')
            and (not self.instance or attrs.get('email') != self.instance.email)
        ):
            if app_settings.A2_EMAIL_IS_UNIQUE and qs.filter(email__iexact=attrs['email']).exists():
                already_used = True
            if ou and ou.email_is_unique and qs.filter(ou=ou, email__iexact=attrs['email']).exists():
                already_used = True

        errors = {}
        if already_used:
            errors['email'] = 'email already used'
        if attrs.get('password') and attrs.get('hashed_password'):
            errors['password'] = 'conflict with provided hashed_password'
        if attrs.get('hashed_password'):
            try:
                hasher = identify_hasher(attrs.get('hashed_password'))
            except ValueError:
                errors['hashed_password'] = 'unknown hash format'
            else:
                try:
                    hasher.safe_summary(attrs.get('hashed_password'))
                except Exception:
                    errors['hashed_password'] = 'hash format error'
        authenticator = utils_misc.get_password_authenticator()
        if authenticator.is_phone_authn_active and (
            value := attrs.get('attributes', {}).get(authenticator.phone_identifier_field.name, None)
        ):
            qs = AttributeValue.objects.filter(
                attribute=authenticator.phone_identifier_field,
                content=value,
            )
            if self.instance:
                qs.exclude(object_id=self.instance.id)
            # manage ou- or global-uniqueness settings
            ou = attrs.get('ou', None) or get_default_ou()
            if not app_settings.A2_PHONE_IS_UNIQUE:
                if not ou.phone_is_unique:
                    qs = qs.none()
                else:
                    qs = qs.filter(object_id__in=User.objects.filter(ou=ou))
            if qs.exists():
                errors['attributes'] = _('This phone number identifier is already used.')

        if errors:
            raise serializers.ValidationError(errors)
        return attrs

    class Meta:
        model = get_user_model()
        extra_kwargs = {
            'uuid': {
                'read_only': False,
                'required': False,
            }
        }
        exclude = ('phone', 'user_permissions', 'groups', 'keepalive')


class UserSerializer(BaseUserSerializer):
    '''Serializer used for create/update methods'''

    def __new__(cls, *args, **kwargs):
        # Override __new__() method to return the FastUserSerializer for the list()
        # method, the presence of many=True indicate a listing endpoint.
        #
        # If a list[User] serializer was used in update/created mode, this
        # mechanism should be changed.
        if kwargs.pop('many', False):
            return FastUserSerializer(*args, **kwargs, many=True)
        return super().__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kwargs):
        self.include_roles = kwargs.pop('include_roles', True)
        super().__init__(*args, **kwargs)
        attributes = Attribute.objects.all()
        if (
            (request := self.context.get('request'))
            and isinstance(request.user, APIClient)
            and (attrs := request.user.allowed_user_attributes.all())
        ):
            attributes = attrs

        for at in attributes:
            if at.name in self.fields:
                self.fields[at.name].required = at.required
                if at.required and isinstance(self.fields[at.name], serializers.CharField):
                    self.fields[at.name].allow_blank = False
            else:
                self.fields[at.name] = at.get_drf_field()
            self.fields[at.name + '_verified'] = serializers.BooleanField(
                source='is_verified.%s' % at.name, required=False
            )
        for key in self.fields:
            if key in app_settings.A2_REQUIRED_FIELDS:
                self.fields[key].required = True

        # A2_API_USERS_REQUIRED_FIELDS override all other sources of requiredness
        if app_settings.A2_API_USERS_REQUIRED_FIELDS:
            for key in self.fields:
                self.fields[key].required = key in app_settings.A2_API_USERS_REQUIRED_FIELDS

        if self.include_roles:
            self.fields['roles'] = RoleCustomField(many=True, read_only=True, source='roles_and_parents')


class FastUserSerializer(BaseUserSerializer):
    def __init__(self, *args, **kwargs):
        # will be read by FastUserListSerializer
        self.include_roles = kwargs.pop('include_roles', True)
        super().__init__(*args, **kwargs)

    # Serializer used for the case of listing of users (GET /api/users/,
    # GET /api/users/find_duplicates/, GET /api/roles/.../memberships/)
    class Meta(BaseUserSerializer.Meta):
        list_serializer_class = FastUserListSerializer


class DuplicateUserSerializer(FastUserSerializer):
    duplicate_distance = serializers.FloatField(required=True, source='dist')
    text = serializers.CharField(required=True, source='get_full_name')


# override to handle ambiguous naive DateTime on DST change
class IsoDateTimeField(BaseIsoDateTimeField):
    def __init__(self, *args, **kwargs):
        self.bound = kwargs.pop('bound')
        assert self.bound in ['upper', 'lesser']
        super().__init__(*args, **kwargs)

    def strptime(self, value, format):
        try:
            return super().strptime(value, format)
        except (NonExistentTimeError, AmbiguousTimeError):
            parsed = parse_datetime(value)
            possible = sorted(
                [
                    handle_timezone(parsed, is_dst=True),
                    handle_timezone(parsed, is_dst=False),
                ]
            )
            if self.bound == 'lesser':
                return possible[0]
            elif self.bound == 'upper':
                return possible[1]


class IsoDateTimeFilter(BaseIsoDateTimeFilter):
    @property
    def field_class(self):
        if self.lookup_expr.startswith('gt'):
            return partial(IsoDateTimeField, bound='lesser')
        elif self.lookup_expr.startswith('lt'):
            return partial(IsoDateTimeField, bound='upper')
        else:
            raise NotImplementedError


class UsersFilter(FilterSet):
    class Meta:
        model = get_user_model()
        fields = {
            'username': ['exact', 'iexact'],
            'first_name': [
                'exact',
                'iexact',
                'icontains',
                'gte',
                'lte',
                'gt',
                'lt',
            ],
            'last_name': [
                'exact',
                'iexact',
                'icontains',
                'gte',
                'lte',
                'gt',
                'lt',
            ],
            'modified': [
                'gte',
                'lte',
                'gt',
                'lt',
            ],
            'date_joined': [
                'gte',
                'lte',
                'gt',
                'lt',
            ],
            'email': [
                'exact',
                'iexact',
            ],
            'ou__slug': [
                'exact',
            ],
        }
        filter_overrides = {
            models.DateTimeField: {
                'filter_class': IsoDateTimeFilter,
            }
        }


class ChangeEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class FreeTextSearchFilter(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        if 'q' in request.GET:
            queryset = queryset.free_text_search(request.GET['q'])
        return queryset


class UsersAPIPagination(pagination.CursorPagination):
    page_size_query_param = 'limit'
    max_page_size = 100

    def __init__(self):
        self.offset_cutoff = app_settings.A2_API_USERS_NUMBER_LIMIT


class UsersAPI(api_mixins.GetOrCreateMixinView, HookMixin, ExceptionHandlerMixin, ModelViewSet):
    queryset = User.objects.all()
    ordering_fields = ['username', 'first_name', 'last_name', 'modified', 'date_joined']
    lookup_field = 'uuid'
    serializer_class = UserSerializer
    # https://django-filter.readthedocs.io/en/master/guide/migration.html#view-attributes-renamed-867
    #
    # MigrationNotice: `UsersAPI.filter_class` attribute should be renamed
    # `filterset_class`. See:
    # https://django-filter.readthedocs.io/en/master/guide/migration.html
    filter_class = UsersFilter
    filterset_class = UsersFilter
    filter_backends = [FreeTextSearchFilter] + api_settings.DEFAULT_FILTER_BACKENDS
    pagination_class = UsersAPIPagination

    include_roles = True

    @property
    def ordering(self):
        if 'q' in self.request.GET:
            return ['dist', 'last_name__immutable_unaccent', 'first_name__immutable_unaccent']
        return User._meta.ordering

    def get_serializer(self, *args, **kwargs):
        include_roles = get_boolean_flag(self.request, 'include-roles', self.include_roles)
        kwargs['include_roles'] = include_roles
        return super().get_serializer(*args, **kwargs)

    def get_queryset(self):
        qs = super().get_queryset()
        qs = qs.select_related('ou')
        new_qs = hooks.call_hooks_first_result('api_modify_queryset', self, qs)
        if new_qs is not None:
            return new_qs
        return qs

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        queryset = self.request.user.filter_by_perm(['custom_user.view_user'], queryset)
        # filter users authorized for a specified service
        if 'service-slug' in self.request.GET:
            service_slug = self.request.GET['service-slug']
            service_ou = self.request.GET.get('service-ou', '')
            service = (
                Service.objects.filter(slug=service_slug, ou__slug=service_ou)
                .prefetch_related('authorized_roles')
                .first()
            )
            if service:
                if service.authorized_roles.all():
                    queryset = queryset.filter(roles__in=service.authorized_roles.children())
                    queryset = queryset.distinct()
            else:
                queryset = queryset.none()
        return queryset

    def filter_queryset_by_ou_perm(self, perm):
        queryset = User.objects
        allowed_ous = []

        if self.request.user.has_perm(perm):
            return queryset

        for ou in OrganizationalUnit.objects.all():
            if self.request.user.has_ou_perm(perm, ou):
                allowed_ous.append(ou)
        if not allowed_ous:
            raise PermissionDenied('You do not have permission to perform this action.')

        queryset = queryset.filter(ou__in=allowed_ous)
        return queryset

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

    def check_perm(self, perm, ou):
        if ou:
            if not self.request.user.has_ou_perm(perm, ou):
                raise PermissionDenied('You do not have permission %s in %s' % (perm, ou))
        else:
            if not self.request.user.has_perm(perm):
                raise PermissionDenied('You do not have permission %s' % perm)

    def perform_create(self, serializer):
        super().perform_create(serializer)
        self.request.journal.record('manager.user.creation', form=serializer, api=True)

    def perform_update(self, serializer):
        super().perform_update(serializer)
        attributes = serializer.validated_data.pop('attributes', {})
        serializer.validated_data.update(attributes)
        self.request.journal.record('manager.user.profile.edit', form=serializer, api=True)

    def perform_destroy(self, instance):
        self.check_perm('custom_user.delete_user', instance.ou)
        self.request.journal.record('manager.user.deletion', target_user=instance, api=True)
        super().perform_destroy(instance)

    class SynchronizationSerializer(serializers.Serializer):
        known_uuids = serializers.ListField(child=serializers.CharField())
        full_known_users = serializers.BooleanField(required=False)
        timestamp = serializers.DateTimeField(required=False)
        keepalive = serializers.BooleanField(required=False)

    def check_unknown_uuids(self, remote_uuids, users):
        return set(remote_uuids) - {user.uuid for user in users}

    def check_modified_uuids(self, timestamp, users, unknown_uuids):
        modified_users_uuids = set()
        user_ct = ContentType.objects.get_for_model(get_user_model())
        reference_ids = [reference_integer(user) for user in users]
        user_events = Event.objects.filter(
            models.Q(reference_ids__overlap=reference_ids) | models.Q(user__in=users),
            timestamp__gt=timestamp,
        )
        users_pks = {user.pk: user for user in users}
        for user_event in user_events:
            for ct_id, instance_pk in user_event.get_reference_ids():
                if (
                    ct_id == user_ct.pk
                    and instance_pk in users_pks
                    and users_pks[instance_pk].uuid not in modified_users_uuids
                ):
                    modified_users_uuids.add(users_pks[instance_pk].uuid)
        return modified_users_uuids

    @action(detail=False, methods=['post'], permission_classes=(permissions.IsAuthenticated,))
    def synchronization(self, request):
        serializer = self.SynchronizationSerializer(data=request.data)
        queryset = self.filter_queryset_by_ou_perm('custom_user.search_user')

        if not serializer.is_valid():
            response = {'result': 0, 'errors': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)
        hooks.call_hooks('api_modify_serializer_after_validation', self, serializer)
        remote_uuids = serializer.validated_data.get('known_uuids', [])
        users = queryset.filter(uuid__in=remote_uuids).only('id', 'uuid')
        unknown_uuids = self.check_unknown_uuids(remote_uuids, users)
        data = {
            'result': 1,
            'unknown_uuids': unknown_uuids,
        }

        timestamp = serializer.validated_data.get('timestamp', None)
        if timestamp:
            data['modified_users_uuids'] = self.check_modified_uuids(timestamp, users, unknown_uuids)

        full_known_users = serializer.validated_data.get('full_known_users', None)
        if full_known_users:
            # reload users to get all fields
            known_users = User.objects.filter(pk__in=[user.pk for user in users[:1000]])
            data['known_users'] = FastUserSerializer(known_users, many=True).data
        # update keepalive if requested and:
        # - user is an administrator of users,
        # - user is a publik service using publik signature.
        # It currently excludes APIClient and OIDCClient
        keepalive = serializer.validated_data.get('keepalive', False)
        if keepalive:
            if not (
                getattr(request.user, 'is_publik_service', False)
                or (isinstance(request.user, User) and request.user.has_perm('custom_user.admin_user'))
            ):
                raise PermissionDenied('keepalive requires the admin_user permission')
            self._update_keep_alive(actor=request.user, targeted_users=users)
        hooks.call_hooks('api_modify_response', self, 'synchronization', data)
        return Response(data)

    def _update_keep_alive(self, actor, targeted_users, period_in_days=30):
        # do not write to db uselessly, one keepalive event by month is ok
        start = now()
        threshold = start - datetime.timedelta(days=period_in_days)
        users_to_update = User.objects.filter(pk__in=targeted_users).exclude(
            models.Q(date_joined__gt=threshold)
            | models.Q(last_login__gt=threshold)
            | models.Q(keepalive__gt=threshold)
        )
        with transaction.atomic(savepoint=False):
            users_to_update.update(keepalive=start)
            actor = actor if isinstance(actor, User) else getattr(actor, 'oidc_client', None)
            for user in users_to_update.only('id'):
                journal.record('user.notification.activity', actor=actor, target_user=user, api=True)

    @action(
        detail=True,
        methods=['post'],
        url_path='force-password-reset',
        permission_classes=(DjangoPermission('custom_user.reset_password_user'),),
    )
    def force_password_reset(self, request, uuid):
        user = self.get_object()
        PasswordReset.objects.get_or_create(user=user)
        request.journal.record('manager.user.password.change.force', target_user=user, api=True)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(
        detail=True,
        methods=['post'],
        url_path='password-reset',
        permission_classes=(DjangoPermission('custom_user.reset_password_user'),),
    )
    def password_reset(self, request, uuid):
        user = self.get_object()
        # An user without email cannot receive the token
        if not user.email:
            return Response(
                {'result': 0, 'reason': 'User has no mail'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        utils_misc.send_password_reset_mail(user, request=request)
        request.journal.record('manager.user.password.reset.request', target_user=user, api=True)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['post'], permission_classes=(DjangoPermission('custom_user.change_user'),))
    def email(self, request, uuid):
        user = self.get_object()
        serializer = ChangeEmailSerializer(data=request.data)
        if not serializer.is_valid():
            response = {'result': 0, 'errors': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)
        user.set_email_verified(False)
        user.save()
        utils_misc.send_email_change_email(user, serializer.validated_data['email'], request=request)
        return Response({'result': 1})

    @action(detail=False, methods=['get'], permission_classes=(DjangoPermission('custom_user.search_user'),))
    def find_duplicates(self, request):
        serializer = self.get_serializer(data=request.query_params, partial=True)
        if not serializer.is_valid():
            response = {'data': [], 'err': 1, 'err_desc': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data

        first_name = data.get('first_name')
        last_name = data.get('last_name')
        if not (first_name and last_name):
            response = {
                'data': [],
                'err': 1,
                'err_desc': 'first_name and last_name parameters are mandatory.',
            }
            return Response(response, status.HTTP_400_BAD_REQUEST)

        ou = None
        if 'ou' in request.query_params:
            ou = data['ou']

        attributes = data.pop('attributes', {})
        birthdate = attributes.get('birthdate')
        qs = User.objects.find_duplicates(first_name, last_name, birthdate=birthdate, ou=ou)

        return Response(
            {
                'data': DuplicateUserSerializer(qs, many=True, include_roles=False).data,
                'err': 0,
            }
        )


class RolesFilter(FilterSet):
    admin = BooleanFilter(method='admin_filter')
    internal = BooleanFilter(method='internal_filter')
    q = CharFilter(method='q_filter')

    def admin_filter(self, queryset, name, value):
        if value is True:
            queryset = queryset.filter_admin_roles()
        if value is False:
            queryset = queryset.exclude_admin_roles()
        return queryset

    def internal_filter(self, queryset, name, value):
        if value is True:
            queryset = queryset.filter_internal_roles()
        if value is False:
            queryset = queryset.exclude_internal_roles()
        return queryset

    def q_filter(self, queryset, name, value):
        if value:
            queryset = queryset.filter(name__trigram_strict_word_similar=value)
        return queryset

    class Meta:
        model = Role
        fields = {
            'uuid': ['exact'],
            'name': ['exact', 'iexact', 'icontains', 'startswith'],
            'slug': ['exact', 'iexact', 'icontains', 'startswith'],
            'ou__slug': ['exact'],
        }


class RolesAPI(api_mixins.GetOrCreateMixinView, ExceptionHandlerMixin, ModelViewSet):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = RoleSerializer
    filter_backends = api_settings.DEFAULT_FILTER_BACKENDS
    filterset_class = RolesFilter
    lookup_field = 'uuid'
    queryset = Role.objects.all()
    lookup_value_regex = r'[0-9a-f]{32}'

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        return self.request.user.filter_by_perm('a2_rbac.view_role', queryset)

    def perform_destroy(self, instance):
        if not self.request.user.has_perm(perm='a2_rbac.delete_role', obj=instance):
            raise PermissionDenied('User %s can\'t create role %s' % (self.request.user, instance))
        self.request.journal.record('manager.role.deletion', role=instance, api=True)
        super().perform_destroy(instance)

    def perform_create(self, serializer):
        super().perform_create(serializer)
        self.request.journal.record('manager.role.creation', role=serializer.instance, api=True)

    def perform_update(self, serializer):
        super().perform_update(serializer)
        self.request.journal.record('manager.role.edit', role=serializer.instance, form=serializer, api=True)


class RolesBySlugAPI(RolesAPI):
    lookup_field = 'slug'
    lookup_value_regex = r'(?:[-a-zA-Z0-9_]+:)?(?:[-a-zA-Z0-9_]+:)?[-a-zA-Z0-9_]+'

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        lookup_value = self.kwargs['slug']
        if lookup_value.count(':') > 1:
            ou_slug, service_slug, role_slug = lookup_value.split(':', 2)
            filter_kwargs = {'ou__slug': ou_slug, 'service_slug': service_slug, 'slug': role_slug}
        elif lookup_value.count(':') == 1:
            ou_slug, role_slug = lookup_value.split(':', 1)
            filter_kwargs = {'ou__slug': ou_slug, 'slug': role_slug}
        else:
            filter_kwargs = {'slug': lookup_value}

        try:
            obj = get_object_or_404(queryset, **filter_kwargs)
        except Role.MultipleObjectsReturned:
            raise api_mixins.Conflict(_('Multiple roles found'), 'multiple-roles-found')

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj


class RolesMixin:
    def initial(self, request, *, role_uuid=None, ou_slug=None, service_slug=None, role_slug=None, **kwargs):
        super().initial(request, **kwargs)
        role_qs = request.user.filter_by_perm('a2_rbac.view_role', Role.objects.all())
        if role_uuid:
            filter_kwargs = {'uuid': role_uuid}
        elif ou_slug and service_slug and role_slug:
            filter_kwargs = {'ou__slug': ou_slug, 'service_slug': service_slug, 'slug': role_slug}
        elif ou_slug and role_slug:
            filter_kwargs = {'ou__slug': ou_slug, 'slug': role_slug}
        else:
            filter_kwargs = {'slug': role_slug}
        try:
            self.role = get_object_or_404(role_qs, **filter_kwargs)
        except Role.MultipleObjectsReturned:
            raise api_mixins.Conflict(_('Multiple roles found'), 'multiple-roles-found')


class RolesMembersAPI(RolesMixin, UsersAPI):
    def get_queryset(self):
        if self.request.GET.get('nested', 'false').lower() in ('true', '1'):
            qs = self.role.all_members()
        else:
            qs = self.role.members.all()
        return qs


roles_members = RolesMembersAPI.as_view({'get': 'list'})


class ProfileSerializer(serializers.ModelSerializer):
    data = serializers.JSONField(binary=False)
    email = serializers.EmailField(required=False, allow_blank=True)

    def create(self, validated_data):
        return Profile(**validated_data)

    def update(self, validated_data):
        # not supported yet
        pass

    class Meta:
        model = Profile
        fields = (
            'identifier',
            'email',
            'data',
        )
        extra_kwargs = {
            'identifier': {
                'required': False,
                'allow_blank': True,
                'max_length': 256,
            }
        }


class UserProfilesAPI(ExceptionHandlerMixin, APIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ProfileSerializer

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        User = get_user_model()
        self.profile_type = get_object_or_404(ProfileType, slug=kwargs['profile_type_slug'])
        self.user = get_object_or_404(User, uuid=kwargs['user_uuid'])
        self.identifier = request.GET.get('identifier', '')

    def get(self, request, *args, **kwargs):
        if not request.user.has_perm('custom_user.view_profile'):
            raise PermissionDenied('User not allowed to view user profiles')
        if 'identifier' in request.GET:
            # request on a single entity
            profile = get_object_or_404(
                Profile, user=self.user, profile_type=self.profile_type, identifier=self.identifier
            )
            return Response(self.serializer_class(profile).data)
        else:
            # user's profiles of a given type
            profiles = Profile.objects.filter(
                user=self.user,
                profile_type=self.profile_type,
            )
            return Response([self.serializer_class(profile).data for profile in profiles])

    def post(self, request, *args, **kwargs):
        if not request.user.has_perm('custom_user.create_profile'):
            raise PermissionDenied('User not allowed to create user profiles')
        try:
            profile = Profile.objects.get(
                user=self.user, profile_type=self.profile_type, identifier=self.identifier
            )
        except Profile.DoesNotExist:
            data = request.data.copy()
            data.update({'identifier': self.identifier})
            serializer = self.serializer_class(data=data)
            if not serializer.is_valid():
                response = {'data': [], 'err': 1, 'err_desc': serializer.errors}
                return Response(response, status.HTTP_400_BAD_REQUEST)
            profile = serializer.save()
            profile.profile_type = self.profile_type
            profile.user = self.user
            profile.save()  # fixme double db access
            request.journal.record(
                'user.profile.add',
                user=request.user,
                profile=profile,
            )
            return Response(
                {'result': 1, 'detail': _('Profile successfully assigned to user')}, status=status.HTTP_200_OK
            )
        else:
            response = {
                'data': [],
                'err': 1,
                'err_desc': 'cannot overwrite already existing profile. use PUT verb instead',
            }
            return Response(response, status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        profile = get_object_or_404(
            Profile, user=self.user, profile_type=self.profile_type, identifier=self.identifier
        )
        if not request.user.has_perm('custom_user.change_profile', obj=profile):
            raise PermissionDenied('User not allowed to change user profiles')
        if request.data.get('data', None) is not None:
            profile.data = request.data['data']
        if request.data.get('email', None) is not None:
            profile.email = request.data['email']
        profile.save()
        request.journal.record(
            'user.profile.update',
            user=request.user,
            profile=profile,
        )
        return Response({'result': 1, 'detail': _('Profile successfully updated')}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        profile = get_object_or_404(
            Profile, user=self.user, profile_type=self.profile_type, identifier=self.identifier
        )
        if not request.user.has_perm('custom_user.delete_profile', obj=profile):
            raise PermissionDenied('User not allowed to delete user profiles')
        request.journal.record(
            'user.profile.delete',
            user=request.user,
            profile=profile,
        )
        profile.delete()
        return Response(
            {'result': 1, 'detail': _('Profile successfully removed from user')}, status=status.HTTP_200_OK
        )


user_profiles = UserProfilesAPI.as_view()


class UserServiceDataAPI(ExceptionHandlerMixin, APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        self.user = get_object_or_404(User, uuid=kwargs['user_uuid'])
        self.service = get_object_or_404(
            Service.objects.select_related().select_subclasses(), slug=kwargs['service_slug']
        )

    def get(self, request, *args, **kwargs):
        if not (
            getattr(request.user, 'is_publik_service', False)  # hobo.rest_authentication.PublikAuthentication
            or (
                hasattr(request.user, 'has_perms')
                and request.user.has_perms(('authentic2.view_service', 'custom_user.view_user'))
            )
        ):
            raise PermissionDenied('requires view_service and view_user permission')
        data = {
            'service': {
                'slug': self.service.slug,
                'name': self.service.name,
                'type': self.service.__class__.__name__,
            },
        }
        if hasattr(self.service, 'get_user_data'):
            data['user'] = self.service.get_user_data(self.user)
        return Response({'err': 0, 'result': 1, 'data': data}, status=status.HTTP_200_OK)


user_service_data = UserServiceDataAPI.as_view()


class RoleMembershipAPI(ExceptionHandlerMixin, RolesMixin, APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def initial(self, request, *, member_uuid=None, **kwargs):
        super().initial(request, **kwargs)
        self.member_uuid = member_uuid

    def get(self, request, *args, **kwargs):
        if self.request.GET.get('nested', 'false').lower() in ('true', '1'):
            user_qs = self.role.all_members()
        else:
            user_qs = self.role.members.all()
        user_qs = request.user.filter_by_perm('custom_user.search_user', user_qs)
        member = get_object_or_404(user_qs, uuid=self.member_uuid)
        return Response(UserSerializer(member).data)

    def post(self, request, *args, **kwargs):
        if not request.user.has_perm('a2_rbac.manage_members_role', obj=self.role):
            raise PermissionDenied('User not allowed to manage role members')
        user_qs = request.user.filter_by_perm('custom_user.search_user', User.objects.all())
        new_member = get_object_or_404(user_qs, uuid=self.member_uuid)
        self.role.members.add(new_member)
        request.journal.record('manager.role.membership.grant', role=self.role, member=new_member, api=True)
        return Response(
            {'result': 1, 'detail': _('User successfully added to role')}, status=status.HTTP_201_CREATED
        )

    def delete(self, request, *args, **kwargs):
        if not request.user.has_perm('a2_rbac.manage_members_role', obj=self.role):
            raise PermissionDenied('User not allowed to manage role members')
        user_qs = request.user.filter_by_perm('custom_user.search_user', User.objects.all())
        member = get_object_or_404(user_qs, uuid=self.member_uuid)
        self.role.members.remove(member)
        request.journal.record('manager.role.membership.removal', role=self.role, member=member, api=True)
        return Response(
            {'result': 1, 'detail': _('User successfully removed from role')}, status=status.HTTP_200_OK
        )


role_membership = RoleMembershipAPI.as_view()


class RoleMembershipsAPI(ExceptionHandlerMixin, APIView):
    permission_classes = (permissions.IsAuthenticated,)
    http_method_names = ['post', 'put', 'patch', 'delete']

    def initial(self, request, *, role_uuid=None, role_slug=None, **kwargs):
        super().initial(request, role_uuid=role_uuid, role_slug=role_slug, **kwargs)
        User = get_user_model()
        if role_uuid:
            self.role = get_object_or_404(Role, uuid=role_uuid)
        if role_slug:
            self.role = get_object_or_404(Role, slug=role_slug)
        self.members = set()

        perm = 'a2_rbac.manage_members_role'
        authorized = request.user.has_perm(perm, obj=self.role)
        if not authorized:
            raise PermissionDenied('User not allowed to manage role members')

        if not isinstance(request.data, dict):
            raise ValidationError(_('Payload must be a dictionary'))

        if request.method != 'GET' and not 'data' in request.data:
            raise ValidationError(_("Invalid payload (missing 'data' key)"))

        for entry in request.data.get('data', ()):
            try:
                uuid = entry['uuid']
            except TypeError:
                raise ValidationError(_("List elements of the 'data' dict entry must be dictionaries"))
            except KeyError:
                raise ValidationError(_("Missing 'uuid' key for dict entry %s of the 'data' payload") % entry)
            try:
                self.members.add(User.objects.get(uuid=uuid))
            except User.DoesNotExist:
                raise ValidationError(_('No known user for UUID %s') % entry['uuid'])

        if not self.members and request.method in ('POST', 'DELETE'):
            raise ValidationError(_('No valid user UUID'))

    def post(self, request, *args, **kwargs):
        self.role.members.add(*self.members)
        for member in self.members:
            request.journal.record('manager.role.membership.grant', role=self.role, member=member, api=True)
        return Response(
            {'result': 1, 'detail': _('Users successfully added to role')}, status=status.HTTP_201_CREATED
        )

    def delete(self, request, *args, **kwargs):
        self.role.members.remove(*self.members)
        for member in self.members:
            request.journal.record('manager.role.membership.removal', role=self.role, member=member, api=True)
        return Response(
            {'result': 1, 'detail': _('Users successfully removed from role')}, status=status.HTTP_200_OK
        )

    def patch(self, request, *args, **kwargs):
        old_members = set(self.role.members.all())
        self.role.members.set(self.members)
        for member in self.members:
            request.journal.record('manager.role.membership.grant', role=self.role, member=member, api=True)
        for member in old_members.difference(self.members):
            request.journal.record('manager.role.membership.removal', role=self.role, member=member, api=True)
        return Response(
            {'result': 1, 'detail': _('Users successfully assigned to role')}, status=status.HTTP_200_OK
        )

    def put(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)


role_memberships = RoleMembershipsAPI.as_view()


class PublikMixin:
    def finalize_response(self, request, response, *args, **kwargs):
        '''Adapt error response to Publik schema'''
        response = super().finalize_response(request, response, *args, **kwargs)
        if isinstance(response.data, dict) and 'err' not in response.data:
            if list(response.data.keys()) == ['detail'] and isinstance(response.data['detail'], ErrorDetail):
                response.data = {
                    'err': 1,
                    'err_class': response.data['detail'].code,
                    'err_desc': str(response.data['detail']),
                }
            elif 'errors' in response.data:
                response.data['err'] = 1
                response.data.pop('result', None)
                response.data['err_desc'] = response.data.pop('errors')
        return response


class RoleFiliationSerializer(RoleSerializer):
    direct = serializers.BooleanField(read_only=True)

    class Meta(RoleSerializer.Meta):
        fields = RoleSerializer.Meta.fields + ('direct',)


class RoleFiliationMixin:
    accessor = ''
    permission_classes = [
        DjangoRBACPermission(
            perms_map={
                'GET': [],
            },
            object_perms_map={
                'GET': ['a2_rbac.view_role'],
            },
        )
    ]
    serializer_class = RoleFiliationSerializer
    queryset = Role.objects.all()

    def get(self, request, *args, **kwargs):
        if not self.accessor:
            raise NotImplementedError  # pragma: no cover
        direct = None if 'all' in self.request.GET else True
        qs = getattr(self.role, self.accessor)(include_self=False, annotate=not direct, direct=direct)
        qs = request.user.filter_by_perm('a2_rbac.search_role', qs)
        qs = qs.order_by('id')
        serializer = self.get_serializer(qs, many=True)
        return Response({'err': 0, 'data': serializer.data})


class RolesParentsAPI(PublikMixin, RolesMixin, RoleFiliationMixin, GenericAPIView):
    accessor = 'parents'


roles_parents = RolesParentsAPI.as_view()


class RolesChildrenAPI(PublikMixin, RolesMixin, RoleFiliationMixin, GenericAPIView):
    accessor = 'children'


roles_children = RolesChildrenAPI.as_view()


class RoleParentingSerializer(serializers.ModelSerializer):
    parent = NaturalKeyRelatedField(queryset=Role.objects.all())
    direct = serializers.BooleanField(read_only=True)

    class Meta:
        model = RoleParenting
        fields = [
            'parent',
            'direct',
        ]


class RolesParentsRelationshipsAPI(PublikMixin, RolesMixin, GenericAPIView):
    permission_classes = [
        DjangoRBACPermission(
            perms_map={
                'GET': [],
                'POST': [],
                'DELETE': [],
            },
            object_perms_map={
                'GET': ['a2_rbac.view_role'],
                'POST': ['a2_rbac.manage_members_role'],
                'DELETE': ['a2_rbac.manage_members_role'],
            },
        )
    ]
    serializer_class = RoleParentingSerializer
    queryset = RoleParenting.alive.all()

    def get(self, request, *args, **kwargs):
        return self.list(request)

    def list(self, request):
        qs = RoleParenting.alive.filter(child=self.role)
        if 'all' not in self.request.GET:
            qs = qs.filter(direct=True)
        qs = qs.filter(parent__in=self.request.user.filter_by_perm('a2_rbac.view_role', Role.objects.all()))
        qs = qs.order_by('id')
        serializer = self.get_serializer(qs, many=True)
        return Response({'err': 0, 'data': serializer.data})

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        parent = serializer.validated_data['parent']
        self.check_object_permissions(self.request, parent)
        self.role.add_parent(parent)
        return self.list(request)

    def delete(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        parent = serializer.validated_data['parent']
        self.check_object_permissions(self.request, parent)
        self.role.remove_parent(parent)
        return self.list(request)


roles_parents_relationships = RolesParentsRelationshipsAPI.as_view()


class BaseOrganizationalUnitSerializer(serializers.ModelSerializer):
    slug = serializers.SlugField(
        required=False,
        allow_blank=False,
        max_length=256,
        default=SlugFromNameDefault(),
    )

    class Meta:
        model = OrganizationalUnit
        fields = '__all__'


class OrganizationalUnitAPI(api_mixins.GetOrCreateMixinView, ExceptionHandlerMixin, ModelViewSet):
    permission_classes = (DjangoPermission('a2_rbac.search_organizationalunit'),)
    serializer_class = BaseOrganizationalUnitSerializer
    lookup_field = 'uuid'
    lookup_value_regex = r'[0-9a-f]{32}'

    def get_queryset(self):
        return OrganizationalUnit.objects.all()


class OrganizationalUnitBySlugAPI(OrganizationalUnitAPI):
    lookup_field = 'slug'
    lookup_value_regex = r'[-a-zA-Z0-9_]+'


router = SimpleRouter()
router.register(r'users', UsersAPI, basename='a2-api-users')
router.register(r'ous', OrganizationalUnitAPI, basename='a2-api-ous-by-uuid')
router.register(r'ous', OrganizationalUnitBySlugAPI, basename='a2-api-ous-by-slug')
router.register(r'roles', RolesAPI, basename='a2-api-roles')
router.register(r'roles', RolesBySlugAPI, basename='a2-api-roles-by-slug')


class CheckPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class CheckAPIClientSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    ou = serializers.SlugRelatedField(
        queryset=OrganizationalUnit.objects.all(),
        slug_field='slug',
        default=None,
        required=False,
        allow_null=True,
    )
    ip = serializers.IPAddressField(required=False, allow_null=True, default=None)
    allowed_user_attributes = serializers.SlugRelatedField(
        slug_field='name',
        many=True,
        read_only=True,
    )


class CheckPasswordAPI(BaseRpcView):
    permission_classes = (DjangoPermission('custom_user.search_user'),)
    serializer_class = CheckPasswordSerializer

    def rpc(self, request, serializer):
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        result = {}
        for authenticator in self.get_authenticators():
            if hasattr(authenticator, 'authenticate_credentials'):
                try:
                    user, dummy_oidc_client = authenticator.authenticate_credentials(
                        username, password, request=request
                    )
                    result['result'] = 1
                    if hasattr(user, 'oidc_client'):
                        result['oidc_client'] = True
                    break
                except AuthenticationFailed as exc:
                    result['result'] = 0
                    result['errors'] = [exc.detail]
        return result, status.HTTP_200_OK


check_password = CheckPasswordAPI.as_view()


class CheckAPIClientAPI(BaseRpcView):
    permission_classes = (DjangoPermission('custom_user.search_user'),)
    serializer_class = CheckAPIClientSerializer

    def rpc(self, request, serializer):
        identifier = serializer.validated_data['identifier']
        password = serializer.validated_data['password']
        ou = serializer.validated_data.get('ou', None)
        client_ip = serializer.validated_data.get('ip', None)
        api_client = None
        try:
            api_clients = APIClient.objects.by_identifier(identifier).all()
            for client in api_clients:
                if client.check_password(password):
                    api_client = client
                    break
            else:
                raise APIClient.DoesNotExist
        except APIClient.DoesNotExist:
            pass

        result = {}
        if (
            api_client is None
            or not api_client.ip_authorized(client_ip)
            or not api_client.check_password(password)
            or (ou and ou != api_client.ou)
        ):
            result['err'] = 1
            result['err_desc'] = 'api client not found'
            return result, status.HTTP_200_OK

        su_roles = (
            Role.objects.for_user(api_client).filter(is_superuser=True).values_list('service', flat=True)
        )

        service_su = {
            ou.slug: {service.slug: service.pk in su_roles for service in Service.objects.filter(ou=ou)}
            for ou in OrganizationalUnit.objects.all()
        }

        result['err'] = 0
        result['data'] = {
            'id': api_client.id,
            'name': api_client.name,
            'is_active': api_client.is_active,
            'is_anonymous': api_client.is_anonymous,
            'is_authenticated': api_client.is_authenticated,
            'is_superuser': api_client.is_superuser,
            'ou': api_client.ou.slug if api_client.ou else None,
            'restrict_to_anonymised_data': api_client.restrict_to_anonymised_data,
            'roles': Role.objects.for_user(api_client).values_list('uuid', flat=True),
            'service_superuser': service_su,
            'allowed_user_attributes': [attr.name for attr in api_client.allowed_user_attributes.all()],
        }
        return result, status.HTTP_200_OK


check_api_client = CheckAPIClientAPI.as_view()


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


class ValidatePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, allow_blank=True)


class ValidatePasswordAPI(BaseRpcView):
    permission_classes = ()
    authentication_classes = (CsrfExemptSessionAuthentication,)
    serializer_class = ValidatePasswordSerializer

    def rpc(self, request, serializer):
        password_checker = get_password_checker()
        checks = []
        result = {'result': 1, 'checks': checks}
        ok = True
        for check in password_checker(serializer.validated_data['password']):
            ok = ok and check.result
            checks.append(
                {
                    'result': check.result,
                    'label': check.label,
                }
            )
        result['ok'] = ok
        return result, status.HTTP_200_OK


validate_password = ValidatePasswordAPI.as_view()


class PasswordStrengthSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, allow_blank=True)
    inputs = serializers.DictField(child=serializers.CharField(allow_blank=True), default={})
    min_strength = serializers.IntegerField(required=False)


class PasswordStrengthAPI(BaseRpcView):
    permission_classes = ()
    authentication_classes = (CsrfExemptSessionAuthentication,)
    serializer_class = PasswordStrengthSerializer

    def rpc(self, request, serializer):
        report = get_password_strength(
            serializer.validated_data['password'],
            user=request.user,
            inputs=serializer.validated_data['inputs'],
        )
        min_strength = None
        if 'min_strength' in serializer.validated_data:
            min_strength = serializer.validated_data['min_strength']
        if min_strength is None:
            hint_text = _('To create a more secure password, you can %(hint)s')
        elif report.strength < min_strength:
            hint_text = _('Your password is too weak. To create a secure password, please %(hint)s')
        else:
            hint_text = _(
                'Your password is strong enough. To create an even more secure password, you could %(hint)s'
            )
        hint_text %= {'hint': '<span class="a2-password-hint--hint">%s</span>' % report.hint}

        result = {
            'result': 1,
            'strength': report.strength,
            'strength_label': report.strength_label,
            'hint': report.hint,
            'hint_html': hint_text,
        }
        return result, status.HTTP_200_OK


password_strength = PasswordStrengthAPI.as_view()


class AuthnHealthcheckAPI(APIView):
    permission_classes = (DjangoPermission('authenticators.search_baseauthenticator'),)
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        authn = utils_misc.get_password_authenticator()
        data = {
            'accept_email_authentication': authn.accept_email_authentication,
            'accept_phone_authentication': authn.accept_phone_authentication,
            'phone_identifier_field': getattr(authn.phone_identifier_field, 'name', ''),
        }
        return Response({'err': 0, 'data': data})


authn_healthcheck = AuthnHealthcheckAPI.as_view()


class AddressAutocompleteAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        if not getattr(settings, 'ADDRESS_AUTOCOMPLETE_URL', None):
            return Response({})
        try:
            response = requests.get(
                settings.ADDRESS_AUTOCOMPLETE_URL, params=request.GET, timeout=settings.REQUESTS_TIMEOUT
            )
            response.raise_for_status()
            return Response(response.json())
        except RequestException:
            return Response({})


address_autocomplete = AddressAutocompleteAPI.as_view()


class ServiceOUField(serializers.ListField):
    def to_internal_value(self, data):
        data = data[0].split(' ')
        if not len(data) == 2:
            raise ValidationError('This field should be a service slug and an OU slug separated by space.')
        return super().to_internal_value(data)


class StatisticsSerializer(serializers.Serializer):
    TIME_INTERVAL_CHOICES = [('day', _('Day')), ('month', _('Month')), ('year', _('Year'))]
    GROUP_BY_CHOICES = [
        ('authentication_type', _('Authentication type')),
        ('service', _('Service')),
        ('service_ou', _('Organizational unit')),
    ]

    time_interval = serializers.ChoiceField(choices=TIME_INTERVAL_CHOICES, default='month')
    group_by = serializers.ChoiceField(choices=GROUP_BY_CHOICES, default='global')
    service = ServiceOUField(child=serializers.SlugField(max_length=256), required=False)
    services_ou = serializers.SlugField(required=False, allow_blank=False, max_length=256)
    users_ou = serializers.SlugField(required=False, allow_blank=False, max_length=256)
    start = serializers.DateTimeField(required=False, input_formats=['iso-8601', '%Y-%m-%d'])
    end = serializers.DateTimeField(required=False, input_formats=['iso-8601', '%Y-%m-%d'])


def stat(**kwargs):
    '''Extend action decorator to allow passing statistics related info.'''
    name = kwargs['name']
    kwargs['detail'] = False
    decorator = action(**kwargs)

    def wraps(func):
        func.name = name
        return decorator(func)

    return wraps


class StatisticsAPI(ViewSet):
    permission_classes = (permissions.IsAuthenticated,)

    def list(self, request):
        statistics = []
        time_interval_field = StatisticsSerializer().get_fields()['time_interval']
        common_filters = [
            {
                'id': 'time_interval',
                'label': _('Time interval'),
                'options': [
                    {'id': key, 'label': label} for key, label in time_interval_field.choices.items()
                ],
                'required': True,
                'default': time_interval_field.default,
            }
        ]
        group_by_field = StatisticsSerializer().get_fields()['group_by']
        group_by_filter = {
            'id': 'group_by',
            'label': _('Group by'),
            'options': [{'id': key, 'label': label} for key, label in group_by_field.choices.items()],
            'has_subfilters': True,
        }
        for action in self.get_extra_actions():
            url = self.reverse_action(action.url_name)
            filters = common_filters.copy()

            if action.url_name in (
                'login-new',
                'registration-new',
            ):
                filters.append(group_by_filter)

            data = {
                'name': action.kwargs['name'],
                'url': url,
                'id': action.url_name,
                'filters': filters,
            }
            statistics.append(data)

        return Response(
            {
                'data': statistics,
                'err': 0,
            }
        )

    @cached_property
    def services_ous(self):
        return [
            {'id': ou.slug, 'label': ou.name}
            for ou in OrganizationalUnit.objects.exclude(service__isnull=True)
        ]

    @cached_property
    def users_ous(self):
        return [
            {'id': ou.slug, 'label': ou.name}
            for ou in OrganizationalUnit.objects.exclude(user__isnull=True).order_by('name')
        ]

    @cached_property
    def services(self):
        return [
            {'id': '%s %s' % (service['slug'], service['ou__slug']), 'label': service['name']}
            for service in Service.objects.values('slug', 'name', 'ou__slug').order_by('ou__name', 'name')
        ]

    def get_additional_filters(self, filter_ids):
        filters = []
        if 'service' in filter_ids:
            filters.append({'id': 'service', 'label': _('Service'), 'options': self.services})
        if 'services_ou' in filter_ids and len(self.services_ous) > 1:
            filters.append(
                {
                    'id': 'services_ou',
                    'label': _('Services organizational unit'),
                    'options': self.services_ous,
                }
            )
        if 'users_ou' in filter_ids and len(self.users_ous) > 1:
            filters.append(
                {'id': 'users_ou', 'label': _('Users organizational unit'), 'options': self.users_ous}
            )
        return filters

    def get_statistics(self, request, klass):
        serializer = StatisticsSerializer(data=request.query_params)
        if not serializer.is_valid():
            response = {'data': [], 'err': 1, 'err_desc': serializer.errors}
            return Response(response, status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data

        kwargs = {
            'group_by_time': data['time_interval'],
            'start': data.get('start'),
            'end': data.get('end'),
        }

        subfilters = []
        allowed_filters = []

        method = {
            'global': 'get_global_statistics',
            'authentication_type': 'get_method_statistics',
            'service': 'get_service_statistics',
            'service_ou': 'get_service_ou_statistics',
        }[data['group_by']]

        if data['group_by'] == 'authentication_type':
            allowed_filters = ('services_ou', 'users_ou', 'service')
            subfilters = self.get_additional_filters(allowed_filters)
        elif data['group_by'] == 'global':
            allowed_filters = ('services_ou',)
            subfilters = self.get_additional_filters(allowed_filters)
            kwargs['y_label'] = getattr(self, self.action).name

        service = data.get('service')
        services_ou = data.get('services_ou')
        users_ou = data.get('users_ou')

        if service and 'service' in allowed_filters:
            service_slug, ou_slug = service
            # look for the Service child and parent instances, see #68390 and #64853
            subclass_service_instance = get_object_or_404(
                Service.objects.select_subclasses(), slug=service_slug, ou__slug=ou_slug
            )
            service_instance = Service(pk=subclass_service_instance.pk)
            kwargs['service'] = [subclass_service_instance, service_instance]
        elif services_ou and 'services_ou' in allowed_filters:
            kwargs['services_ou'] = get_object_or_404(OrganizationalUnit, slug=services_ou)

        if users_ou and 'users_ou' in allowed_filters:
            kwargs['users_ou'] = get_object_or_404(OrganizationalUnit, slug=users_ou)

        data = getattr(klass, method)(**kwargs)
        data['subfilters'] = subfilters
        return Response({'data': data, 'err': 0})

    @stat(name=_('Login count'))
    def login_new(self, request):
        return self.get_statistics(request, UserLogin)

    @stat(name=_('Registration count'))
    def registration_new(self, request):
        return self.get_statistics(request, UserRegistration)

    @stat(name=_('Deletion for inactivity count'))
    def inactivity_deletion(self, request):
        return self.get_statistics(request, UserDeletionForInactivity)

    @stat(name=_('Inactivity alert count'))
    def inactivity_alert(self, request):
        return self.get_statistics(request, UserNotificationInactivity)


router.register(r'statistics', StatisticsAPI, basename='a2-api-statistics')
