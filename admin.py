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

import pprint
from copy import deepcopy

from django import forms
from django.conf import settings
from django.contrib import admin
from django.contrib.admin.utils import flatten_fieldsets
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache

from . import app_settings, attribute_kinds, decorators, models
from .custom_user.models import DeletedUser, Profile, ProfileType, User
from .forms.profile import BaseUserForm, modelform_factory
from .nonce.models import Nonce
from .utils import misc as utils_misc


@admin.action(description=_('Cleanup expired objects'))
def cleanup_action(modeladmin, request, queryset):
    queryset.cleanup()


class CleanupAdminMixin(admin.ModelAdmin):
    def get_actions(self, request):
        actions = super().get_actions(request)
        if hasattr(self.model.objects.none(), 'cleanup'):
            actions['cleanup_action'] = cleanup_action, 'cleanup_action', cleanup_action.short_description
        return actions


@admin.register(Nonce)
class NonceModelAdmin(admin.ModelAdmin):
    list_display = ('value', 'context', 'not_on_or_after')


class AttributeValueAdmin(admin.ModelAdmin):
    list_display = ('content_type', 'owner', 'attribute', 'content')


admin.site.register(models.AttributeValue, AttributeValueAdmin)


class LogoutUrlAdmin(admin.ModelAdmin):
    list_display = ('provider', 'logout_url', 'logout_use_iframe', 'logout_use_iframe_timeout')


admin.site.register(models.LogoutUrl, LogoutUrlAdmin)


class AuthenticationEventAdmin(admin.ModelAdmin):
    list_display = ('when', 'who', 'how', 'nonce')
    list_filter = ('how',)
    date_hierarchy = 'when'
    search_fields = ('who', 'nonce', 'how')


admin.site.register(models.AuthenticationEvent, AuthenticationEventAdmin)


class UserExternalIdAdmin(admin.ModelAdmin):
    list_display = ('user', 'source', 'external_id', 'created', 'updated')
    list_filter = ('source',)
    date_hierarchy = 'created'
    search_fields = ('user__username', 'source', 'external_id')


admin.site.register(models.UserExternalId, UserExternalIdAdmin)


DB_SESSION_ENGINES = (
    'django.contrib.sessions.backends.db',
    'django.contrib.sessions.backends.cached_db',
    'mellon.session_backends.cached_db',
)

if settings.SESSION_ENGINE in DB_SESSION_ENGINES:

    @admin.register(Session)
    class SessionAdmin(admin.ModelAdmin):
        @admin.display(description=_('session data'))
        def _session_data(self, obj):
            return pprint.pformat(obj.get_decoded()).replace('\n', '<br>\n')

        list_display = ['session_key', 'ips', 'user', '_session_data', 'expire_date']
        fields = ['session_key', 'ips', 'user', '_session_data', 'expire_date']
        readonly_fields = ['ips', 'user', '_session_data']
        date_hierarchy = 'expire_date'
        actions = ['clear_expired']

        @admin.display(description=_('IP adresses'))
        def ips(self, session):
            content = session.get_decoded()
            ips = content.get('ips', set())
            return ', '.join(ips)

        @admin.display(description=_('user'))
        def user(self, session):
            from django.contrib import auth
            from django.contrib.auth import models as auth_models

            content = session.get_decoded()
            if auth.SESSION_KEY not in content:
                return
            user_id = content[auth.SESSION_KEY]
            if auth.BACKEND_SESSION_KEY not in content:
                return
            backend_class = content[auth.BACKEND_SESSION_KEY]
            backend = auth.load_backend(backend_class)
            try:
                user = backend.get_user(user_id) or auth_models.AnonymousUser()
            except Exception:
                user = _('deleted user %r') % user_id
            return user

        @admin.action(description=_('clear expired sessions'))
        def clear_expired(self, request, queryset):
            queryset.filter(expire_date__lt=timezone.now()).delete()


class ExternalUserListFilter(admin.SimpleListFilter):
    title = _('external')

    parameter_name = 'external'

    def lookups(self, request, model_admin):
        return (('1', _('Yes')), ('0', _('No')))

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        if self.value() == '1':
            return queryset.filter(userexternalid__isnull=False)
        elif self.value() == '0':
            return queryset.filter(userexternalid__isnull=True)
        return queryset


class UserRealmListFilter(admin.SimpleListFilter):
    # Human-readable title which will be displayed in the
    # right admin sidebar just above the filter options.
    title = _('realm')

    # Parameter for the filter that will be used in the URL query.
    parameter_name = 'realm'

    def lookups(self, request, model_admin):
        """
        Returns a list of tuples. The first element in each
        tuple is the coded value for the option that will
        appear in the URL query. The second element is the
        human-readable name for the option that will appear
        in the right sidebar.
        """
        return app_settings.REALMS

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        if self.value():
            return queryset.filter(username__endswith='@' + self.value())
        return queryset


class UserChangeForm(BaseUserForm):
    error_messages = {
        'missing_credential': _('You must at least give a username or an email to your user'),
    }

    password = ReadOnlyPasswordHashField(
        label=_('Password'),
        help_text=_(
            "Raw passwords are not stored, so there is no way to see this user's password, but you can change"
            " the password using <a href=\"password/\">this form</a>."
        ),
    )

    class Meta:
        model = User
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        f = self.fields.get('user_permissions', None)
        if f is not None:
            f.queryset = f.queryset.select_related('content_type')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial['password']

    def clean(self):
        if not self.cleaned_data.get('username') and not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                self.error_messages['missing_credential'],
                code='missing_credential',
            )

    def is_field_locked(self, name):
        return False


class UserCreationForm(BaseUserForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """

    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'missing_credential': _('You must at least give a username or an email to your user'),
    }
    password1 = forms.CharField(label=_('Password'), widget=forms.PasswordInput)
    password2 = forms.CharField(
        label=_('Password confirmation'),
        widget=forms.PasswordInput,
        help_text=_('Enter the same password as above, for verification.'),
    )

    class Meta:
        model = User
        fields = ('username',)

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def clean(self):
        if not self.cleaned_data.get('username') and not self.cleaned_data.get('email'):
            raise forms.ValidationError(
                self.error_messages['missing_credential'],
                code='missing_credential',
            )

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


@admin.register(User)
class AuthenticUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('uuid', 'ou', 'password')}),
        (
            _('Personal info'),
            {
                'fields': (
                    'username',
                    'first_name',
                    'last_name',
                    'email',
                    'email_verified',
                    'phone',
                    'phone_verified_on',
                )
            },
        ),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined', 'deactivation')}),
    )
    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': (
                    'ou',
                    'username',
                    'first_name',
                    'last_name',
                    'email',
                    'email_verified',
                    'phone',
                    'phone_verified_on',
                    'password1',
                    'password2',
                ),
            },
        ),
    )
    readonly_fields = ('uuid',)
    list_filter = UserAdmin.list_filter + (UserRealmListFilter, ExternalUserListFilter)
    list_display = ['__str__', 'ou', 'first_name', 'last_name', 'email', 'phone']
    actions = UserAdmin.actions + ('mark_as_inactive',)

    def get_fieldsets(self, request, obj=None):
        fieldsets = deepcopy(super().get_fieldsets(request, obj))
        if obj:
            if not request.user.is_superuser:
                fieldsets[2][1]['fields'] = filter(lambda x: x != 'is_superuser', fieldsets[2][1]['fields'])
            qs = models.Attribute.objects.all()
            insertion_idx = 2
        else:
            qs = models.Attribute.objects.filter(required=True)
            insertion_idx = 1
        if qs.exists():
            fieldsets = list(fieldsets)
            fieldsets.insert(
                insertion_idx,
                (
                    _('Attributes'),
                    {'fields': [at.name for at in qs if at.name not in ['first_name', 'last_name']]},
                ),
            )
        return fieldsets

    def get_form(self, request, obj=None, **kwargs):
        self.form = modelform_factory(
            self.model, form=UserChangeForm, fields=models.Attribute.objects.values_list('name', flat=True)
        )
        self.add_form = modelform_factory(
            self.model,
            form=UserCreationForm,
            fields=models.Attribute.objects.filter(required=True).values_list('name', flat=True),
        )
        if 'fields' in kwargs:
            fields = kwargs.pop('fields')
        else:
            fields = flatten_fieldsets(self.get_fieldsets(request, obj))
        if obj:
            qs = models.Attribute.objects.all()
        else:
            qs = models.Attribute.objects.filter(required=True)
        non_model_fields = {a.name for a in qs} - {'first_name', 'last_name', 'phone'}
        fields = list(set(fields) - set(non_model_fields))
        kwargs['fields'] = fields
        return super().get_form(request, obj=obj, **kwargs)

    @admin.action(description=_('Mark as inactive'))
    @transaction.atomic
    def mark_as_inactive(self, request, queryset):
        timestamp = timezone.now()
        for user in queryset:
            user.mark_as_inactive(timestamp=timestamp)


class AttributeForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = self.kind_choices()
        self.fields['kind'].choices = choices
        self.fields['kind'].widget = forms.Select(choices=choices)

    @decorators.to_iter
    def kind_choices(self):
        return attribute_kinds.get_choices()

    class Meta:
        model = models.Attribute
        fields = '__all__'


class AttributeAdmin(admin.ModelAdmin):
    form = AttributeForm
    list_display = (
        'label',
        'disabled',
        'name',
        'kind',
        'order',
        'required',
        'asked_on_registration',
        'user_editable',
        'user_visible',
    )
    list_editable = ('order',)

    def get_queryset(self, request):
        return self.model.all_objects.all()


admin.site.register(models.Attribute, AttributeAdmin)


@admin.register(DeletedUser)
class DeletedUserAdmin(admin.ModelAdmin):
    list_display = ['deleted', 'old_user_id', 'old_uuid', 'old_email']
    date_hierarchy = 'deleted'
    search_fields = ['=old_user_id', '^old_uuid', 'old_email']


@admin.register(ProfileType)
class ProfileTypeAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'name', 'slug']
    readonly_fields = ['uuid']


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['profile_type', 'user', 'identifier', 'email']


@never_cache
def login(request, extra_context=None):
    return utils_misc.redirect_to_login(request, login_url=utils_misc.get_manager_login_url())


admin.site.login = login


@never_cache
def logout(request, extra_context=None):
    return utils_misc.redirect_to_login(request, login_url='auth_logout')


admin.site.logout = logout

admin.site.register(models.PasswordReset)
