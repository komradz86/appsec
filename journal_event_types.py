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

from django.utils.translation import gettext_lazy as _
from django.utils.translation import gettext_noop as N_

from authentic2.a2_rbac.models import OrganizationalUnit as OU
from authentic2.apps.authenticators.models import BaseAuthenticator
from authentic2.apps.journal.models import EventTypeDefinition
from authentic2.apps.journal.utils import Statistics, form_to_old_new
from authentic2.custom_user.models import User, get_attributes_map

from .models import Service


class EventTypeWithService(EventTypeDefinition):
    @classmethod
    def record(cls, *, user=None, session=None, references=None, data=None, api=False, service=None):
        if service:
            if not data:
                data = {}
            data['service_name'] = str(service)
            if not references:
                references = []
            # use a reference to the Service model, not a subclass
            references = [Service(pk=service.pk)] + references
        return super().record(user=user, session=session, references=references, data=data, api=api)

    @classmethod
    def get_service_name(cls, event):
        (service,) = event.get_typed_references(Service)
        if service is not None:
            return str(service)
        if 'service_name' in event.data:
            return event.data['service_name']
        return ''


class EventTypeWithHow(EventTypeWithService):
    @classmethod
    def record(cls, *, user, session, service, how):
        return super().record(user=user, session=session, service=service, data={'how': how})

    @classmethod
    def get_method_statistics(
        cls, group_by_time, service=None, services_ou=None, users_ou=None, start=None, end=None
    ):
        which_references = None
        if services_ou and not service:
            services = Service.objects.filter(ou=services_ou)
            if not services:
                which_references = []
            else:
                # look for the Service child and parent instances, see #68390 and #64853
                which_references = [services, list(services.select_subclasses())]
        elif service:
            which_references = service

        qs = cls.get_statistics(
            group_by_time=group_by_time,
            group_by_field='how',
            which_references=which_references,
            users_ou=users_ou,
            start=start,
            end=end,
        )
        stats = Statistics(qs, time_interval=group_by_time)

        for stat in qs:
            stats.add(x_label=stat[group_by_time], y_label=stat['how'], value=stat['count'])
        return stats.to_json(get_y_label=lambda x: _(login_method_label(x or '')))

    @classmethod
    def _get_method_statistics_by_service_or_ou(cls, group_by_time, reference, **kwargs):
        qs = cls.get_statistics(group_by_time, group_by_field='service_name', **kwargs)
        stats = Statistics(qs, time_interval=group_by_time)

        if reference == 'service':
            services = Service.objects.all()
            reference_labels = {str(service): str(service) for service in services}
            stats.set_y_labels(service.name for service in services)
        elif reference == 'ou':
            reference_labels = {
                str(service): str(service.ou) for service in Service.objects.all().select_related('ou')
            }
            stats.set_y_labels(OU.objects.values_list('name', flat=True))
        else:
            raise NotImplementedError

        for stat in qs:
            y_label = (
                reference_labels.get(stat['service_name'], stat['service_name'])
                if stat['service_name'] is not None
                else None
            )
            stats.add(x_label=stat[group_by_time], y_label=y_label, value=stat['count'])

        return stats.to_json()

    @classmethod
    def get_service_statistics(cls, group_by_time, start=None, end=None):
        return cls._get_method_statistics_by_service_or_ou(group_by_time, 'service', start=start, end=end)

    @classmethod
    def get_service_ou_statistics(cls, group_by_time, start=None, end=None):
        return cls._get_method_statistics_by_service_or_ou(group_by_time, 'ou', start=start, end=end)


def login_method_label(how):
    if how.startswith('password'):
        return _('password')
    elif how == 'france-connect':
        return 'FranceConnect'
    elif how == 'saml':
        return 'SAML'
    elif how == 'oidc':
        return 'OpenID Connect'
    elif how == 'su':
        return _('login as token')
    elif how:
        return how
    else:
        return _('none')


def get_attributes_label(attributes_new_values):
    attributes_map = get_attributes_map()
    for name in attributes_new_values:
        if name in ('email', 'first_name', 'last_name'):
            yield str(User._meta.get_field(name).verbose_name)
        else:
            if name in attributes_map:
                yield attributes_map[name].label
            else:
                yield name


class UserLogin(EventTypeWithHow):
    name = 'user.login'
    label = _('login')

    @classmethod
    def get_message(cls, event, context):
        how = event.get_data('how')
        return _('login using {method}').format(method=login_method_label(how))


class UserLoginFailure(EventTypeWithService):
    name = 'user.login.failure'
    label = _('login failure')

    @classmethod
    def record(cls, *, authenticator, service, username=None, user=None, reason=None):
        return super().record(
            user=user,
            service=service,
            data={
                'username': username,
                'reason': reason,
            },
            references=[authenticator],
        )

    @classmethod
    def get_message(cls, event, context):
        username = event.get_data('username')
        reason = event.get_data('reason')

        (service, authenticator) = event.get_typed_references(Service, BaseAuthenticator)
        if service is None:
            (authenticator,) = event.get_typed_references(BaseAuthenticator)

        if username:
            msg = _('login failure with username "{username}"').format(username=username)
        else:
            msg = _('unknown failed login attempt')
        if authenticator and context != authenticator:
            msg += _(' on authenticator {authenticator}').format(authenticator=authenticator)
        if reason:
            msg += _(' (reason: {reason})').format(reason=reason)
        return msg


class UserRegistrationRequest(EventTypeDefinition):
    name = 'user.registration.request'
    label = _('registration request')

    @classmethod
    def record(cls, *, email):
        return super().record(data={'email': email.lower()})

    @classmethod
    def get_message(cls, event, context):
        email = event.get_data('email')
        return _('registration request with email "%s"') % email


class UserRegistration(EventTypeWithHow):
    name = 'user.registration'
    label = _('registration')

    @classmethod
    def get_message(cls, event, context):
        how = event.get_data('how')
        return _('registration using {method}').format(method=login_method_label(how))


class UserLogout(EventTypeWithService):
    name = 'user.logout'
    label = _('logout')

    @classmethod
    def record(cls, *, user, session, service):
        return super().record(user=user, session=session, service=service)

    @classmethod
    def get_message(cls, event, context):
        return _('logout')


class UserRequestPasswordReset(EventTypeDefinition):
    name = 'user.password.reset.request'
    label = _('password reset request')

    @classmethod
    def record(cls, *, user, email):
        return super().record(user=user, data={'email': email.lower()})

    @classmethod
    def get_message(cls, event, context):
        email = event.get_data('email')
        if email:
            return _('password reset request with email "%s"') % email
        return super().get_message(event, context)


class UserResetPassword(EventTypeDefinition):
    name = 'user.password.reset'
    label = _('password reset')

    @classmethod
    def record(cls, *, user, session):
        return super().record(user=user, session=session)


class UserResetPasswordFailure(EventTypeDefinition):
    name = 'user.password.reset.failure'
    label = _('password reset failure')

    @classmethod
    def record(cls, *, email):
        return super().record(data={'email': email})

    @classmethod
    def get_message(cls, event, context):
        email = event.get_data('email')
        if email:
            return _('password reset failure with email "%s"') % email
        return super().get_message(event, context)


class UserChangePassword(EventTypeWithService):
    name = 'user.password.change'
    label = _('password change')

    @classmethod
    def record(cls, *, user, session, service):
        return super().record(user=user, session=session, service=service)


class UserEdit(EventTypeWithService):
    name = 'user.profile.edit'
    label = _('profile edit')

    @classmethod
    def record(cls, *, user, session, service, form):
        data = form_to_old_new(form)
        return super().record(user=user, session=session, service=service, data=data)

    @classmethod
    def get_message(cls, event, context):
        new = event.get_data('new')
        if new:
            edited_attributes = ', '.join(get_attributes_label(new))
            return _('profile edit (%s)') % edited_attributes
        return super().get_message(event, context)


class UserDeletion(EventTypeWithService):
    name = 'user.deletion'
    label = _('user deletion')

    @classmethod
    def record(cls, *, user, session, service):
        return super().record(user=user, session=session, service=service)


class UserDeletionForInactivity(EventTypeWithService):
    name = 'user.deletion.inactivity'
    label = _('user deletion for inactivity')

    @classmethod
    def record(cls, *, user, days_of_inactivity):
        return super().record(
            user=user,
            data={
                'days_of_inactivity': days_of_inactivity,
                'identifier': user.email or user.phone_identifier,
            },
        )

    @classmethod
    def get_message(cls, event, context):
        days_of_inactivity = event.get_data('days_of_inactivity')
        identifier = event.get_data('identifier')
        return _(
            'user deletion after {days_of_inactivity} days of inactivity, notification sent to "{identifier}".'
        ).format(days_of_inactivity=days_of_inactivity, identifier=identifier)


class UserServiceSSO(EventTypeWithHow):
    name = 'user.service.sso'
    label = _('service single sign on')

    @classmethod
    def get_message(cls, event, context):
        service_name = cls.get_service_name(event)
        return _('service single sign on with "{service}"').format(service=service_name)


class UserServiceSSOAuthorization(EventTypeWithService):
    name = 'user.service.sso.authorization'
    label = _('consent to single sign on')

    @classmethod
    def record(cls, *, user, session, service, **kwargs):
        return super().record(user=user, session=session, service=service, data=kwargs)

    @classmethod
    def get_message(cls, event, context):
        service_name = cls.get_service_name(event)
        return _('authorization of single sign on with "{service}"').format(service=service_name)


class UserServiceSSORefusal(EventTypeWithService):
    name = 'user.service.sso.refusal'
    label = _('do not consent to single sign on')

    @classmethod
    def record(cls, *, user, session, service, **kwargs):
        return super().record(user=user, session=session, service=service, data=kwargs)

    @classmethod
    def get_message(cls, event, context):
        service_name = cls.get_service_name(event)
        return _('refusal of single sign on with "{service}"').format(service=service_name)


class UserServiceSSOUnauthorization(EventTypeWithService):
    name = 'user.service.sso.unauthorization'
    label = _('remove consent to single sign on')

    @classmethod
    def record(cls, *, user, session, service):
        return super().record(user=user, session=session, service=service)

    @classmethod
    def get_message(cls, event, context):
        service_name = cls.get_service_name(event)
        return _('unauthorization of single sign on with "{service}"').format(service=service_name)


class UserServiceSSODenied(EventTypeWithService):
    name = 'user.service.sso.denial'
    label = _('was denied single-sign-on')

    @classmethod
    def record(cls, *, user, session, service, **kwargs):
        return super().record(user=user, session=session, service=service, data=kwargs)

    @classmethod
    def get_message(cls, event, context):
        service_name = cls.get_service_name(event)
        return _('was denied single sign on with "{service}"').format(service=service_name)


class UserEmailChangeRequest(EventTypeDefinition):
    name = 'user.email.change.request'
    label = _('email change request')

    @classmethod
    def record(cls, *, user, session, new_email):
        data = {
            'old_email': user.email,
            'email': new_email,
        }
        return super().record(user=user, session=session, data=data)

    @classmethod
    def get_message(cls, event, context):
        new_email = event.get_data('email')
        return _('email change request for email address "{0}"').format(new_email)


class UserEmailChange(EventTypeDefinition):
    name = 'user.email.change'
    label = _('email change')

    @classmethod
    def record(cls, *, user, session, old_email, new_email):
        data = {
            'old_email': old_email,
            'email': new_email,
        }
        return super().record(user=user, session=session, data=data)

    @classmethod
    def get_message(cls, event, context):
        new_email = event.get_data('email')
        old_email = event.get_data('old_email')
        return _('email address changed from "{0}" to "{1}"').format(old_email, new_email)


class UserPhoneChangeRequest(EventTypeDefinition):
    name = 'user.phone.change.request'
    label = _('phone change request')

    @classmethod
    def record(cls, *, user, old_phone, session, new_phone):
        data = {
            'old_phone': old_phone,
            'new_phone': new_phone,
        }
        return super().record(user=user, session=session, data=data)

    @classmethod
    def get_message(cls, event, context):
        new_phone = event.get_data('new_phone')
        return _('phone change request to number "{0}"').format(new_phone)


class UserPhoneChange(EventTypeDefinition):
    name = 'user.phone.change'
    label = _('phone change')

    @classmethod
    def record(cls, *, user, session, old_phone, new_phone):
        data = {
            'old_phone': old_phone,
            'new_phone': new_phone,
        }
        return super().record(user=user, session=session, data=data)

    @classmethod
    def get_message(cls, event, context):
        new_phone = event.get_data('new_phone')
        old_phone = event.get_data('old_phone')
        return _('phone number changed from "{0}" to "{1}"').format(old_phone, new_phone)


class UserProfileAdd(EventTypeDefinition):
    name = 'user.profile.add'
    label = _('user profile creation')

    @classmethod
    def record(cls, *, user, profile):
        profile_type = ''
        if profile.profile_type is not None:
            profile_type = profile.profile_type.name or profile.profile_type.slug
        data = {
            'profile_type': profile_type,
            'object_user': profile.user.get_full_name(),
            'identifier': profile.identifier,
        }
        return super().record(user=user, data=data)

    @classmethod
    def get_message(cls, event, context):
        profile_type = event.get_data('profile_type')
        object_user = event.get_data('object_user')
        identifier = event.get_data('identifier')
        if identifier:
            msg = N_('profile "{identifier}" of type "{profile_type}" created for user "{object_user}"')
        else:
            msg = N_('profile of type "{profile_type}" created for user "{object_user}"')
        return _(msg).format(profile_type=profile_type, object_user=object_user, identifier=identifier)


class UserProfileUpdate(EventTypeDefinition):
    name = 'user.profile.update'
    label = _('user profile update')

    @classmethod
    def record(cls, *, user, profile):
        profile_type = ''
        if profile.profile_type is not None:
            profile_type = profile.profile_type.name or profile.profile_type.slug
        data = {
            'profile_type': profile_type,
            'object_user': profile.user.get_full_name(),
            'identifier': profile.identifier,
        }
        return super().record(user=user, data=data)

    @classmethod
    def get_message(cls, event, context):
        profile_type = event.get_data('profile_type')
        object_user = event.get_data('object_user')
        identifier = event.get_data('identifier')
        if identifier:
            msg = N_('profile "{identifier}" of type "{profile_type}" updated for user "{object_user}"')
        else:
            msg = N_('profile of type "{profile_type}" updated for user "{object_user}"')
        return _(msg).format(profile_type=profile_type, object_user=object_user, identifier=identifier)


class UserProfileDelete(EventTypeDefinition):
    name = 'user.profile.delete'
    label = _('user profile deletion')

    @classmethod
    def record(cls, *, user, profile):
        profile_type = ''
        if profile.profile_type is not None:
            profile_type = profile.profile_type.name or profile.profile_type.slug
        data = {
            'profile_type': profile_type,
            'object_user': profile.user.get_full_name(),
            'identifier': profile.identifier,
        }
        return super().record(user=user, data=data)

    @classmethod
    def get_message(cls, event, context):
        profile_type = event.get_data('profile_type')
        object_user = event.get_data('object_user')
        identifier = event.get_data('identifier')
        if identifier:
            msg = N_('profile "{identifier}" of type "{profile_type}" deleted for user "{object_user}"')
        else:
            msg = N_('profile of type "{profile_type}" deleted for user "{object_user}"')
        return _(msg).format(profile_type=profile_type, object_user=object_user, identifier=identifier)


class UserNotificationInactivity(EventTypeDefinition):
    name = 'user.notification.inactivity'
    label = _('user inactivity notification')

    @classmethod
    def record(cls, *, user, days_of_inactivity, days_to_deletion):
        data = {
            'days_of_inactivity': days_of_inactivity,
            'days_to_deletion': days_to_deletion,
            'identifier': user.email or user.phone_identifier,
        }
        return super().record(user=user, data=data)

    @classmethod
    def get_message(cls, event, context):
        days_of_inactivity = event.get_data('days_of_inactivity')
        days_to_deletion = event.get_data('days_to_deletion')
        identifier = event.get_data('identifier')
        return _(
            'notification sent to "{identifier}" after {days_of_inactivity} days of inactivity. '
            'Account will be deleted in {days_to_deletion} days.'
        ).format(
            days_of_inactivity=days_of_inactivity, days_to_deletion=days_to_deletion, identifier=identifier
        )


class UserNotificationActivity(EventTypeWithService):
    name = 'user.notification.activity'
    label = _('user activity notification')

    @classmethod
    def record(cls, *, actor, target_user):
        user = actor if isinstance(actor, User) else None
        service = actor if isinstance(actor, Service) else None
        data = {
            'target_user': str(target_user),
            'target_user_pk': target_user.pk,
        }
        references = [target_user]
        return super().record(user=user, service=service, data=data, references=references)

    @classmethod
    def get_message(cls, event, context):
        actor_user = event.user
        actor_service, target_user = event.get_typed_references(Service, User)
        if actor_service is None:
            (target_user,) = event.get_typed_references(User)
        if actor_user is not None:
            actor = _('user "{0}"').format(actor_user)
        elif actor_service:
            actor = _('service "{0}"').format(actor_service)
        else:
            actor = _('unknown actor')
        if context == target_user:
            return _('user activity notified by {0}').format(actor)
        else:
            return _('user "{0}" activity notified by {1}').format(target_user, actor)


class UserSuTokenGeneration(EventTypeDefinition):
    name = 'user.su_token_generation'
    label = _('login as token generated')

    @classmethod
    def record(cls, *, user, session, as_username, as_userid):
        return super().record(
            user=user, session=session, data={'as_username': as_username, 'as_userid': as_userid}
        )

    @classmethod
    def get_message(cls, event, context):
        as_username = event.get_data('as_username')
        as_userid = event.get_data('as_userid')
        return _(
            'login as token generated for "%(username)s" (id=%(id)d)'
            % {'username': as_username, 'id': as_userid}
        )


class ProviderKeysetChange(EventTypeDefinition):
    name = 'provider.keyset.change'
    label = _('identity provider keyset change')

    @classmethod
    def record(cls, *, provider, new_keyset, old_keyset):
        new_keys = list(new_keyset - old_keyset)
        new_keys.sort()
        old_keys = list(old_keyset - new_keyset)
        old_keys.sort()
        data = {
            'new': ', '.join(new_keys) or '—',
            'old': ', '.join(old_keys) or '—',
            'provider': provider,
        }
        return super().record(data=data)

    @classmethod
    def get_message(cls, event, context):
        new = event.get_data('new')
        old = event.get_data('old')
        provider = event.get_data('provider')
        return _(
            f'Provider {provider} renewed its keyset with new keys [{new}] whereas old keys [{old}] are now deprecated'
        )
