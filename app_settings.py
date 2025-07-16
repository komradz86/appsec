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

import sys

from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _


class Setting:
    SENTINEL = object()

    def __init__(self, default=SENTINEL, definition='', names=None):
        self.names = names or []
        if isinstance(self.names, str):
            self.names = [self.names]
        self.names = set(self.names)
        self.default = default
        self.definition = definition

    def has_default(self):
        return self.default != self.SENTINEL


class AppSettings:
    def __init__(self, defaults):
        self.defaults = defaults

    @property
    def settings(self):
        if not hasattr(self, '_settings'):
            from django.conf import settings

            self._settings = settings
        return self._settings

    @property
    def REALMS(self):
        realms = {}
        if self.A2_REGISTRATION_REALM:
            realms[self.A2_REGISTRATION_REALM] = self.A2_REGISTRATION_REALM

        def add_realms(new_realms):
            for realm in new_realms:
                if not isinstance(realm, (tuple, list)):
                    realms[realm] = realm
                else:
                    realms[realm[0]] = realm[1]

        from django.contrib.auth import get_backends

        for backend in get_backends():
            if hasattr(backend, 'get_realms'):
                add_realms(backend.get_realms())
        if self.A2_REALMS:
            add_realms(self.A2_REALMS)
        return realms.items()

    @property
    def A2_USER_CAN_RESET_PASSWORD(self):
        if hasattr(self.settings, 'A2_USER_CAN_RESET_PASSWORD'):
            return self.settings.A2_USER_CAN_RESET_PASSWORD
        if hasattr(self.settings, 'A2_CAN_RESET_PASSWORD'):
            return self.settings.A2_CAN_RESET_PASSWORD
        return self.defaults['A2_USER_CAN_RESET_PASSWORD'].default

    def __getattr__(self, key):
        if key not in self.defaults:
            raise AttributeError('unknown key %s' % key)
        if hasattr(self.settings, key):
            return getattr(self.settings, key)
        if self.defaults[key].names:
            for other_key in self.defaults[key].names:
                if hasattr(self.settings, other_key):
                    return getattr(self.settings, other_key)
        if self.defaults[key].has_default():
            return self.defaults[key].default
        raise ImproperlyConfigured(
            'missing setting %s(%s) is mandatory' % (key, self.defaults[key].description)
        )


default_settings = dict(
    ATTRIBUTE_BACKENDS=Setting(
        names=('A2_ATTRIBUTE_BACKENDS',),
        default=(
            'authentic2.attributes_ng.sources.format',
            'authentic2.attributes_ng.sources.function',
            'authentic2.attributes_ng.sources.django_user',
            'authentic2.attributes_ng.sources.ldap',
            'authentic2.attributes_ng.sources.service_roles',
        ),
        definition='List of attribute backend classes or modules',
    ),
    CAFILE=Setting(
        names=('AUTHENTIC2_CAFILE', 'CAFILE'),
        default=None,
        definition='File containing certificate chains as PEM certificates',
    ),
    A2_REGISTRATION_CAN_DELETE_ACCOUNT=Setting(
        default=True, definition='Can user self delete their account and all their data'
    ),
    A2_REGISTRATION_CAN_CHANGE_PASSWORD=Setting(
        default=True, definition='Allow user to change its own password'
    ),
    A2_REGISTRATION_EMAIL_BLACKLIST=Setting(
        default=[], definition='List of forbidden email wildcards, ex.: ^.*@ville.fr$'
    ),
    A2_REGISTRATION_REDIRECT=Setting(
        default=None,
        definition=(
            'Forced redirection after each redirect, NEXT_URL substring is replaced by the original next_url'
            ' passed to /accounts/register/'
        ),
    ),
    A2_PROFILE_CAN_EDIT_PROFILE=Setting(default=True, definition='Can user self edit their profile'),
    A2_PROFILE_CAN_MANAGE_FEDERATION=Setting(default=True, definition='Can user manage its federations'),
    A2_PROFILE_CAN_MANAGE_SERVICE_AUTHORIZATIONS=Setting(
        default=True, definition='Allow user to revoke granted services access to its account profile data'
    ),
    A2_PROFILE_DISPLAY_EMPTY_FIELDS=Setting(default=False, definition='Include empty fields in profile view'),
    A2_HOMEPAGE_URL=Setting(default=None, definition='IdP has no homepage, redirect to this one.'),
    A2_USER_CAN_RESET_PASSWORD=Setting(default=None, definition='Allow online reset of passwords'),
    A2_USER_CAN_RESET_PASSWORD_BY_USERNAME=Setting(
        default=False, definition='Allow password reset request by username'
    ),
    A2_EMAIL_IS_UNIQUE=Setting(default=False, definition="Users' email address must be unique"),
    A2_REGISTRATION_EMAIL_IS_UNIQUE=Setting(
        default=False, definition='Email address declared at registration time must be unique'
    ),
    A2_PHONE_IS_UNIQUE=Setting(default=False, definition="Users' phone number must be unique"),
    A2_REGISTRATION_PHONE_IS_UNIQUE=Setting(
        default=False, definition='Phone number declared at registration time must be unique'
    ),
    A2_REGISTRATION_FORM_USERNAME_REGEX=Setting(
        default=r'^[\w.@+-]+$', definition='Regex to validate usernames'
    ),
    A2_REGISTRATION_FORM_USERNAME_HELP_TEXT=Setting(
        default=_('Required. At most 30 characters. Letters, digits, and @/./+/-/_ only.')
    ),
    A2_REGISTRATION_FORM_USERNAME_LABEL=Setting(default=_('Username')),
    A2_REGISTRATION_REALM=Setting(
        default=None, definition='Default realm to assign to self-registrated users'
    ),
    A2_PROFILE_FIELDS=Setting(default=(), definition='Fields to show to the user in the profile page'),
    A2_REGISTRATION_FIELDS=Setting(
        default=(), definition='Fields from the user model that must appear on the registration form'
    ),
    A2_REQUIRED_FIELDS=Setting(default=(), definition='User fields that are required'),
    A2_REGISTRATION_REQUIRED_FIELDS=Setting(
        default=(), definition='Fields from the registration form that must be required'
    ),
    A2_PRE_REGISTRATION_FIELDS=Setting(default=(), definition='User fields to ask with email'),
    A2_REALMS=Setting(default=(), definition='List of realms to search user accounts'),
    A2_USERNAME_REGEX=Setting(default=None, definition='Regex that username must validate'),
    A2_USERNAME_LABEL=Setting(default=None, definition='Alternate username label for the login form'),
    A2_USERNAME_HELP_TEXT=Setting(
        default=None, definition='Help text to explain validation rules of usernames'
    ),
    A2_USERNAME_IS_UNIQUE=Setting(default=True, definition='Check username uniqueness'),
    A2_LOGIN_FORM_OU_SELECTOR_LABEL=Setting(default=None, definition='Label of OU field on login page'),
    A2_REGISTRATION_USERNAME_IS_UNIQUE=Setting(
        default=True, definition='Check username uniqueness on registration'
    ),
    IDP_BACKENDS=(),
    A2_OPENED_SESSION_COOKIE_NAME=Setting(default='A2_OPENED_SESSION', definition='Authentic session open'),
    A2_OPENED_SESSION_COOKIE_DOMAIN=Setting(default=None),
    A2_ATTRIBUTE_KINDS=Setting(default=(), definition='List of other attribute kinds'),
    A2_ATTRIBUTE_KIND_PROFILE_IMAGE_SIZE=Setting(
        default=200, definition='Width and height for a profile image'
    ),
    A2_VALIDATE_EMAIL=Setting(
        default=False, definition='Validate user email server by doing an RCPT command'
    ),
    A2_VALIDATE_EMAIL_DOMAIN=Setting(default=True, definition='Validate user email domain'),
    A2_PASSWORD_POLICY_MIN_CLASSES=Setting(
        default=3, definition='Minimum number of characters classes to be present in passwords'
    ),
    A2_PASSWORD_POLICY_CLASS=Setting(
        default='authentic2.passwords.DefaultPasswordChecker',
        definition='path of a class to validate passwords',
    ),
    A2_PASSWORD_POLICY_SHOW_LAST_CHAR=Setting(
        default=False, definition='Show last character in password fields'
    ),
    A2_PASSWORD_POLICY_DICTIONARIES=Setting(
        default={}, definition='Dictionary of {name: path} entries to load for password strength checking'
    ),
    A2_SUGGESTED_EMAIL_DOMAINS=Setting(
        default=[
            'gmail.com',
            'msn.com',
            'hotmail.com',
            'hotmail.fr',
            'wanadoo.fr',
            'yahoo.fr',
            'yahoo.com',
            'laposte.net',
            'free.fr',
            'orange.fr',
            'numericable.fr',
        ],
        definition='List of suggested email domains',
    ),
    A2_LOGIN_FAILURE_COUNT_BEFORE_WARNING=Setting(
        default=0,
        definition=(
            'Failure count before logging a warning to authentic2.user_login_failure. No warning will be send'
            ' if value is 0.'
        ),
    ),
    PUSH_PROFILE_UPDATES=Setting(default=False, definition='Push profile update to linked services'),
    TEMPLATE_VARS=Setting(default={}, definition='Variable to pass to templates'),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_FACTOR=Setting(
        default=1.8,
        definition='exponential backoff factor duration as seconds until next try after a login failure',
    ),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_DURATION=Setting(
        default=1,
        definition='exponential backoff base factor duration as seconds until next try after a login failure',
    ),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_MAX_DURATION=Setting(
        default=3600,
        definition=(
            'maximum exponential backoff maximum duration as seconds until next try after a login failure'
        ),
    ),
    A2_LOGIN_EXPONENTIAL_RETRY_TIMEOUT_MIN_DURATION=Setting(
        default=10,
        definition=(
            'minimum exponential backoff maximum duration as seconds until next try after a login failure'
        ),
    ),
    A2_VERIFY_SSL=Setting(default=True, definition='Verify SSL certificate in HTTP requests'),
    A2_ATTRIBUTE_KIND_TITLE_CHOICES=Setting(default=(), definition='Choices for the title attribute kind'),
    A2_CORS_WHITELIST=Setting(
        default=(), definition='List of origin URL to whitelist, must be scheme://netloc[:port]'
    ),
    A2_EMAIL_CHANGE_TOKEN_LIFETIME=Setting(
        default=7200, definition='Lifetime in seconds of the token sent to verify email adresses'
    ),
    A2_DELETION_REQUEST_LIFETIME=Setting(
        default=48 * 3600, definition='Lifetime in seconds of the user account deletion request'
    ),
    A2_REDIRECT_WHITELIST=Setting(
        default=(), definition='List of origins which are authorized to ask for redirection.'
    ),
    A2_API_USERS_REQUIRED_FIELDS=Setting(
        default=(), definition='List of fields to require on user\'s API, override other settings'
    ),
    A2_API_USERS_ALLOW_IP_RESTRICTIONS=Setting(
        default=False, definition='Enable IP restrictions for API clients'
    ),
    A2_USER_FILTER=Setting(
        default={},
        definition='Filters (as in QuerySet.filter() to apply to User queryset before authentication',
    ),
    A2_USER_EXCLUDE=Setting(
        default={},
        definition=(
            'Exclusion filter (as in QuerySet.exclude() to apply to User queryset before authentication'
        ),
    ),
    A2_LOGIN_REDIRECT_AUTHENTICATED_USERS_TO_HOMEPAGE=Setting(
        default=False, definition='Redirect authenticated users to homepage'
    ),
    A2_LOGIN_DISPLAY_A_CANCEL_BUTTON=Setting(
        default=False,
        definition='Display a cancel button.This is only applicable for Liberty single sign on requests',
    ),
    A2_SET_RANDOM_PASSWORD_ON_RESET=Setting(
        default=True,
        definition='Set a random password on request to reset the password from the front-office',
    ),
    A2_ACCOUNTS_URL=Setting(default=None, definition='IdP has no account page, redirect to this one.'),
    A2_ACCOUNTS_DISPLAY_COMPLETION_RATIO=Setting(
        default=False, definition='Display user\'s profile completion ratio.'
    ),
    A2_CACHE_ENABLED=Setting(default=True, definition='Disable all cache decorators for testing purpose.'),
    A2_ALLOW_PHONE_AUTHN_MANAGEMENT=Setting(
        default=False,
        definition='Allow phone-authentication backoffice-management by authentic\'s administrators',
    ),
    A2_USER_DELETED_KEEP_DATA=Setting(
        default=['email', 'uuid', 'phone'], definition='User data to keep after deletion'
    ),
    A2_USER_DELETED_KEEP_DATA_DAYS=Setting(
        default=365, definition='Number of days to keep data on deleted users'
    ),
    A2_TOKEN_EXISTS_WARNING=Setting(
        default=True, definition='If an active token exists, warn user before generating a new one.'
    ),
    A2_SMS_CODE_EXISTS_WARNING=Setting(
        default=True, definition='If an active SMS code exists, warn user before generating a new one.'
    ),
    A2_DUPLICATES_THRESHOLD=Setting(
        default=0.7, definition='Trigram similarity threshold for considering user as duplicate.'
    ),
    A2_FTS_THRESHOLD=Setting(default=0.2, definition='Trigram similarity threshold for free text search.'),
    A2_DUPLICATES_BIRTHDATE_BONUS=Setting(
        default=0.3, definition='Bonus in case of birthdate match (no bonus is 0, max is 1).'
    ),
    A2_EMAIL_FORMAT=Setting(
        default='multipart/alternative',
        definition='Send email as "multiplart/alternative" or limit to "text/plain" or "text/html".',
    ),
    A2_CLEAN_UNUSED_ACCOUNTS_MAX_MAIL_PER_PERIOD=Setting(
        default=250,
        definition='Maximum number of mails to send per period',
    ),
    A2_API_USERS_NUMBER_LIMIT=Setting(
        default=1000,
        definition='Maximum number of users returned by REST API',
    ),
)

app_settings = AppSettings(default_settings)
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
