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
import logging.config
import os

# Load default from Django
from django.conf import global_settings
from django.utils.translation import gettext_lazy as _

from . import logger

# debian/debian_config.py::extract_settings_from_environ expects CACHES to be in its NAMESPACE
CACHES = global_settings.CACHES

BASE_DIR = os.path.dirname(__file__)

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'please-change-me-with-a-very-long-random-string'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False
DEBUG_DB = False
MEDIA = 'media'
MEDIA_ROOT = 'media'
MEDIA_URL = '/media/'

# See https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'authentic2',
    }
}

# Cookies
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
LANGUAGE_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SAMESITE = 'None'
LANGUAGE_COOKIE_SAMESITE = 'None'

# Hey Entr'ouvert is in France !!
TIME_ZONE = 'Europe/Paris'
LANGUAGE_CODE = 'fr'
USE_TZ = True

# Static files

STATIC_URL = '/static/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'authentic2.a2_rbac.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.static',
                'authentic2.context_processors.a2_processor',
                'authentic2.context_processors.home',
                'authentic2.context_processors.constant_aliases',
                'publik_django_templatetags.wcs.context_processors.wcs_objects',
            ],
            'builtins': [
                'publik_django_templatetags.publik.templatetags.publik',
                'publik_django_templatetags.wcs.templatetags.wcs',
            ],
        },
    },
]


MIDDLEWARE = (
    'authentic2.middleware.null_character_middleware',
    'authentic2.middleware.StoreRequestMiddleware',
    'authentic2.middleware.RequestIdMiddleware',
    'authentic2.middleware.ServiceAccessControlMiddleware',
    'authentic2.middleware.CookieTestMiddleware',
    'authentic2.middleware.XForwardedForMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'authentic2.middleware.journal_middleware',
)

MIDDLEWARE += (
    'authentic2.middleware.DisplayMessageBeforeRedirectMiddleware',
    'authentic2.middleware.CollectIPMiddleware',
    'authentic2.middleware.ViewRestrictionMiddleware',
    'authentic2.middleware.OpenedSessionCookieMiddleware',
)

ROOT_URLCONF = 'authentic2.urls'

STATICFILES_FINDERS = list(global_settings.STATICFILES_FINDERS) + ['gadjo.finders.XStaticFinder']

LOCALE_PATHS = (os.path.join(BASE_DIR, 'locale'),)

INSTALLED_APPS = (
    'django.contrib.staticfiles',
    'django.contrib.contenttypes',
    'authentic2.custom_user',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',
    'django.contrib.humanize',
    'django.contrib.postgres',
    'django_select2',
    'django_tables2',
    'mellon',
    'authentic2_auth_fc',
    'authentic2_auth_saml',
    'authentic2_auth_oidc',
    'authentic2_idp_cas',
    'authentic2_idp_oidc',
    'authentic2.nonce',
    'authentic2.saml',
    'authentic2.idp',
    'authentic2.idp.saml',
    'authentic2.attribute_aggregator',
    'authentic2.disco_service',
    'authentic2.manager',
    'authentic2.apps.authenticators',
    'authentic2.apps.journal',
    'authentic2.backends',
    'authentic2.app.Authentic2Config',
    'django_rbac',
    'authentic2.a2_rbac',
    'gadjo',
    'publik_django_templatetags',
    'rest_framework',
    'xstatic.pkg.jquery',
    'xstatic.pkg.jquery_ui',
    'xstatic.pkg.select2',
    'django.forms',
)

# authentication
AUTHENTICATION_BACKENDS = (
    'authentic2.backends.models_backend.ModelBackend',
    'authentic2.backends.ldap_backend.LDAPBackend',
    'authentic2.backends.ldap_backend.LDAPBackendPasswordLost',
    'authentic2.backends.models_backend.DummyModelBackend',
    'authentic2.custom_user.backends.DjangoRBACBackend',
    'authentic2_auth_saml.backends.SAMLBackend',
    'authentic2_auth_oidc.backends.OIDCBackend',
    'authentic2_auth_fc.backends.FcBackend',
)
CSRF_FAILURE_VIEW = 'authentic2.views.csrf_failure_view'


LOGIN_REDIRECT_URL = '/'
LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'

# Registration
ACCOUNT_ACTIVATION_DAYS = 2

# Authentic2 settings

###########################
# Authentication settings
###########################
AUTH_USER_MODEL = 'custom_user.User'

###########################
# RBAC settings
###########################
RBAC_OU_MODEL = 'a2_rbac.OrganizationalUnit'
RBAC_PERMISSION_MODEL = 'a2_rbac.Permission'
RBAC_ROLE_MODEL = 'a2_rbac.Role'
RBAC_ROLE_PARENTING_MODEL = 'a2_rbac.RoleParenting'

#############################
# Identity Provider settings
#############################

# List of IdP backends, mainly used to show available services in the homepage
# of user, and to handle SLO for each protocols
IDP_BACKENDS = ('authentic2.idp.saml.backend.SamlBackend',)

# Whether to autoload SAML 2.0 identity providers and services metadata
# Only https URLS are accepted.
# Can be none, sp, idp or both

PASSWORD_HASHERS = list(global_settings.PASSWORD_HASHERS) + [
    'authentic2.hashers.Drupal7PasswordHasher',
    'authentic2.hashers.SHA256PasswordHasher',
    'authentic2.hashers.SSHA1PasswordHasher',
    'authentic2.hashers.SMD5PasswordHasher',
    'authentic2.hashers.SHA1OLDAPPasswordHasher',
    'authentic2.hashers.MD5OLDAPPasswordHasher',
    'authentic2.hashers.PloneSHA1PasswordHasher',
]

# Serialization module to support natural keys in generic foreign keys
SERIALIZATION_MODULES = {
    'json': 'authentic2.serializers',
}

LOGGING_CONFIG = None
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'filters': {
        'cleaning': {
            '()': 'authentic2.utils.misc.CleanLogMessage',
        },
        'request_context': {
            '()': 'authentic2.log_filters.RequestContextFilter',
        },
        'force_debug': {
            '()': 'authentic2.log_filters.ForceDebugFilter',
        },
    },
    'formatters': {
        'verbose': {
            'format': (
                '[%(asctime)s] %(ip)s %(user)s %(request_id)s %(levelname)s %(name)s.%(funcName)s:'
                ' %(message)s'
            ),
            'datefmt': '%Y-%m-%d %a %H:%M:%S',
        },
        'verbose_db': {
            'format': '[%(asctime)s] - - - %(levelname)s %(name)s.%(funcName)s: %(message)s',
            'datefmt': '%Y-%m-%d %a %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['cleaning', 'request_context'],
        },
        # remove request_context filter for db log to prevent infinite loop
        # when logging sql query to retrieve the session user
        'console_db': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose_db',
            'filters': ['cleaning'],
        },
    },
    'loggers': {
        # even when debugging seeing SQL queries is too much, activate it
        # explicitly using DEBUG_DB
        'django.db': {
            'handlers': ['console_db'],
            'level': logger.SettingsLogLevel('INFO', debug_setting='DEBUG_DB'),
            'propagate': False,
        },
        'django': {
            'level': 'INFO',
        },
        # django_select2 outputs debug message at level INFO
        'django_select2': {
            'level': 'WARNING',
        },
        # lasso has the bad habit of logging everything as errors
        'Lasso': {
            'filters': ['force_debug'],
        },
        'libxml2': {
            'filters': ['force_debug'],
        },
        'libxmlsec': {
            'filters': ['force_debug'],
        },
        '': {
            'handlers': ['console'],
            'level': logger.SettingsLogLevel('INFO'),
        },
    },
}

MIGRATION_MODULES = {
    'auth': 'authentic2.auth_migrations_18',
}

# Django REST Framework
REST_FRAMEWORK = {
    'NON_FIELD_ERRORS_KEY': '__all__',
    'DEFAULT_PARSER_CLASSES': [
        'authentic2.utils.rest_framework.UnflattenJSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'authentic2.authentication.Authentic2Authentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.OrderingFilter',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 100,
}


# Authentic2 Auth SAML
MELLON_ADAPTER = ('authentic2_auth_saml.adapters.AuthenticAdapter',)
MELLON_LOOKUP_BY_ATTRIBUTES = [
    {'saml_attribute': 'email', 'user_field': 'email', 'ignore-case': True},
    {'saml_attribute': 'username', 'user_field': 'username'},
]

# timeout used in python-requests call, in seconds
# we use 28s by default: timeout just before web server, which is usually 30s
REQUESTS_TIMEOUT = 28

# Permissions

DJANGO_RBAC_PERMISSIONS_HIERARCHY = {
    'view': ['search'],
    'change_password': ['view', 'search'],
    'change_email': ['view', 'search'],
    'reset_password': ['view', 'search'],
    'activate': ['view', 'search'],
    'admin': [
        'change',
        'delete',
        'add',
        'view',
        'change_password',
        'reset_password',
        'activate',
        'search',
        'change_email',
        'manage_members',
        'manage_authorizations',
    ],
    'change': ['view', 'search', 'manage_members'],
    'delete': ['view', 'search'],
    'add': ['view', 'search'],
    'manage_members': ['view', 'search'],
    'manage_authorizations': ['view', 'search'],
}

FORM_RENDERER = 'django.forms.renderers.TemplatesSetting'

SILENCED_SYSTEM_CHECKS = ['auth.W004']

SMS_SENDER = 'EO'
SMS_URL = ''

# allowed character set in SMS codes, without visually ambiguous characters (no '0' or 'O', and no '1', 'I' or 'L').
SMS_CODE_ALLOWED_CHARACTERS = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'
SMS_CODE_LENGTH = 8
SMS_CODE_DURATION = 180

# Get select2 from local copy.
SELECT2_JS = '/static/xstatic/select2.min.js'
SELECT2_CSS = '/static/xstatic/select2.min.css'

# Phone prefixes by country for phone number as authentication identifier
PHONE_COUNTRY_CODES = {
    '32': {
        'region': 'BE',
        'region_desc': _('Belgium'),
        'example_value': '042 11 22 33',
    },
    '33': {
        'region': 'FR',
        'region_desc': _('Metropolitan France'),
        'example_value': '06 39 98 01 23',
    },
    '262': {
        'region': 'RE',
        'region_desc': _('Réunion'),
        'example_value': '06 39 98 01 23',
    },
    '508': {
        'region': 'PM',
        'region_desc': _('Saint Pierre and Miquelon'),
        'example_value': '06 39 98 01 23',
    },
    '590': {
        'region': 'GP',
        'region_desc': _('Guadeloupe'),
        'example_value': '06 39 98 01 23',
    },
    '594': {
        'region': 'GF',
        'region_desc': _('French Guiana'),
        'example_value': '06 39 98 01 23',
    },
    '596': {
        'region': 'MQ',
        'region_desc': _('Martinique'),
        'example_value': '06 39 98 01 23',
    },
}

DEFAULT_COUNTRY_CODE = '33'

AUTHENTICATOR_SHOW_CONDITIONS = {
    'is_for_backoffice': "'backoffice' in login_hint",
    'is_for_frontoffice': "'backoffice' not in login_hint",
}

#
# Load configuration file
#

if 'AUTHENTIC2_SETTINGS_FILE' in os.environ:
    with open(os.environ['AUTHENTIC2_SETTINGS_FILE']) as fd:
        exec(fd.read())
logging.config.dictConfig(LOGGING)
