import os

# Debian defaults
DEBUG = False

PROJECT_NAME = 'authentic2-multitenant'

#
# hobotization (multitenant)
#
with open('/usr/lib/hobo/debian_config_common.py') as fd:
    exec(fd.read())

# Add the XForwardedForMiddleware
MIDDLEWARE = ('authentic2.middleware.XForwardedForMiddleware',) + MIDDLEWARE

# Add authentic settings loader
TENANT_SETTINGS_LOADERS = ('hobo.multitenant.settings_loaders.Authentic',) + TENANT_SETTINGS_LOADERS

# Add authentic2 hobo agent
INSTALLED_APPS = ('hobo.agent.authentic2',) + INSTALLED_APPS

# Configure argon2 to be preferred for password hashes
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

LOGGING['filters'].update(
    {
        'cleaning': {
            '()': 'authentic2.utils.misc.CleanLogMessage',
        },
    }
)
for handler in LOGGING['handlers'].values():
    handler.setdefault('filters', []).append('cleaning')

if 'syslog' in LOGGING['handlers']:
    # django_select2 outputs debug message at level INFO
    LOGGING['loggers']['django_select2'] = {
        'handlers': ['syslog'],
        'level': 'WARNING',
    }

A2_PASSWORD_POLICY_DICTIONARIES = {'richelieu': '/usr/share/authentic2/richelieu'}

# Rest Authentication Class for services access
REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] += (
    'authentic2.authentication.Authentic2Authentication',
    'rest_framework.authentication.SessionAuthentication',
)
HOBO_ANONYMOUS_SERVICE_USER_CLASS = 'hobo.rest_authentication.AnonymousAuthenticServiceUser'

# HOBO Skeletons

HOBO_SKELETONS_DIR = os.path.join(VAR_DIR, 'skeletons')

CONFIG_FILE = '/etc/%s/config.py' % PROJECT_NAME
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as fd:
        exec(fd.read())

# run additional settings snippets
with open('/usr/lib/hobo/debian_config_settings_d.py') as fd:
    exec(fd.read())
