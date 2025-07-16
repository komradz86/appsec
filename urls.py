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

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.contrib.staticfiles.views import serve
from django.urls import include, path, re_path
from django.utils.translation import gettext_lazy as _
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.generic import RedirectView
from django.views.generic.base import TemplateView
from django.views.static import serve as media_serve

import authentic2.idp.saml.app_settings
import authentic2_auth_fc.urls
import authentic2_auth_oidc.urls
import authentic2_auth_saml.urls
import authentic2_idp_cas.app_settings
import authentic2_idp_oidc.urls
from authentic2.decorators import lasso_required, required, setting_enabled

from . import plugins, views

admin.autodiscover()

accounts_urlpatterns = [
    path(
        r'activate/<a2_token:registration_token>/',
        views.registration_completion,
        name='registration_activate',
    ),
    path('delete/', login_required(views.AccountDeleteView.as_view()), name='delete_account'),
    re_path(
        r'validate-deletion/(?P<deletion_token>[\w: -]+)/$',
        views.ValidateDeletionView.as_view(),
        name='validate_deletion',
    ),
    path('edit/', views.edit_profile, name='profile_edit'),
    path('edit/required/', views.edit_required_profile, name='profile_required_edit'),
    re_path(r'^edit/(?P<scope>[-\w]+)/$', views.edit_profile, name='profile_edit_with_scope'),
    path('change-email/', views.email_change, name='email-change'),
    path('change-email/verify/', views.email_change_verify, name='email-change-verify'),
    path('change-phone/', views.phone_change, name='phone-change'),
    path(
        'change-phone/verify/<uuid:token>/',
        views.phone_change_verify,
        name='phone-change-verify',
    ),
    path('verify-phone/', views.phone_verify, name='phone-verify'),
    path(
        'consents/',
        login_required(views.consents),
        name='consents',
    ),
    path(
        'consents/<int:pk>/delete/',
        login_required(views.consent_delete),
        name='consent-delete',
    ),
    path('', views.profile, name='account_management'),
    # Password change
    path('password/change/', views.password_change, name='password_change'),
    # permament redirections for views moved to root
    path('register/', RedirectView.as_view(permanent=True, pattern_name='registration_register')),
    path('register/complete/', RedirectView.as_view(permanent=True, pattern_name='registration_complete')),
    path('register/closed/', RedirectView.as_view(permanent=True, pattern_name='registration_disallowed')),
    path(
        r'password/reset/confirm/<a2_token:token>/',
        RedirectView.as_view(permanent=True, pattern_name='password_reset_confirm'),
    ),
    path('password/reset/', RedirectView.as_view(permanent=True, pattern_name='password_reset')),
    path(
        'password/reset/instructions/',
        RedirectView.as_view(permanent=True, pattern_name='password_reset_instructions'),
    ),
    re_path(
        r'^password/reset/.*',
        RedirectView.as_view(permanent=True, pattern_name='invalid-password-reset-urls'),
    ),
]

urlpatterns = [
    path('', views.homepage, name='auth_homepage'),
    path('login/', views.login, name='auth_login'),
    path(r'login/token/<a2_token:token>/', views.token_login, name='token_login'),
    path('logout/', views.logout, name='auth_logout'),
    path(r'su/<a2_b64uuid:uuid>/', views.su, name='su'),
    path('accounts/', include(accounts_urlpatterns)),
    re_path(r'^admin/', admin.site.urls),
    path('idp/', include('authentic2.idp.urls')),
    path('manage/', include('authentic2.manager.urls')),
    path('api/', include('authentic2.api_urls')),
    path('continue/', views.display_message_and_continue, name='continue'),
    re_path(r'^\.well-known/change-password$', RedirectView.as_view(pattern_name='password_change')),
    # Registration
    path('register/', views.RegistrationView.as_view(), name='registration_register'),
    path('register/complete/', views.registration_complete, name='registration_complete'),
    path(
        'register/closed/',
        TemplateView.as_view(template_name='registration/registration_closed.html'),
        name='registration_disallowed',
    ),
    path(
        'register/input_code/<uuid:token>/',
        views.input_sms_code,
        name='input_sms_code',
    ),
    # Password reset
    path(
        r'password/reset/confirm/<a2_token:token>/',
        views.password_reset_confirm,
        name='password_reset_confirm',
    ),
    path('password/reset/', views.password_reset, name='password_reset'),
    path(
        'password/reset/instructions/',
        views.password_reset_instructions,
        name='password_reset_instructions',
    ),
    re_path(
        r'^password/reset/.*',
        views.old_view_redirect,
        kwargs={
            'to': 'password_reset',
            'message': _('Your password reset link has become invalid, please reset your password again.'),
        },
        name='invalid-password-reset-urls',
    ),
]

try:
    if getattr(settings, 'DISCO_SERVICE', False):
        urlpatterns += [
            (r'^disco_service/', include('disco_service.disco_responder')),
        ]
except Exception:
    pass

if settings.DEBUG:  # pragma: no cover
    urlpatterns += [path(r'^static/<path:path>', serve)]
    urlpatterns += [path(r'^media/<path:path>', media_serve, {'document_root': settings.MEDIA_ROOT})]

if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    import debug_toolbar  # pylint: disable=import-error

    urlpatterns = [
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns

# prevent click-jacking on authentic views
urlpatterns = required(xframe_options_deny, urlpatterns)

urlpatterns = plugins.register_plugins_urls(urlpatterns)

authentic2_idp_saml_urls = required(
    (setting_enabled('ENABLE', settings=authentic2.idp.saml.app_settings), lasso_required()),
    [path('idp/saml2/', include('authentic2.idp.saml.urls'))],
)

authentic2_idp_cas_urls = required(
    (setting_enabled('ENABLE', settings=authentic2_idp_cas.app_settings),),
    [path('idp/cas/', include('authentic2_idp_cas.urls'))],
)

urlpatterns = (
    authentic2_auth_fc.urls.urlpatterns
    + authentic2_idp_oidc.urls.urlpatterns
    + authentic2_idp_cas_urls
    + authentic2_auth_oidc.urls.urlpatterns
    + authentic2_auth_saml.urls.urlpatterns
    + authentic2_idp_saml_urls
    + urlpatterns
)

handler403 = 'authentic2.views.permission_denied'
