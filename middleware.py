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

import time
import uuid

try:
    import threading
except ImportError:
    threading = None

import urllib.parse

from django import http
from django.conf import settings
from django.contrib import messages
from django.db.models import Model
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext as _

from . import app_settings, plugins
from .utils import misc as utils_misc


class CollectIPMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        # only collect IP if session is used
        if not hasattr(request, 'session') or request.session.is_empty():
            return response

        ips = set(request.session.setdefault('ips', []))
        ip = request.META.get('REMOTE_ADDR', None)
        if ip and ip not in ips:
            ips.add(ip)
            request.session['ips'] = list(ips)
            request.session.modified = True
        return response


class OpenedSessionCookieMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        # do not emit cookie for API requests
        enabled = True
        if request.path.startswith('/api/'):
            enabled = False
        if not app_settings.A2_OPENED_SESSION_COOKIE_DOMAIN:
            enabled = False
        # disable common domain cookie during view restriction
        if request.session.get('view_restriction'):
            enabled = False

        name = app_settings.A2_OPENED_SESSION_COOKIE_NAME

        if app_settings.A2_OPENED_SESSION_COOKIE_DOMAIN == 'parent':
            domain = request.get_host().split('.', 1)[1]
        else:
            domain = app_settings.A2_OPENED_SESSION_COOKIE_DOMAIN

        if enabled and hasattr(request, 'user') and request.user.is_authenticated:
            if name not in request.COOKIES:
                response.set_cookie(
                    name,
                    value=uuid.uuid4().hex,
                    max_age=None,
                    domain=domain,
                    secure=settings.SESSION_COOKIE_SECURE,
                    httponly=True,
                    samesite='None',
                )
        elif app_settings.A2_OPENED_SESSION_COOKIE_NAME in request.COOKIES:
            response.delete_cookie(name, domain=domain)
        return response


class RequestIdMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not hasattr(request, 'request_id'):
            request_id_header = getattr(settings, 'REQUEST_ID_HEADER', None)
            if request_id_header and request.META.get(request_id_header):
                request.request_id = request.META[request_id_header]
            else:
                request.request_id = 'r:' + hex(id(request))[2:].upper()


class StoreRequestMiddleware(MiddlewareMixin):
    collection = {}

    def process_request(self, request):
        StoreRequestMiddleware.collection[threading.current_thread()] = request

    def process_response(self, request, response):
        StoreRequestMiddleware.collection.pop(threading.current_thread(), None)
        return response

    def process_exception(self, request, exception):
        StoreRequestMiddleware.collection.pop(threading.current_thread(), None)

    @classmethod
    def get_request(cls):
        return cls.collection.get(threading.current_thread())


class ViewRestrictionMiddleware(MiddlewareMixin):
    RESTRICTION_SESSION_KEY = 'view-restriction'

    def check_view_restrictions(self, request):
        '''Check if a restriction on accessible views must be applied'''

        user = request.user

        # If the session is unlogged, do nothing
        if user is None or not user.is_authenticated:
            return None

        # If the latest check was succesfull, do nothing.
        now = time.time()
        last_time = request.session.get('last_view_restriction_check', 0)
        if now - last_time <= 60:
            return None

        view = self.check_password_reset_view_restriction(request, user)
        if view:
            return view

        view = self.check_required_on_login_attribute_restriction(request, user)
        if view:
            return view

        for plugin in plugins.get_plugins():
            if hasattr(plugin, 'check_view_restrictions'):
                view = plugin.check_view_restrictions(request, user)
                if view:
                    return view

        # do not check for 60 seconds
        request.session['last_password_reset_check'] = now
        return None

    def check_required_on_login_attribute_restriction(self, request, user):
        # do not bother superuser with this
        if user.is_superuser:
            return None

        if user.ou and not user.ou.check_required_on_login_attributes:
            return None

        missing = user.get_missing_required_on_login_attributes()
        if missing:
            return 'profile_required_edit'
        return None

    def check_password_reset_view_restriction(self, request, user):
        # If user is authenticated and a password_reset_flag is set, force
        # redirect to password change and show a message.
        from . import models

        if (
            user.is_authenticated
            and isinstance(user, Model)
            and models.PasswordReset.objects.filter(user=request.user).exists()
        ):
            if request.resolver_match.url_name != 'password_change':
                messages.warning(request, _('You must change your password to continue'))
            return 'password_change'

    def process_view(self, request, view_func, view_args, view_kwargs):
        '''If current view is not the one where we should be, redirect'''
        view_flag = getattr(view_func, 'enable_view_restriction', False)
        if not view_flag:
            return

        view = self.check_view_restrictions(request)
        if not view:
            if 'view_restriction' in request.session:
                del request.session['view_restriction']
            return
        request.session['view_restriction'] = True

        url_name = request.resolver_match.url_name

        # do not block on the restricted view
        if url_name == view:
            return
        response = utils_misc.redirect_and_come_back(request, view)
        if view_flag == 'check':
            request.view_restriction_response = response
            return
        return response


class XForwardedForMiddleware(MiddlewareMixin):
    """Copy the first address from X-Forwarded-For header to the REMOTE_ADDR meta.

    This middleware should only be used if you are sure the header cannot be
    forged (behind a reverse proxy for example)."""

    def process_request(self, request):
        if 'x-forwarded-for' in request.headers:
            request.META['REMOTE_ADDR'] = request.headers['X-Forwarded-For'].split(',')[0].strip()


class DisplayMessageBeforeRedirectMiddleware(MiddlewareMixin):
    """Verify if messages are currently stored and if there is a redirection to another domain, in
    this case show an intermediate page.
    """

    def process_response(self, request, response):
        # Check if response is a redirection
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        # Check if location is to another domain
        url = response['Location']
        if not url:
            return response
        if not getattr(response, 'display_message', True):
            return response
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme and not parsed_url.netloc:
            return response
        parsed_request_url = urllib.parse.urlparse(request.build_absolute_uri())
        if (parsed_request_url.scheme == parsed_url.scheme or not parsed_url.scheme) and (
            parsed_request_url.netloc == parsed_url.netloc
        ):
            return response
        # Check if there is some messages to show
        storage = messages.get_messages(request)
        if not storage:
            return response
        new_response = utils_misc.redirect(
            request, 'continue', resolve=True, next_url=url, sign_next_url=True
        )
        if len(response.cookies):
            new_response.cookies = response.cookies
        return new_response


class ServiceAccessControlMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        if not isinstance(exception, (utils_misc.ServiceAccessDenied,)):
            return None
        return utils_misc.unauthorized_view(request, exception.service)


class CookieTestMiddleware(MiddlewareMixin):
    COOKIE_NAME = 'cookie-test'

    @classmethod
    def check(cls, request):
        return cls.COOKIE_NAME in request.COOKIES

    def process_response(self, request, response):
        if not self.check(request):
            # set test cookie for 1 year
            response.set_cookie(
                self.COOKIE_NAME,
                '1',
                max_age=365 * 24 * 3600,
                secure=settings.SESSION_COOKIE_SECURE,
                httponly=True,
                samesite='Lax',
            )
        return response


def journal_middleware(get_response):
    from . import journal

    def middleware(request):
        request.journal = journal.Journal(request=request)
        return get_response(request)

    return middleware


def null_character_middleware(get_response):
    def middleware(request):
        def check_query_dict(qd):
            for key in qd:
                for value in qd.getlist(key):
                    if '\0' in value:
                        return False
            return True

        if not check_query_dict(request.GET):
            return http.HttpResponseBadRequest('null character in query string')

        if request.content_type == 'application/x-www-form-urlencoded':
            if not check_query_dict(request.POST):
                return http.HttpResponseBadRequest('null character in form data')

        return get_response(request)

    return middleware
