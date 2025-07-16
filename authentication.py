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

import inspect

try:
    from django.utils.deprecation import CallableTrue
except ImportError:
    CallableTrue = True

from rest_framework.authentication import BasicAuthentication
from rest_framework.exceptions import AuthenticationFailed

from authentic2.models import APIClient
from authentic2_idp_oidc.models import OIDCClient


class OIDCUser:
    """Fake user class to return in case OIDC authentication"""

    def __init__(self, oidc_client):
        self.oidc_client = oidc_client
        self.authenticated = False

    def has_perm(self, *args, **kwargs):
        return True

    def has_perm_any(self, *args, **kwargs):
        return True

    def has_ou_perm(self, *args, **kwargs):
        return True

    def filter_by_perm(self, perms, queryset):
        return queryset

    @property
    def is_authenticated(self):
        return CallableTrue

    def __str__(self):
        return f'OIDC Client "{self.oidc_client}"'


class Authentic2Authentication(BasicAuthentication):
    def authenticate_credentials(self, userid, password, request=None):
        # try Simple OIDC Authentication
        try:
            client = OIDCClient.objects.get(client_id=userid, client_secret=password)
            if not client.has_api_access:
                raise AuthenticationFailed('OIDC client does not have access to the API')
            if client.identifier_policy not in (client.POLICY_UUID, client.POLICY_PAIRWISE_REVERSIBLE):
                raise AuthenticationFailed('OIDC Client identifier policy does not allow access to the API')
            user = OIDCUser(client)
            user.authenticated = True
            return (user, True)
        except OIDCClient.DoesNotExist:
            pass

        for api_client in APIClient.objects.by_identifier(userid):
            if not api_client.ip_authorized(request.META['REMOTE_ADDR']):
                continue
            if api_client.check_password(password):
                return api_client, None

        # try BasicAuthentication
        if 'request' in inspect.signature(super().authenticate_credentials).parameters:
            # compatibility with DRF 3.4
            return super().authenticate_credentials(userid, password, request=request)
        return super().authenticate_credentials(userid, password)
