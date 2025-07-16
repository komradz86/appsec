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

from . import app_settings, constants
from .models import Setting
from .utils import misc as utils_misc
from .utils.service import get_home_url, get_service


class UserFederations:
    '''Provide access to all federations of the current user'''

    def __init__(self, request):
        self.request = request

    def __getattr__(self, name):
        d = {'provider': None, 'links': []}
        if name.startswith('service_'):
            try:
                provider_id = int(name.split('_', 1)[1])
            except ValueError:
                pass
            else:
                links = utils_misc.accumulate_from_backends(self.request, 'links')
                for provider, link in links:
                    if provider.id != provider_id:
                        continue
                    d['provider'] = provider
                    d['links'].append(link)
            return d
        return super().__getattr__(name)


def a2_processor(request):
    variables = {}
    variables.update(app_settings.TEMPLATE_VARS)
    variables['federations'] = UserFederations(request)
    if hasattr(request, 'session'):
        variables['LAST_LOGIN'] = request.session.get(constants.LAST_LOGIN_SESSION_KEY)
        variables['USER_SWITCHED'] = constants.SWITCH_USER_SESSION_KEY in request.session
        if service := get_service(request):
            variables['service'] = service
            variables['service_colour'] = service.colour
            if service.logo:
                variables['service_logo_url'] = service.logo.url
            if service.ou:
                variables['service_ou_colour'] = service.ou.colour
                if service.ou.logo:
                    variables['service_ou_logo_url'] = service.ou.logo.url
            if type(service).__name__ == 'LibertyProvider':
                # generic appearance settings for SAML services
                sso_settings = Setting.objects.filter_namespace('sso')
                if any(sso_settings.values_list('value', flat=True)):
                    for setting in sso_settings:
                        variables[setting.key.split(':')[-1]] = setting.value
                    variables['show_service_infos'] = True
                    variables['service_custom_appearance'] = True
            else:
                if any([service.colour, service.logo, service.ou.colour, service.ou.logo]):
                    # client specific appearence for third-party OIDC services
                    variables['service_custom_appearance'] = True
                variables['show_service_infos'] = True
    return variables


def home(request):
    if not hasattr(request, 'session'):
        # pure WSGIRequest, most probably happening for a request to a non-existant tenant.
        return {}
    ctx = {}
    service = get_service(request)
    if service:
        ctx['home_service'] = service
        if service.ou:
            ctx['home_ou'] = service.ou
    ctx['home_url'] = get_home_url(request)
    return ctx


def constant_aliases(request):
    '''Provides aliases for true false & null matching python's values
    True False & None'''
    return {'true': True, 'false': False, 'null': None}
