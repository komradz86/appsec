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

from django.urls import include, path

from . import api_views

urlpatterns = [
    path('password-change/', api_views.password_change, name='a2-api-password-change'),
    path('user/', api_views.user, name='a2-api-user'),
    path(
        r'users/<user_uuid:user_uuid>/profiles/<slug:profile_type_slug>/',
        api_views.user_profiles,
        name='a2-api-user-profiles',
    ),
    path(
        'users/<user_uuid:user_uuid>/service/<slug:service_slug>/',
        api_views.user_service_data,
        name='a2-api-user-service-data',
    ),
    path('check-password/', api_views.check_password, name='a2-api-check-password'),
    path('check-api-client/', api_views.check_api_client, name='a2-api-check-api-client'),
    path('validate-password/', api_views.validate_password, name='a2-api-validate-password'),
    path('password-strength/', api_views.password_strength, name='a2-api-password-strength'),
    path('address-autocomplete/', api_views.address_autocomplete, name='a2-api-address-autocomplete'),
    path('authn-healthcheck/', api_views.authn_healthcheck, name='a2-api-authn-healthcheck'),
]

# other roles APIs
roles_urls = [
    path('members/', api_views.roles_members),
    path('members/<user_uuid:member_uuid>/', api_views.role_membership),
    path('relationships/members/', api_views.role_memberships),
    path('parents/', api_views.roles_parents),
    path('children/', api_views.roles_children),
    path('relationships/parents/', api_views.roles_parents_relationships),
]

urlpatterns += [
    path('roles/<a2_uuid:role_uuid>/', include(roles_urls)),
    path('roles/<slug:ou_slug>:<slug:service_slug>:<slug:role_slug>/', include(roles_urls)),
    path('roles/<slug:ou_slug>:<slug:role_slug>/', include(roles_urls)),
    path('roles/<slug:role_slug>/', include(roles_urls)),
]

# main router
urlpatterns += api_views.router.urls
