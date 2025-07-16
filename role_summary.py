# authentic2 - versatile identity manager
# Copyright (C) 2010-2023 Entr'ouvert
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

import json
import logging
import os.path
import urllib

import requests
from atomicwrites import AtomicWriter
from django.conf import settings
from django.db import connection
from django.utils.translation import gettext as _

from .a2_rbac.models import Role

try:
    from hobo.requests_wrapper import Requests
except ImportError:  # fallback on python requests, no Publik signature
    from requests.sessions import Session as Requests  # pylint: disable=ungrouped-imports

logger = logging.getLogger(__name__)


def build_roles_summary_cache():
    def _requests(url):
        logger.debug('role-summary: retrieving url %s', url)
        try:
            resp = Requests().get(url=url, timeout=settings.REQUESTS_TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.debug('role-summary: error %s', e)
            return []
        try:
            json_data = resp.json()
        except (json.JSONDecodeError, requests.exceptions.RequestException) as e:
            logger.debug('role-summary: error %s', e)
            return []
        if json_data.get('err', 0) != 0:
            logger.debug('role-summary: error %s', json_data)
            return []
        logger.debug('role-summary: response %s', json_data)
        return json_data.get('data', [])

    role_cache_data = {}
    for role in Role.objects.all():
        role_cache_data[role.uuid] = {
            'slug': role.slug,
            'name': role.name,
            'parents': {
                parent.uuid for parent in role.parents(include_self=False, annotate=False, direct=None)
            },
        }

    try:
        services = settings.KNOWN_SERVICES
    except AttributeError:
        services = {}

    data = {}
    for service_type, services in settings.KNOWN_SERVICES.items():
        if service_type == 'authentic':
            continue
        for service_data in services.values():
            url = urllib.parse.urljoin(service_data['url'], 'api/export-import/')
            for type_object in _requests(url):
                for object in _requests(type_object['urls']['list']):
                    if 'dependencies' not in object['urls']:
                        continue
                    for dep in _requests(object['urls']['dependencies']):
                        if dep['type'] != 'roles':
                            continue
                        dep_uuid = dep['uuid']
                        for role_uuid, role_data in role_cache_data.items():
                            if dep_uuid != role_uuid and dep_uuid not in role_data['parents']:
                                continue
                            if role_uuid not in data:
                                data[role_uuid] = {
                                    'slug': role_data['slug'],
                                    'name': role_data['name'],
                                    'parents': [parent for parent in role_data['parents']],
                                    'type_objects': [],
                                    'parents_type_objects': [],
                                }
                            match_key = 'type_objects' if dep_uuid == role_uuid else 'parents_type_objects'
                            if (
                                not data[role_uuid][match_key]
                                or data[role_uuid][match_key][-1]['id'] != type_object['id']
                            ):
                                type_object_copy = type_object.copy()
                                type_object_copy['hit'] = []
                                data[role_uuid][match_key].append(type_object_copy)
                            if object not in data[role_uuid][match_key][-1]['hit']:
                                data[role_uuid][match_key][-1]['hit'].append(object)

    return data


def get_roles_summary_cache_path():
    try:
        tenant_dir = connection.tenant.get_directory()
    except AttributeError:
        return
    return os.path.join(tenant_dir, 'roles-summary.json')


def get_roles_summary_cache():
    try:
        path = get_roles_summary_cache_path()
        if not path or not os.path.exists(path):
            return {}
        with open(path) as fd:
            roles_summary_cache = json.load(fd)
    except Exception as e:
        logger.exception('failed to load role summary cache')
        roles_summary_cache = {'error': _('Loading of roles summary cache failed: %s') % e}
    return roles_summary_cache


def write_roles_summary_cache():
    try:
        path = get_roles_summary_cache_path()
        if not path:
            return
        roles_summary_cache = build_roles_summary_cache()
    except Exception as e:
        logger.exception('failed to build role summary cache')
        roles_summary_cache = get_roles_summary_cache()
        roles_summary_cache['error'] = _('Building of roles summary cache failed: %s') % e

    try:
        with AtomicWriter(path, mode='w', overwrite=True).open() as fd:
            json.dump(roles_summary_cache, fd, indent=2)
    except Exception:
        logger.exception('failed to build role summary cache')
