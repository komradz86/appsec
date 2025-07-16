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


import json
import logging
import uuid
from functools import wraps

from django.contrib import messages
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import NON_FIELD_ERRORS, ValidationError
from django.core.validators import validate_slug
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from authentic2.a2_rbac.models import Operation, OrganizationalUnit, Permission, Role, RoleParenting
from authentic2.a2_rbac.utils import get_default_ou
from authentic2.decorators import errorcollector
from authentic2.utils.lazy import lazy_join


def update_model(obj, d):
    for attr, value in d.items():
        setattr(obj, attr, value)
    errors = {}
    with errorcollector(errors):
        if hasattr(obj, 'validate'):
            obj.validate()

    with errorcollector(errors):
        if hasattr(obj, 'validate_unique'):
            obj.validate_unique()
    if errors:
        errorlist = []
        for key, messages in list(errors.items()):
            if key == NON_FIELD_ERRORS:
                errorlist.extend(messages)
            else:
                value = getattr(obj, key)

                def error_list(messages):
                    for message in messages:
                        if isinstance(message, ValidationError):
                            yield message.message
                        else:
                            yield message

                for message in error_list(messages):
                    errorlist.append(
                        format_lazy(
                            '{}="{}": {}', obj.__class__._meta.get_field(key).verbose_name, value, message
                        )
                    )
        raise ValidationError(errorlist)
    obj.save()


class ExportContext:
    _role_qs = None
    _ou_qs = None
    export_roles = None
    export_ous = None

    def __init__(self, role_qs=None, ou_qs=None, export_roles=True, export_ous=True):
        self._role_qs = role_qs
        self._ou_qs = ou_qs
        self.export_roles = export_roles
        self.export_ous = export_ous

    @property
    def role_qs(self):
        return self._role_qs or Role.objects.all()

    @property
    def ou_qs(self):
        return self._ou_qs or OrganizationalUnit.objects.all()


def export_site(context=None):
    context = context or ExportContext()
    d = {}
    if context.export_roles:
        d['roles'] = export_roles(context)
    if context.export_ous:
        d['ous'] = export_ous(context)
    return d


def export_ous(context):
    return [ou.export_json() for ou in context.ou_qs]


def export_roles(context):
    """Serialize roles in role_queryset"""
    return [role.export_json(parents=True, permissions=True) for role in context.role_qs]


def search_ou(ou_d):
    try:
        OU = OrganizationalUnit
        return OU.objects.get_by_natural_key_json(ou_d)
    except OU.DoesNotExist:
        return None


def search_role(role_d, ou=None):
    try:
        role = Role.objects.get_by_natural_key_json(role_d)
    except (Role.DoesNotExist, Role.MultipleObjectsReturned):
        return None
    else:
        if ou and role.ou != ou:
            # Allow creation of the role in a different OU
            role_d.pop('uuid')
            return None
        return role


class ImportContext:
    """Holds information on how to perform the import.

    ou_delete_orphans: if True any existing ou that is not found in the export will
                       be deleted

    role_delete_orphans: if True any existing role that is not found in the export will
                         be deleted


    role_attributes_update: legacy, for each role in the import data,
                            attributes will deleted and re-created


    role_parentings_update: for each role in the import data,
                            parentings will deleted and re-created

    role_permissions_update: for each role in the import data,
                             permissions will deleted and re-created
    """

    def __init__(
        self,
        *,
        import_roles=True,
        import_ous=True,
        role_delete_orphans=False,
        role_parentings_update=True,
        role_permissions_update=True,
        role_attributes_update=True,
        ou_delete_orphans=False,
        set_ou=None,
        allowed_ous=None,
        set_absent_ou_to_default=None,
        request=None,
    ):
        self.import_roles = import_roles
        self.import_ous = import_ous
        self.role_delete_orphans = role_delete_orphans
        self.ou_delete_orphans = ou_delete_orphans
        self.role_parentings_update = role_parentings_update
        self.role_permissions_update = role_permissions_update
        self.role_attributes_update = role_attributes_update
        self.set_ou = set_ou
        self.allowed_ous = allowed_ous
        self.set_absent_ou_to_default = set_absent_ou_to_default
        self.request = request


def wraps_validationerror(func):
    @wraps(func)
    def f(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except ValidationError as e:
            raise ValidationError(
                _('Role "%(name)s": %(errors)s')
                % {
                    'name': self._role_d.get('name', self._role_d.get('slug')),
                    'errors': lazy_join(', ', [v.message for v in e.error_list]),
                }
            )

    return f


class RoleDeserializer:
    def __init__(self, d, import_context):
        self._import_context = import_context
        self._obj = None
        self._parents = None
        self._attributes = None
        self._permissions = None

        self._role_d = {}
        for key, value in d.items():
            if key == 'parents':
                self._parents = value
            elif key == 'attributes':
                self._attributes = value
            elif key == 'permissions':
                self._permissions = value
            else:
                self._role_d[key] = value

    @wraps_validationerror
    def deserialize(self):
        if self._import_context.set_ou:
            ou = self._import_context.set_ou
        elif 'ou' in self._role_d:
            ou_d = self._role_d['ou']
            has_ou = bool(ou_d)
            ou = None if not has_ou else search_ou(ou_d)
            if has_ou and not ou:
                raise ValidationError(_("Can't import role because missing Organizational Unit: %s") % ou_d)
            if self._import_context.allowed_ous and ou not in self._import_context.allowed_ous:
                raise ValidationError(
                    _("Can't import role because missing permissions on Organizational Unit: %s") % ou_d
                )
        elif self._import_context.set_absent_ou_to_default:
            ou = get_default_ou()
        else:
            name = self._role_d.get('name') or self._role_d.get('slug') or self._role_d.get('uuid')
            raise ValidationError(_('Missing Organizational Unit for role: %s') % name)

        obj = search_role(self._role_d, ou=self._import_context.set_ou)

        kwargs = self._role_d.copy()
        kwargs['ou'] = ou
        kwargs.pop('service', None)

        if 'uuid' in kwargs:
            if not isinstance(kwargs['uuid'], str):
                raise ValidationError(_("Cannot import role '%s' with invalid uuid") % kwargs.get('name'))
            try:
                uuid.UUID(kwargs['uuid'])
            except ValueError:
                raise ValidationError(_("Cannot import role '%s' with invalid uuid") % kwargs.get('name'))

        if 'slug' in kwargs:
            if not isinstance(kwargs['slug'], str):
                raise ValidationError(_("Cannot import role '%s' with invalid slug") % kwargs.get('name'))
            try:
                validate_slug(kwargs['slug'])
            except ValidationError:
                raise ValidationError(_("Cannot import role '%s' with invalid slug") % kwargs.get('name'))

        if obj:  # Role already exist
            self._obj = obj
            status = 'updated'
            update_model(self._obj, kwargs)
        else:  # Create role
            if 'uuid' in kwargs and not kwargs['uuid']:
                raise ValidationError(_("Cannot import role '%s' with empty uuid") % kwargs.get('name'))
            self._obj = Role.objects.create(**kwargs)
            status = 'created'

        # Ensure admin role is created.
        # Absoluteley necessary to create
        # parentings relationship later on,
        # since we don't deserialize technical role.
        self._obj.get_admin_role()
        return self._obj, status

    @wraps_validationerror
    def attributes(self):
        """Compatibility with old import files, set Role fields using attributes data"""
        created, deleted = [], []
        # Create attributes
        if self._attributes:
            for attr_dict in self._attributes:
                setattr(self._obj, attr_dict['name'], json.loads(attr_dict['value']))

        return created, deleted

    @wraps_validationerror
    def parentings(self):
        """Update parentings (delete everything then create)"""
        created, deleted = [], []
        for parenting in RoleParenting.objects.filter(child=self._obj, direct=True):
            parenting.delete()
            deleted.append(parenting)

        if self._parents:
            for parent_d in self._parents:
                parent = search_role(parent_d)
                if not parent:
                    raise ValidationError(_('Could not find parent role: %s') % parent_d)
                created.append(RoleParenting.objects.create(child=self._obj, direct=True, parent=parent))

        return created, deleted

    @wraps_validationerror
    def permissions(self):
        """Update permissions (delete everything then create)"""
        created, deleted = [], []
        for perm in self._obj.permissions.all():
            perm.delete()
            deleted.append(perm)
        self._obj.permissions.clear()
        if self._permissions:
            for perm in self._permissions:
                op = Operation.objects.get_by_natural_key_json(perm['operation'])
                ou = OrganizationalUnit.objects.get_by_natural_key_json(perm['ou']) if perm['ou'] else None
                ct = ContentType.objects.get_by_natural_key_json(perm['target_ct'])
                target = ct.model_class().objects.get_by_natural_key_json(perm['target'])
                perm = Permission.objects.create(operation=op, ou=ou, target_ct=ct, target_id=target.pk)
                self._obj.permissions.add(perm)
                created.append(perm)

        return created, deleted


class ImportResult:
    def __init__(self):
        self.roles = {'created': [], 'updated': []}
        self.ous = {'created': [], 'updated': []}
        self.attributes = {'created': [], 'deleted': []}
        self.parentings = {'created': [], 'deleted': []}
        self.permissions = {'created': [], 'deleted': []}

    def update_roles(self, role, d_status):
        self.roles[d_status].append(role)

    def update_ous(self, ou, status):
        self.ous[status].append(ou)

    def _bulk_update(self, attrname, created, deleted):
        attr = getattr(self, attrname)
        attr['created'].extend(created)
        attr['deleted'].extend(deleted)

    def update_attributes(self, created, deleted):
        self._bulk_update('attributes', created, deleted)

    def update_parentings(self, created, deleted):
        self._bulk_update('parentings', created, deleted)

    def update_permissions(self, created, deleted):
        self._bulk_update('permissions', created, deleted)

    def to_str(self, verbose=False):
        res = ''
        for attr in ('roles', 'ous', 'parentings', 'permissions', 'attributes'):
            data = getattr(self, attr)
            for status in ('created', 'updated', 'deleted'):
                if status in data:
                    s_data = data[status]
                    res += '%s %s %s\n' % (len(s_data), attr, status)
        return res


def import_ou(ou_d, request=None):
    OU = OrganizationalUnit
    ou = search_ou(ou_d)
    if ou is None:
        logger = logging.getLogger(__name__)
        if ou_d.get('default'):
            if request:
                messages.warning(
                    request,
                    _("New organizational unit {} can't be set as default.").format(
                        ou_d.get('name') or ou_d.get.get('slug', '')
                    ),
                )
            logger.warning(
                'new organizational unit %s can\'t be set as default',
                ou_d.get('name') or ou_d.get.get('slug', ''),
            )
            ou_d['default'] = False
        ou = OU.objects.create(**ou_d)
        status = 'created'
    else:
        update_model(ou, ou_d)
        status = 'updated'
    # Ensure admin role is created
    ou.get_admin_role()
    return ou, status


def import_site(json_d, import_context=None):
    import_context = import_context or ImportContext()
    result = ImportResult()

    if not isinstance(json_d, dict):
        raise ValidationError(_('Import file is invalid: not a dictionnary'))

    if import_context.import_ous:
        for ou_d in json_d.get('ous', []):
            result.update_ous(*import_ou(ou_d, request=import_context.request))

    if import_context.import_roles:
        roles_ds = []
        for role_d in json_d.get('roles', []):
            # ignore internal roles
            slug = role_d.get('slug')
            if isinstance(slug, str) and slug.startswith('_'):
                continue
            roles_ds.append(RoleDeserializer(role_d, import_context))

        for ds in roles_ds:
            result.update_roles(*ds.deserialize())

        if import_context.role_attributes_update:
            for ds in roles_ds:
                result.update_attributes(*ds.attributes())

        if import_context.role_parentings_update:
            for ds in roles_ds:
                result.update_parentings(*ds.parentings())

        if import_context.role_permissions_update:
            for ds in roles_ds:
                result.update_permissions(*ds.permissions())

        if import_context.ou_delete_orphans:
            raise ValidationError(
                _('Unsupported context value for ou_delete_orphans : %s') % (import_context.ou_delete_orphans)
            )

        if import_context.role_delete_orphans:
            # FIXME : delete each role that is in DB but not in the export
            raise ValidationError(
                _('Unsupported context value for role_delete_orphans : %s')
                % (import_context.role_delete_orphans)
            )

    return result
