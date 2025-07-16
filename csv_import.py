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

import csv
import io

import attr
import phonenumbers
from chardet.universaldetector import UniversalDetector
from django import forms
from django.contrib.auth.hashers import identify_hasher
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.core.validators import RegexValidator
from django.db import IntegrityError, models
from django.db.transaction import atomic
from django.utils.encoding import force_bytes, force_str
from django.utils.timezone import now
from django.utils.translation import gettext as _

from authentic2 import app_settings
from authentic2.a2_rbac.models import Role
from authentic2.a2_rbac.utils import get_default_ou
from authentic2.apps.journal.journal import Journal
from authentic2.custom_user.models import User
from authentic2.forms.profile import BaseUserForm, modelform_factory
from authentic2.models import Attribute, AttributeValue, PasswordReset, UserExternalId
from authentic2.utils.misc import parse_phone_number, send_password_reset_mail


# http://www.attrs.org/en/stable/changelog.html :
# 19.2.0
# ------
# The cmp argument to attr.s() and attr.ib() is now deprecated.
# Please use eq to add equality methods (__eq__ and __ne__) and order to add
# ordering methods (__lt__, __le__, __gt__, and __ge__) instead - just like
# with dataclasses.
#
# DeprecationWarning: The usage of `cmp` is deprecated and will be removed on
# or after 2021-06-01.  Please use `eq` and `order` instead.
# description = attr.ib(default='', cmp=False)
#
def attrib(**kwargs):
    if [int(x) for x in attr.__version__.split('.')] >= [19, 2]:
        if 'cmp' in kwargs:
            kwargs['eq'] = kwargs['cmp']
            kwargs['order'] = kwargs['cmp']
            del kwargs['cmp']
    return attr.ib(**kwargs)


def attrs(func=None, **kwargs):
    if [int(x) for x in attr.__version__.split('.')] >= [19, 2]:
        if 'cmp' in kwargs:
            kwargs['eq'] = kwargs['cmp']
            kwargs['order'] = kwargs['cmp']
            del kwargs['cmp']
    if func is None:
        return attr.s(**kwargs)
    else:
        return attr.s(func, **kwargs)


class UTF8Recoder:
    def __init__(self, fd):
        self.fd = fd

    def __iter__(self):
        return self

    def __next__(self):
        return force_str(self.fd.__next__().encode('utf-8'))

    next = __next__


class UnicodeReader:
    def __init__(self, fd, dialect='excel', **kwargs):
        self.reader = csv.reader(UTF8Recoder(fd), dialect=dialect, **kwargs)

    def __next__(self):
        row = self.reader.__next__()
        return [force_bytes(s).decode('utf-8') for s in row]

    def __iter__(self):
        return self

    next = __next__


class CsvImporter:
    rows = None
    error = None
    error_description = None
    encoding = None

    def run(self, fd_or_str, encoding):
        if isinstance(fd_or_str, bytes):
            input_fd = io.BytesIO(fd_or_str)
        elif isinstance(fd_or_str, str):
            input_fd = io.StringIO(fd_or_str)
        elif not hasattr(fd_or_str, 'read1'):
            try:
                # pylint: disable=consider-using-with
                input_fd = open(fd_or_str.fileno(), closefd=False, mode='rb')
            except Exception:
                try:
                    fd_or_str.seek(0)
                except Exception:
                    pass
                content = fd_or_str.read()
                if isinstance(content, str):
                    input_fd = io.StringIO(content)
                else:
                    input_fd = io.BytesIO(content)
        else:
            input_fd = fd_or_str

        assert hasattr(input_fd, 'read'), 'fd_or_str is not a string or a file object'

        def set_encoding(input_fd, encoding):
            # detect StringIO
            if hasattr(input_fd, 'line_buffering'):
                return input_fd

            if encoding == 'detect':
                detector = UniversalDetector()

                try:
                    for line in input_fd:
                        detector.feed(line)
                        if detector.done:
                            break
                    else:
                        self.error = Error('cannot-detect-encoding', _('Cannot detect encoding'))
                        return None
                    detector.close()
                    encoding = detector.result['encoding']
                finally:
                    input_fd.seek(0)

            if not hasattr(input_fd, 'readable'):
                # pylint: disable=consider-using-with
                input_fd = open(input_fd.fileno(), 'rb', closefd=False)
            return io.TextIOWrapper(input_fd, encoding=encoding)

        def parse_csv(input_fd):
            try:
                content = force_str(input_fd.read().encode('utf-8'))
            except UnicodeDecodeError:
                self.error = Error('bad-encoding', _('Bad encoding'))
                return False
            try:
                dialect = csv.Sniffer().sniff(content)
            except csv.Error as e:
                self.error = Error('unknown-csv-dialect', _('Unknown CSV dialect: %s') % e)
                return False
            finally:
                input_fd.seek(0)

            if not dialect:
                self.error = Error('unknown-csv-dialect', _('Unknown CSV dialect'))
                return False
            try:
                reader = UnicodeReader(input_fd, dialect)
                self.rows = list(reader)
            except (csv.Error, TypeError) as e:
                self.error = Error('csv-read-error', _('Cannot read CSV: %s') % e)
                return False
            return True

        with input_fd:
            final_input_fd = set_encoding(input_fd, encoding)
            if final_input_fd is None:
                return False
            return parse_csv(final_input_fd)


@attrs
class CsvHeader:
    column = attrib()
    name = attrib(default='')
    field = attrib(default=False, converter=bool)
    attribute = attrib(default=False, converter=bool)
    create = attrib(default=True, metadata={'flag': True})
    update = attrib(default=True, metadata={'flag': True})
    key = attrib(default=False, metadata={'flag': True})
    unique = attrib(default=False, metadata={'flag': True})
    globally_unique = attrib(default=False, metadata={'flag': True})
    verified = attrib(default=False, metadata={'flag': True})
    delete = attrib(default=False, metadata={'flag': True})
    clear = attrib(default=False, metadata={'flag': True})

    @property
    def flags(self):
        flags = []
        for attribute in attr.fields(self.__class__):
            if attribute.metadata.get('flag'):
                if getattr(self, attribute.name, attribute.default):
                    flags.append(attribute.name)
                else:
                    flags.append('no-' + attribute.name.replace('_', '-'))
        return flags


@attrs
class Error:
    code = attrib()
    description = attrib(default='', cmp=False)


@attrs(cmp=False)
class LineError(Error):
    line = attrib(default=0)
    column = attrib(default=0)

    @classmethod
    def from_error(cls, error):
        return cls(**attr.asdict(error))  # pylint: disable=not-a-mapping

    def as_error(self):
        return Error(self.code, self.description)

    def __eq__(self, other):
        if isinstance(other, Error):
            return self.as_error() == other
        return (self.code, self.line, self.column) == (other.code, other.line, other.column)


SOURCE_NAME = '_source_name'
SOURCE_ID = '_source_id'
SOURCE_COLUMNS = {SOURCE_NAME, SOURCE_ID}
ROLE_NAME = '_role_name'
ROLE_SLUG = '_role_slug'
PASSWORD_HASH = 'password_hash'
REGISTRATION = '@registration'
REGISTRATION_RESET_EMAIL = 'send-email'
FORCE_PASSWORD_RESET = '@force-password-reset'
SPECIAL_COLUMNS = SOURCE_COLUMNS | {ROLE_NAME, ROLE_SLUG, REGISTRATION, FORCE_PASSWORD_RESET, PASSWORD_HASH}


class ImportUserForm(BaseUserForm):
    locals()[ROLE_NAME] = forms.CharField(label=_('Role name'), required=False)
    locals()[ROLE_SLUG] = forms.CharField(label=_('Role slug'), required=False)
    choices = [
        (REGISTRATION_RESET_EMAIL, _('Email user so they can set a password')),
    ]
    locals()[REGISTRATION] = forms.ChoiceField(
        choices=choices, label=_('Registration option'), required=False
    )
    locals()[PASSWORD_HASH] = forms.CharField(label=_('Password hash'), required=False)
    locals()[FORCE_PASSWORD_RESET] = forms.BooleanField(label=_('Force password reset'), required=False)

    def clean(self):
        super(BaseUserForm, self).clean()
        self._validate_unique = False

    def clean_password_hash(self):
        password_hash = self.cleaned_data['password_hash']
        try:
            # first we look for a correct hasher…
            hasher = identify_hasher(password_hash)
        except ValueError:
            raise ValidationError(_('Unknown hashing algorithm.'))
        try:
            # …yet identifying a hasher doesn't prevent inconsistencies betweeen hashers and hash
            # format from happening, therefore a more thorough check has to be performed
            hasher.decode(password_hash)
        except ValueError:
            raise ValidationError(_('Invalid format for %s hasher') % hasher.algorithm)
        return password_hash

    class Meta:
        exclude = ('keepalive',)


class ImportUserFormWithExternalId(ImportUserForm):
    locals()[SOURCE_NAME] = forms.CharField(
        label=_('Source name'),
        required=False,
        validators=[
            RegexValidator(
                r'^[a-zA-Z0-9_-]+$',
                _('_source_name must contain no spaces and only letters, digits, - and _'),
                'invalid',
            )
        ],
    )
    locals()[SOURCE_ID] = forms.CharField(label=_('Source external id'))


@attrs
class CsvRow:
    line = attrib()
    cells = attrib(default=[])
    errors = attrib(default=[])
    is_valid = attrib(default=True)
    action = attrib(default=None)
    user_first_seen = attrib(default=True)

    def __getitem__(self, header):
        for cell in self.cells:
            if header in (cell.header, cell.header.name):
                return cell
        raise KeyError(header.name)

    ACTIONS = {
        'update': _('update'),
        'create': _('create'),
    }

    @property
    def action_display(self):
        return self.ACTIONS.get(self.action, self.action)

    @property
    def has_errors(self):
        return self.errors or self.has_cell_errors

    @property
    def has_cell_errors(self):
        return any(cell.errors for cell in self)

    def __iter__(self):
        return iter(self.cells)

    def __len__(self):
        return len(self.cells)


@attrs
class CsvCell:
    line = attrib()
    header = attrib()
    value = attrib(default=None)
    missing = attrib(default=False)
    errors = attrib(default=[])
    action = attrib(default=None)

    @property
    def column(self):
        return self.header.column


class Simulate(Exception):
    pass


class CancelImport(Exception):
    pass


class UserCsvImporter:
    csv_importer = None
    errors = None
    headers = None
    headers_by_name = None
    rows = None
    has_errors = False
    ou = None
    updated = 0
    created = 0
    rows_with_errors = 0
    _missing_roles = None

    def __init__(self, user_import_uuid, report_uuid, user=None):
        self.user = user
        self.import_uuid = user_import_uuid
        self.report_uuid = report_uuid
        self._journal = Journal(user=user)

    def __getstate__(self):
        state = self.__dict__.copy()
        # Do not pickle user or journal
        state.pop('user', None)
        state.pop('_journal', None)
        return state

    def add_error(self, line_error):
        if not hasattr(line_error, 'line'):
            line_error = LineError.from_error(line_error)
        self.errors.append(line_error)

    def run(self, fd_or_str, encoding, ou=None, simulate=False, progress_callback=None):
        self.ou = ou or get_default_ou()
        self.errors = []
        self._missing_roles = set()
        self.csv_importer = CsvImporter()
        self.max_user_id = User.objects.aggregate(max=models.Max('id'))['max'] or -1
        self.simulate = simulate
        self.record_run(_('import started'))

        def parse_csv():
            if not self.csv_importer.run(fd_or_str, encoding):
                self.add_error(self.csv_importer.error)

        def do_import():
            unique_map = {}

            try:
                with atomic():
                    for i, row in enumerate(self.rows):
                        if progress_callback:
                            progress_callback(_('importing'), i, len(self.rows))
                        try:
                            if not self.do_import_row(row, unique_map):
                                self.rows_with_errors += 1
                                row.is_valid = False
                        except CancelImport:
                            self.rows_with_errors += 1
                        if row.errors or not row.is_valid:
                            self.has_errors = True
                    if simulate:
                        raise Simulate
            except Simulate:
                pass

        def parse_rows():
            self.parse_rows(progress_callback)

        for action in [parse_csv, self.parse_header_row, parse_rows, do_import]:
            action()
            if self.errors:
                break

        self.record_run(_('import ended'))

        self.has_errors = self.has_errors or bool(self.errors)
        return not bool(self.errors)

    def parse_header_row(self):
        self.headers = []
        self.headers_by_name = {}

        try:
            header_row = self.csv_importer.rows[0]
        except IndexError:
            self.add_error(Error('no-header-row', _('Missing header row')))
            return

        for i, head in enumerate(header_row):
            self.parse_header(head, column=i + 1)

        if not self.headers:
            self.add_error(Error('empty-header-row', _('Empty header row')))
            return

        key_counts = sum(1 for header in self.headers if header.key)

        if not key_counts:
            if self.email_is_unique and 'email' in self.headers_by_name:
                self.headers_by_name['email'].key = True
            elif self.username_is_unique and 'username' in self.headers_by_name:
                self.headers_by_name['username'].key = True
            else:
                self.add_error(Error('missing-key-column', _('Missing key column')))
        if key_counts > 1:
            self.add_error(Error('too-many-key-columns', _('Too many key columns')))

        header_names = set(self.headers_by_name)
        if header_names & SOURCE_COLUMNS and not SOURCE_COLUMNS.issubset(header_names):
            self.add_error(
                Error('invalid-external-id-pair', _('You must have a _source_name and a _source_id column'))
            )
        if ROLE_NAME in header_names and ROLE_SLUG in header_names:
            self.add_error(
                Error('invalid-role-column', _('Either specify role names or role slugs, not both'))
            )

    def parse_header(self, head, column):
        splitted = head.split()
        try:
            header = CsvHeader(column, splitted[0])
            if header.name in self.headers_by_name:
                self.add_error(Error('duplicate-header', _('Header "%s" is duplicated') % header.name))
                return
            self.headers_by_name[header.name] = header
        except IndexError:
            header = CsvHeader(column)
        else:
            if header.name in SOURCE_COLUMNS:
                if header.name == SOURCE_ID:
                    header.key = True
            elif header.name not in SPECIAL_COLUMNS:
                try:
                    if header.name in ['email', 'first_name', 'last_name', 'username']:
                        User._meta.get_field(header.name)
                        header.field = True
                        if header.name == 'email':
                            # by default email are expected to be verified
                            header.verified = True
                        if header.name == 'email' and self.email_is_unique:
                            header.unique = True
                            if app_settings.A2_EMAIL_IS_UNIQUE:
                                header.globally_unique = True
                        if header.name == 'username' and self.username_is_unique:
                            header.unique = True
                            if app_settings.A2_USERNAME_IS_UNIQUE:
                                header.globally_unique = True
                except FieldDoesNotExist:
                    pass
                if not header.field:
                    try:
                        Attribute.objects.get(name=header.name)
                        header.attribute = True
                    except Attribute.DoesNotExist:
                        pass

        self.headers.append(header)

        if not (header.field or header.attribute) and header.name not in SPECIAL_COLUMNS:
            self.add_error(
                LineError(
                    'unknown-or-missing-attribute',
                    _('unknown or missing attribute "%s"') % head,
                    line=1,
                    column=column,
                )
            )
            return

        for flag in splitted[1:]:
            if header.name in SOURCE_COLUMNS:
                self.add_error(
                    LineError(
                        'flag-forbidden-on-source-columns',
                        _('You cannot set flags on _source_name and _source_id columns'),
                        line=1,
                    )
                )
                break
            value = True
            if flag.startswith('no-'):
                value = False
                flag = flag[3:]
            flag = flag.replace('-', '_')
            try:
                if not getattr(attr.fields(CsvHeader), flag).metadata['flag']:
                    raise TypeError
                setattr(header, flag, value)
            except (AttributeError, TypeError, KeyError):
                self.add_error(LineError('unknown-flag', _('unknown flag "%s"'), line=1, column=column))

    def parse_rows(self, progress_callback=None):
        base_form_class = ImportUserForm
        if SOURCE_NAME in self.headers_by_name:
            base_form_class = ImportUserFormWithExternalId
        form_class = modelform_factory(User, fields=self.headers_by_name.keys(), form=base_form_class)
        rows = self.rows = []
        for i, row in enumerate(self.csv_importer.rows[1:]):
            if progress_callback:
                progress_callback(_('parsing'), i, len(self.csv_importer.rows))
            if not row:
                # ignore empy lines
                continue
            csv_row = self.parse_row(form_class, row, line=i + 2)
            self.has_errors = self.has_errors or not (csv_row.is_valid)
            rows.append(csv_row)

    def parse_row(self, form_class, row, line):
        data = {}
        errors = {}
        for header in self.headers:
            value = row[header.column - 1]

            data[header.name] = value.strip()

            try:
                attr = Attribute.objects.get(name=header.name)
            except Attribute.DoesNotExist:
                pass
            else:
                if attr.kind == 'phone_number' and (attr.required or data[header.name]):
                    pn = parse_phone_number(data[header.name])
                    if pn:
                        # fill multi value field
                        data['%s_0' % header.name] = str(pn.country_code)
                        data['%s_1' % header.name] = phonenumbers.format_number(
                            pn, phonenumbers.PhoneNumberFormat.NATIONAL
                        )
                        data.pop(header.name)
                    else:
                        # E.164 compliant parsing failed, leave the number untouched, add an error
                        errors.update({header.name: [_('Enter a valid phone number.')]})

        form = form_class(data=data)
        form.errors.update(errors)
        form.is_valid()

        def get_form_errors(form, name):
            return [Error('data-error', str(value)) for value in form.errors.get(name, [])]

        cells = [
            CsvCell(
                line=line,
                header=header,
                value=form.cleaned_data.get(header.name),
                missing=header.name not in data,
                errors=get_form_errors(form, header.name),
            )
            for header in self.headers
        ]
        cell_errors = any(bool(cell.errors) for cell in cells)
        errors = get_form_errors(form, '__all__')
        return CsvRow(line=line, cells=cells, errors=errors, is_valid=not bool(cell_errors or errors))

    @property
    def email_is_unique(self):
        return app_settings.A2_EMAIL_IS_UNIQUE or self.ou.email_is_unique

    @property
    def username_is_unique(self):
        return app_settings.A2_USERNAME_IS_UNIQUE or self.ou.username_is_unique

    @property
    def allow_duplicate_key(self):
        return ROLE_NAME in self.headers_by_name or ROLE_SLUG in self.headers_by_name

    @property
    def missing_roles(self):
        return sorted(self._missing_roles or [])

    def check_unique_constraints(self, row, unique_map, user=None):
        ou_users = User.objects.filter(ou=self.ou)
        # ignore new users
        users = User.objects.exclude(id__gt=self.max_user_id)
        if user:
            users = users.exclude(pk=user.pk)
            ou_users = ou_users.exclude(pk=user.pk)
        errors = []
        for cell in row:
            header = cell.header
            if header.name == SOURCE_ID:
                unique_key = (SOURCE_ID, row[SOURCE_NAME].value, cell.value)
            elif header.key or header.globally_unique or header.unique:
                if not cell.value:
                    # empty values are not checked
                    continue
                unique_key = (header.name, cell.value)
            else:
                continue
            if unique_key in unique_map:
                if user and self.allow_duplicate_key:
                    row.user_first_seen = False
                else:
                    errors.append(
                        Error(
                            'unique-constraint-failed',
                            _(
                                'Unique constraint on column "%(column)s" failed: value already appear on'
                                ' line %(line)d'
                            )
                            % {'column': header.name, 'line': unique_map[unique_key]},
                        )
                    )
            else:
                unique_map[unique_key] = row.line

        for cell in row:
            if (not cell.header.globally_unique and not cell.header.unique) or (
                user and not cell.header.update
            ):
                continue
            if not cell.value:
                continue
            qs = ou_users
            if cell.header.globally_unique:
                qs = users
            if cell.header.field:
                unique = not qs.filter(**{cell.header.name: cell.value}).exists()
            elif cell.header.attribute:
                atvs = AttributeValue.objects.filter(attribute__name=cell.header.name, content=cell.value)
                unique = not qs.filter(attribute_values__in=atvs).exists()
            if not unique:
                if user and self.allow_duplicate_key:
                    row.user_first_seen = False
                else:
                    errors.append(
                        Error(
                            'unique-constraint-failed',
                            _('Unique constraint on column "%s" failed') % cell.header.name,
                        )
                    )
        row.errors.extend(errors)
        row.is_valid = row.is_valid and not bool(errors)
        return not bool(errors)

    @atomic
    def do_import_row(self, row, unique_map):
        if not row.is_valid:
            return False
        success = True

        for header in self.headers:
            if header.key:
                header_key = header
                break
        else:
            assert False, 'should not happen'

        user = None
        if header_key.name == SOURCE_ID:
            # lookup by external id
            source_name = row[SOURCE_NAME].value
            source_id = row[SOURCE_ID].value
            userexternalids = UserExternalId.objects.filter(source=source_name, external_id=source_id)
            users = User.objects.filter(userexternalid__in=userexternalids)[:2]
        else:
            # lookup by field/attribute
            key_value = row[header_key].value
            if header_key.field:
                if header_key.name == 'email':
                    # use specific lookup logic for email, to be
                    # case-insensitive and prevent unicode shenanigans
                    # also strip() value to prevent duplicates
                    users = User.objects.filter(ou=self.ou).filter_by_email(email=key_value.strip())
                else:
                    users = User.objects.filter(ou=self.ou, **{header_key.name: key_value})
            elif header_key.attribute:
                atvs = AttributeValue.objects.filter(attribute__name=header_key.name, content=key_value)
                users = User.objects.filter(ou=self.ou, attribute_values__in=atvs)
            users = users[:2]

        if users:
            row.action = 'update'
        else:
            row.action = 'create'

        if len(users) > 1:
            row.errors.append(
                Error('key-matches-too-many-users', _('Key value "%s" matches too many users') % key_value)
            )
            return False

        user = None
        if users:
            user = users[0]

        if not self.check_unique_constraints(row, unique_map, user=user):
            return False
        if not row.user_first_seen:
            cell = next(c for c in row.cells if c.header.name in {ROLE_NAME, ROLE_SLUG})
            return self.add_role(cell, user)

        if not user:
            user = User(ou=self.ou)
            user.set_random_password()
            self.record(_('create'), user)

        for cell in row.cells:
            if not cell.header.field:
                continue
            if (row.action == 'create' and cell.header.create) or (
                row.action == 'update' and cell.header.update
            ):
                value = cell.value
                if cell.header.name == 'email':
                    value = value.strip()
                if getattr(user, cell.header.name) != cell.value:
                    setattr(user, cell.header.name, value)
                    self.record(_('update property'), user, cell.header.name, value)
                    if cell.header.name == 'email' and cell.header.verified:
                        user.set_email_verified(True, source='csv')
                        self.record(_('set email verified'), user)
                    if cell.header.name == 'phone' and cell.header.verified:
                        user.phone_verified_on = now()
                        self.record(_('set phone verified'), user)
                    cell.action = 'updated'
                    continue
            cell.action = 'nothing'

        user.save()

        if header_key.name == SOURCE_ID and row.action == 'create':
            try:
                UserExternalId.objects.create(user=user, source=source_name, external_id=source_id)
            except IntegrityError:
                # should never happen since we have a unique index...
                source_full_id = '%s.%s' % (source_name, source_id)
                row.errors.append(
                    Error('external-id-already-exist', _('External id "%s" already exists') % source_full_id)
                )
                raise CancelImport

        for cell in row.cells:
            if cell.header.field or not cell.header.attribute:
                continue
            if (row.action == 'create' and cell.header.create) or (
                row.action == 'update' and cell.header.update
            ):
                attributes = user.attributes
                if cell.header.verified:
                    attributes = user.verified_attributes
                if getattr(attributes, cell.header.name) != cell.value:
                    setattr(attributes, cell.header.name, cell.value)
                    self.record(_('update attribute'), user, cell.header.name, cell.value)
                    cell.action = 'updated'
                    continue
            cell.action = 'nothing'

        for cell in row.cells:
            if cell.header.field or cell.header.attribute:
                continue
            if cell.header.name in {ROLE_NAME, ROLE_SLUG}:
                success &= self.add_role(cell, user, do_clear=True)
            elif cell.header.name == REGISTRATION and row.action == 'create':
                success &= self.registration_option(cell, user)
            elif cell.header.name == FORCE_PASSWORD_RESET:
                success &= self.force_password_reset(cell, user)
            elif cell.header.name == PASSWORD_HASH:
                user.password = cell.value
                user.save()
                self.record(_('password update'), user)

        setattr(self, row.action + 'd', getattr(self, row.action + 'd') + 1)
        return success

    def add_role(self, cell, user, do_clear=False):
        if not cell.value.strip():
            return True
        try:
            if cell.header.name == ROLE_NAME:
                role = Role.objects.get(name=cell.value, ou=self.ou)
            elif cell.header.name == ROLE_SLUG:
                role = Role.objects.get(slug=cell.value, ou=self.ou)
        except Role.DoesNotExist:
            self._missing_roles.add(cell.value)
            cell.errors.append(Error('role-not-found', _('Role "%s" does not exist') % cell.value))
            return False
        if not self.has_manage_role_permission(role):
            cell.errors.append(
                Error('role-unauthorized', _('You are not allowed to manage role "%s"') % cell.value)
            )
            return False
        if cell.header.delete:
            if role in user.roles.all():
                self.record(_('remove'), user, 'role', role)
            user.roles.remove(role)
        elif cell.header.clear:
            if not self.has_manage_roles_permission(user):
                cell.errors.append(
                    Error('roles-unauthorized', _('You are not allowed to clear roles for this user'))
                )
                return False
            if do_clear:
                user.roles.clear()
            self.record(_('roles clear'), user)
            self.record(_('add'), user, 'role', role)
            user.roles.add(role)
        else:
            if role not in user.roles.all():
                self.record(_('add'), user, 'role', role)
            user.roles.add(role)
        cell.action = 'updated'
        return True

    def has_manage_roles_permission(self, user):
        """Insure we have permission to manage ALL roles of a user"""
        for role in user.roles.all():
            if not self.has_manage_role_permission(role):
                return False
        return True

    def has_manage_role_permission(self, role):
        """Insure we have permission to manage a role"""
        if self.user is None:
            # we are in a CLI import, no need to check permissions
            return True
        return self.user.has_perm('a2_rbac.manage_members_role', obj=role)

    def registration_option(self, cell, user):
        if cell.value == REGISTRATION_RESET_EMAIL and not self.simulate:
            send_password_reset_mail(
                user,
                template_names=[
                    'authentic2/manager/user_create_registration_email',
                    'authentic2/password_reset',
                ],
                next_url='/accounts/',
                context={'user': user},
            )
        return True

    def force_password_reset(self, cell, user):
        if cell.value:
            PasswordReset.objects.get_or_create(user=user)
        return True

    def record_run(self, action):
        if self.simulate or not self._journal:
            return
        self._journal.record(
            'manager.user.csvimport.run',
            action_name=action,
            import_uuid=self.import_uuid,
            report_uuid=self.report_uuid,
        )

    def record(self, action_name, user, fieldname=None, value=None):
        if self.simulate or not self._journal:
            return
        self._journal.record(
            'manager.user.csvimport.action',
            import_uuid=self.import_uuid,
            report_uuid=self.report_uuid,
            action_name=action_name,
            user_uuid=user.uuid,
            fieldname=fieldname,
            value=value,
        )
