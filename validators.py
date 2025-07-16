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


import re
import smtplib

import dns.exception
import dns.resolver
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator as DjangoEmailValidator
from django.core.validators import RegexValidator
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from . import app_settings


# copied from http://www.djangotips.com/real-email-validation
class EmailValidator:
    def __init__(self, rcpt_check=False):
        self.rcpt_check = rcpt_check

    def query_mxs(self, domain):
        try:
            mxs = dns.resolver.query(domain, 'MX')
            mxs = [str(mx.exchange).rstrip('.') for mx in mxs]
            return mxs
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException:
            pass

        for record_type in ('AAAA', 'A'):
            try:
                mxs = dns.resolver.query(domain, record_type)
                mxs = [str(mx.address).rstrip('.') for mx in mxs]
                return mxs
            except dns.resolver.NXDOMAIN:
                return []
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException:
                pass
        return []

    def check_rcpt(self, value, mxs):
        for server in mxs:
            try:
                with smtplib.SMTP() as smtp:
                    smtp.connect(server)
                    status = smtp.helo()
                    if status[0] != 250:
                        continue
                    smtp.mail('')
                    status = smtp.rcpt(value)
                if status[0] // 100 == 5:
                    raise ValidationError(_('Invalid email address'), code='invalid-fails-rcpt')
                break
            except smtplib.SMTPServerDisconnected:
                continue
            except smtplib.SMTPConnectError:
                continue

    LOCALPART_FORBIDDEN_RE = re.compile(r'^(?:[./|]|.*[@%!`#&?]|.*/\.\./)')

    def __call__(self, value):
        DjangoEmailValidator()(value)

        localpart, hostname = value.split('@', 1)
        if self.LOCALPART_FORBIDDEN_RE.match(localpart):
            raise ValidationError(DjangoEmailValidator.message, code=DjangoEmailValidator.code)
        if app_settings.A2_VALIDATE_EMAIL_DOMAIN:
            mxs = self.query_mxs(hostname)
            if not mxs:
                raise ValidationError(
                    _('Email domain (%(dom)s) does not exists') % {'dom': hostname}, code='invalid-domain'
                )
            if self.rcpt_check and app_settings.A2_VALIDATE_EMAIL:
                self.check_rcpt(value, mxs)


email_validator = EmailValidator()


class PhoneNumberValidator(RegexValidator):
    def __init__(self, *args, **kwargs):
        self.regex = r'^\+?\d{,20}$'
        super().__init__(*args, **kwargs)


class UsernameValidator(RegexValidator):
    def __init__(self, *args, **kwargs):
        self.regex = app_settings.A2_REGISTRATION_FORM_USERNAME_REGEX
        super().__init__(*args, **kwargs)


@deconstructible
class ProhibitNullCharactersValidator:
    """Validate that the string doesn't contain the null character."""

    message = _('Null characters are not allowed.')
    code = 'null_characters_not_allowed'

    def __init__(self, message=None, code=None):
        if message is not None:
            self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value):
        if '\x00' in str(value):
            raise ValidationError(self.message, code=self.code)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.message == other.message and self.code == other.code


class HexaColourValidator(RegexValidator):
    """Validates that the string is a hexadecimal colour"""

    def __init__(self, *args, **kwargs):
        self.regex = '#[0-9a-fA-F]{6}'
        self.message = _('Hexadecimal value only allowed.')
        super().__init__(*args, **kwargs)
