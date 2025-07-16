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

import base64
import hashlib
import math
from binascii import hexlify, unhexlify
from collections import OrderedDict

from django.contrib.auth import hashers
from django.contrib.auth.hashers import make_password
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes, force_str
from django.utils.translation import gettext_noop as _


class Drupal7PasswordHasher(hashers.BasePasswordHasher):
    """
    Secure password hashing using the algorithm used by Drupal 7 (recommended)
    """

    algorithm = 'drupal7_sha512'
    iterations = 10000
    digest = hashlib.sha512
    alphabet = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    def atoi64(self, v):
        return self.alphabet.find(v)

    def i64toa(self, v):
        return self.alphabet[v]

    def b64encode(self, v):
        out = ''
        count = len(v)
        i = 0
        while i < count:
            value = v[i]
            i += 1
            out += self.i64toa(value & 0x3F)
            if i < count:
                value |= v[i] << 8
            out += self.i64toa((value >> 6) & 0x3F)
            if i == count:
                break
            i += 1
            if i < count:
                value |= v[i] << 16
            out += self.i64toa((value >> 12) & 0x3F)
            if i == count:
                break
            i += 1
            out += self.i64toa((value >> 18) & 0x3F)
        return out

    def from_drupal(self, encoded):
        ident, log_count, salt, h = encoded[:3], encoded[3], encoded[4:12], encoded[12:]
        if ident != '$S$':
            raise ValueError('Not a Drupal7 SHA-512 hashed password')
        count = 1 << self.atoi64(log_count)
        return '%s$%s$%s$%s' % (self.algorithm, count, salt, h)

    def to_drupal(self, encoded):
        dummy_algo, count, salt, h = encoded.split('$', 3)
        count = self.i64toa(math.ceil(math.log(int(count), 2)))
        return '$S$%s%s%s' % (count, salt, h)

    def encode(self, password, salt, iterations):
        assert password
        assert salt and '$' not in salt
        h = salt.encode()
        password = password.encode()
        for dummy in range(iterations + 1):
            h = self.digest(h + password).digest()
        return '%s$%d$%s$%s' % (self.algorithm, iterations, salt, self.b64encode(h)[:43])

    def verify(self, password, encoded):
        algorithm, iterations, salt, dummy = encoded.split('$', 3)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, int(iterations))
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, iterations, salt, hash = encoded.split('$', 3)
        assert algorithm == self.algorithm
        return OrderedDict(
            [
                (_('algorithm'), algorithm),
                (_('iterations'), iterations),
                (_('salt'), hashers.mask_hash(salt)),
                (_('hash'), hashers.mask_hash(hash)),
            ]
        )


class CommonPasswordHasher(hashers.BasePasswordHasher):
    """
    The Salted MD5 password hashing algorithm (not recommended)
    """

    algorithm = None
    digest = None

    def encode(self, password, salt):
        assert password
        assert '$' not in salt
        hash = self.digest(force_bytes(salt + password)).hexdigest()
        return '%s$%s$%s' % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, salt, dummy_hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        return OrderedDict(
            [
                (_('algorithm'), algorithm),
                (_('salt'), hashers.mask_hash(salt, show=2)),
                (_('hash'), hashers.mask_hash(hash)),
            ]
        )


OPENLDAP_ALGO_MAPPING = {
    'SHA': ('sha-oldap', 0, True),
    'SSHA': ('ssha-oldap', 20, True),
    'MD5': ('md5-oldap', 0, True),
    'SMD5': ('md5-oldap', 16, True),
}


def olap_password_to_dj(password):
    '''Convert an LDAP password for Django use eventually hashed'''
    if password[0] == '{' and '}' in password:
        algo = password[1:].split('}')[0].upper()
        if algo not in OPENLDAP_ALGO_MAPPING:
            raise ValueError('unknown algorithm %r' % algo)
        password = password[1:].split('}')[1]
        try:
            password = base64.b64decode(password)
        except ValueError:
            raise ValueError('unable to decode base64 hash %r' % password)
        algo_name, salt_offset, hex_encode = OPENLDAP_ALGO_MAPPING[algo]
        salt, password = (password[salt_offset:], password[:salt_offset]) if salt_offset else ('', password)
        if hex_encode:
            password = force_str(hexlify(password), encoding='ascii')
        salt = force_str(hexlify(force_bytes(salt)), encoding='ascii')
        return '%s$%s$%s' % (algo_name, salt, password)
    else:
        return make_password(password)


class OpenLDAPPasswordHasher(CommonPasswordHasher):
    def encode(self, password, salt):
        assert password
        assert b'$' not in salt
        hash = self.digest(force_bytes(password + salt)).hexdigest()
        salt = force_str(hexlify(salt), encoding='ascii')
        return '%s$%s$%s' % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        hash = unhexlify(hash)
        salt = unhexlify(salt)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(force_bytes(password), salt)
        return constant_time_compare(encoded, encoded_2)


class SHA256PasswordHasher(CommonPasswordHasher):
    algorithm = 'sha256'
    digest = hashlib.sha256


class SSHA1PasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'ssha-oldap'
    digest = hashlib.sha1


class SMD5PasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'smd5-oldap'
    digest = hashlib.md5


class SHA1OLDAPPasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'sha-oldap'
    digest = hashlib.sha1

    def salt(self):
        return ''


class MD5OLDAPPasswordHasher(OpenLDAPPasswordHasher):
    algorithm = 'md5-oldap'
    digest = hashlib.md5

    def salt(self):
        return ''


class JoomlaPasswordHasher(CommonPasswordHasher):
    algorithm = 'joomla'
    digest = hashlib.md5

    def encode(self, password, salt):
        assert password
        assert b'$' not in salt
        hash = self.digest(force_bytes(password) + salt).hexdigest()
        salt = force_str(hexlify(force_bytes(salt)), encoding='ascii')
        return '%s$md5$%s$%s' % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, dummy_subalgo, salt, dummy_hash = encoded.split('$', 3)
        salt = unhexlify(salt)
        if algorithm != self.algorithm:
            raise ValueError('not a joomla encoded password')
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

    @classmethod
    def from_joomla(cls, encoded):
        if encoded.startswith('$P$'):
            raise NotImplementedError
        if encoded.startswith('$'):
            raise NotImplementedError
        if encoded.startswith('{SHA256}'):
            raise NotImplementedError

        if ':' in encoded:
            h, salt = encoded.split(':', 1)
        else:
            h, salt = encoded, ''
        salt = force_str(hexlify(force_bytes(salt)), encoding='ascii')

        return '%s$md5$%s$%s' % (cls.algorithm, salt, h)

    @classmethod
    def to_joomla(cls, encoded):
        algorithm, subalgo, salt, _hash = encoded.split('$', 4)
        if algorithm != cls.algorithm:
            raise ValueError('not a joomla encoded password')
        if subalgo != 'md5':
            raise NotImplementedError
        if salt:
            return '%s:%s' % (_hash, force_str(unhexlify(force_bytes(salt))))
        else:
            return _hash


class PloneSHA1PasswordHasher(hashers.SHA1PasswordHasher):
    # from https://www.fourdigits.nl/blog/converting-plone-data-to-django/
    """
    The SHA1 password hashing algorithm used by Plone.

    Plone uses `password + salt`, Django has `salt + password`.
    """

    algorithm = 'plonesha1'
    _prefix = '{SSHA}'

    def encode(self, password, salt):
        """Encode a plain text password into a plonesha1 style hash."""
        assert password is not None
        assert salt
        password = force_bytes(password)
        salt = force_bytes(salt)

        hashed = base64.b64encode(hashlib.sha1(password + salt).digest() + salt)
        return '%s$%s%s' % (self.algorithm, self._prefix, force_str(hashed))

    def verify(self, password, encoded):
        """Verify the given password against the encoded string."""
        algorithm, data = encoded.split('$', 1)
        assert algorithm == self.algorithm

        # throw away the prefix
        if data.startswith(self._prefix):
            data = data[len(self._prefix) :]

        # extract salt from encoded data
        intermediate = base64.b64decode(data)
        salt = intermediate[20:].strip()

        password_encoded = self.encode(password, salt)
        return constant_time_compare(password_encoded, encoded)

    def safe_summary(self, encoded):
        algorithm, hash = encoded.split('$', 1)
        assert algorithm == self.algorithm
        return OrderedDict(
            [
                (_('algorithm'), algorithm),
                (_('hash'), hashers.mask_hash(hash)),
            ]
        )
