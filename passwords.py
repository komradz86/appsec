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

import abc
import os
import random
import re
import string

from django.core.exceptions import ValidationError
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from zxcvbn import zxcvbn
from zxcvbn.frequency_lists import FREQUENCY_LISTS
from zxcvbn.matching import build_ranked_dict

from . import app_settings
from .utils.misc import get_password_authenticator


def generate_password():
    """Generate a password that validates current password policy.

    Beware that custom regex validation cannot be validated.
    """
    digits = string.digits
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    punc = string.punctuation

    authenticator = get_password_authenticator()
    min_len = max(authenticator.password_min_length, 8)
    min_class_count = max(app_settings.A2_PASSWORD_POLICY_MIN_CLASSES, 3)
    new_password = []

    generator = random.SystemRandom()
    while len(new_password) < min_len:
        for cls in (digits, lower, upper, punc)[:min_class_count]:
            new_password.append(generator.choice(cls))
    generator.shuffle(new_password)
    return ''.join(new_password)


class PasswordChecker(metaclass=abc.ABCMeta):
    class Check:
        def __init__(self, label, result):
            self.label = label
            self.result = result

    @abc.abstractmethod
    def __call__(self, password, **kwargs):
        """Return an iterable of Check objects giving the list of checks and
        their result."""
        return []


class DefaultPasswordChecker(PasswordChecker):
    @property
    def min_length(self):
        return self.authenticator.password_min_length

    @property
    def at_least_one_lowercase(self):
        return app_settings.A2_PASSWORD_POLICY_MIN_CLASSES > 0

    @property
    def at_least_one_digit(self):
        return app_settings.A2_PASSWORD_POLICY_MIN_CLASSES > 1

    @property
    def at_least_one_uppercase(self):
        return app_settings.A2_PASSWORD_POLICY_MIN_CLASSES > 2

    @property
    def regexp(self):
        return self.authenticator.password_regex

    @property
    def regexp_label(self):
        return self.authenticator.password_regex_error_msg

    def __call__(self, password, **kwargs):
        self.authenticator = get_password_authenticator()
        if self.min_length:
            yield self.Check(
                result=len(password) >= self.min_length, label=_('%s characters') % self.min_length
            )

        if self.at_least_one_lowercase:
            yield self.Check(result=any(c.islower() for c in password), label=_('1 lowercase letter'))

        if self.at_least_one_digit:
            yield self.Check(result=any(c.isdigit() for c in password), label=_('1 digit'))

        if self.at_least_one_uppercase:
            yield self.Check(result=any(c.isupper() for c in password), label=_('1 uppercase letter'))

        if self.regexp and self.regexp_label:
            yield self.Check(result=bool(re.match(self.regexp, password)), label=self.regexp_label)


def get_password_checker(*args, **kwargs):
    return import_string(app_settings.A2_PASSWORD_POLICY_CLASS)(*args, **kwargs)


class StrengthReport:
    def __init__(self, strength, hint):
        self.strength = strength
        self.strength_label = [_('Very Weak'), _('Weak'), _('Fair'), _('Good'), _('Strong')][strength]
        self.hint = hint


def get_password_strength(password, user=None, inputs=None, authenticator=None):
    authenticator = authenticator or get_password_authenticator()

    user_inputs = {}
    if user is not None and hasattr(user, 'attributes'):
        user_inputs = {name: attr.content for name, attr in user.attributes.values.items() if attr.content}
        user_inputs['email'] = user.email

    if inputs is not None:
        user_inputs.update(inputs)

    splitted_inputs = set()
    for input in user_inputs.values():
        # check against full inputs and each word of it
        if not input:
            continue
        splitted_inputs.add(input)
        splitted_inputs.update(input.split(' '))

    min_length = authenticator.password_min_length

    hint = _('add more words or characters.')
    strength = 0
    if min_length and len(password) < min_length:
        hint = _('use at least %s characters.') % min_length
    elif password:
        report = zxcvbn(password, user_inputs=splitted_inputs or [''])
        strength = report['score']
        hint = get_hint(report['sequence'])

    return StrengthReport(strength, hint)


def get_hint(matches):
    matches = sorted(matches, key=lambda m: len(m['token']), reverse=True)
    for match in matches:
        hint = get_hint_for_match(match)
        if hint:
            return hint
    return _('use a longer password.')


def get_hint_for_match(match):
    pattern = match['pattern']
    hint = None
    if pattern == 'spatial':
        if match['turns'] == 1:
            hint = _('avoid straight rows of keys like "{token}".')
        else:
            hint = _('avoid short keyboard patterns like "{token}".')

    if pattern == 'repeat':
        hint = _('avoid repeated words and characters like "{token}".')

    if pattern == 'sequence':
        hint = _('avoid sequences like "{token}".')

    if pattern == 'regex':
        if match['regex_name'] == 'recent_year':
            hint = _('avoid recent years.')

    if pattern == 'date':
        hint = _('avoid dates and years that are associated with you.')

    if pattern == 'dictionary':
        if match['dictionary_name'] == 'user_inputs':
            hint = _('avoid "{token}" : it\'s similar to one of your personal informations.')
        elif match['l33t'] or match['reversed']:
            hint = _('avoid "{token}" : it\'s similar to a commonly used password')
        else:
            hint = _('avoid "{token}" : it\'s a commonly used password.')

    if hint is not None:
        return hint.format(token=match['token'])

    return None


def validate_password(password, user=None, inputs=None, authenticator=None):
    if password == '':
        return

    authenticator = authenticator or get_password_authenticator()

    min_strength = authenticator.min_password_strength
    min_length = authenticator.password_min_length

    if min_strength is not None:
        if get_password_strength(password, user=user, inputs=inputs).strength < min_strength:
            raise ValidationError(_('This password is not strong enough.'))

        if min_length > len(password):
            raise ValidationError(_('Password must be at least %s characters.') % min_length)
    else:
        # legacy password policy
        password_checker = get_password_checker()
        errors = [not check.result for check in password_checker(password)]
        if any(errors):
            raise ValidationError(_('This password is not accepted.'))


def init_password_dictionaries():
    # add zxcvbn built-in dictionaries
    import zxcvbn.matching

    frequency_lists = dict(FREQUENCY_LISTS)
    for name, path in app_settings.A2_PASSWORD_POLICY_DICTIONARIES.items():
        if not os.path.exists(path):
            continue

        with open(path) as dictionary_file:
            frequency_lists[name] = [line.lower() for line in dictionary_file.read().splitlines()]

    zxcvbn.matching.RANKED_DICTIONARIES = {}
    for name, freq_list in frequency_lists.items():
        zxcvbn.matching.RANKED_DICTIONARIES[name] = build_ranked_dict(freq_list)


def generate_apiclient_password(length=45):
    password = [random.choice(string.ascii_letters + string.digits) for _ in range(length)]
    idx = random.sample(list(range(length)), 3)
    charsets = [string.ascii_letters.upper(), string.ascii_letters.lower(), string.digits]
    for i, pos in enumerate(idx):
        password[pos] = random.choice(charsets[i])
    return ''.join(password)


def validate_apiclient_password(password, min_length=43):
    hints = []
    if len(password) < min_length:
        hints = [_('%s characters') % min_length]

    char_sets = (
        (set(string.ascii_letters.upper()), _('1 uppercase letter')),
        (set(string.ascii_letters.lower()), _('1 lowercase letter')),
        (set(string.digits), _('1 digit')),
    )

    hints += [hint for charset, hint in char_sets if not (set(password) & charset)]
    if hints:
        return False, _('Password must contain at least %s.') % ', '.join(hints)
    else:
        return True, None
