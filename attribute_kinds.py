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
import binascii
import datetime
import hashlib
import os
import re
import string
import uuid
from itertools import chain

import phonenumbers
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.validators import RegexValidator
from django.urls import reverse, reverse_lazy
from django.utils import html
from django.utils.functional import keep_lazy
from django.utils.translation import get_supported_language_variant
from django.utils.translation import gettext_lazy as _
from django.utils.translation import pgettext_lazy
from gadjo.templatetags.gadjo import xstatic
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as DrfValidationError
from rest_framework.fields import empty

from . import app_settings
from .decorators import to_iter
from .forms import fields, widgets
from .plugins import collect_from_plugins


@keep_lazy(str)
def capfirst(value):
    return value and value[0].upper() + value[1:]


DEFAULT_TITLE_CHOICES = (
    (pgettext_lazy('title', 'Mrs'), pgettext_lazy('title', 'Mrs')),
    (pgettext_lazy('title', 'Mr'), pgettext_lazy('title', 'Mr')),
)


class DateWidget(widgets.DateWidget):
    help_text = _('Format: yyyy-mm-dd')


class DateField(forms.DateField):
    widget = DateWidget


class DateRestField(serializers.DateField):
    default_error_messages = {
        'blank': _('This field may not be blank.'),
    }

    def __init__(self, **kwargs):
        self.allow_blank = kwargs.pop('allow_blank', False)
        self.trim_whitespace = kwargs.pop('trim_whitespace', True)
        super().__init__(**kwargs)

    def run_validation(self, data=empty):
        # Test for the empty string here so that it does not get validated,
        # and so that subclasses do not need to handle it explicitly
        # inside the `to_internal_value()` method.
        if data == '' or (self.trim_whitespace and str(data).strip() == ''):
            if not self.allow_blank:
                self.fail('blank')
            return ''
        return super().run_validation(data)


class BirthdateWidget(DateWidget):
    def __init__(self, *args, **kwargs):
        attrs = kwargs.setdefault('attrs', {})
        options = kwargs.setdefault('options', {})
        options['endDate'] = '-1d'
        options['startDate'] = '1900-01-01'
        attrs['min'] = '1900-01-01'
        attrs['max'] = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        super().__init__(*args, **kwargs)


def validate_birthdate(value):
    if value and not (datetime.date(1900, 1, 1) <= value < datetime.date.today()):
        raise ValidationError(_('birthdate must be in the past and greater or equal than 1900-01-01.'))


class BirthdateField(forms.DateField):
    widget = BirthdateWidget
    default_validators = [
        validate_birthdate,
    ]


class BirthdateRestField(DateRestField):
    default_validators = [
        validate_birthdate,
    ]


class AddressAutocompleteInput(forms.Select):
    template_name = 'authentic2/widgets/address_autocomplete.html'

    class Media:
        js = [
            xstatic('jquery.js', 'jquery.min.js'),
            settings.SELECT2_JS,
            'authentic2/manager/js/select2_locale.js',
            reverse_lazy('a2-manager-javascript-catalog'),
            'authentic2/js/address_autocomplete.js',
        ]
        css = {
            'screen': [settings.SELECT2_CSS],
        }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.attrs['data-select2-url'] = reverse('a2-api-address-autocomplete')
        self.attrs['class'] = 'address-autocomplete'


class AddressAutocompleteField(forms.CharField):
    widget = AddressAutocompleteInput


@to_iter
def get_title_choices():
    return app_settings.A2_ATTRIBUTE_KIND_TITLE_CHOICES or DEFAULT_TITLE_CHOICES


def validate_phone_number(value):
    conf = []
    for conf_key in (
        'region',
        'region_desc',
        'example_value',
    ):
        conf.append(settings.PHONE_COUNTRY_CODES[settings.DEFAULT_COUNTRY_CODE].get(conf_key))
    try:
        phonenumbers.parse(value)
    except phonenumbers.NumberParseException:
        try:
            phonenumbers.parse(
                value,
                conf[0],
            )
        except phonenumbers.NumberParseException:
            raise ValidationError(
                _('Phone number must be dialable from {location} (e.g. {example}).').format(
                    location=conf[1], example=conf[2]
                )
            )


french_validate_phone_number = RegexValidator(
    r'^[0][0-9]{9}$', message=_('A french phone number must start with a zero then another nine digits.')
)


def clean_number(number):
    cleaned_number = re.sub(r'[-.\s/]', '', number)
    validate_phone_number(cleaned_number)
    return cleaned_number


class FrenchPhoneNumberField(forms.CharField):
    widget = widgets.PhoneNumberInput

    def __init__(self, *args, **kwargs):
        kwargs['validators'] = (french_validate_phone_number,)
        kwargs.setdefault('help_text', _('ex.: 0699999999, 01 23 45 67 89, 09.87.65.43.21'))
        super().__init__(*args, **kwargs)

    def clean(self, value):
        if value not in self.empty_values:
            value = clean_number(value)
        value = super().clean(value)
        return value


class PhoneNumberDRFField(serializers.CharField):
    default_validators = [validate_phone_number]

    def to_internal_value(self, data):
        if isinstance(data, (list, tuple)):
            data = data[0]
        try:
            cleaned_data = clean_number(data)
        except ValidationError as e:
            raise DrfValidationError(str(e))
        data = super().to_internal_value(cleaned_data)
        default_country = settings.PHONE_COUNTRY_CODES[settings.DEFAULT_COUNTRY_CODE]['region']
        try:
            pn = phonenumbers.parse(data)
        except phonenumbers.NumberParseException:
            pn = phonenumbers.parse(data, default_country)
        return phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)


class FrenchPhoneNumberDRFField(serializers.CharField):
    default_validators = [french_validate_phone_number]

    def to_internal_value(self, data):
        return super().to_internal_value(clean_number(data))


validate_fr_postcode = RegexValidator(r'^\d{5}$', message=_('The value must be a valid french postcode'))


class FrPostcodeField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('help_text', _('ex.: 13260'))
        super().__init__(*args, **kwargs)

    def clean(self, value):
        value = super().clean(value)
        if value not in self.empty_values:
            value = value.strip()
            validate_fr_postcode(value)
        return value

    def widget_attrs(self, widget):
        return {'inputmode': 'numeric'}


class FrPostcodeDRFField(serializers.CharField):
    default_validators = [validate_fr_postcode]


class ProfileImageFile:
    def __init__(self, name):
        self.name = name

    @property
    def url(self):
        return default_storage.url(self.name)


def date_serialize(date):
    if date and isinstance(date, datetime.date):
        return date.isoformat()
    return ''


def date_deserialize(iso_string):
    if iso_string and isinstance(iso_string, str):
        return datetime.datetime.strptime(iso_string, '%Y-%m-%d').date()
    return None


def profile_image_serialize(uploadedfile):
    if not uploadedfile:
        return ''
    if hasattr(uploadedfile, 'url'):
        return uploadedfile.name
    h_computation = hashlib.md5()
    for chunk in uploadedfile.chunks():
        h_computation.update(chunk)
    hexdigest = h_computation.hexdigest()
    stored_file = default_storage.save(os.path.join('profile-image', hexdigest + '.jpeg'), uploadedfile)
    return stored_file


def profile_image_deserialize(name):
    if name:
        return ProfileImageFile(name)
    return None


def profile_image_html_value(attribute, value):
    if value:
        fragment = '<a href="%s"><img class="%s" src="%s"/></a>' % (value.url, attribute.name, value.url)
        return html.mark_safe(fragment)
    return ''


def profile_attributes_ng_serialize(ctx, value):
    if value and getattr(value, 'url', None):
        request = ctx.get('request')
        if request:
            return request.build_absolute_uri(value.url)
        else:
            return value.url
    return None


class Base64ImageField(serializers.ImageField):
    def to_internal_value(self, data):
        if data == '':
            return None

        if isinstance(data, str):
            if ';base64,' in data:
                data = data.split(';base64,')[1]
            try:
                decoded_file = base64.b64decode(data, validate=True)
            except binascii.Error:
                raise DrfValidationError(_('Invalid base64 encoding.'))

            data = SimpleUploadedFile(name=str(uuid.uuid4()), content=decoded_file)

        return super().to_internal_value(data)


def language_choices():
    return settings.LANGUAGES


def language_default():
    return get_supported_language_variant(settings.LANGUAGE_CODE)


def language_html_value(attribute, value):
    for key, label in language_choices():
        if value == key:
            return label
    return ''


DEFAULT_ALLOW_BLANK = True
DEFAULT_MAX_LENGTH = 256

DEFAULT_ATTRIBUTE_KINDS = [
    {
        'label': _('string'),
        'name': 'string',
        'field_class': forms.CharField,
        'kwargs': {
            'max_length': DEFAULT_MAX_LENGTH,
        },
    },
    {
        'label': _('title'),
        'name': 'title',
        'field_class': forms.ChoiceField,
        'kwargs': {
            'choices': get_title_choices(),
            'widget': forms.RadioSelect,
        },
        'rest_framework_field_class': serializers.ChoiceField,
        'rest_framework_field_kwargs': {
            'choices': [str(key) for key, value in DEFAULT_TITLE_CHOICES] + [''],
        },
    },
    {
        'label': _('boolean'),
        'name': 'boolean',
        'field_class': forms.BooleanField,
        'serialize': lambda x: str(int(bool(x))),
        'deserialize': lambda x: bool(int(x)),
        'rest_framework_field_class': serializers.BooleanField,
        'rest_framework_field_kwargs': {
            'allow_null': True,
        },
        'html_value': lambda attribute, value: _('True') if value else _('False'),
    },
    {
        'label': _('date'),
        'name': 'date',
        'field_class': DateField,
        'serialize': date_serialize,
        'deserialize': date_deserialize,
        'rest_framework_field_class': DateRestField,
    },
    {
        'label': _('birthdate'),
        'name': 'birthdate',
        'field_class': BirthdateField,
        'serialize': date_serialize,
        'deserialize': date_deserialize,
        'rest_framework_field_class': BirthdateRestField,
    },
    {
        'label': _('address (autocomplete)'),
        'name': 'address_auto',
        'field_class': AddressAutocompleteField,
    },
    {
        'label': _('french postcode'),
        'name': 'fr_postcode',
        'field_class': FrPostcodeField,
        'rest_framework_field_class': FrPostcodeDRFField,
    },
    {
        'label': _('phone number'),
        'name': 'phone_number',
        'field_class': fields.PhoneField,
        'rest_framework_field_class': PhoneNumberDRFField,
    },
    {
        'label': _('french phone number'),
        'name': 'fr_phone_number',
        'field_class': FrenchPhoneNumberField,
        'rest_framework_field_class': FrenchPhoneNumberDRFField,
    },
    {
        'label': _('profile image'),
        'name': 'profile_image',
        'field_class': fields.ProfileImageField,
        'serialize': profile_image_serialize,
        'deserialize': profile_image_deserialize,
        'rest_framework_field_class': Base64ImageField,
        'rest_framework_field_kwargs': {
            'use_url': True,
            'allow_empty_file': True,
            '_DjangoImageField': fields.ProfileImageField,
        },
        'html_value': profile_image_html_value,
        'attributes_ng_serialize': profile_attributes_ng_serialize,
        'csv_importable': False,
    },
    {
        'label': _('language'),
        'name': 'language',
        'default': language_default,
        'field_class': forms.ChoiceField,
        'html_value': language_html_value,
        'kwargs': {
            'choices': language_choices,
            'widget': forms.Select,
        },
    },
]


def get_attribute_kinds():
    attribute_kinds = {}
    for attribute_kind in chain(DEFAULT_ATTRIBUTE_KINDS, app_settings.A2_ATTRIBUTE_KINDS):
        attribute_kinds[attribute_kind['name']] = attribute_kind
    for attribute_kind in chain(*collect_from_plugins('attribute_kinds')):
        attribute_kinds[attribute_kind['name']] = attribute_kind
    return attribute_kinds


@to_iter
def get_choices():
    '''Produce a choice list to use in form fields'''
    for d in get_attribute_kinds().values():
        yield (d['name'], capfirst(d['label']))


def only_digits(value):
    return ''.join(x for x in value if x in string.digits)


def validate_lun(value):
    l = [(int(x) * (1 + i % 2)) for i, x in enumerate(reversed(value))]  # noqa: E741
    return sum(x - 9 if x > 10 else x for x in l) % 10 == 0


def validate_siret(value):
    RegexValidator(r'^( *[0-9] *){14}$', _('SIRET number must contain 14 digits'))(value)
    value = only_digits(value)
    if not validate_lun(value) or not validate_lun(value[:9]):
        raise ValidationError(_('SIRET validation code does not match'))


class SIRETField(forms.CharField):
    default_validators = [validate_siret]

    def to_python(self, value):
        value = super().to_python(value)
        value = only_digits(value)
        return value

    def widget_attrs(self, widget):
        return {'inputmode': 'numeric'}


def contribute_to_form(attribute_descriptions, form):
    for attribute_description in attribute_descriptions:
        attribute_description.contribute_to_form(form)


def get_form_field(kind, **kwargs):
    defn = get_attribute_kinds()[kind]
    if 'kwargs' in defn:
        kwargs.update(defn['kwargs'])
    return defn['field_class'](**kwargs)


def identity(x):
    return x


def get_kind(kind):
    d = get_attribute_kinds()[kind]
    d.setdefault('default', None)
    d.setdefault('serialize', identity)
    d.setdefault('deserialize', identity)
    rest_field_kwargs = d.setdefault('rest_framework_field_kwargs', {})
    if 'rest_framework_field_class' not in d:
        d['rest_framework_field_class'] = serializers.CharField
        rest_field_kwargs.setdefault('allow_blank', DEFAULT_ALLOW_BLANK)
        rest_field_kwargs.setdefault('max_length', DEFAULT_MAX_LENGTH)
    return d
