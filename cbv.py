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

import functools

from django.forms import Form
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

from .forms.utils import NextUrlFormMixin
from .utils import hooks
from .utils import misc as utils_misc
from .utils.views import csrf_token_check


class ValidateCSRFMixin:
    """Move CSRF token validation inside the form validation.

    This mixin must always be the leftest one and if your class override
    form_valid() dispatch() you should move those overrides in a base
    class.
    """

    @method_decorator(csrf_exempt)
    @method_decorator(ensure_csrf_cookie)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, *args, **kwargs):
        for form in args:
            if isinstance(form, Form):
                csrf_token_check(self.request, form)
        if not form.is_valid():
            return self.form_invalid(form)
        return super().form_valid(*args, **kwargs)


@functools.cache
def make_next_url_form_class(form_class):
    if issubclass(form_class, NextUrlFormMixin):
        return form_class
    return type(f'NextURL{form_class.__name__}', (form_class, NextUrlFormMixin), {})


class NextUrlViewMixin:
    '''Mixin for TemplateView or FormView, form class will use NextUrlFormMixin'''

    next_url = None

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.next_url = utils_misc.select_next_url(request, self.next_url, include_post=True)

    def get_form_class(self):
        return make_next_url_form_class(super().get_form_class())

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.setdefault('initial', {})['next_url'] = self.next_url
        kwargs['request'] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs['next_url'] = self.next_url
        return super().get_context_data(**kwargs)


class SuccessUrlViewMixin(NextUrlViewMixin):
    def get_success_url(self):
        return self.next_url or super().get_success_url()


class TemplateNamesMixin:
    def get_template_names(self):
        if hasattr(self, 'template_names'):
            return self.template_names
        return super().get_template_names()


class HookMixin:
    def get_form(self):
        form = super().get_form()
        hooks.call_hooks('front_modify_form', self, form)
        return form
