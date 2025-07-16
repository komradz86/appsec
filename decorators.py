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
from contextlib import contextmanager
from functools import wraps
from json import dumps as json_dumps

from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.debug import technical_404_response

from . import app_settings

# XXX: import to_list for retrocompaibility
from .utils.misc import to_iter, to_list  # pylint: disable=unused-import


def unless(test, message):
    '''Decorator returning a 404 status code if some condition is not met'''

    def decorator(func):
        @wraps(func)
        def f(request, *args, **kwargs):
            if not test():
                return technical_404_response(request, Http404(message))
            return func(request, *args, **kwargs)

        return f

    return decorator


def setting_enabled(name, settings=app_settings):
    '''Generate a decorator for enabling a view based on a setting'''
    full_name = getattr(settings, 'prefix', '') + name

    def test():
        return getattr(settings, name, False)

    return unless(test, 'please enable %s' % full_name)


def lasso_required():
    def test():
        try:
            import lasso  # pylint: disable=unused-import

            return True
        except ImportError:
            return False

    return unless(test, 'please install lasso')


def required(wrapping_functions, patterns_rslt):
    """
    Used to require 1..n decorators in any view returned by a url tree

    Usage:
      urlpatterns = required(func,patterns(...))
      urlpatterns = required((func,func,func),patterns(...))

    Note:
      Use functools.partial to pass keyword params to the required
      decorators. If you need to pass args you will have to write a
      wrapper function.

    Example:
      from functools import partial

      urlpatterns = required(
          partial(login_required,login_url='/accounts/login/'),
          patterns(...)
      )
    """
    if not hasattr(wrapping_functions, '__iter__'):
        wrapping_functions = (wrapping_functions,)

    return [_wrap_instance__resolve(wrapping_functions, instance) for instance in patterns_rslt]


def _wrap_instance__resolve(wrapping_functions, instance):
    if not hasattr(instance, 'resolve'):
        return instance
    resolve = getattr(instance, 'resolve')

    def _wrap_func_in_returned_resolver_match(*args, **kwargs):
        rslt = resolve(*args, **kwargs)

        if not hasattr(rslt, 'func'):
            return rslt
        f = getattr(rslt, 'func')

        for _f in reversed(wrapping_functions):
            # @decorate the function from inner to outter
            f = _f(f)

        setattr(rslt, 'func', f)

        return rslt

    setattr(instance, 'resolve', _wrap_func_in_returned_resolver_match)
    return instance


@contextmanager
def errorcollector(error_dict):
    try:
        yield
    except ValidationError as e:
        e.update_error_dict(error_dict)


def json(func):
    '''Convert view to a JSON or JSON web-service supporting CORS'''
    from . import cors

    @wraps(func)
    def f(request, *args, **kwargs):
        jsonp = False
        # Differentiate JSONP from AJAX
        if request.method == 'GET':
            for variable in ('jsonpCallback', 'callback'):
                if variable in request.GET:
                    identifier = request.GET[variable]
                    if not re.match(r'^[$a-zA-Z_][0-9a-zA-Z_$]*$', identifier):
                        return HttpResponseBadRequest(
                            'invalid JSONP callback name', content_type='text/plain'
                        )
                    jsonp = True
                    break
        # 1. check origin
        if jsonp:
            origin = request.headers.get('Referer')
            if not origin:
                # JSONP is unusable for people without referers
                return HttpResponseForbidden('missing referrer', content_type='text/plain')
            origin = cors.make_origin(origin)
        else:
            origin = request.headers.get('Origin')
        if origin:
            if not cors.check_origin(request, origin):
                return HttpResponseForbidden('bad origin', content_type='text/plain')
        # 2. build response
        result = func(request, *args, **kwargs)
        json_str = json_dumps(result)
        if jsonp:
            response = HttpResponse(content_type='application/javascript')
            json_str = '%s(%s);' % (identifier, json_str)
        else:
            response = HttpResponse(content_type='application/json')
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Allow-Headers'] = 'x-requested-with'
        response.write(json_str)
        return response

    return f
