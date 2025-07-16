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

"""
Use django's app registry to find plugins

Propose helper methods to load urls from plugins
"""
import logging

from django.apps import apps
from django.urls import include, path

logger = logging.getLogger(__name__)


__ALL__ = ['get_plugins']

PLUGIN_CACHE = {}


DEFAULT_GROUP_NAME = 'authentic2.plugin'


def get_plugins(group_name=DEFAULT_GROUP_NAME, use_cache=True):
    """Traverse every app in app registry and instantiate a plugin if the app defines one."""
    if group_name in PLUGIN_CACHE and use_cache:
        return PLUGIN_CACHE[group_name]
    plugins = []
    if apps.ready:
        for app_config in apps.get_app_configs():
            if hasattr(app_config, 'get_a2_plugin'):
                plugins.append(app_config.get_a2_plugin())
        PLUGIN_CACHE[group_name] = plugins

    return plugins


def register_plugins_urls(urlpatterns, group_name=DEFAULT_GROUP_NAME):
    """Call get_before_urls and get_after_urls on all plugins providing them
    and add those urls to the given urlpatterns.

    URLs returned by get_before_urls() are added to the head of urlpatterns
    and those returned by get_after_urls() are added to the tail of
    urlpatterns.
    """
    plugins = get_plugins(group_name)
    before_urls = []
    after_urls = []
    for plugin in plugins:
        if hasattr(plugin, 'get_before_urls'):
            urls = plugin.get_before_urls()
            before_urls.append(path('', include(urls)))
        if hasattr(plugin, 'get_after_urls'):
            urls = plugin.get_after_urls()
            after_urls.append(path('', include(urls)))

    return before_urls + urlpatterns + after_urls


def collect_from_plugins(name, *args, **kwargs):
    """
    Collect a property or the result of a function from plugins.
    """
    accumulator = []
    for plugin in get_plugins():
        if not hasattr(plugin, name):
            continue
        attribute = getattr(plugin, name)
        if hasattr(attribute, '__call__'):
            accumulator.append(attribute(*args, **kwargs))
        else:
            accumulator.append(attribute)
    return accumulator


def init():
    for plugin in get_plugins():
        if hasattr(plugin, 'init'):
            plugin.init()
