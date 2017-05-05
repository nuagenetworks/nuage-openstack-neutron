# Copyright 2017 Nokia
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.quota import resource_registry
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import constants as nuage_constants
NUAGE_PLUGIN_STATS = 'nuage_plugin_stats'

resource = {}
RESOURCE_ATTRIBUTE_MAP = {
    NUAGE_PLUGIN_STATS: {
        'server': {'is_visible': True},
        'serverauth': {'is_visible': True},
        'serverssl': {'is_visible': True},
        'server_timeout': {'is_visible': True},
        'server_max_retries': {'is_visible': True},
        'base_uri': {'is_visible': True},
        'organization': {'is_visible': True},
        'auth_resource': {'is_visible': True},
        'default-net-partition': {'is_visible': True},
        'api_count': {'is_visible': True}
    },
}


class Nuage_plugin_stats(api_extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "nuage plugin stats"

    @classmethod
    def get_alias(cls):
        return "nuage-plugin-stats"

    @classmethod
    def get_description(cls):
        return "Nuage Plugin Statistics"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/pluginstats/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2016-01-21T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin(
            nuage_constants.NUAGE_PLUGIN_STATS)
        resource_name = 'nuage_plugin_stats'
        collection_name = resource_name.replace('_', '-')
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name, dict())
        resource_registry.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                          plugin, params, allow_bulk=True)
        return [extensions.ResourceExtension(collection_name, controller)]
