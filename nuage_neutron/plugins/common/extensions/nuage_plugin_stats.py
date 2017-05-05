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
from neutron import manager
from neutron.quota import resource_registry

from nuage_neutron.plugins.common import constants as nuage_constants
NUAGE_PLUGIN_STATS = 'nuage_plugin_stats'

resource = {}
RESOURCE_ATTRIBUTE_MAP = {
    NUAGE_PLUGIN_STATS: {
        'server': {'is_visible': True},
        'serverauth': {'is_visible': False},
        'serverssl': {'is_visible': False},
        'server_timeout': {'is_visible': False},
        'server_max_retries': {'is_visible': False},
        'base_uri': {'is_visible': False},
        'organization': {'is_visible': False},
        'auth_resource': {'is_visible': False},
        'default-net-partition': {'is_visible': False},
        'api_count': {'is_visible': True},
        'time_spent_in_nuage': {'is_visible': True},
        'time_spent_in_core': {'is_visible': True},
        'total_time_spent': {'is_visible': True}
    },
}


class Nuage_plugin_stats(extensions.ExtensionDescriptor):
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
        plugin = manager.NeutronManager.get_service_plugins()[
            nuage_constants.NUAGE_PLUGIN_STATS]
        resource_name = 'nuage_plugin_stats'
        collection_name = resource_name.replace('_', '-')
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name, dict())
        resource_registry.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                          plugin, params, allow_bulk=True)
        return [extensions.ResourceExtension(collection_name, controller)]
