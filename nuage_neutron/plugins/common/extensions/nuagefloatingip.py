# Copyright 2016 Alcatel-Lucent USA Inc.
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
from neutron import quota
from nuage_neutron.plugins.common import constants as nuage_constants


NUAGE_FLOATINGIP = 'nuage_floatingip'
NUAGE_FLOATINGIPS = '%ss' % NUAGE_FLOATINGIP
RESOURCE_ATTRIBUTE_MAP = {
    NUAGE_FLOATINGIPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'floating_ip_address': {'allow_post': False, 'allow_put': False,
                                'is_visible': True},
        'assigned': {'allow_post': False, 'allow_put': False,
                     'is_visible': True}
    },
}
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        NUAGE_FLOATINGIP: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None
        }
    }
}


class Nuagefloatingip(extensions.ExtensionDescriptor):
    """Extension class supporting Nuage Floatingips."""

    @classmethod
    def get_name(cls):
        return "nuage vsd floatingip"

    @classmethod
    def get_alias(cls):
        return "nuage-vsd-floatingip"

    @classmethod
    def get_description(cls):
        return "The nuage-floatingip extension"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/floatingips/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2016-01-21T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_service_plugins()[
            nuage_constants.NUAGE_PORT_ATTRIBUTES_SERVICE_PLUGIN]
        resource_name = 'nuage_floatingip'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        quota.QUOTAS.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                          plugin, params, allow_bulk=True)
        ex = extensions.ResourceExtension(collection_name, controller)
        exts.append(ex)
        return exts

    @classmethod
    def get_extended_resources(cls, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}
