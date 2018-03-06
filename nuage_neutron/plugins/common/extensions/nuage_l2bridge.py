# Copyright 2018 NOKIA
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

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager
from neutron.quota import resource_registry
from neutron_lib.api import converters as lib_converters
from neutron_lib.api import validators as lib_validators
from neutron_lib import constants as lib_constants

from nuage_neutron.plugins.common import constants as nuage_constants
from nuage_neutron.plugins.common import exceptions as nuage_exc

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'nuage_l2bridges': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'nuage_subnet_id': {'allow_post': False, 'allow_put': False,
                            'is_visible': True, 'default': ''},
        'networks': {'allow_post': False, 'allow_put': False,
                     'is_visible': True, 'default': ''},
        'physnets': {'allow_post': True, 'allow_put': True,
                     'default': lib_constants.ATTR_NOT_SPECIFIED,
                     'convert_list_to':
                         lib_converters.convert_kvp_list_to_dict,
                     'validate': {'type:physnets': None},
                     'enforce_policy': True,
                     'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}
    }
}


def _validate_physnets(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for Physnets: '%s'") % data
        raise nuage_exc.NuageBadRequest(msg=msg)

    for physnet in data:
        if not isinstance(physnet, dict):
            msg = _("Invalid data format for physnet: '%s'") % physnet
            raise nuage_exc.NuageBadRequest(msg=msg)

        if 'physnet_name' not in physnet:
            msg = _("physnet_name is a required parameter: '%s'") % physnet
            raise nuage_exc.NuageBadRequest(msg=msg)
        if 'segmentation_id' not in physnet:
            msg = _("segmentaiton_id is a required parameter: '%s'") % physnet
            raise nuage_exc.NuageBadRequest(msg=msg)
        if 'segmentation_type' not in physnet:
            msg = _("segmentation_type is a required parameter: "
                    "'%s'") % physnet
            raise nuage_exc.NuageBadRequest(msg=msg)


lib_validators.add_validator('type:physnets', _validate_physnets)


class Nuage_l2bridge(extensions.ExtensionDescriptor):
    """Extension class supporting Nuage L2bridge."""

    @classmethod
    def get_name(cls):
        return "Nuage L2Bridge"

    @classmethod
    def get_alias(cls):
        return "nuage-l2bridge"

    @classmethod
    def get_description(cls):
        return "Nuage L2Bridge"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/l2bridges/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2018-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = manager.NeutronManager.get_service_plugins()[
            nuage_constants.NUAGE_L2BRIDGE_SERVICE_PLUGIN]
        resource_name = 'nuage_l2bridge'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        resource_registry.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                          plugin, params, allow_bulk=True)
        ex = extensions.ResourceExtension(collection_name, controller)
        return [ex]
