# Copyright 2015 Alcatel-Lucent USA Inc.
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
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as nexception
from neutron import manager
from neutron import quota


class GatewayInvalidVlanValue(nexception.InvalidInput):
    message = _("Invalid value for vlan %(vlan)s. It must be 0 to 4094.")


def convert_validate_vlan_value(vlan):
    if vlan is None:
        raise GatewayInvalidVlanValue(vlan=None)
    try:
        val = int(vlan)
    except (ValueError, TypeError):
        raise GatewayInvalidVlanValue(vlan=vlan)

    if 0 <= val <= 4094:
        return val
    else:
        raise GatewayInvalidVlanValue(vlan=val)

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'nuage_gateways': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'type': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'template': {'allow_post': False, 'allow_put': False,
                     'validate': {'type:string': None},
                     'is_visible': True},
        'systemid': {'allow_post': False, 'allow_put': False,
                     'validate': {'type:string': None},
                     'is_visible': True},
    },
    'nuage_gateway_ports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'vlan': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'usermnemonic': {'allow_post': False, 'allow_put': False,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'physicalname': {'allow_post': False, 'allow_put': False,
                         'validate': {'type:string': None},
                         'is_visible': True},
    },

    'nuage_gateway_vlans': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'value': {'allow_post': True, 'allow_put': False,
                  'convert_to': convert_validate_vlan_value,
                  'default': None, 'is_visible': True},
        'action': {'allow_post': True, 'allow_put': True,
                   'is_visible': True, 'default': None,
                   'validate': {'type:values': [None, 'assign', 'unassign']}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'gateway': {'allow_post': True, 'allow_put': False,
                    'required_by_policy': True, 'default': None,
                    'is_visible': True},
        'gatewayport': {'allow_post': True, 'allow_put': False,
                        'required_by_policy': True,
                        'is_visible': True},
        'tenant': {'allow_post': False, 'allow_put': True,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'vport': {'allow_post': False, 'allow_put': False,
                  'validate': {'type:uuid': None},
                  'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'usermnemonic': {'allow_post': False, 'allow_put': False,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'assigned': {'allow_post': False, 'allow_put': False,
                     'validate': {'type:string': None},
                     'is_visible': True},
    },
    'nuage_gateway_vports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'type': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'interface': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'gatewayvlan': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:uuid': None},
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'subnet': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:uuid_or_none': None}, 'default': None,
                   'is_visible': True},
        'port': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:uuid_or_none': None}, 'default': None,
                 'is_visible': True},
        'tenant': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'gateway': {'allow_post': False, 'allow_put': False,
                    'required_by_policy': True, 'default': None,
                    'is_visible': True},
        'gatewayport': {'allow_post': False, 'allow_put': False,
                        'required_by_policy': True,
                        'is_visible': True},
        'vlan': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:string': None},
                 'default': None, 'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:string': None},
                 'default': None, 'is_visible': True},
    }
}


class Nuagegateway(object):
    """Extension class supporting gateway.
    """

    @classmethod
    def get_name(cls):
        return "nuage-gateway"

    @classmethod
    def get_alias(cls):
        return "nuage-gateway"

    @classmethod
    def get_description(cls):
        return "Nuage Gateway"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/gateway/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['nuage_gateway', 'nuage_gateway_port',
                              'nuage_gateway_vlan',
                              'nuage_gateway_vport']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            quota.QUOTAS.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True)
            ex = extensions.ResourceExtension(collection_name,
                                              controller)
            exts.append(ex)

        return exts