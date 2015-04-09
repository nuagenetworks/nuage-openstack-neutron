# Copyright 2014 Alcatel-Lucent USA Inc.
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

import abc

from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager
from neutron import quota


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'vsd_subnets': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, },
        'cidr': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'gateway': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'tenant_id': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'ip_version': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'net_partition': {'allow_post': False, 'allow_put': False,
                          'is_visible': True},
        'linked': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'DHCP_enabled': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        },
    }

class Vsd_subnet(object):
    """Extension class supporting vsd_subnet.
    """

    @classmethod
    def get_name(cls):
        return "VsdSubnet"

    @classmethod
    def get_alias(cls):
        return "vsd-subnet"

    @classmethod
    def get_description(cls):
        return "VsdSubnet"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/vsd_subnet/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        resource_name = 'vsd_subnet'
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


class VsdSubnetPluginBase(object):
    @abc.abstractmethod
    def get_vsd_subnet(self, context, id, fields=None):
        pass
