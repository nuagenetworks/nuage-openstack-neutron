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

from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions as api_extensions

from nuage_neutron.plugins.common import constants

NET_PARTITIONS = 'net_partitions'
PROJECT_NET_PARTITIONS = 'project_net_partition_mappings'

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    NET_PARTITIONS: {
        'id': {
            'allow_post': False,
            'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True
        },
        'name': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': '',
            'validate': {'type:name_not_default': None},
            'enforce_policy': True
        },
        'description': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': '',
            'validate': {'type:string_or_none': None},
            'enforce_policy': True
        },
        'tenant_id': {
            'allow_post': True,
            'allow_put': False,
            'required_by_policy': True,
            'is_visible': True
        },
    },
    PROJECT_NET_PARTITIONS: {
        # Project acts as implicit id here
        'id': {
            'allow_post': False,
            'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': False
        },
        'project': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': None,
            'validate': {'type:string': None},
            'enforce_policy': True
        },
        'net_partition_id': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': None,
            'validate': {'type:string': None},
            'enforce_policy': True
        },
        'tenant_id': {
            'allow_post': True,
            'allow_put': False,
            'required_by_policy': True,
            'is_visible': False
        },
    }
}


class Netpartition(api_extensions.ExtensionDescriptor):
    """Extension class supporting net_partition."""

    @classmethod
    def get_name(cls):
        return "NetPartition"

    @classmethod
    def get_alias(cls):
        return "net-partition"

    @classmethod
    def get_description(cls):
        return "NetPartition"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/net_partition/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.NUAGE_APIS,
                                                   translate_name=True)
