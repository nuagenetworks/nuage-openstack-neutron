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

from neutron.api import extensions as api_extensions
from neutron.api.v2 import resource_helper

from nuage_neutron.plugins.common import constants


RESOURCE_ATTRIBUTE_MAP = {
    'vsd_organisations': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, },
    },
    'vsd_domains': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, },
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, },
        'net_partition_id': {'allow_post': False, 'allow_put': False,
                             'is_visible': True, }
    },
    'vsd_zones': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'vsd_domain_id': {'allow_post': False, 'allow_put': False,
                          'is_visible': True, }
    },
    'vsd_subnets': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True, },
        'cidr': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'ipv6_cidr': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'gateway': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'ipv6_gateway': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        'ip_version': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'net_partition': {'allow_post': False, 'allow_put': False,
                          'is_visible': True},
        'vsd_zone_id': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'linked': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },
}


class Vsd_resource(api_extensions.ExtensionDescriptor):
    """Extension class supporting Vsd_resources."""

    @classmethod
    def get_name(cls):
        return "vsd-resource"

    @classmethod
    def get_alias(cls):
        return "vsd-resource"

    @classmethod
    def get_description(cls):
        return "Vsd Resource"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/vsd_resource/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-04-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.NUAGE_APIS,
                                                   translate_name=True)
