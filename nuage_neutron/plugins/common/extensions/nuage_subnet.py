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

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants as lib_constants

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc


def convert_nuage_underlay(value):
    if value is None:
        return None
    try:
        value = value.lower()
        assert value in [constants.NUAGE_UNDERLAY_OFF,
                         constants.NUAGE_UNDERLAY_ROUTE,
                         constants.NUAGE_UNDERLAY_SNAT,
                         constants.NUAGE_UNDERLAY_INHERITED]
    except Exception:
        msg = "Possible values for {} are: {}, {}, {}, {}.".format(
            constants.NUAGE_UNDERLAY,
            constants.NUAGE_UNDERLAY_OFF,
            constants.NUAGE_UNDERLAY_ROUTE,
            constants.NUAGE_UNDERLAY_SNAT,
            constants.NUAGE_UNDERLAY_INHERITED
        )
        raise nuage_exc.NuageBadRequest(msg=msg)
    return value


EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        'net_partition': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'validate': {'type:string_or_none': None}
        },
        'nuagenet': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'validate': {'type:uuid_or_none': None}
        },
        'underlay': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'convert_to': converters.convert_to_boolean_if_not_none,
        },
        'vsd_managed': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'enforce_policy': True
        },
        'nuage_uplink': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': None,
            'validate': {'type:uuid_or_none': None}
        },
        'vsd_id': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'enforce_policy': True
        },
        'nuage_net_partition_id': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'enforce_policy': True
        },
        'nuage_underlay': {
            'allow_post': False,
            'allow_put': True,
            'is_visible': True,
            'enforce_policy': True,
            'convert_to': convert_nuage_underlay
        },
        'nuage_l2bridge': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'enforce_policy': True
        }
    },
}


class Nuage_subnet(api_extensions.ExtensionDescriptor):
    """Extension class supporting Nuage subnet."""

    @classmethod
    def get_name(cls):
        return "Nuage subnet"

    @classmethod
    def get_alias(cls):
        return "nuage-subnet"

    @classmethod
    def get_description(cls):
        return "Nuage subnet"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/subnets/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
