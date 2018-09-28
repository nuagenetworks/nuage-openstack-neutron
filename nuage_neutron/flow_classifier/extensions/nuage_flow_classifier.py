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

from networking_sfc._i18n import _
from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as neutron_exc


class FlowClassifierInvalidVlanValue(neutron_exc.InvalidInput):
    message = _("Flow Classifier has invalid vlan value %(vlan)s.")


def normalize_vlan_value(vlan):
    if vlan is None:
        return None
    try:
        val = int(vlan)
    except (ValueError, TypeError):
        raise FlowClassifierInvalidVlanValue(vlan=vlan)

    if lib_constants.MIN_VLAN_TAG <= val <= lib_constants.MAX_VLAN_TAG:
        return val
    else:
        raise FlowClassifierInvalidVlanValue(vlan=vlan)


EXTENDED_ATTRIBUTES_2_0 = {
    'flow_classifiers': {
        'vlan_range_min': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'convert_to': normalize_vlan_value,
            'enforce_policy': True
        },
        'vlan_range_max': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'convert_to': normalize_vlan_value,
            'enforce_policy': True
        },
    }
}


class Nuage_flow_classifier(api_extensions.ExtensionDescriptor):
    """Extension class supporting nuage flow classifier."""

    @classmethod
    def get_name(cls):
        return "Nuage flow classifier"

    @classmethod
    def get_alias(cls):
        return "nuage-flow-classifier"

    @classmethod
    def get_description(cls):
        return "Nuage Flow Classifier"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
