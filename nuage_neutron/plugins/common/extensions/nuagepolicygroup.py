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

from oslo_log import log as logging

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.quota import resource_registry
from neutron_lib.api import converters as lib_converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators as lib_validators
from neutron_lib import constants as lib_constants
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import constants as nuage_constants

LOG = logging.getLogger(__name__)


def validate_port_policy_groups(nuage_policy_groups, valid_values=None):
    if not isinstance(nuage_policy_groups, list):
        msg = _("'%s' is not a list") % nuage_policy_groups
        LOG.debug(msg)
        return msg

lib_validators.add_validator('type:validate_port_policy_groups',
                             validate_port_policy_groups)

NUAGE_POLICY_GROUPS = 'nuage_policy_groups'
RESOURCE_ATTRIBUTE_MAP = {
    NUAGE_POLICY_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'description': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'scope': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
        'evpn_tag': {'allow_post': False, 'allow_put': False,
                     'is_visible': True},
        'pg_id': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
        'ports': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
    },
}
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        NUAGE_POLICY_GROUPS: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'convert_to': lib_converters.convert_none_to_empty_list,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'validate': {'type:validate_port_policy_groups': None},
        }
    }
}


class Nuagepolicygroup(api_extensions.ExtensionDescriptor):
    """Extension class supporting Nuage policy groups."""

    @classmethod
    def get_name(cls):
        return "nuage policygroup"

    @classmethod
    def get_alias(cls):
        return "nuage-policy-group"

    @classmethod
    def get_description(cls):
        return "The nuage-policy-groups extension"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/policygroups/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2016-01-21T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = directory.get_plugin(
            nuage_constants.NUAGE_PORT_ATTRIBUTES_SERVICE_PLUGIN)
        resource_name = 'nuage_policy_group'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        resource_registry.register_resource_by_name(resource_name)
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
