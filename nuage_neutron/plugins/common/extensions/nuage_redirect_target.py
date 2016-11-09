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

import netaddr

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.common import constants as const
from neutron.common import exceptions as nexception
from neutron import manager
from neutron.quota import resource_registry
from neutron_lib import constants as lib_constants
from nuage_neutron.plugins.common import constants as nuage_constants

supported_protocols = [const.PROTO_NAME_TCP,
                       const.PROTO_NAME_UDP, const.PROTO_NAME_ICMP]
PROTO_NAME_TO_NUM = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1
}


class RedirectTargetRuleInvalidPortRange(nexception.InvalidInput):
    message = _("For TCP/UDP protocols, port_range_min must be "
                "<= port_range_max")


class RedirectTargetRuleInvalidPortValue(nexception.InvalidInput):
    message = _("Invalid value for port %(port)s")


class RedirectTargetRuleInvalidIcmpValue(nexception.InvalidInput):
    message = _("Invalid value for ICMP %(field)s (%(attr)s) "
                "%(value)s. It must be 0 to 255.")


class RedirectTargetRuleMissingIcmpType(nexception.InvalidInput):
    message = _("ICMP code (port-range-max) %(value)s is provided"
                " but ICMP type (port-range-min) is missing.")


class RedirectTargetInUse(nexception.InUse):
    message = _("Redirect Group %(id)s in use.")


class RedirectTargetRuleInvalidProtocol(nexception.InvalidInput):
    message = _("Redirect target rule protocol %(protocol)s not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 142) are supported.")


class RedirectTargetRuleProtocolRequiredWithPorts(nexception.InvalidInput):
    message = _("Must also specifiy protocol if port range is given.")


class RedirectTargetRuleRemoteGroupAndRemoteIpPrefix(nexception.InvalidInput):
    message = _("Only remote_ip_prefix or remote_group_id may "
                "be provided.")


class RedirectTargetNoDomainOrL2Domain(nexception.BadRequest):
    message = _("No domain or l2domain found on vsd.")


def convert_to_list_or_none(value_list):
    if value_list == 'None':
        return []
    if value_list:
        values = value_list.split(',')
        return values
    return value_list


def convert_protocol(value):
    if value is None:
        return
    try:
        val = int(value)
        if val >= 0 and val <= 142:
            # Set value of protocol number to string due to bug 1381379,
            # PostgreSQL fails when it tries to compare integer with string,
            # that exists in db.
            return str(value)
        raise RedirectTargetRuleInvalidProtocol(
            protocol=value, values=supported_protocols)
    except (ValueError, TypeError):
        if value.lower() in supported_protocols:
            return PROTO_NAME_TO_NUM[value.lower()]
        raise RedirectTargetRuleInvalidProtocol(
            protocol=value, values=supported_protocols)
    except AttributeError:
        raise RedirectTargetRuleInvalidProtocol(
            protocol=value, values=supported_protocols)


def convert_validate_port_value(port):
    if port is None:
        return port
    try:
        val = int(port)
    except (ValueError, TypeError):
        raise RedirectTargetRuleInvalidPortValue(port=port)

    # VSD requires port number 0 not valid
    if val >= 1 and val <= 65535:
        return val
    else:
        raise RedirectTargetRuleInvalidPortValue(port=port)


def convert_ip_prefix_to_cidr(ip_prefix):
    if not ip_prefix:
        return
    try:
        cidr = netaddr.IPNetwork(ip_prefix)
        return str(cidr)
    except (ValueError, TypeError, netaddr.AddrFormatError):
        raise nexception.InvalidCIDR(input=ip_prefix)


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'nuage_redirect_targets': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'description': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'redundancy_enabled': {'allow_post': True, 'allow_put': False,
                               'is_visible': True, 'default': '',
                               'validate': {'type:boolean': None}},
        'insertion_mode': {'allow_post': True, 'allow_put': False,
                           'is_visible': True, 'default': None,
                           'validate': {'type:string': None}},
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': None,
                      'validate': {'type:uuid_or_none': None}},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': None,
                      'validate': {'type:uuid_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'ports': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
    },
    'nuage_redirect_target_vips': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'virtual_ip_address': {'allow_post': True, 'allow_put': False,
                               'is_visible': True, 'default': None,
                               'validate': {'type:ip_address': None}},
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': None,
                      'validate': {'type:uuid': None}},
        'redirect_target_id': {'allow_post': True, 'allow_put': False,
                               'is_visible': True, 'default': None,
                               'validate': {'type:uuid': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'nuage_redirect_target_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'redirect_target_id': {'allow_post': True, 'allow_put': False,
                               'is_visible': True, 'default': None,
                               'validate': {'type:uuid': None}},
        'remote_group_id': {'allow_post': True, 'allow_put': False,
                            'default': None, 'is_visible': True},
        'origin_group_id': {'allow_post': True, 'allow_put': False,
                            'default': None, 'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol},
        'priority': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None},
        'action': {'allow_post': True, 'allow_put': False,
                   'is_visible': True, 'default': None},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'remote_ip_prefix': {'allow_post': True, 'allow_put': False,
                             'default': None, 'is_visible': True,
                             'convert_to': convert_ip_prefix_to_cidr},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    }
}


REDIRECTTARGETS = 'nuage_redirect_targets'
NOREDIRECTTARGETS = 'no_nuage_redirect_targets'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        REDIRECTTARGETS: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'convert_to': convert_to_list_or_none,
            'default': lib_constants.ATTR_NOT_SPECIFIED
        }
    }
}


class Nuage_redirect_target(extensions.ExtensionDescriptor):
    """Extension class supporting Redirect Target."""

    @classmethod
    def get_name(cls):
        return "Nuage RedirectTarget"

    @classmethod
    def get_alias(cls):
        return "nuage-redirect-target"

    @classmethod
    def get_description(cls):
        return "Nuage RedirectTarget"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/redirecttarget/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_service_plugins()[
            nuage_constants.NUAGE_PORT_ATTRIBUTES_SERVICE_PLUGIN]
        for resource_name in ['nuage_redirect_target',
                              'nuage_redirect_target_rule',
                              'nuage_redirect_target_vip']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            resource_registry.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True)
            ex = extensions.ResourceExtension(collection_name,
                                              controller)
            exts.append(ex)

        return exts

    @classmethod
    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}
