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

from neutron.api.v2 import attributes as attr
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager
from neutron import quota


def convert_nuage_services(value):
    if value is None:
        return
    new_list = []
    for elem in value.split(','):
        new_list.append(elem.strip())
    ret_str = ','.join(new_list)
    return ret_str

nuage_svc_supported_protocols = [const.PROTO_NAME_ICMP, const.PROTO_NAME_TCP,
                                 const.PROTO_NAME_UDP]

nuage_svc_supported_protocol_num = [const.PROTO_NUM_ICMP, const.PROTO_NUM_TCP,
                                    const.PROTO_NUM_UDP]

nuage_svc_supported_dscp = range(0, 64)

nuage_svc_supported_port = range(1, 65536)

nuage_svc_supported_protocols_map = {
    'tcp': const.PROTO_NUM_TCP,
    'udp': const.PROTO_NUM_UDP,
    'icmp': const.PROTO_NUM_ICMP
}

nuage_svc_supported_ethertypes = ['ipv4', 'ipv6', 'arp']

nuage_svc_supported_ethertypes_map = {
    'ipv4': "0x0800",
    'ipv6': "0x86DD",
    'arp': "0x0806"
}


class NuageServiceInvalidProtocol(exceptions.InvalidInput):
    message = _("Nuage Service protocol %(protocol)s not supported. "
                "Only protocol values %(values)s and their integer "
                "representations (1, 6, 17) are supported.")


class NuageServiceInvalidDscp(exceptions.InvalidInput):
    message = _("Nuage Service dscp %(dscp)s not supported. "
                "Only dscp values 0-63 are supported. Default is '*'.")


class NuageServiceInvalidPortValue(exceptions.InvalidInput):
    message = _("Invalid value for port %(port)s. Port must be *,"
                " a single port number, or a port range (1 - 65535).")


class NuageServiceInvalidEtherType(exceptions.InvalidInput):
    message = _("Nuage Service ethertype %(ethertype)s not supported. "
                "Only ethertype values %(values)s and their hex "
                "representations (0x0800, 0x86DD, 0x0806) are supported.")


def convert_dscp(value):
    if value is None:
        return
    if value == '*':
        return value
    try:
        val = int(value)
    except (ValueError, TypeError, AttributeError):
        raise NuageServiceInvalidDscp(
            dscp=value, values=nuage_svc_supported_dscp)
    else:
        if val in nuage_svc_supported_dscp:
            return val
        else:
            raise NuageServiceInvalidDscp(dscp=value,
                                          values=nuage_svc_supported_dscp)


def validate_port(value):
    try:
        val = int(value)
    except (ValueError, TypeError, AttributeError):
        raise NuageServiceInvalidPortValue(
            port=value, values='')
    else:
        if val not in nuage_svc_supported_port:
            raise NuageServiceInvalidPortValue(port=value, values='')


def convert_port(value):
    if value == '*' or value == 'N/A':
        pass
    elif '-' in value:
        for port in value.split('-'):
            validate_port(port)
    else:
        validate_port(value)
    return value


def convert_ethertype(ethertype):
    if ethertype is None:
        return
    if ethertype.lower() in nuage_svc_supported_ethertypes:
        return nuage_svc_supported_ethertypes_map[ethertype.lower()]
    raise NuageServiceInvalidEtherType(ethertype=ethertype,
                                       values=nuage_svc_supported_ethertypes)


def convert_protocol(protocol):
    if protocol is None:
        return
    try:
        if int(protocol) in nuage_svc_supported_protocol_num:
            return str(protocol)
        raise NuageServiceInvalidProtocol(
            protocol=protocol, values=nuage_svc_supported_protocols)
    except (ValueError, TypeError):
        if protocol.lower() in nuage_svc_supported_protocols:
            return nuage_svc_supported_protocols_map[protocol.lower()]
        raise NuageServiceInvalidProtocol(
            protocol=protocol, values=nuage_svc_supported_protocols)
    except AttributeError:
        raise NuageServiceInvalidProtocol(
            protocol=protocol, values=nuage_svc_supported_protocols)

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'appdports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'tier_id': {'allow_post': True, 'allow_put': False,
                    'is_visible': True,
                    'validate': {'type:uuid': None}},
        'mac_address': {'allow_post': False, 'allow_put': False,
                        'default': attr.ATTR_NOT_SPECIFIED,
                        'validate': {'type:mac_address': None},
                        'is_visible': True},
        'fixed_ips': {'allow_post': False, 'allow_put': False,
                      'default': attr.ATTR_NOT_SPECIFIED,
                      'validate': {'type:fixed_ips': None},
                      'is_visible': True},
        'device_id': {'allow_post': False, 'allow_put': False,
                      'default': '', 'is_visible': True},
        'device_owner': {'allow_post': False, 'allow_put': False,
                         'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'applications': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'associateddomainid': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:uuid': None},
                               'is_visible': True},
        'applicationdomain_id': {'allow_post': True, 'allow_put': False,
                                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'application_domains': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'applicationDeploymentPolicy': {'allow_post': False, 'allow_put': False,
                                        'is_visible': True, 'default': '',
                                        'validate': {'type:name_not_default': None}},
        'nuage_domain_template': {'allow_post': True, 'allow_put': False,
                                  'is_visible': True, 'default': None,
                                  'validate': {'type:uuid_or_none': None}},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'flows': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'origin_tier': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:uuid': None},
                        'is_visible': True},
        'dest_tier': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'application_id': {'allow_post': False , 'allow_put': False,
                           'validate': {'type:uuid': None},
                           'is_visible': True},
        'src_addr_overwrite': {'allow_post': True, 'allow_put': False,
                               'is_visible': True, 'default': '',
                               'validate': {'type:string_or_none': None}},
        'dest_addr_overwrite': {'allow_post': True, 'allow_put': False,
                                'is_visible': True, 'default': '',
                                'validate': {'type:string_or_none': None}},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'nuage_services': {'allow_post': True, 'allow_put': False,
                           'is_visible': True, 'default': None,
                           'convert_to': convert_nuage_services},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'services': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol},
        'ethertype': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': "ipv4",
                      'convert_to': convert_ethertype},
        'direction': {'allow_post': True, 'allow_put': False,
                      'default': "REFLEXIVE", 'is_visible': True},
        'dscp': {'allow_post': True, 'allow_put': False,
                 'default': "*", 'is_visible': True,
                 'convert_to': convert_dscp},
        'src_port': {'allow_post': True, 'allow_put': False,
                     'default': "N/A", 'is_visible': True,
                     'convert_to': convert_port},
        'dest_port': {'allow_post': True, 'allow_put': False,
                      'default': "N/A", 'is_visible': True,
                      'convert_to': convert_port},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'tiers': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'app_id': {'allow_post': True, 'allow_put': False,
                   'is_visible': True,
                   'validate': {'type:uuid': None}},
        'fip_pool_id': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED,
                        'validate': {'type:uuid': None}},
        'type': {'allow_post': True, 'allow_put': False,
                 'is_visible': True,
                 'validate': {'type:string_or_none': None}},
        'cidr': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': "N/A",
                 'validate': {'type:string_or_none': None}},
        'associatedappid': {'allow_post': False, 'allow_put': False,
                            'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
}


class Appdesigner(object):
    """Extension class supporting nuage_app_partition.
    """

    @classmethod
    def get_name(cls):
        return "Appdesigner"

    @classmethod
    def get_alias(cls):
        return "appdesigner"

    @classmethod
    def get_description(cls):
        return "Appdesigner"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/appdesigner/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['appdport', 'application', 'application_domain',
                              'flow', 'service', 'tier']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            quota.QUOTAS.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params,
                                              allow_bulk=True)
            ex = extensions.ResourceExtension(collection_name, controller)
            exts.append(ex)
        return exts
