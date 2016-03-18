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

from neutron.common import constants


DEVICE_OWNER_VIP_NUAGE = 'nuage:vip'

DEVICE_OWNER_IRONIC = 'compute:ironic'

AUTO_CREATE_PORT_OWNERS = [
    constants.DEVICE_OWNER_DHCP,
    constants.DEVICE_OWNER_ROUTER_INTF,
    constants.DEVICE_OWNER_ROUTER_GW,
    constants.DEVICE_OWNER_FLOATINGIP,
    DEVICE_OWNER_VIP_NUAGE,
    DEVICE_OWNER_IRONIC
]

DHCP_OPTION_NAME_TO_NUMBER = {
    'netmask': 1,
    'time-offset': 2,
    'router': 3,
    'time-server': 4,
    'dns-server': 6,
    'log-server': 7,
    'lpr-server': 9,
    'hostname': 12,
    'boot-file-size': 13,
    'domain-name': 15,
    'swap-server': 16,
    'root-path': 17,
    'extension-path': 18,
    'ip-forward-enable': 19,
    'non-local-source-routing': 20,
    'policy-filter': 21,
    'max-datagram-reassembly': 22,
    'default-ttl': 23,
    'mtu': 26,
    'all-subnets-local': 27,
    'broadcast': 28,
    'router-discovery': 31,
    'router-solicitation': 32,
    'static-route': 33,
    'trailer-encapsulation': 34,
    'arp-timeout': 35,
    'ethernet-encap': 36,
    'tcp-ttl': 37,
    'tcp-keepalive': 38,
    'nis-domain': 40,
    'nis-server': 41,
    'ntp-server': 42,
    'netbios-ns': 44,
    'netbios-dd': 45,
    'netbios-nodetype': 46,
    'netbios-scope': 47,
    'x-windows-fs': 48,
    'x-windows-dm': 49,
    'requested-address': 50,
    'vendor-class': 60,
    'nis+-domain': 64,
    'nis+-server': 65,
    'tftp-server': 66,
    'bootfile-name': 67,
    'mobile-ip-home': 68,
    'smtp-server': 69,
    'pop3-server': 70,
    'nntp-server': 71,
    'irc-server': 74,
    'user-class': 77,
    'client-arch': 93,
    'client-interface-id': 94,
    'client-machine-id': 97,
    'domain-search': 119,
    'sip-server': 120,
    'classless-static-route': 121,
    'vendor-id-encap': 125,
    'server-ip-address': 255
}

NOVA_PORT_OWNER_PREF = 'compute:'

SR_TYPE_FLOATING = "FLOATING"

DEVICE_OWNER_DHCP_NUAGE = "network:dhcp:nuage"

DEF_L3DOM_TEMPLATE_PFIX = '_def_L3_Template'
DEF_L2DOM_TEMPLATE_PFIX = '_def_L2_Template'
DEF_NUAGE_ZONE_PREFIX = 'def_zone'
SOFTWARE = 'SOFTWARE'

HOST_VPORT = 'HOST'
VM_VPORT = 'VM'
APPD_PORT = 'appd'

TIER_STANDARD = 'STANDARD'
TIER_NETWORK_MACRO = 'NETWORK_MACRO'
TIER_APPLICATION = 'APPLICATION'
TIER_APPLICATION_EXTENDED_NETWORK = 'APPLICATION_EXTENDED_NETWORK'

MAX_VSD_INTEGER = 2147483647  # Maximum Java integer value. 2^31-1

NUAGE_PAT_NOT_AVAILABLE = 'not_available'
NUAGE_PAT_DEF_ENABLED = 'default_enabled'
NUAGE_PAT_DEF_DISABLED = 'default_disabled'

RES_NOT_FOUND = 404
RES_CONFLICT = 409

L2DOMAIN = 'L2Domain'
L3SUBNET = 'Subnet'
ENABLED = 'ENABLED'
DISABLED = 'DISABLED'
INHERITED = 'INHERITED'

AFTER_UPDATE = 'after_update_nuage'
