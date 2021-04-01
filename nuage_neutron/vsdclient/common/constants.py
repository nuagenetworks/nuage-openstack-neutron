# Copyright 2016 NOKIA
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

REST_SUCCESS_CODES = range(200, 300)
DEF_OPENSTACK_USER = 'os_user'
DEF_OPENSTACK_USER_EMAIL = 'osuser@nuage-openstack.com'
REST_SERV_UNAVAILABLE_CODE = 503
REST_SERV_INTERNAL_ERROR = 500

VSD_RESP_OBJ = 3
CONFLICT_ERR_CODE = 409
RES_NOT_FOUND = 404
RES_EXISTS_INTERNAL_ERR_CODE = '2510'
SUBNET_NAME_DUPLICATE_ERROR = '2505'
VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = '2039'
VSD_IP_IN_USE_ERR_CODE = '2704'
VSD_PRIORITY_CONFLICT_ERR_CODE = '2591'
VSD_VM_ALREADY_RESYNC = '2715'
VSD_VM_EXISTS_ON_VPORT = '7010'
VSD_VM_EXIST = '2506'
VSD_VPORT_ATTACHED_NET_ID_CHANGED = '2747'
VSD_PG_IN_USE = '7097'
PG_VPORT_DOMAIN_CONFLICT = '7309'
VSD_SUBNET_FULL = '2702'
VSD_DUPLICATE_VMIPRESERVATION = '7205'

PATCH_ADD = 'add'
PATCH_REMOVE = 'remove'
PATCH_CHOICES = [PATCH_ADD, PATCH_REMOVE]


NUAGE_ACL_INGRESS = 'ingress'
NUAGE_ACL_EGRESS = 'egress'
NUAGE_ACL_INGRESS_TEMPLATE = 'ingressacltemplate'
NUAGE_ACL_EGRESS_TEMPLATE = 'egressacltemplate'
NUAGE_DEFAULT_L2_INGRESS_ACL = '_def_ibl2acl'
NUAGE_DEFAULT_L2_EGRESS_ACL = '_def_obl2acl'
NUAGE_DEFAULT_L3_INGRESS_ACL = '_def_ibl3acl'
NUAGE_DEFAULT_L3_EGRESS_ACL = '_def_obl3acl'

# need to better integrate this ...
# --- also , these are in HEX ! ---
DHCP_OPTIONS = {
    4: {
        'gateway_ip': '03',
        'dns_nameservers': '06',
        'classless-static-route': '79',  # 121
        'microsoft-classless-static-route': 'f9'  # 249
    },
    6: {
        'dns_nameservers': '17'  # 23
    }
}
DHCP_ROUTER_OPTION = '03'

# these options, the user needs to enter as hex
PRCS_DHCP_OPT_AS_RAW_HEX = {
    4: [46, 77, 94, 97, 121, 125, 255],
    6: []}

NOVA_PORT_OWNER_PREF = 'compute:'

TEMPLATE_ISOLATED_ZONE = 'openstack-isolated'
TEMPLATE_SHARED_ZONE = 'openstack-shared'

NOT_SUPPORTED_ACL_ATTR_MSG = "ethertype value: %s not supported by nuage " \
                             "plugin"
NUAGE_ACL_PROTOCOL_ANY_MAPPING = ['tcp', 'udp']
RES_POLICYGROUPS = 'policygroups'

AUDIT_LOG_DIRECTORY = '/nuageaudit'
AUDIT_LOG_FILENAME = '/audit.log'

HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])

NETWORK_TYPE_L2 = 'l2'
NETWORK_TYPE_L3 = 'l3'

IPV4_ETHERTYPE = '0x0800'
IPV6_ETHERTYPE = '0x86DD'

DUALSTACK = "DUALSTACK"
IPV4 = "IPV4"
IPV6 = "IPV6"
OS_IPV4 = "IPv4"
OS_IPV6 = "IPv6"

NUAGE_SUPPORTED_ETHERTYPES = [OS_IPV4, OS_IPV6]
NUAGE_SUPPORTED_ETHERTYPES_IN_HEX = [IPV4_ETHERTYPE, IPV6_ETHERTYPE]

ANY_IPV4_IP = '0.0.0.0/0'
ANY_IPV6_IP = '::/0'

IPV4_VERSION = 4
IPV6_VERSION = 6


NUAGE_PAT_DEF_ENABLED = 'default_enabled'
NUAGE_PAT_DEF_DISABLED = 'default_disabled'

ENTERPRISE = 'enterprise'
ENABLED = 'ENABLED'
DISABLED = 'DISABLED'
BRIDGE_VPORT_TYPE = 'BRIDGE'
HOST_VPORT_TYPE = 'HOST'
DOMAIN = 'domain'
L2DOMAIN = 'l2domain'
SUBNET = 'subnet'
ASSIGN_VLAN = 'assign'
UNASSIGN_VLAN = 'unassign'
SOFTWARE = 'SOFTWARE'
HARDWARE = 'HARDWARE'
VPORT = 'VPORT'
SW_GW_TYPES = ['VRSG', 'VRSB']
# HW_GW_TYPES = ... all the rest, no need to hardcode here
REDUNDANT_ESGW = 'ETHERNET_SEGMENT_GW_GROUP'
REDUNDANT_RG = 'REDUNDANCY_GROUP'
SINGLE_GW = 'SINGLE_GW'
VSD_GW_REDUNDANCY_TYPES = [SINGLE_GW, REDUNDANT_RG, REDUNDANT_ESGW]
VSD_TUNNEL_TYPES = {
    'VXLAN': 'VXLAN',
    'MPLS': 'MPLS',
    'GRE': 'GRE',
    'DEFAULT': 'DC_DEFAULT'
}

INFINITY = 'INFINITY'

TIER_STANDARD = 'STANDARD'
TIER_NETWORK_MACRO = 'NETWORK_MACRO'
TIER_APPLICATION = 'APPLICATION'
TIER_APPLICATION_EXTENDED_NETWORK = 'APPLICATION_EXTENDED_NETWORK'

NUAGE_LDAP_MODE = 'CMS'

NUAGE_PLCY_GRP_ALLOW_ALL = 'PG_ALLOW_ALL'
PORTSECURITY = 'port_security_enabled'

NUAGE_PERMISSION_USE = 'USE'
NUAGE_PERMISSION_READ = 'READ'
NUAGE_PERMISSION_ALL = 'ALL'
NUAGE_PERMISSION_EXTEND = 'EXTEND'
NUAGE_PERMISSION_DEPLOY = 'DEPLOY'
NUAGE_PERMISSION_INSTANTIATE = 'INSTANTIATE'

MAX_BULK_PUT = 500
MAX_BULK_DELETE = 150

# Translate Openstack direction definition to
# VSD direction defintion (opposite).
DIRECTIONS_OS_VSD = {'egress': 'ingress',
                     'ingress': 'egress'}
