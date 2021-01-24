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

DEVICE_OWNER_VIP_NUAGE = 'nuage:vip'

DEVICE_OWNER_IRONIC = 'compute:ironic'

DEVICE_OWNER_DHCP_NUAGE = "network:dhcp:nuage"

DEVICE_OWNER_OCTAVIA_HEALTHMGR = "Octavia:health-mgr"

DEVICE_OWNER_OCTAVIA = "Octavia"

VIPS_FOR_PORT_IPS = 'vips_for_port_ips'

DHCP_OPTION_NAME_TO_NUMBER = {
    4: {
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
        'server-ip-address': 255},
    6: {
        'dns-server': 23,
        'domain-search': 24
    }
}

MIN_MECH_NUAGE_SERVICE_PLUGINS_IN_CONFIG = {
    'NuageL3':
        'nuage_neutron.plugins.common.'
        'service_plugins.l3.NuageL3Plugin',
    'NuageAPI': 'nuage_neutron.plugins.common.service_plugins.'
                'nuage_apis.NuageApi',
    'NuagePortAttributes': 'nuage_neutron.plugins.common.'
                           'service_plugins.port_attributes.'
                           'service_plugin.'
                           'NuagePortAttributesServicePlugin'}

MIN_MECH_NUAGE_EXTENSIONS_IN_CONFIG = {
    'nuage_network': 'nuage_neutron.plugins.'
                     'nuage_ml2.nuage_network_ext_driver.'
                     'NuageNetworkExtensionDriver',
    'nuage_subnet': 'nuage_neutron.plugins.'
                    'nuage_ml2.nuage_subnet_ext_driver.'
                    'NuageSubnetExtensionDriver',
    'nuage_port': 'nuage_neutron.plugins.nuage_ml2.'
                  'nuage_port_ext_driver.NuagePortExtensionDriver',
    'port_security': 'neutron.plugins.ml2.extensions.port_security.'
                     'PortSecurityExtensionDriver'}

MECH_NUAGE = {'nuage': 'nuage_neutron.plugins.nuage_ml2.mech_nuage.'
                       'NuageMechanismDriver'}

NOVA_PORT_OWNER_PREF = 'compute:'

SR_TYPE_FLOATING = "FLOATING"

SHARED_INFRASTRUCTURE = 'Shared Infrastructure'
SHARED_DOMAIN_TEMPLATE = 'Shared Domain template'
SHARED_ZONE_TEMPLATE = 'Shared Zone template'
SHARED_FIP_UNDERLAY_ENABLED_DOMAIN_NAME = 'Shared FIP-Underlay Enabled Domain'

DEF_L3DOM_TEMPLATE_PFIX = '_def_L3_Template'
DEF_L2DOM_TEMPLATE_PFIX = '_def_L2_Template'
DEF_NUAGE_ZONE_PREFIX = 'def_zone'
SOFTWARE = 'SOFTWARE'
HARDWARE = 'HARDWARE'

L2DOMAIN = 'l2domain'
DOMAIN = 'domain'
SUBNET = 'subnet'
VPORT = 'VPORT'
BRIDGE_VPORT_TYPE = 'BRIDGE'
HOST_VPORT = 'HOST'
VM_VPORT = 'VM'

MAX_VSD_INTEGER = 2147483647  # Maximum Java integer value. 2^31-1
MAX_VSD_PRIORITY = 999999999

MAX_SG_PER_PORT = 30

NUAGE_UNDERLAY_SNAT = 'snat'
NUAGE_UNDERLAY_ROUTE = 'route'
NUAGE_UNDERLAY_OFF = 'off'
NUAGE_UNDERLAY_NOT_AVAILABLE = 'not_available'
NUAGE_UNDERLAY_INHERITED = 'inherited'

NUAGE_UNDERLAY_FIP = 'fip'

NUAGE_UNDERLAY = 'nuage_underlay'
NUAGE_UNDERLAY_INI = 'nuage_underlay_default'

AGGREGATE_FLOWS = 'nuage_aggregate_flows'
AGGREGATE_FLOWS_OFF = 'off'
AGGREGATE_FLOWS_PBR = 'pbr'
AGGREGATE_FLOWS_ROUTE = 'route'

RES_NOT_FOUND = 404
RES_CONFLICT = 409

NETWORK_MACRO_IP_PREFIX_ERROR_CODE = '2529'
NETWORK_MACRO_IP_HOST_BITS_ERROR_CODE = '2526'

# Following are the VSD internal error codes for
# invalid CIDR in network macros.
NOT_SUPPORTED_NW_MACRO = [NETWORK_MACRO_IP_PREFIX_ERROR_CODE,
                          NETWORK_MACRO_IP_HOST_BITS_ERROR_CODE]

ENABLED = 'ENABLED'
DISABLED = 'DISABLED'

IP_TYPE_IPV4 = 'IPV4'
IP_TYPE_IPV6 = 'IPV6'

NUAGE_APIS = 'NUAGE_APIS'
NUAGE_L3_SERVICE_PLUGIN = 'NUAGE_L3_PLUGIN'
NUAGE_NET_TOPOLOGY_SERVICE_PLUGIN = 'NUAGE_NET_TOPOLOGY'
NUAGE_PORT_ATTRIBUTES_SERVICE_PLUGIN = 'NUAGE_PORT_ATTRIBUTES_SERVICES'
NUAGE_PLUGIN_STATS = 'NUAGE_PLUGIN_STATS'
NUAGE_L2BRIDGE_SERVICE_PLUGIN = 'NUAGE_L2BRIDGE'
NUAGE_IPRESERVATIONS_SERVICE_PLUGIN = 'NUAGE_IPRESERVATION'

NUAGE_ML2_DRIVER_NAME = 'nuage'
NUAGE_ML2_SRIOV_DRIVER_NAME = 'nuage_sriov'
NUAGE_ML2_BM_DRIVER_NAME = 'nuage_baremetal'
NUAGE_ML2_HWVTEP_DRIVER_NAME = 'nuage_hwvtep'

AFTER_CREATE = 'after_create_nuage'
AFTER_UPDATE = 'after_update_nuage'
AFTER_DELETE = 'after_delete_nuage'
BEFORE_UPDATE = 'before_update_nuage'
BEFORE_CREATE = 'before_create_nuage'

DEBUG_API_STATS = "api_stats"
DEBUG_TIMING_STATS = "timing_stats"

SFC_PARAMS = 'service_function_parameters'

L2BRIDGE_SUBNET_EQUAL_ATTRIBUTES = ['cidr', 'gateway_ip', 'enable_dhcp',
                                    'ipv6_ra_mode', 'ipv6_address_mode',
                                    'host_routes', 'dns_nameservers']

VSD_MANAGED_SUBNET_UPDATABLE_ATTRIBUTES = {"name", "description",
                                           "allocation_pools", "updated_at",
                                           "revision_number"}

NUAGE_HYBRID_MPLS_NET_TYPE = 'nuage_hybrid_mpls'
