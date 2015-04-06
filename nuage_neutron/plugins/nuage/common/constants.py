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

AUTO_CREATE_PORT_OWNERS = [
    constants.DEVICE_OWNER_DHCP,
    constants.DEVICE_OWNER_ROUTER_INTF,
    constants.DEVICE_OWNER_ROUTER_GW,
    constants.DEVICE_OWNER_FLOATINGIP,
    DEVICE_OWNER_VIP_NUAGE
]

NOVA_PORT_OWNER_PREF = 'compute:'

SR_TYPE_FLOATING = "FLOATING"

DEVICE_OWNER_DHCP_NUAGE = "network:dhcp:nuage"

DEF_L3DOM_TEMPLATE_PFIX = '_def_L3_Template'
DEF_L2DOM_TEMPLATE_PFIX = '_def_L2_Template'
DEF_NUAGE_ZONE_PREFIX = 'def_zone'

HOST_VPORT = 'HOST'
VM_VPORT = 'VM'
APPD_PORT = 'appd'

TIER_STANDARD = 'STANDARD'
TIER_NETWORK_MACRO = 'NETWORK_MACRO'
TIER_APPLICATION = 'APPLICATION'
TIER_APPLICATION_EXTENDED_NETWORK = 'APPLICATION_EXTENDED_NETWORK'
