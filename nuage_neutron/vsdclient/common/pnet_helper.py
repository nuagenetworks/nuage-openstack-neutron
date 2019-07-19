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

import logging

from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import nuagelib

VSD_RESP_OBJ = constants.VSD_RESP_OBJ
UUID_PATTERN = constants.UUID_PATTERN

LOG = logging.getLogger(__name__)


def validate_provider_phy_net(restproxy_serv, physical_network):
    req_params = {
        'port_id': physical_network
    }
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
    gw_port = restproxy_serv.get(nuage_gw_port.get_resource(),
                                 required=True)[0]
    return gw_port['portType'] == "ACCESS"


def check_gw_enterprise_permissions(restproxy_serv, params):
    nuage_gw = nuagelib.NuageGateway(create_params=params)
    ent_perms = restproxy_serv.get(nuage_gw.get_ent_perm(),
                                   required=True)
    if not ent_perms:
        return False
    else:
        # check if gateway has permissions for current net partition
        if ent_perms[0]['permittedEntityID'] != (
                params['np_id']):
            msg = ("Gateway doesn't have enterprisepermisssions set for "
                   "net_parttion %s") % params['np_id']
            raise Exception(msg)
        return True


def check_gw_port_enterprise_permissions(restproxy_serv, params):
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=params)
    permissions = restproxy_serv.get(nuage_gw_port.get_ent_perm(),
                                     required=True)
    if not permissions:
        return False
    else:
        # check if gateway port has permissions for current net partition
        if permissions[0]['permittedEntityID'] != (params['np_id']):
            msg = ("Gateway port doesn't have enterprisepermisssions"
                   " set for net_parttion %s") % params['np_id']
            raise Exception(msg)
        return True


def get_gw_personality(restproxy_serv, params):
    nuage_gw = nuagelib.NuageGateway(create_params=params)
    gws = restproxy_serv.get(nuage_gw.get_resource_by_id(),
                             required=True)
    return gws[0]['personality'] if gws else None


def delete_vlan_for_gw_port(restproxy_serv, vport):
    # Delete vlan obj on gateway port
    nuage_gw_port = nuagelib.NuageGatewayPort()
    nuage_vlan = vport['VLANID']
    restproxy_serv.delete(nuage_gw_port.delete_vlan(nuage_vlan))
