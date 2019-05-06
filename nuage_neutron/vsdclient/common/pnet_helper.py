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


def validate_vlan_id(restproxy_serv, physical_network, vlan_id):
    req_params = {
        'port_id': physical_network
    }
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET', nuage_gw_port.get_resource(),
                                        '')
    if not nuage_gw_port.validate(response):
        raise nuage_gw_port.get_rest_proxy_error()

    gw_port_vlans = restproxy_serv.rest_call('GET', nuage_gw_port.post_vlan(),
                                             '')

    if not nuage_gw_port.validate(gw_port_vlans):
        raise nuage_gw_port.get_rest_proxy_error()

    if gw_port_vlans[3]:
        for vlan in gw_port_vlans[3]:
            if vlan['value'] == vlan_id:
                return False

    return True


def check_gw_enterprise_permissions(restproxy_serv, params):
    nuage_gw = nuagelib.NuageGateway(create_params=params)
    gw_ent_perm_resp = restproxy_serv.rest_call(
        'GET', nuage_gw.get_ent_perm(), '')
    if not nuage_gw.validate(gw_ent_perm_resp):
        raise nuage_gw.get_rest_proxy_error()

    if not gw_ent_perm_resp[VSD_RESP_OBJ]:
        return False
    else:
        # check if gateway has permissions for current net partition
        if gw_ent_perm_resp[VSD_RESP_OBJ][0]['permittedEntityID'] != (
                params['np_id']):
            msg = ("Gateway doesn't have enterprisepermisssions set for "
                   "net_parttion %s") % params['np_id']
            raise Exception(msg)
        return True


def check_gw_port_enterprise_permissions(restproxy_serv, params):
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=params)
    gw_port_ent_perm_response = restproxy_serv.rest_call(
        'GET',
        nuage_gw_port.get_ent_perm(), '')

    if not nuage_gw_port.validate(gw_port_ent_perm_response):
        raise nuage_gw_port.get_rest_proxy_error()

    if not gw_port_ent_perm_response[VSD_RESP_OBJ]:
        return False
    else:
        # check if gateway port has permissions for current net partition
        if gw_port_ent_perm_response[VSD_RESP_OBJ][0]['permittedEntityID'] != (
                params['np_id']):
            msg = ("Gateway port doesn't have enterprisepermisssions"
                   " set for net_parttion %s") % params['np_id']
            raise Exception(msg)
        return True


def get_gw_personality(restproxy_serv, params):
    nuage_gw = nuagelib.NuageGateway(create_params=params)
    gw_resp = restproxy_serv.rest_call('GET', nuage_gw.get_resource_by_id(),
                                       '')
    if not nuage_gw.validate(gw_resp):
        raise nuage_gw.get_rest_proxy_error()
    if gw_resp[VSD_RESP_OBJ]:
        return gw_resp[VSD_RESP_OBJ][0]['personality']


def delete_vlan_for_gw_port(restproxy_serv, vport):
    # Delete vlan obj on gateway port
    nuage_gw_port = nuagelib.NuageGatewayPort()
    nuage_vlan = vport['VLANID']
    restproxy_serv.delete(nuage_gw_port.delete_vlan(nuage_vlan))
