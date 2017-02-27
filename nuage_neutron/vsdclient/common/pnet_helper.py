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
import re

from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

VSD_RESP_OBJ = constants.VSD_RESP_OBJ
UUID_PATTERN = constants.UUID_PATTERN

LOG = logging.getLogger(__name__)


def validate_provider_network(restproxy_serv, network_type, physical_network,
                              vlan_id):
    match = re.match(UUID_PATTERN, physical_network)
    if not match:
        msg = ("provider:physical_network should be a valid uuid")
        raise restproxy.RESTProxyError(msg)

    if not validate_provider_phy_net(restproxy_serv, physical_network):
        msg = ("provider:physical_network is not of type ACCESS")
        raise restproxy.RESTProxyError(msg)

    if not validate_vlan_id(restproxy_serv, physical_network, vlan_id):
        msg = ("provider:vlan_id is in use")
        raise restproxy.RESTProxyError(msg)


def validate_provider_phy_net(restproxy_serv, physical_network):
    req_params = {
        'port_id': physical_network
    }
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
    gw_port = restproxy_serv.rest_call('GET', nuage_gw_port.get_resource(), '')
    if not nuage_gw_port.validate(gw_port):
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)

    if gw_port[VSD_RESP_OBJ]:
        if gw_port[VSD_RESP_OBJ][0]['portType'] == "ACCESS":
            return True

    return False


def validate_vlan_id(restproxy_serv, physical_network, vlan_id):
    req_params = {
        'port_id': physical_network
    }
    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET', nuage_gw_port.get_resource(),
                                        '')
    if not nuage_gw_port.validate(response):
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)

    gw_port_vlans = restproxy_serv.rest_call('GET', nuage_gw_port.post_vlan(),
                                             '')

    if not nuage_gw_port.validate(gw_port_vlans):
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)

    if gw_port_vlans[3]:
        for vlan in gw_port_vlans[3]:
            if vlan['value'] == vlan_id:
                return False

    return True


def process_provider_network(restproxy_serv, pg_obj, params):
    pnet_binding = params.get('pnet_binding')
    np_id = params['netpart_id']

    gw_port = pnet_binding['physical_network']
    req_params = {
        'port_id': gw_port,
        'np_id': params['netpart_id']
    }

    nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET', nuage_gw_port.get_resource(),
                                        '')
    if not nuage_gw_port.validate(response):
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)
    nuage_gw_id = nuage_gw_port.get_gw(response)

    gw_params = {
        'gw_id': nuage_gw_id,
        'np_id': params['netpart_id']
    }

    gw_port_ent_perm = False
    gw_ent_perm = check_gw_enterprise_permissions(restproxy_serv, gw_params)
    if not gw_ent_perm:
        gw_port_ent_perm = check_gw_port_enterprise_permissions(
            restproxy_serv, req_params)
    # create vlan on gw port
    vlan_id = pnet_binding['vlan_id']
    response = restproxy_serv.rest_call('POST', nuage_gw_port.post_vlan(),
                                        nuage_gw_port.post_vlan_data(vlan_id))
    if not nuage_gw_port.validate(response):
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)
    nuage_vlan_id = nuage_gw_port.get_response_id(response)
    params['nuage_vlan_id'] = nuage_vlan_id

    # if the enterprise permission is not set for gateway
    # and gateway port,  set enterprise permission for vlan
    # for the current net partition
    if not gw_ent_perm and not gw_port_ent_perm:
        # Add permissions to extend the vlan on gateway port for this np
        req_params = {
            'vlan_id': nuage_vlan_id,
            'np_id': params['netpart_id']
        }
        nuage_vlan = nuagelib.NuageVlan(create_params=req_params)
        response = restproxy_serv.rest_call('POST',
                                            nuage_vlan.get_ent_perm(),
                                            nuage_vlan.ent_perm_update(np_id))
        if not nuage_vlan.validate(response):
            raise restproxy.RESTProxyError(nuage_vlan.error_msg)

    # Get gateway personality, as for gateway of type VSG, policygroup of
    # type hardware to be used
    gw_type = get_gw_personality(restproxy_serv, gw_params)

    params['gw_type'] = gw_type
    create_bridge_vport_iface_for_pnet(restproxy_serv, pg_obj, params)


def create_bridge_vport_iface_for_pnet(restproxy_serv, pg_obj, params):
    l2domain_id = params.get('l2domain_id')
    nuage_subnet_id = params.get('nuage_subnet_id')
    gw_type = params.get('gw_type')
    nuage_vlan_id = params.get('nuage_vlan_id')

    # Create vport of type bridge and attach vlan
    vport_params = {
        'vlan': nuage_vlan_id,
        'type': 'BRIDGE',
        'name': 'Bridge Vport ' + nuage_vlan_id,
        'externalID': params.get('neutron_subnet_id')
    }

    if l2domain_id:
        nuagel2domain = nuagelib.NuageL2Domain()
        vport_response = restproxy_serv.rest_call(
            'POST',
            nuagel2domain.vport_post(l2domain_id),
            nuagel2domain.vport_post_data(vport_params))

        if not nuagel2domain.validate(vport_response):
            raise restproxy.RESTProxyError(nuagel2domain.error_msg)

        if vport_response[VSD_RESP_OBJ]:
            vport_id = vport_response[VSD_RESP_OBJ][0]['ID']
        # Create Bridge interface in the vport
        nuage_vport = nuagelib.NuageVPort()

        bridge_iface = restproxy_serv.rest_call(
            'POST', nuage_vport.post_bridge_interface(vport_id),
            nuage_vport.post_bridge_iface_data(
                constants.L2DOMAIN.upper(),
                "BRIDGE INTERFACE(" + vport_id + ")",
                params.get('neutron_subnet_id')))
        if not nuage_vport.validate(bridge_iface):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        # Create a policygroup for this bridge vport and create default rules
        nuage_policygroup_id = \
            pg_obj.create_policygroup_default_allow_any_rule(
                l2domain_id, None, params.get('neutron_subnet_id'), gw_type)
        # Add vport to the policygroup
        pg_obj.update_vport_policygroups(vport_id, [nuage_policygroup_id])
    else:
        nuage_subnet = nuagelib.NuageSubnet()
        vport_response = restproxy_serv.rest_call(
            'POST',
            nuage_subnet.vport_post(nuage_subnet_id),
            nuage_subnet.vport_post_data(vport_params))

        if not nuage_subnet.validate(vport_response):
            raise restproxy.RESTProxyError(nuage_subnet.error_msg)

        if vport_response[VSD_RESP_OBJ]:
            vport_id = vport_response[VSD_RESP_OBJ][0]['ID']
        # Create Bridge interface in the vport
        nuage_vport = nuagelib.NuageVPort()
        bridge_iface = restproxy_serv.rest_call(
            'POST', nuage_vport.post_bridge_interface(vport_id),
            nuage_vport.post_bridge_iface_data(
                "SUBNET",
                "BRIDGE INTERFACE(" + vport_id + ")",
                params.get('neutron_subnet_id')))
        if not nuage_vport.validate(bridge_iface):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        # Get rtr id from nuage_subnet_id
        nuage_rtr_id = helper._get_nuage_domain_id_from_subnet(
            restproxy_serv, nuage_subnet_id)
        # Create a policygroup for this bridge vport and create default rules
        nuage_policygroup_id = \
            pg_obj.create_policygroup_default_allow_any_rule(
                None, nuage_rtr_id, params.get('neutron_subnet_id'), gw_type)
        # Add vport to the policygroup
        pg_obj.update_vport_policygroups(vport_id, [nuage_policygroup_id])


def check_gw_enterprise_permissions(restproxy_serv, params):
    nuage_gw = nuagelib.NuageGateway(create_params=params)
    gw_ent_perm_resp = restproxy_serv.rest_call(
        'GET', nuage_gw.get_ent_perm(), '')
    if not nuage_gw.validate(gw_ent_perm_resp):
        raise restproxy.RESTProxyError(nuage_gw.error_msg)

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
        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)

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
        raise restproxy.RESTProxyError(nuage_gw.error_msg)
    if gw_resp[VSD_RESP_OBJ]:
        return gw_resp[VSD_RESP_OBJ][0]['personality']


def delete_resources_created_for_l2dom_providernet(restproxy_serv, l2domid):
    nuagel2domain = nuagelib.NuageL2Domain()
    # Get bridge vport on given l2domain
    bridge_vports = restproxy_serv.rest_call(
        'GET', nuagel2domain.get_all_vports(l2domid), '',
        nuagel2domain.extra_headers_vport_get())
    if not nuagel2domain.validate(bridge_vports):
        raise restproxy.RESTProxyError(nuagel2domain.error_msg)

    # Delete bridge interface and bridge vport if it is subnet created for
    # provider net
    if bridge_vports and bridge_vports[VSD_RESP_OBJ]:
        nuage_vport = nuagelib.NuageVPort()
        bridge_vport = bridge_vports[VSD_RESP_OBJ][0]

        bridge_iface = restproxy_serv.rest_call(
            'GET', nuage_vport.post_bridge_interface(bridge_vport['ID']),
            '')
        if not nuage_vport.validate(bridge_iface):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        if bridge_iface and bridge_iface[VSD_RESP_OBJ]:
            bridge_iface_id = bridge_iface[VSD_RESP_OBJ][0]['ID']
            restproxy_serv.rest_call(
                'DELETE',
                nuage_vport.del_bridge_interface(bridge_iface_id),
                '')

        # Delete bridge vport
        nuage_vport = nuagelib.NuageVPort({'vport_id': bridge_vport['ID']})
        restproxy_serv.delete(nuage_vport.delete_resource())

        # Delete vlan obj on gateway port
        delete_vlan_for_gw_port(restproxy_serv, bridge_vport)


def delete_resources_created_for_domainsubnet_providernet(
        restproxy_serv, pg_obj, nuage_subn_id, neutron_subn_id):
    # Get vports on the given nuage domain subnet
    nuagel3domsub = nuagelib.NuageSubnet()
    bridge_vports = restproxy_serv.rest_call(
        'GET', nuagel3domsub.get_all_vports(nuage_subn_id), '',
        nuagel3domsub.extra_headers_vport_get())
    if not nuagel3domsub.validate(bridge_vports):
        raise restproxy.RESTProxyError(nuagel3domsub.error_msg)

    # Delete bridge interface and bridge vport if it is subnet created for
    # provider net
    if bridge_vports and bridge_vports[3]:
        nuage_vport = nuagelib.NuageVPort()
        vport = bridge_vports[VSD_RESP_OBJ][0]

        bridge_iface = restproxy_serv.rest_call(
            'GET', nuage_vport.post_bridge_interface(vport['ID']),
            '')

        if not nuage_vport.validate(bridge_iface):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        if bridge_iface and bridge_iface[VSD_RESP_OBJ]:
            bridge_iface_id = \
                bridge_iface[constants.VSD_RESP_OBJ][0]['ID']
            restproxy_serv.rest_call(
                'DELETE',
                nuage_vport.del_bridge_interface(bridge_iface_id),
                '')

        # Delete bridge vport
        nuage_vport = nuagelib.NuageVPort({'vport_id': vport['ID']})
        restproxy_serv.rest_call(
            'DELETE', nuage_vport.get_resource(), '')

        # Delete vlan obj on gateway port
        delete_vlan_for_gw_port(restproxy_serv, vport)

    # Get defaultPG on nuage domain and delete if it is subnet created for
    # providernet
    if bridge_vports:
        nuage_dom_id = helper.get_domain_id_by_nuage_subnet_id(
            restproxy_serv, nuage_subn_id)
        params = {
            'domain_id': nuage_dom_id
        }
        nuage_policygroup = nuagelib.NuagePolicygroup(create_params=params)
        pg_name = 'defaultPG-' + neutron_subn_id
        nuage_policygroups = restproxy_serv.get(
            nuage_policygroup.post_resource(),
            extra_headers=nuage_policygroup.extra_headers_get_name(pg_name))

        if nuage_policygroups:
            nuage_policygroup_id = nuage_policygroups[0]['ID']
            if nuage_policygroup_id:
                pg_obj._delete_policy_group(nuage_policygroup_id)


def delete_vlan_for_gw_port(restproxy_serv, vport):
    # Delete vlan obj on gateway port
    nuage_gw_port = nuagelib.NuageGatewayPort()
    nuage_vlan = vport['VLANID']
    restproxy_serv.delete(nuage_gw_port.delete_vlan(nuage_vlan))
