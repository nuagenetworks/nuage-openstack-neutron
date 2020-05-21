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

try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)


def _add_policy_group_for_no_port_sec(gw_type, subn_id, rtr_id, pg_obj,
                                      nuage_vport_id):
    policy_group_list = []
    params = {
        'l2dom_id': subn_id,
        'rtr_id': rtr_id,
        'type': constants.HOST_VPORT_TYPE,
        'sg_type': (constants.SOFTWARE if gw_type in constants.SW_GW_TYPES
                    else constants.HARDWARE)
    }
    pg_id = pg_obj.create_nuage_sec_grp_for_no_port_sec(params)
    policy_group_list.append(pg_id)
    pg_obj.update_vport_policygroups(nuage_vport_id, policy_group_list)


def _create_vport_interface(subnet_id, pg_obj, restproxy_serv,
                            subn_type, vport_type, policy_group, params):
    gw_type = params.get('gw_type')
    nuage_vlan_id = params.get('nuage_vlan_id')

    req_params = dict()
    extra_params = {
        'vlan': nuage_vlan_id,
        'externalID': get_vsd_external_id(params.get('externalid')),
        'description': "Created by Nuage Neutron plugin"
    }

    if vport_type == constants.BRIDGE_VPORT_TYPE:
        extra_params['type'] = constants.BRIDGE_VPORT_TYPE
        extra_params['name'] = 'Bridge Vport ' + nuage_vlan_id
    else:
        extra_params['type'] = constants.HOST_VPORT_TYPE
        extra_params['name'] = 'Host Vport ' + nuage_vlan_id
        extra_params[constants.PORTSECURITY] = params[constants.PORTSECURITY]

    nuage_vport = nuagelib.NuageVPort(create_params=req_params,
                                      extra_params=extra_params)
    if subn_type == constants.SUBNET:
        req_params['subnet_id'] = subnet_id
        extra_params['net_type'] = constants.SUBNET.upper()
        resource_url = nuage_vport.post_vport_for_subnet()
    else:
        req_params['l2domain_id'] = subnet_id
        extra_params['net_type'] = constants.L2DOMAIN.upper()
        resource_url = nuage_vport.post_vport_for_l2domain()

    # create the vport
    vport = restproxy_serv.post(
        resource_url,
        nuage_vport.post_vport_data(),
        on_res_exists=restproxy_serv.retrieve_by_external_id,
        ignore_err_codes=[restproxy.REST_VLAN_IN_USE_ERR_CODE])[0]

    # create the interface
    nuage_vport_id = vport['ID']
    req_params['vport_id'] = nuage_vport_id

    if vport_type == constants.BRIDGE_VPORT_TYPE:
        # Setting the intf name as "BRIDGE INTERFACE(<vport_id>)"
        extra_params['name'] = "BRIDGE INTERFACE(" + nuage_vport_id + ")"
        nuage_interface = nuagelib.NuageBridgeInterface(
            create_params=req_params,
            extra_params=extra_params)
        resource_url = nuage_interface.post_resource_by_vport()
    else:
        extra_params['ipaddress'] = params['ipaddress']
        extra_params['ipaddress_v6'] = params.get('ipaddress_v6')
        extra_params['mac'] = params['mac']
        extra_params['externalID'] = get_vsd_external_id(params['externalid'])

        nuage_interface = nuagelib.NuageHostInterface(
            create_params=req_params,
            extra_params=extra_params)
        resource_url = nuage_interface.post_resource_by_vport()

    vport_intf = restproxy_serv.post(
        resource_url,
        nuage_interface.post_iface_data(),
        on_res_exists=restproxy_serv.retrieve_by_external_id,
        ignore_err_codes=[restproxy.REST_IFACE_EXISTS_ERR_CODE])[0]

    if policy_group and not params.get('nuage_managed_subnet'):
        if subn_type == constants.SUBNET:
            nuage_rtr_id = helper._get_nuage_domain_id_from_subnet(
                restproxy_serv, subnet_id)
            _add_policy_group_for_no_port_sec(gw_type, None, nuage_rtr_id,
                                              pg_obj, nuage_vport_id)
        else:
            _add_policy_group_for_no_port_sec(gw_type, subnet_id, None,
                                              pg_obj, nuage_vport_id)
    return {
        'vport': vport,
        'interface': vport_intf
    }


def create_vport_interface(restproxy_serv, pg_obj, params,
                           vport_type, create_policy_group=True):
    l2domain_id = params.get('l2domain_id')
    nuage_subnet_id = params.get('nuage_subnet_id')

    if vport_type == constants.BRIDGE_VPORT_TYPE:
        if l2domain_id:
            return _create_vport_interface(l2domain_id,
                                           pg_obj, restproxy_serv,
                                           constants.L2DOMAIN,
                                           constants.BRIDGE_VPORT_TYPE,
                                           create_policy_group,
                                           params)
        else:
            return _create_vport_interface(nuage_subnet_id,
                                           pg_obj, restproxy_serv,
                                           constants.SUBNET,
                                           constants.BRIDGE_VPORT_TYPE,
                                           create_policy_group,
                                           params)
    else:
        if l2domain_id:
            return _create_vport_interface(l2domain_id,
                                           pg_obj, restproxy_serv,
                                           constants.L2DOMAIN,
                                           constants.HOST_VPORT_TYPE,
                                           create_policy_group,
                                           params)
        else:
            return _create_vport_interface(nuage_subnet_id,
                                           pg_obj, restproxy_serv,
                                           constants.SUBNET,
                                           constants.HOST_VPORT_TYPE,
                                           create_policy_group,
                                           params)


def get_tenant_perm(restproxy_serv, vlan_id, required=False):
    req_params = {
        'vlan_id': vlan_id
    }

    nuage_perm = nuagelib.NuagePermission(create_params=req_params)
    permissions = restproxy_serv.get(nuage_perm.get_resource_by_vlan(),
                                     required=required)
    return permissions[0] if permissions else None


def get_gateway_port_vlan(restproxy_serv, nuage_vlan_id):
    req_params = {
        'vlan_id': nuage_vlan_id
    }
    nuage_gw_vlan = nuagelib.NuageVlan(create_params=req_params)
    return restproxy_serv.get(nuage_gw_vlan.get_resource(),
                              required=True)[0]


def get_gateway_port(restproxy_serv, gw_port_id, gw_id=None):
    # gw_port_id can actually be a name/id. In case of VSG, port name can
    # have a '/'. In that case we just return.
    if '/' in gw_port_id:
        return

    gw_port = None
    any_hw_personality = 'VSG'  # don't care which, as long as it is a HW one

    # -------------------------------------------------------------------------
    # Below loop iterates over non-redundant or redundant gw ports.
    #
    # When non-redundant, endpoint is always /ports.
    # When redundant, for HW, endpoint is /gatewayredundantports, for SW it is
    # /ports. Hence, when we set personality to HW and loop over both
    # redundancy modes, we cover all cases.
    #
    # If this invariant ever changes, we need a nested loop, looping over
    # personalities, and inside, loop over redundancy modes
    # -------------------------------------------------------------------------
    for nuage_gw_port in [nuagelib.NuageGatewayPortBase.factory(
            create_params={
                'port_id': gw_port_id,
                'personality': any_hw_personality
            },
            extra_params=None,
            redundant=redundant) for redundant in [False, True]]:

        try:
            gw_port = restproxy_serv.get(nuage_gw_port.get_resource(),
                                         required=True)[0]
            break
        except restproxy.ResourceNotFoundException:
            continue
    if not gw_port:
        return []
    if gw_id:
        if gw_port['parentID'] != gw_id:
            msg = (_("Port %(port)s not found on gateway %(gw)s")
                   % {'port': gw_port_id,
                      'gw': gw_id})
            raise restproxy.ResourceNotFoundException(msg)
    return gw_port


def get_gateway(restproxy_serv, gw_id):
    req_params = {
        'gw_id': gw_id
    }
    for nuage_gw in [nuagelib.NuageGatewayBase.factory(
            create_params=req_params,
            extra_params=None,
            redundant=redundant) for redundant in [False, True]]:
        try:
            gateway = restproxy_serv.get(nuage_gw.get_resource_by_id(),
                                         required=True)[0]
            gateway['redundant'] = 'redundantGatewayStatus' in gateway
            return gateway
        except restproxy.RESTProxyError:
            continue
    raise restproxy.ResourceNotFoundException(
        msg='GW:{} not found!'.format(gw_id))


def get_gateway_by_vlan(restproxy_serv, nuage_vlan_id):
    # Get the vlan
    nuage_vlan = get_gateway_port_vlan(restproxy_serv, nuage_vlan_id)

    # Get the gateway
    nuage_gw = get_gateway(restproxy_serv, nuage_vlan['gatewayID'])

    return nuage_gw


def get_nuage_vport_by_name(restproxy_serv, nuage_subnet_id,
                            nuage_vport_name, subnet_type):
    req_params = dict()
    extra_params = {
        'vport_name': nuage_vport_name
    }

    nuage_vport = nuagelib.NuageVPort(create_params=req_params,
                                      extra_params=extra_params)

    if subnet_type == constants.L2DOMAIN:
        req_params['l2domain_id'] = nuage_subnet_id
        res_url = nuage_vport.get_vports_for_l2domain()
    else:
        req_params['subnet_id'] = nuage_subnet_id
        res_url = nuage_vport.get_vports_for_subnet()
    vports = restproxy_serv.get(res_url,
                                nuage_vport.extra_headers_get_by_name(),
                                required=True)
    return vports[0] if vports else None


def get_nuage_vport(restproxy_serv, nuage_vport_id):
    req_params = {
        'vport_id': nuage_vport_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    try:
        vports = restproxy_serv.get(nuage_vport.get_resource(), required=True)
        return vports[0]
    except restproxy.RESTProxyError as e:
        if e.code == constants.RES_NOT_FOUND:
            # This is because HEAT does not call get_all before get. So we
            # explicitly have to return empty list and not throw an exception.
            return None
        raise


def delete_nuage_vport(restproxy_serv, nuage_vport_id):
    req_params = {
        'vport_id': nuage_vport_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    restproxy_serv.delete(nuage_vport.delete_resource())


def get_interface_by_vport(restproxy_serv, nuage_vport_id, type):
    req_params = {
        'vport_id': nuage_vport_id
    }
    if type == constants.BRIDGE_VPORT_TYPE:
        nuage_intf = nuagelib.NuageBridgeInterface(create_params=req_params)
    elif type == constants.HOST_VPORT_TYPE:
        nuage_intf = nuagelib.NuageHostInterface(create_params=req_params)
    host_interfaces = restproxy_serv.get(nuage_intf.get_resource_by_vport(),
                                         required=True)
    return host_interfaces[0] if host_interfaces else None


def delete_nuage_interface(restproxy_serv, nuage_intf_id, type):
    req_params = {
        'interface_id': nuage_intf_id
    }
    if type == constants.BRIDGE_VPORT_TYPE:
        nuage_intf = nuagelib.NuageBridgeInterface(create_params=req_params)
    elif type == constants.HOST_VPORT_TYPE:
        nuage_intf = nuagelib.NuageHostInterface(create_params=req_params)
    restproxy_serv.delete(nuage_intf.delete_resource())


def get_policygroup_for_host_vport(restproxy_serv, vport_id):
    req_params = {
        'vport_id': vport_id
    }
    nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
    policy_groups = restproxy_serv.get(
        nuage_policygroup.get_policygroups_for_vport(),
        required=True)
    return policy_groups[0] if policy_groups else None


def get_vports_for_subnet(restproxy_serv, nuage_subnet_id):
    req_params = {
        'subnet_id': nuage_subnet_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    return restproxy_serv.get(nuage_vport.get_vports_for_subnet(),
                              required=True)


def get_vports_for_l2domain(restproxy_serv, nuage_l2dom_id):
    req_params = {
        'l2domain_id': nuage_l2dom_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    return restproxy_serv.get(nuage_vport.get_vports_for_l2domain(),
                              required=True)


def get_vports_for_policygroup(restproxy_serv, policygroup_id):
    req_params = {
        'policygroup_id': policygroup_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    return restproxy_serv.get(nuage_vport.get_vports_for_policygroup(),
                              required=True)


def get_gateways_for_netpart(restproxy_serv, netpart_id):
    req_params = {
        'netpart_id': netpart_id
    }

    nuage_gw = nuagelib.NuageGateway(create_params=req_params)
    return restproxy_serv.get(nuage_gw.get_resource_for_netpart(),
                              required=True)


def get_ent_permission_on_gateway(restproxy_serv, gw_id, redundancy=False):
    req_params = {
        'gw_id': gw_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    ent_permissions = restproxy_serv.get(
        nuage_ent_perm.get_resource_by_gw(redundancy),
        required=True)
    return ent_permissions[0] if ent_permissions else None


def get_ent_permission_on_port(restproxy_serv, gw_port_id, redundancy=False):
    req_params = {
        'port_id': gw_port_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    ent_permissions = restproxy_serv.get(
        nuage_ent_perm.get_resource_by_port(redundancy),
        required=True)
    return ent_permissions[0] if ent_permissions else None


def get_ent_permission_on_vlan(restproxy_serv, gw_vlan_id):
    req_params = {
        'vlan_id': gw_vlan_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    ent_permissions = restproxy_serv.get(nuage_ent_perm.get_resource_by_vlan(),
                                         required=True)
    return ent_permissions[0] if ent_permissions else None


def make_gateway_dict(gateway):
    ret = {
        'gw_id': gateway['ID'],
        'gw_name': gateway['name'],
        'gw_type': gateway['personality'],
        'gw_status': gateway.get('pending', False),
        'gw_template': gateway.get('templateID', None),
        'gw_system_id': gateway.get('systemID', None),
        'gw_redundant': 'redundantGatewayStatus' in gateway
    }
    return ret


def make_gw_port_dict(port):
    ret = {
        'gw_port_id': port['ID'],
        'gw_port_name': port['name'],
        'gw_port_status': port['status'],
        'gw_port_phy_name': port['physicalName'],
        'gw_port_vlan': port['VLANRange'],
        'gw_port_mnemonic': port['userMnemonic'],
        'gw_redundant_port_id': port.get('associatedRedundantPortID')
    }
    return ret


def make_gw_vlan_dict(vlan):
    ret = {
        'gw_vlan_id': vlan['ID'],
        'gw_vlan_port_id': vlan['parentID'],
        'gw_vlan_gw_id': vlan['gatewayID'],
        'gw_vlan_value': vlan['value'],
        'gw_vlan_vport_id': vlan['vportID'],
        'gw_vlan_mnemonic': vlan['userMnemonic'],
        'gw_vlan_status': vlan['status'],
        'gw_vlan_assigned_to': vlan.get('assignedTo')
    }
    return ret
