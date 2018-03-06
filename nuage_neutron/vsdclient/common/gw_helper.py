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


def _create_policygroup_for_vport(gw_type, subn_id, rtr_id, neutron_subnet,
                                  pg_obj, restproxy_serv, vport, subn_type):
    # Create a policygroup for this bridge vport and create default rules
    create_policygroup = True
    nuage_policygroup = get_policygroup_for_interface(
        restproxy_serv, neutron_subnet,
        gw_type, vport['type'], subn_type)
    if nuage_policygroup:
        nuage_policygroup_id = nuage_policygroup[0]
        if (nuage_policygroup[1] == constants.HARDWARE and
                gw_type == constants.GW_TYPE['VSG']):
            # policygroup for vsg already exists
            create_policygroup = False
        elif (nuage_policygroup[1] == constants.SOFTWARE and
                gw_type == constants.GW_TYPE['VRSG']):
            # policygroup for vrsg already exists
            create_policygroup = False

    if create_policygroup:
        # Add the vport type to the gateway type, because when we need a way
        # to distinguish policygroups for bridge/host vport on the same subnet.
        pg_name = ''.join(['defaultPG-', gw_type, '-', vport['type'], '-',
                           helper.get_subnet_name(neutron_subnet)])
        nuage_policygroup_id = (
            pg_obj.create_policygroup_default_allow_any_rule(
                subn_id, rtr_id, neutron_subnet, gw_type,
                pg_name))

    # Add vport to the policygroup
    try:
        pg_obj.update_vport_policygroups(vport['ID'], [nuage_policygroup_id])
    except Exception:
        LOG.error("Error while associating vport %(vport)s to policygroup %("
                  "policygroup)s", {'vport': vport['ID'],
                                    'policygroup': nuage_policygroup_id})
        if create_policygroup:
            # Delete the policygroup in case of an exception.
            pg_obj.delete_nuage_policy_group(nuage_policygroup_id)
        raise


def _add_policy_group_for_port_sec(gw_type, subn_id, rtr_id, pg_obj,
                                   nuage_vport_id):
    policy_group_list = []
    params = {
        'l2dom_id': subn_id,
        'rtr_id': rtr_id,
        'type': constants.HOST_VPORT_TYPE,
        'sg_type': (constants.HARDWARE
                    if gw_type == constants.GW_TYPE['VSG']
                    else constants.SOFTWARE)
    }
    pg_id = pg_obj.create_nuage_sec_grp_for_port_sec(params)
    if pg_id:
        params['sg_id'] = pg_id
        pg_obj.create_nuage_sec_grp_rule_for_port_sec(params)
        policy_group_list.append(pg_id)
        pg_obj.update_vport_policygroups(nuage_vport_id, policy_group_list)


def _create_vport_interface(subnet_id, pg_obj, restproxy_serv,
                            subn_type, vport_type, policy_group, params):
    gw_type = params.get('gw_type')
    nuage_vlan_id = params.get('nuage_vlan_id')

    req_params = dict()
    extra_params = {
        'vlan': nuage_vlan_id,
        'externalID': get_vsd_external_id(params.get('externalid'))
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

    if policy_group:
        if (not params.get('nuage_managed_subnet') and
                params.get('port_security_enabled')):
            if subn_type == constants.SUBNET:
                # Get rtr id from nuage_subnet_id
                nuage_rtr_id = helper._get_nuage_domain_id_from_subnet(
                    restproxy_serv,
                    subnet_id)
                _create_policygroup_for_vport(gw_type, None, nuage_rtr_id,
                                              params.get('neutron_subnet'),
                                              pg_obj, restproxy_serv, vport,
                                              subn_type)
            else:
                _create_policygroup_for_vport(gw_type, subnet_id, None,
                                              params.get('neutron_subnet'),
                                              pg_obj, restproxy_serv, vport,
                                              subn_type)
        if (not params.get('nuage_managed_subnet') and
                not params.get('port_security_enabled')):
            if subn_type == constants.SUBNET:
                nuage_rtr_id = helper._get_nuage_domain_id_from_subnet(
                    restproxy_serv,
                    subnet_id)
                _add_policy_group_for_port_sec(gw_type, None, nuage_rtr_id,
                                               pg_obj, nuage_vport_id)
            else:
                _add_policy_group_for_port_sec(gw_type, subnet_id, None,
                                               pg_obj, nuage_vport_id)

    ret = {
        'vport': vport,
        'interface': vport_intf
    }
    return ret


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


def get_tenant_perm(restproxy_serv, vlan_id):
    req_params = {
        'vlan_id': vlan_id
    }

    nuage_perm = nuagelib.NuagePermission(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET',
        nuage_perm.get_resource_by_vlan(), '')
    if not nuage_perm.validate(response):
        LOG.error("Permissions not available for vlan %s", vlan_id)
        return

    if nuage_perm.check_response_exist(response):
        perm = nuage_perm.get_response_obj(response)
        if perm:
            LOG.debug("Some tenant has permission on vlan %s", vlan_id)
            return perm


def get_gateway_port_vlan(restproxy_serv, nuage_vlan_id):
    req_params = {
        'vlan_id': nuage_vlan_id
    }
    nuage_gw_vlan = nuagelib.NuageVlan(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_gw_vlan.get_resource(), '')
    if not nuage_gw_vlan.validate(response):
        error_code = nuage_gw_vlan.get_error_code(response)
        raise restproxy.RESTProxyError(nuage_gw_vlan.error_msg, error_code)

    return nuage_gw_vlan.get_response_obj(response)


def get_gateway_port(restproxy_serv, gw_port_id, gw_id=None):
    # gw_port_id can actually be a name/id. In case of VSG, port name can
    # have a '/'. In that case we just return.
    if '/' in gw_port_id:
        return

    req_params = {
        'port_id': gw_port_id,
        'personality': constants.GW_TYPE['VSG']
    }
    parent_id = None
    for nuage_gw_port in [nuagelib.NuageGatewayPortBase.factory(
            create_params=req_params,
            extra_params=None,
            redundant=redundant) for redundant in [False, True]]:

        response = restproxy_serv.rest_call('GET',
                                            nuage_gw_port.get_resource(), '')
        if nuage_gw_port.get_validate(response):
            parent_id = nuage_gw_port.get_response_parentid(response)
            break
    if not parent_id:
        err_code = nuage_gw_port.get_error_code(response)
        if err_code == constants.RES_NOT_FOUND:
            return []

        raise restproxy.RESTProxyError(nuage_gw_port.error_msg)
    if gw_id:
        if parent_id == gw_id:
            return nuage_gw_port.get_response_obj(response)
        else:
            msg = (_("Port %(port)s not found on gateway %(gw)s")
                   % {'port': gw_port_id,
                      'gw': gw_id})
            raise restproxy.RESTProxyError(msg)

    return nuage_gw_port.get_response_obj(response)


def get_gateway(restproxy_serv, gw_id):
    req_params = {
        'gw_id': gw_id
    }
    for nuage_gw in [nuagelib.NuageGatewayBase.factory(
            create_params=req_params,
            extra_params=None,
            redundant=redundant) for redundant in [False, True]]:
        response = restproxy_serv.rest_call('GET',
                                            nuage_gw.get_resource_by_id(), '')
        if nuage_gw.validate(response):
            gw = nuage_gw.get_response_obj(response)
            gw['redundant'] = 'redundantGatewayStatus' in gw
            return gw
    err_code = nuage_gw.get_error_code(response)
    raise restproxy.RESTProxyError(nuage_gw.error_msg, err_code)


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

    response = restproxy_serv.rest_call(
        'GET', res_url, '',
        nuage_vport.extra_headers_get_by_name())

    if not nuage_vport.validate(response):
        raise restproxy.RESTProxyError(nuage_vport.error_msg)

    if nuage_vport.check_response_exist(response):
        return nuage_vport.get_response_obj(response)

    return []


def get_nuage_vport(restproxy_serv, nuage_vport_id):
    req_params = {
        'vport_id': nuage_vport_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET', nuage_vport.get_resource(), '')
    if not nuage_vport.validate(response):
        error_code = nuage_vport.get_error_code(response)
        if error_code == constants.RES_NOT_FOUND:
            # This is because HEAT does not call get_all before get. So we
            # explicitly have to return empty list and not throw an exception.
            return []
        raise restproxy.RESTProxyError(nuage_vport.error_msg, error_code)

    if nuage_vport.check_response_exist(response):
        return nuage_vport.get_response_obj(response)


def delete_nuage_vport(restproxy_serv, nuage_vport_id):
    req_params = {
        'vport_id': nuage_vport_id
    }
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    response = restproxy_serv.rest_call('DELETE',
                                        nuage_vport.delete_resource(), '')

    if not nuage_vport.validate(response):
        raise restproxy.RESTProxyError(nuage_vport.error_msg)


def get_interface_by_vport(restproxy_serv, nuage_vport_id, type):
    req_params = {
        'vport_id': nuage_vport_id
    }
    if type == constants.BRIDGE_VPORT_TYPE:
        nuage_intf = nuagelib.NuageBridgeInterface(create_params=req_params)
    elif type == constants.HOST_VPORT_TYPE:
        nuage_intf = nuagelib.NuageHostInterface(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_intf.get_resource_by_vport(),
                                        '')

    if not nuage_intf.validate(response):
        raise restproxy.RESTProxyError(nuage_intf.error_msg)

    if nuage_intf.check_response_exist(response):
        return nuage_intf.get_response_obj(response)


def delete_nuage_interface(restproxy_serv, nuage_intf_id, type):
    req_params = {
        'interface_id': nuage_intf_id
    }
    if type == constants.BRIDGE_VPORT_TYPE:
        nuage_intf = nuagelib.NuageBridgeInterface(create_params=req_params)
    elif type == constants.HOST_VPORT_TYPE:
        nuage_intf = nuagelib.NuageHostInterface(create_params=req_params)

    response = restproxy_serv.rest_call('DELETE',
                                        nuage_intf.delete_resource(), '')

    if not nuage_intf.validate(response):
        raise restproxy.RESTProxyError(nuage_intf.error_msg)


def get_policygroup_for_interface(restproxy_serv, neutron_subnet, gw_type,
                                  vport_type, subn_type):
    nuage_policygroup = nuagelib.NuagePolicygroup()
    pg_name = '-'.join(['defaultPG', gw_type, vport_type,
                        helper.get_subnet_name(neutron_subnet)])
    policygroups = restproxy_serv.get(
        nuage_policygroup.get_all_resources(),
        extra_headers=nuage_policygroup.extra_header_filter(name=pg_name))
    if subn_type == constants.SUBNET:
        domain_type = constants.DOMAIN
    else:
        domain_type = constants.L2DOMAIN

    for pg in policygroups:
        if pg['parentType'] == domain_type:
            return pg['ID'], pg['type']


def get_policygroup_for_host_vport(restproxy_serv, vport_id):
    req_params = {
        'vport_id': vport_id
    }
    nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET', nuage_policygroup.get_policygroups_for_vport(), '')

    if not nuage_policygroup.validate(response):
        raise restproxy.RESTProxyError(nuage_policygroup.error_msg)

    if nuage_policygroup.check_response_exist(response):
        return nuage_policygroup.get_response_objid(response)


def get_vports_for_subnet(restproxy_serv, nuage_subnet_id):
    req_params = {
        'subnet_id': nuage_subnet_id
    }

    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_vport.get_vports_for_subnet(),
                                        '')

    if not nuage_vport.validate(response):
        raise restproxy.RESTProxyError(nuage_vport.error_msg)

    return nuage_vport.get_response_objlist(response)


def get_vports_for_l2domain(restproxy_serv, nuage_l2dom_id):
    req_params = {
        'l2domain_id': nuage_l2dom_id
    }

    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_vport.get_vports_for_l2domain(),
                                        '')

    if not nuage_vport.validate(response):
        raise restproxy.RESTProxyError(nuage_vport.error_msg)

    return nuage_vport.get_response_objlist(response)


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
    response = restproxy_serv.rest_call('GET',
                                        nuage_gw.get_resource_for_netpart(),
                                        '')

    if not nuage_gw.validate(response):
        raise restproxy.RESTProxyError(nuage_gw.error_msg)

    return nuage_gw.get_response_objlist(response)


def get_ent_permission_on_gateway(restproxy_serv, gw_id, redundancy=False):
    req_params = {
        'gw_id': gw_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_ent_perm.get_resource_by_gw(
                                            redundancy),
                                        '')
    if not nuage_ent_perm.validate(response):
        raise restproxy.RESTProxyError(nuage_ent_perm.error_msg)

    return nuage_ent_perm.get_response_obj(response)


def get_ent_permission_on_port(restproxy_serv, gw_port_id, redundancy=False):
    req_params = {
        'port_id': gw_port_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_ent_perm.get_resource_by_port(
                                            redundancy),
                                        '')
    if not nuage_ent_perm.validate(response):
        raise restproxy.RESTProxyError(nuage_ent_perm.error_msg)

    return nuage_ent_perm.get_response_obj(response)


def get_ent_permission_on_vlan(restproxy_serv, gw_vlan_id):
    req_params = {
        'vlan_id': gw_vlan_id
    }
    nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_ent_perm.get_resource_by_vlan(),
                                        '')
    if not nuage_ent_perm.validate(response):
        raise restproxy.RESTProxyError(nuage_ent_perm.error_msg)

    return nuage_ent_perm.get_response_obj(response)


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
