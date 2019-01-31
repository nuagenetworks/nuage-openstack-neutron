# Copyright 2018 NOKIA
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

import ipaddress
import logging

import netaddr

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

VSD_RESP_OBJ = constants.VSD_RESP_OBJ

LOG = logging.getLogger(__name__)


def get_l3dom_policygroup_by_sgid(restproxy_serv, l3dom_id,
                                  sg_id, sg_type=constants.SOFTWARE):
    prefix = 'hw:' if sg_type == constants.HARDWARE else ''
    req_params = {
        'domain_id': l3dom_id,
        'externalID': get_vsd_external_id(prefix + sg_id)
    }

    nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
    policy_groups = restproxy_serv.get(
        nuage_policygroup.post_resource(),
        extra_headers=nuage_policygroup.extra_headers_get_type_and_id(sg_type),
        required=True
    )
    return policy_groups[0]['ID'] if policy_groups else None


def get_l2dom_policygroup_by_sgid(restproxy_serv, l2dom_id,
                                  sg_id, sg_type=constants.SOFTWARE):
    prefix = 'hw:' if sg_type == constants.HARDWARE else ''
    req_params = {
        'domain_id': l2dom_id,
        'externalID': get_vsd_external_id(prefix + sg_id)
    }

    nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
    policy_groups = restproxy_serv.get(
        nuage_policygroup.post_resource_l2dom(),
        extra_headers=nuage_policygroup.extra_headers_get_type_and_id(sg_type),
        required=True
    )
    return policy_groups[0]['ID'] if policy_groups else None


def get_policygroup_by_sgid(restproxy_serv, params):
    neutron_rtr_id = params.get('neutron_rtr_id', None)
    l3dom_id = None
    l2dom_id = params.get('l2dom_id')
    if neutron_rtr_id:
        l3dom_id = helper.get_l3domid_by_router_id(restproxy_serv,
                                                   neutron_rtr_id)
        policygroup_id = get_l3dom_policygroup_by_sgid(
            restproxy_serv, l3dom_id, params['sg_id'])
    else:
        policygroup_id = get_l2dom_policygroup_by_sgid(
            restproxy_serv, params.get('l2dom_id'), params['sg_id'])

    result = {
        'nuage_rtr_id': l3dom_id,
        'nuage_l2dom_id': l2dom_id,
        'policygroup_id': policygroup_id
    }
    return result


def get_l3dom_inbound_acl_id(restproxy_serv, dom_id):
    req_params = {
        'parent_id': dom_id
    }

    nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
    default_l3_acl_name = dom_id + constants.NUAGE_DEFAULT_L3_INGRESS_ACL
    extra_headers = nuageibacl.extra_headers_get_by_name(default_l3_acl_name)
    inbound_acls = restproxy_serv.get(nuageibacl.get_resource_l3(),
                                      extra_headers=extra_headers,
                                      required=True)
    return inbound_acls[0]['ID'] if inbound_acls else None


def get_l3dom_outbound_acl_id(restproxy_serv, dom_id):
    req_params = {
        'parent_id': dom_id
    }

    nuageobacl = nuagelib.NuageOutboundACL(create_params=req_params)
    default_l3_acl_name = dom_id + constants.NUAGE_DEFAULT_L3_EGRESS_ACL
    extra_headers = nuageobacl.extra_headers_get_by_name(default_l3_acl_name)
    outbound_acls = restproxy_serv.get(nuageobacl.get_resource_l3(),
                                       extra_headers=extra_headers,
                                       required=True)
    return outbound_acls[0]['ID'] if outbound_acls else None


def get_l2dom_inbound_acl_id(restproxy_serv, dom_id):
    req_params = {
        'parent_id': dom_id
    }

    nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
    default_l2_acl_name = dom_id + constants.NUAGE_DEFAULT_L2_INGRESS_ACL
    extra_headers = nuageibacl.extra_headers_get_by_name(default_l2_acl_name)
    inbound_acls = restproxy_serv.get(nuageibacl.get_resource_l2(),
                                      extra_headers=extra_headers,
                                      required=True)
    return inbound_acls[0]['ID'] if inbound_acls else None


def get_l2dom_outbound_acl_id(restproxy_serv, dom_id):
    req_params = {
        'parent_id': dom_id
    }

    nuageobacl = nuagelib.NuageOutboundACL(create_params=req_params)
    default_l2_acl_name = dom_id + constants.NUAGE_DEFAULT_L2_EGRESS_ACL
    extra_headers = nuageobacl.extra_headers_get_by_name(default_l2_acl_name)
    outbound_acls = restproxy_serv.get(nuageobacl.get_resource_l2(),
                                       extra_headers=extra_headers,
                                       required=True)
    return outbound_acls[0]['ID'] if outbound_acls else None


def get_inbound_acl_details(restproxy_serv, dom_id, type=constants.SUBNET):
    req_params = {
        'parent_id': dom_id
    }
    nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
    if type == constants.L2DOMAIN:
        default_acl_name = dom_id + constants.NUAGE_DEFAULT_L2_INGRESS_ACL
        url = nuageibacl.get_resource_l2()
    else:
        default_acl_name = dom_id + constants.NUAGE_DEFAULT_L3_INGRESS_ACL
        url = nuageibacl.get_resource_l3()
    extra_headers = nuageibacl.extra_headers_get_by_name(default_acl_name)
    inbound_acls = restproxy_serv.get(url,
                                      extra_headers=extra_headers,
                                      required=True)
    return inbound_acls[0] if inbound_acls else None


def get_remote_policygroup_id(restproxy_serv, sg_id, resourcetype,
                              resource_id, sg_name):
    ext_id = (get_vsd_external_id('hw:' + sg_id) if
              str(sg_name).endswith('_HW') else
              get_vsd_external_id(sg_id))
    req_params = {
        'name': sg_name,
        'domain_id': resource_id,
        'sg_id': sg_id,
        'externalID': ext_id
    }

    nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
    if resourcetype == constants.DOMAIN:
        url = nuage_policygroup.post_resource()
    else:
        url = nuage_policygroup.post_resource_l2dom()

    policygroups = restproxy_serv.get(
        url, extra_headers=nuage_policygroup.extra_headers_get(),
        required=True)
    if policygroups:
        return policygroups[0]['ID']
    else:
        policygroups = restproxy_serv.post(url, nuage_policygroup.post_data())
        return policygroups[0]['ID']


def create_nuage_prefix_macro(restproxy_serv, sg_rule, np_id):
    ipv6_net = ipv4_net = None
    if sg_rule.get('ethertype') == constants.OS_IPV6:
        ipv6_net = netaddr.IPNetwork(sg_rule['remote_ip_prefix'])
        net = ipv6_net
        sg_rule['IPType'] = constants.IPV6
    else:
        ipv4_net = netaddr.IPNetwork(sg_rule['remote_ip_prefix'])
        net = ipv4_net
        sg_rule['IPType'] = constants.IPV4

    net_name = str(str(ipaddress.ip_address(
        net.ip).exploded).replace(':', '-')).replace('.', '-')

    macro_name = str(sg_rule.get('ethertype')) + '_' + \
        net_name + '_' + str(net.prefixlen)
    req_params = {
        'net_partition_id': np_id,
        'net': ipv4_net,
        'name': macro_name,
        'ethertype': sg_rule.get('ethertype'),
        'ipv6_net': ipv6_net,
        'IPType': sg_rule['IPType']
    }
    nuage_np_net = nuagelib.NuageNetPartitionNetwork(create_params=req_params)
    response = restproxy_serv.get(
        nuage_np_net.get_resource(), '',
        nuage_np_net.extra_headers_get_netadress(req_params))
    if response:
        return response[0]['ID']

    response = restproxy_serv.post(
        nuage_np_net.post_resource(),
        nuage_np_net.post_data(),
        on_res_exists=None,
        ignore_err_codes=[restproxy.REST_NW_MACRO_EXISTS_INTERNAL_ERR_CODE])
    if response:
        return response[0]['ID']
    else:
        response = restproxy_serv.get(
            nuage_np_net.get_resource(), '',
            nuage_np_net.extra_headers_get_netadress(req_params),
            required=True)
        return response[0]['ID']
