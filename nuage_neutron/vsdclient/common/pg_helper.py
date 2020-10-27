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

from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

VSD_RESP_OBJ = constants.VSD_RESP_OBJ

LOG = logging.getLogger(__name__)


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

    macro_name = str(sg_rule.get('ethertype', constants.OS_IPV4)) + '_' + \
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
