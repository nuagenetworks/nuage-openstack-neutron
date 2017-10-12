# Copyright 2017 NOKIA
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

from neutron._i18n import _
from nuage_neutron.plugins.common import exceptions


def get_nuage_vport(vsdclient, port, required=True):
    port_params = {
        'neutron_port_id': port['port']['id'],
        'l2dom_id': port['subnet_mapping']['nuage_subnet_id'],
        'l3dom_id': port['subnet_mapping']['nuage_subnet_id']
    }
    return vsdclient.get_nuage_vport_by_neutron_id(
        port_params,
        required=required)


def validate_switchports(vsdclient, tenant_id, switchports):
    vsdports = dict()
    if not len(switchports):
        return None
    for switchport in switchports:
        filters = {'system_id': [switchport.get('switch_info')]}
        gws = vsdclient.get_gateways(tenant_id, filters)
        if len(gws) == 0:
            msg = (_("No gateway found: %s")
                   % filters['system_id'][0])
            raise exceptions.NuageBadRequest(msg=msg)
        port_mnemonic = _convert_ifindex_to_ifname(
            switchport.get('port_id'))
        filters = {'gateway': [gws[0]['gw_id']],
                   'name': [port_mnemonic]}
        gw_ports = vsdclient.get_gateway_ports(tenant_id,
                                               filters)
        if len(gw_ports) == 0:
            msg = (_("No gateway port found: %s")
                   % filters['name'][0])
            raise exceptions.NuageBadRequest(msg=msg)
        port = gw_ports[0]
        if port.get('gw_redundant_port_id') is not None:
            port_id = port.get('gw_redundant_port_id')
            redundant = True
        else:
            port_id = port.get('gw_port_id')
            redundant = False
        vsd_port = {
            'port_id': port_id,
            'personality': gws[0]['gw_type'],
            'redundant': redundant
        }
        if port_id not in vsdports:
            vsdports[port_id] = []
        vsdports[port_id].append(vsd_port)
    if len(vsdports) > 1:
        msg = (_("Not all switchports belong to the same redundancy Group"))
        raise exceptions.NuageBadRequest(msg=msg)
    return vsdports[vsdports.keys()[0]][0]


def _convert_ifindex_to_ifname(ifindex):
    """_convert_ifindex_to_ifname. In case local_link_information is

    obtained by inspector, VSG TOR will send snmp ifIndex in
    port id TLV, which is not known to VSD, here we assume that numeric
    value is snmp ifIndex and do conversion, otherwise it is a port
    mnemonic.
    High Port Count format:
      32 bits unsigned integer, from most significant to least significant:
      3 bits: 000 -> indicates physical port
      4 bits: slot number
      2 bits: High part of port number
      2 bits: mda number
      6 bits: Low part of port number
      15 bits: channel number
    High and low part of port number need to be combined to create 8 bit
    unsigned int

    """
    if not ifindex:
        return None
    if not ifindex.isdigit():
        return ifindex
    return "%s/%s/%s" % (
        (int(ifindex) >> 25),
        (int(ifindex) >> 21) & 0x3,
        ((int(ifindex) >> 15) & 0x3f) | ((int(ifindex) >> 17) & 0xc0))
