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


from oslo_log import log as logging

from neutron import context as neutron_context
from neutron.extensions import portsecurity

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants as const
from nuage_neutron.plugins.nuage_baremetal.drivers import utils
from nuage_neutron.plugins.nuage_baremetal import network_api as api


LOG = logging.getLogger(__name__)


class NuageGatewayDriverBridge(base_plugin.RootNuagePlugin,
                               api.NetworkProvisioningApi):
    """Back-end mechanism driver implementation

    for baremetal provisioning using bridge vports.
    """

    def __init__(self):
        """initialize the network provision driver."""
        self.context = neutron_context.get_admin_context()
        config.nuage_register_cfg_opts()
        self.init_vsd_client()

    def create_port(self, port_dict):
        """create_port. This call makes the REST request to VSD

        for provisioning VLAN/Vport for the gateway

        """
        port = port_dict['port']
        gw_ports = port.get('link_info')
        segmentation_id = port_dict['segmentation_id']
        vsd_port = utils.validate_switchports(self.vsdclient,
                                              port.get('tenant_id'),
                                              gw_ports)

        params = {
            'gatewayport': vsd_port['port_id'],
            'value': segmentation_id,
            'redundant': vsd_port['redundant'],
            'personality': vsd_port['personality']
        }
        vlan = self.vsdclient.create_gateway_vlan(params)
        LOG.debug("created vlan: %(vlan_dict)s", {'vlan_dict': vlan})
        # create dummy subnet - we need only id

        subnet = {'id': port['fixed_ips'][0]['subnet_id']}
        params = {
            'gatewayinterface': vlan['ID'],
            'np_id': port_dict['subnet_mapping']['net_partition_id'],
            'tenant': port['tenant_id'],
            'port': port,
            'subnet': subnet,
            'enable_dhcp': port_dict['enable_dhcp'],
            'nuage_managed_subnet':
                port_dict['subnet_mapping']['nuage_managed_subnet'],
            'port_security_enabled': False,
            'personality': vsd_port['personality']
        }
        vsd_subnet = self.vsdclient \
            .get_nuage_subnet_by_id(
                port_dict['subnet_mapping']['nuage_subnet_id'])
        params['vsd_subnet'] = vsd_subnet

        vport = self.vsdclient.create_gateway_vport_no_usergroup(
            self.context.tenant_id,
            params)
        LOG.debug("created vport: %(vport_dict)s",
                  {'vport_dict': vport})
        if (vsd_port['personality'] == 'VSG' and
                port.get(portsecurity.PORTSECURITY)):
            LOG.warn("Port %(port)s has %(attr)s set to True. But source "
                     "address spoofing will be allowed for the bridge "
                     "vport %(vport)s. Unsupported by VSG to provide "
                     "anti-spoofing.", {'port': port['id'],
                                        'attr': portsecurity.PORTSECURITY,
                                        'vport': vport['vport']['ID']})

    def bind_port(self, port):
        """bind_port.

        """
        pass

    def update_port(self, port_map):
        """update_port. This call makes the REST request to VSD

        for (un)provision VLAN/VPort on gateway port where bare metal
        is connected.
        """

        LOG.debug("update_port with port dict %(port)s",
                  {'port': port_map})
        vport = utils.get_nuage_vport(self.vsdclient, port_map, False)
        # gridinv: will be called typically when ironic will
        # update instance port in tenant network with proper binding
        # at this point we will have a VM vport existing in VSD which
        # needs to be cleaned up
        if vport and vport['type'] == const.VM_VPORT:
            try:
                self.vsdclient.delete_nuage_vport(
                    vport['ID'])
            except Exception as e:
                LOG.error("Failed to delete vport from vsd {vport id: %s}"
                          % vport['ID'])
                raise e

    def delete_port(self, port_dict):
        """delete_port. This call makes the REST request to VSD

        for un provision VLAN/VPort for the gateway port where
        bare metal is connected.
        """
        port = port_dict['port']
        LOG.debug("delete_port with port_id %(port_id)s",
                  {'port_id': port['id']})

        vport = utils.get_nuage_vport(self.vsdclient,
                                      port_dict,
                                      required=False)
        if not vport:
            LOG.debug("couldn't find a vport")
        else:
            LOG.debug("Deleting vport %(vport)s", {'vport': vport})
            self.vsdclient.delete_nuage_gateway_vport_no_usergroup(
                port['tenant_id'],
                vport)
            if vport.get('VLANID'):
                LOG.debug("Deleting vlan %(vlan)s",
                          {'vlan': vport['VLANID']})
                self.vsdclient.delete_gateway_port_vlan(vport['VLANID'])
