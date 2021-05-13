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

from neutron._i18n import _

from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import net_topology_db as ext_db

from oslo_log import helpers as log_helpers


class NuageNetTopologyPlugin(ext_db.NuageGwPortMappingDbMixin,
                             BaseNuagePlugin):

    supported_extension_aliases = ['net-topology']

    def __init__(self):
        super(NuageNetTopologyPlugin, self).__init__()

    def get_plugin_type(self):
        return constants.NUAGE_NET_TOPOLOGY_SERVICE_PLUGIN

    def get_plugin_description(self):
        return "Nuage Neutron Net Topology Service plugin"

    def _validate_switchport(self, context, switchport_mapping):
        filters = {'system_id': [switchport_mapping['switch_id']]}
        gws = self.vsdclient.get_gateways(context.tenant_id, filters)
        if len(gws) == 0:
            msg = (_("No gateway found %s")
                   % filters['system_id'][0])
            raise nuage_exc.NuageBadRequest(msg=msg)
        filters = {'gateway': [gws[0]['gw_id']],
                   'physicalName': [switchport_mapping['port_id']]}
        gw_ports = self.vsdclient.get_gateway_ports(context.tenant_id,
                                                    filters)
        if len(gw_ports) == 0:
            msg = (_("No gateway port found %s")
                   % filters['physicalName'][0])
            raise nuage_exc.NuageBadRequest(msg=msg)
        return (gw_ports[0].get('gw_port_id'),
                gw_ports[0].get('gw_redundant_port_id'))

    @log_helpers.log_method_call
    def create_switchport_mapping(self, context, switchport_mapping):
        s = switchport_mapping['switchport_mapping']
        with context.session.begin(subtransactions=True):
            gw_port_id, gw_rport_id = self._validate_switchport(context, s)
            switchport_mapping['switchport_mapping']['port_uuid'] = gw_port_id
            switchport_mapping['switchport_mapping']['redundant_port_uuid'] = (
                gw_rport_id)
            gw_map = super(NuageNetTopologyPlugin,
                           self).create_switchport_mapping(context,
                                                           switchport_mapping)
        return gw_map

    @log_helpers.log_method_call
    def delete_switchport_mapping(self, context, id):
        with context.session.begin(subtransactions=True):
            super(NuageNetTopologyPlugin,
                  self).delete_switchport_mapping(context, id)

    @log_helpers.log_method_call
    def update_switchport_mapping(self, context, id, switchport_mapping):
        orig = self.get_switchport_mapping(context, id)
        with context.session.begin(subtransactions=True):
            s = switchport_mapping['switchport_mapping']
            if not s.get('port_id'):
                s['port_id'] = orig['port_id']
            if not s.get('switch_id'):
                s['switch_id'] = orig['switch_id']
            gw_port_id, gw_rport_id = self._validate_switchport(context, s)
            s['port_uuid'] = gw_port_id
            s['redundant_port_uuid'] = gw_rport_id
            if (s.get('pci_slot') and
                s.get('pci_slot') != orig.get('pci_slot') or
                s.get('host_id') and
                    s.get('host_id') != orig.get('host_id')):
                if not s.get('host_id'):
                    s['host_id'] = orig['host_id']
                if not s.get('pci_slot'):
                    s['pci_slot'] = orig['pci_slot']
                self._validate_host_pci(context, s)
            gw_map = super(NuageNetTopologyPlugin,
                           self).update_switchport_mapping(context, id,
                                                           switchport_mapping)
            return gw_map
