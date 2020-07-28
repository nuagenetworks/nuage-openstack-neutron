# Copyright 2019 Nokia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

from neutron_lib.api.definitions import portbindings
from neutron_lib.api import validators as lib_validators
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api

import netaddr
from neutron._i18n import _
from neutron.db import db_base_plugin_v2
from neutron.plugins.ml2.drivers import mech_agent
from oslo_db import exception as db_exc
from oslo_log import log

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants as p_const
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import net_topology_db as ext_db
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.utils import context_log
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id

LOG = log.getLogger(__name__)


class NuageHwVtepMechanismDriver(base_plugin.RootNuagePlugin,
                                 mech_agent.SimpleAgentMechanismDriverBase):

    def __init__(self):
        self._default_np_id = None
        self._l2_plugin = None
        self._l3_plugin = None

        self.agent_type = constants.AGENT_TYPE_OVS
        vif_details = {portbindings.CAP_PORT_FILTER: False}
        self.supported_vnic_types = [portbindings.VNIC_NORMAL]
        self.supported_network_types = [constants.TYPE_FLAT,
                                        constants.TYPE_VLAN]
        mech_agent.SimpleAgentMechanismDriverBase.__init__(
            self,
            agent_type=constants.AGENT_TYPE_OVS,
            vif_type=portbindings.VIF_TYPE_OVS,
            vif_details=vif_details,
            supported_vnic_types=self.supported_vnic_types
        )

    def initialize(self):
        LOG.debug('Initializing driver')
        self.init_vsd_client()
        db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS += [
            p_const.DEVICE_OWNER_DHCP_NUAGE]
        LOG.debug('Initializing complete')

    def get_allowed_network_types(self, agent=None):
        return self.supported_network_types

    def check_vlan_transparency(self, context):
        """driver vlan transparency support."""
        return True

    @staticmethod
    def is_network_device_port(port):
        return port.get('device_owner', '').startswith(
            constants.DEVICE_OWNER_PREFIXES)

    @staticmethod
    def is_network_dhcp_port(port):
        return (port.get('device_owner', '') ==
                constants.DEVICE_OWNER_DHCP)

    def provisioning_required(self, port):
        return (self.is_network_dhcp_port(port) or not
                self.is_network_device_port(port))

    def _validate_create_subnet(self, db_context, network, prefixlen,
                                subnet, vsd_managed, l2bridge):
        network_subnets = self.core_plugin.get_subnets(
            db_context,
            filters={'network_id': [subnet['network_id']]})
        if vsd_managed:
            self._validate_create_vsd_managed_subnet(network, subnet)
        else:
            self._validate_create_openstack_managed_subnet(
                db_context, subnet, network_subnets)
        subnet_ids = [s['id'] for s in network_subnets]
        subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
            db_context.session,
            subnet_ids)
        if len(set([vsd_managed] + [m['nuage_managed_subnet']
                                    for m in subnet_mappings])) > 1:
            msg = _("Can't mix openstack and vsd managed subnets under 1 "
                    "network.")
            raise exceptions.NuageBadRequest(resource='subnet', msg=msg)

        ipv4s = len([s for s in network_subnets if self._is_ipv4(s)])
        ipv6s = len([s for s in network_subnets if self._is_ipv6(s)])

        if ipv4s > 1 or ipv6s > 1:
            msg = _("HWVTEP driver only supports single subnet networks "
                    "or dualstack networks")
            raise exceptions.NuageBadRequest(msg=msg)

        # nuage_l2bridge tests
        if l2bridge:
            # For l2bridges, certain parameters need to be equal for all
            # bridged subnets, as they are reflected on VSD.
            bridged_subnets = nuagedb.get_subnets_for_nuage_l2bridge(
                db_context.session,
                l2bridge['id'])
            # Make subnet dict to include extensions
            ipv_bridged = [
                self.core_plugin._make_subnet_dict(s)
                for s in bridged_subnets if
                s['id'] != subnet['id'] and
                s['ip_version'] == subnet['ip_version']]
            if not ipv_bridged:
                return
            for param in p_const.L2BRIDGE_SUBNET_EQUAL_ATTRIBUTES:
                self._validate_l2bridge_added_subnet_parameter(
                    ipv_bridged[0], subnet, param, l2bridge)

    def check_subnet_is_nuage_l3(self, context, subnet):
        return False, None

    @handle_nuage_api_errorcode
    def create_subnet_precommit(self, context):
        subnet = context.current
        network = context.network.current
        db_context = context._plugin_context
        prefixlen = netaddr.IPNetwork(subnet['cidr']).prefixlen
        nuagenet_set = lib_validators.is_attr_set(subnet.get('nuagenet'))
        if not self.is_network_type_supported(network):
            return
        with db_context.session.begin(subtransactions=True):
            self.create_nuage_subnet_precommit(db_context,
                                               network,
                                               prefixlen, subnet,
                                               nuagenet_set)

    def delete_subnet_precommit(self, context):
        subnet = context.current
        db_context = context._plugin_context
        context.nuage_mapping = nuagedb.get_subnet_l2dom_by_id(
            db_context.session, subnet['id'])
        context.dual_stack_subnet = self.get_dual_stack_subnet(db_context,
                                                               subnet)

    @context_log
    @handle_nuage_api_errorcode
    def delete_subnet_postcommit(self, context):
        db_context = context._plugin_context
        subnet = context.current
        network = context.network.current
        mapping = context.nuage_mapping
        dual_stack_subnet = context.dual_stack_subnet
        if not mapping:
            return

        if self._is_os_mgd(mapping):
            if network.get('nuage_l2bridge'):
                with db_context.session.begin(subtransactions=True):
                    l2bridge = nuagedb.get_nuage_l2bridge_blocking(
                        db_context.session, network['nuage_l2bridge'])
                    attempt = 0
                    while True:
                        try:
                            bridged_subnets = (
                                nuagedb.get_subnets_for_nuage_l2bridge(
                                    db_context.session, l2bridge['id']))
                            break
                        except db_exc.DBDeadlock:
                            if attempt < 25:
                                LOG.debug("Retrying to get bridged subnets"
                                          " due to Deadlock.")
                                attempt += 1
                                time.sleep(0.2)
                                continue
                            msg = ("Chance of a hanging L2Domain on VSD for"
                                   "resource nuage-l2bridge: %s",
                                   l2bridge['id'])
                            raise Exception(msg)
                    ipv4s = [s['id'] for s in bridged_subnets
                             if self._is_ipv4(s) and s['id'] != subnet['id']]
                    ipv6s = [s['id'] for s in bridged_subnets
                             if self._is_ipv6(s) and s['id'] != subnet['id']]
                    if ((self._is_ipv4(subnet) and ipv4s) or
                            (self._is_ipv6(subnet) and ipv6s)):
                        return
                    elif not ipv4s and not ipv6s:
                        l2bridge['nuage_subnet_id'] = None
                    else:
                        # Delete subnet from dualstack on vsd
                        dual_stack_subnet = self.core_plugin.get_subnet(
                            db_context, ipv4s[0] if ipv4s else ipv6s[0])
            if dual_stack_subnet:
                v4 = v6 = None
                if self._is_ipv4(subnet):
                    v6 = dual_stack_subnet
                else:
                    v4 = dual_stack_subnet
                self.vsdclient.delete_subnet(mapping=mapping,
                                             ipv4_subnet=v4,
                                             ipv6_subnet=v6)
                return
            else:
                l2_id, l3_sub_id = get_l2_and_l3_sub_id(mapping)
                self.vsdclient.delete_subnet(l3_vsd_subnet_id=l3_sub_id,
                                             l2dom_id=l2_id,
                                             mapping=mapping)
        else:
            # VSD managed could be ipv6 + ipv4. If only one of the 2 is
            # deleted, the use permission should not be removed yet.
            # Also, there can be multiple subnets mapped to same VSD subnet.
            clean_groups = True
            other_mappings = nuagedb.get_subnet_l2doms_by_nuage_id(
                db_context.session,
                mapping['nuage_subnet_id'])

            if other_mappings:
                for other_mapping in other_mappings:
                    other_subnet = context._plugin.get_subnet(
                        db_context,
                        other_mapping['subnet_id'])
                    if subnet['tenant_id'] == other_subnet['tenant_id']:
                        clean_groups = False
                        break

            if clean_groups:
                self._cleanup_group(db_context,
                                    mapping['net_partition_id'],
                                    mapping['nuage_subnet_id'], subnet)

        filters = {
            'network_id': [subnet['network_id']],
            'device_owner': [p_const.DEVICE_OWNER_DHCP_NUAGE]
        }
        nuage_dhcp_ports = self.core_plugin.get_ports(db_context, filters)
        for nuage_dhcp_port in nuage_dhcp_ports:
            if not nuage_dhcp_port.get('fixed_ips'):
                self.delete_dhcp_nuage_port_by_id(db_context,
                                                  nuage_dhcp_port['id'])

    @handle_nuage_api_errorcode
    @context_log
    def update_subnet_precommit(self, context):
        self.update_subnet(context)

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    @context_log
    def create_port_postcommit(self, context):
        port = context.current
        if (port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
                not in self.supported_vnic_types):
            return
        if context.segments_to_bind:
            self._create_port_on_switch(context)

    def update_port_precommit(self, context):
        nuage_bindings = ext_db.get_switchport_binding_by_neutron_port(
            context._plugin_context, context.current['id'])
        context.nuage_bindings = nuage_bindings

    @context_log
    def update_port_postcommit(self, context):
        port = context.current
        if (port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
                not in self.supported_vnic_types):
            return
        if ((context.host != context.original_host and
                context.original_host) or not port.get('fixed_ips')):
            self._delete_port_on_switch(context)
        self._create_port_on_switch(context)

    def delete_port_precommit(self, context):
        port = context.current
        if (port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
                not in self.supported_vnic_types):
            return
        db_context = context._plugin_context
        nuage_bindings = ext_db.get_switchport_binding_by_neutron_port(
            db_context, context.current['id'])
        context.nuage_bindings = nuage_bindings
        with db_context.session.begin(subtransactions=True):
            ext_db.delete_switchport_binding(db_context,
                                             context.current['id'])

    @context_log
    def delete_port_postcommit(self, context):
        port = context.current
        if (port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
                not in self.supported_vnic_types):
            return
        self._delete_port_on_switch(context)

    def _get_subnet_mapping(self, db_context, port):
        for fixed_ip in port.get('fixed_ips', []):
            return nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                  fixed_ip['subnet_id'])
        return None

    def _get_redundancy(self, bridge, switch_mappings, tenant_id):
        """_get_redundancy

        This methods checks switch mappings which correspond to
        a particular host,bridge. If any of them is a part of
        redundant port in VSD, than all of them should  belong
        to a single redundancy group. If none of switch mappings
        are part of redundancy group than whole list is returned to
        a caller, otherwise a single entry is returned along with
        RG ID.

        :returns switch_mappings: list of switch mappings plugin
                 has to orchestrate
        :returns redundancy_group_id: VSD RG id to which switch
                 mappings belong or None.

        """
        redundant_ports = ({mapping.get('redundant_port_uuid') for
                           mapping in switch_mappings})
        if len(redundant_ports) > 1:
            # we got a list with only some of the entries redundant
            # this is misconfiguration
            msg = (_("All switchports for bridge %(bridge)s must be"
                     "part of a single redundant port") %
                   {'bridge': bridge})
            raise exceptions.NuageBadRequest(msg=msg)
        elif len(redundant_ports) == 1 and None not in redundant_ports:
            # Active/Active redundancy, fetch RG id and
            # return a single mapping to orchestrate
            rg_port = self.vsdclient.get_gateway_port(
                tenant_id,
                redundant_ports.pop())
            return (switch_mappings[::len(switch_mappings)],
                    rg_port.get('rg_id'))
        else:
            # Single port or Active/Standby redundancy
            return switch_mappings, None

    def _create_bridgeport(self, context, bridge, segmentation_id):
        port = context.current
        ctx = context._plugin_context
        host = port[portbindings.HOST_ID]
        switch_mappings = ext_db.get_switchports_by_host_bridge(
            ctx, host, bridge)
        if not switch_mappings:
            msg = (_("Failed to retrieve switchport mapping "
                     "for host: %(host)s bridge: %(bridge)s") %
                   {'host': host, 'bridge': bridge})
            if self.is_network_dhcp_port(port):
                LOG.warn(msg)
                LOG.warn('network:dhcp port %(port)s will have '
                         'no connectivity',
                         {'port': port['id']})
                return
            else:
                raise exceptions.NuageBadRequest(msg=msg)
        port_bindings = ext_db.get_switchport_binding_by_neutron_port(
            ctx,
            port['id'],
            segmentation_id)
        if port_bindings:
            LOG.info("bridge port(s) %(pb)s for port %(port_id)s "
                     "already exist",
                     {'pb': port_bindings,
                      'port_id': port['id']})
            return
        mappings, rg = self._get_redundancy(bridge,
                                            switch_mappings,
                                            ctx.tenant_id)
        for switchport in mappings:
            vports = ext_db.get_switchport_bindings_by_switchport_vlan(
                ctx,
                switchport['port_uuid'],
                segmentation_id)

            if len(vports) == 0:
                if rg:
                    gw = self.vsdclient.get_gateway(ctx.tenant_id, rg)
                else:
                    filters = {'system_id': [switchport['switch_id']]}
                    gws = self.vsdclient.get_gateways(ctx.tenant_id,
                                                      filters)
                    if len(gws) == 0:
                        msg = (_("No gateway found %s")
                               % filters['system_id'][0])
                        raise exceptions.NuageBadRequest(msg=msg)
                    gw = gws[0]

                subnet_mapping = self._get_subnet_mapping(
                    context._plugin_context,
                    port)
                if not subnet_mapping:
                    LOG.debug("Subnet mapping for port %s could not be found, "
                              "it might have been deleted concurrently.",
                              port['id'])
                    return
                subnet = context._plugin.get_subnet(
                    context._plugin_context,
                    subnet_mapping['subnet_id'])

                params = {
                    'gatewayport': switchport.get('redundant_port_uuid') or
                    switchport['port_uuid'],
                    'value': segmentation_id,
                    'redundant': rg is not None,
                    'personality': gw['gw_type']
                }
                vlan = self.vsdclient.create_gateway_vlan(params)
                LOG.debug("created vlan: %(vlan_dict)s",
                          {'vlan_dict': vlan})
                params = {
                    'gatewayinterface': vlan['ID'],
                    'np_id': subnet_mapping['net_partition_id'],
                    'tenant': port['tenant_id'],
                    'subnet': subnet,
                    'enable_dhcp': subnet['enable_dhcp'],
                    'nuage_managed_subnet':
                        subnet_mapping['nuage_managed_subnet'],
                    'port_security_enabled': False,
                    'personality': gw['gw_type'],
                    'type': p_const.BRIDGE_VPORT_TYPE
                }
                vsd_subnet = self.vsdclient.get_nuage_subnet_by_id(
                    subnet_mapping['nuage_subnet_id'])
                params['vsd_subnet'] = vsd_subnet

                # allow all policy group is a default switch behaviour
                create_policy = False

                vport = self.vsdclient.create_gateway_vport_no_usergroup(
                    ctx.tenant_id,
                    params, create_policy_group=create_policy)
                LOG.debug("created vport: %(vport_dict)s",
                          {'vport_dict': vport})
                bridge_port_id = vport.get('vport').get('ID')
            else:
                bridge_port_id = vports[0]['nuage_vport_id']
            binding = {
                'neutron_port_id': port.get('id'),
                'nuage_vport_id': bridge_port_id,
                'switchport_uuid': switchport['port_uuid'],
                'segmentation_id': segmentation_id,
                'switchport_mapping_id': switchport['id']
            }
            ext_db.add_switchport_binding(ctx, binding)

    def _create_port_on_switch(self, context):
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = port[portbindings.HOST_ID]
        if not port.get('fixed_ips'):
            return
        if not hasattr(context, 'top_bound_segment'):
            return
        if not context.top_bound_segment:
            return
        if not (host and device_id and device_owner):
            return
        if not self.provisioning_required(port):
            return

        for agent in context.host_agents(self.agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                bridge = self.check_segment_for_agent(
                    context.top_bound_segment, agent)
                if bridge:
                    # flat networks will have segmentation_id null,
                    # which maps to vlan 0 on VSP
                    vlan_id = context.top_bound_segment['segmentation_id'] or 0
                    LOG.info("Attempting to create bridgeport for host: "
                             "%(host)s bridge: %(bridge)s with "
                             "segmentation_id: %(vlan_id)s",
                             {'vlan_id': vlan_id,
                              'host': host,
                              'bridge': bridge})
                    self._create_bridgeport(context, bridge, vlan_id)
            else:
                LOG.warning("Refusing to create bridgeport on host with "
                            "dead agent: %s", agent)

    def _delete_port_on_switch(self, context):
        port = context.current
        db_context = context._plugin_context
        if not self.provisioning_required(port):
            return
        port_bindings = context.nuage_bindings
        if not port_bindings:
            return
        with db_context.session.begin(subtransactions=True):
            for binding in port_bindings:
                bindings = ext_db.get_switchport_bindings_by_switchport_vlan(
                    db_context, binding['switchport_uuid'],
                    binding['segmentation_id'])
                if not bindings:
                    vport = self.vsdclient.get_nuage_vport_by_id(
                        binding['nuage_vport_id'],
                        required=False)
                    if vport:
                        LOG.debug("Deleting vport %(vport)s", {'vport': vport})
                        self.vsdclient.delete_nuage_gateway_vport_no_usergroup(
                            port['tenant_id'],
                            vport)
                        if vport.get('VLANID'):
                            LOG.debug("Deleting vlan %(vlan)s",
                                      {'vlan': vport['VLANID']})
                            self.vsdclient.delete_gateway_port_vlan(
                                vport['VLANID'])

    def check_segment_for_agent(self, segment, agent=None):
        network_type = segment[api.NETWORK_TYPE]
        if network_type in self.get_allowed_network_types():
            if agent:
                mappings = self.get_mappings(agent)
                LOG.debug("Checking segment: %(segment)s "
                          "for mappings: %(mappings)s ",
                          {'segment': segment, 'mappings': mappings})
                if segment[api.PHYSICAL_NETWORK] in mappings:
                    return mappings[segment[api.PHYSICAL_NETWORK]]
        return None
