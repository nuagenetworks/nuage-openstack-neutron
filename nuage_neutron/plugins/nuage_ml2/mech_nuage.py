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

import inspect
import time

import netaddr
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils

from neutron._i18n import _
from neutron.api import extensions as neutron_extensions
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import provisioning_blocks
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import port_security as portsecurity
from neutron_lib.api.definitions import portbindings
from neutron_lib.api import validators as lib_validators
from neutron_lib.callbacks import resources
from neutron_lib import constants as os_constants
from neutron_lib import context as n_context
from neutron_lib.exceptions import PortInUse
from neutron_lib.exceptions import SubnetNotFound
from neutron_lib.plugins.ml2 import api

from nuage_neutron.plugins.common.addresspair import NuageAddressPair
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common.exceptions import NuagePortBound
from nuage_neutron.plugins.common import extensions
from nuage_neutron.plugins.common.extensions import nuagepolicygroup
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import ignore_no_update
from nuage_neutron.plugins.common.utils import ignore_not_found
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.plugins.nuage_ml2.securitygroup import NuageSecurityGroup
from nuage_neutron.plugins.nuage_ml2 import trunk_driver

from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id
from nuage_neutron.vsdclient import restproxy

LB_DEVICE_OWNER_V2 = os_constants.DEVICE_OWNER_LOADBALANCERV2
PORT_UNPLUGGED_TYPES = (portbindings.VIF_TYPE_BINDING_FAILED,
                        portbindings.VIF_TYPE_UNBOUND,
                        portbindings.VIF_TYPE_OVS)
DEVICE_OWNER_DHCP = os_constants.DEVICE_OWNER_DHCP

LOG = log.getLogger(__name__)


class NuageMechanismDriver(base_plugin.RootNuagePlugin,
                           api.MechanismDriver,
                           db_base_plugin_v2.NeutronDbPluginV2,
                           agents_db.AgentDbMixin):

    def __init__(self):
        self._core_plugin = None
        self.trunk_driver = None
        self.supported_network_types = [os_constants.TYPE_VXLAN,
                                        constants.NUAGE_HYBRID_MPLS_NET_TYPE]

        super(NuageMechanismDriver, self).__init__()

    def initialize(self):
        LOG.debug('Initializing driver')
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        self._validate_mech_nuage_configuration()
        self.init_vsd_client()
        self._wrap_vsdclient()
        NuageSecurityGroup().register()
        NuageAddressPair().register()
        db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS += [
            constants.DEVICE_OWNER_DHCP_NUAGE]
        self.trunk_driver = trunk_driver.NuageTrunkDriver.create(self)
        LOG.debug('Initializing complete')

    def _validate_mech_nuage_configuration(self):
        service_plugins = constants.MIN_MECH_NUAGE_SERVICE_PLUGINS_IN_CONFIG
        extensions = constants.MIN_MECH_NUAGE_EXTENSIONS_IN_CONFIG
        self._validate_config_for_nuage_driver(constants.NUAGE_ML2_DRIVER_NAME,
                                               service_plugins,
                                               extensions)

    def _wrap_vsdclient(self):
        """Wraps nuageclient methods with try-except to ignore certain errors.

        When updating an entity on the VSD and there is nothing to actually
        update because the values don't change, VSD will throw an error. This
        is not needed for neutron so all these exceptions are ignored.

        When VSD responds with a 404, this is sometimes good (for example when
        trying to update an entity). Yet sometimes this is not required to be
        an actual exception. When deleting an entity that does no longer exist
        it is fine for neutron. Also when trying to retrieve something from VSD
        having None returned is easier to work with than RESTProxy exceptions.
        """

        methods = inspect.getmembers(self.vsdclient,
                                     lambda x: inspect.ismethod(x))
        for m in methods:
            wrapped = ignore_no_update(m[1])
            if m[0].startswith('get_') or m[0].startswith('delete_'):
                wrapped = ignore_not_found(wrapped)
            setattr(self.vsdclient, m[0], wrapped)

    @utils.context_log
    def create_network_precommit(self, context):
        network = context.current
        db_context = context._plugin_context
        # A network attached to an L2bridge is not allowed to be external or
        # shared
        self._validate_network_physnet(db_context, network)

    def _validate_network_physnet(self, context, network):
        l2bridge_id = nuagedb.get_nuage_l2bridge_id_for_network(
            context.session, network['id'])
        if l2bridge_id:
            is_external = network.get(external_net.EXTERNAL)
            if is_external:
                msg = _("It is not allowed to create a network as external in "
                        "a physical_network attached to a nuage_l2bridge")
                raise NuageBadRequest(msg=msg)
            is_shared = network.get('shared')
            if is_shared:
                msg = _("It is not allowed to create a shared network in "
                        "a physical_network attached to a nuage_l2bridge")
                raise NuageBadRequest(msg=msg)
            physnets = self._get_l2bridge_physnets(context, network)
            l2bridges = {p['l2bridge_id'] for p in physnets}
            if len(l2bridges) > 1:
                msg = _("It is not allowed to attach a network to multiple"
                        "nuage_l2bridges.")
                raise NuageBadRequest(msg=msg)

        # Block vxlan and nuage_hybrid_segments in a single network
        self.check_vxlan_mpls_segments_in_network(network.get('segments', []))

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_network_precommit(self, context):
        updated_network = context.current
        original_network = context.original
        db_context = context._plugin_context

        (external_change,
         shared_change,
         physnets_change,
         _) = self._network_no_action(original_network,
                                      updated_network)
        if any([external_change, shared_change, physnets_change]):
            self._validate_update_network(db_context, external_change,
                                          shared_change, physnets_change,
                                          original_network,
                                          updated_network)

        # Block vxlan and nuage_hybrid_segments in a single network
        # This cannot be included in the above structure since after the
        # create segment operation, neutron calls update_network_precommit
        # with the same value for the original and updated network
        self.check_vxlan_mpls_segments_in_network(
            updated_network.get('segments', []))

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_network_postcommit(self, context):
        updated_network = context.current
        original_network = context.original
        db_context = context._plugin_context
        (external_change,
         shared_change,
         physnets_change,
         name_change) = self._network_no_action(original_network,
                                                updated_network)
        if not any([external_change, shared_change, physnets_change,
                    name_change]):
            # No update required
            return
        subnets = self.core_plugin.get_subnets_by_network(
            db_context, updated_network['id'])

        if external_change:
            for subn in subnets:
                subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                    db_context.session, subn['id'])
                LOG.debug("Found subnet %(subn_id)s to l2 domain mapping"
                          " %(nuage_subn_id)s",
                          {'subn_id': subn['id'],
                           'nuage_subn_id':
                               subnet_l2dom['nuage_subnet_id']})
                self.vsdclient.delete_subnet(
                    l2dom_id=subnet_l2dom['nuage_subnet_id'])
                nuagedb.delete_subnetl2dom_mapping(db_context.session,
                                                   subnet_l2dom)
                # delete the neutron port that was reserved with IP of
                # the dhcp server that is reserved.
                # Now, this port is not reqd.
                self.delete_dhcp_nuage_port(db_context, subn)
                self._add_nuage_sharedresource(db_context, subn,
                                               constants.SR_TYPE_FLOATING,
                                               subnets)

        if shared_change and not updated_network.get(external_net.EXTERNAL):
            for subnet in subnets:
                nuage_subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                    db_context.session, subnet['id'])
                if self._is_l2(nuage_subnet_l2dom):
                    # change of perm only reqd in l2dom case
                    self.vsdclient.change_perm_of_subns(
                        nuage_subnet_l2dom['net_partition_id'],
                        nuage_subnet_l2dom['nuage_subnet_id'],
                        updated_network['shared'],
                        subnet['tenant_id'], remove_everybody=True)

        if name_change:
            ipv4s = len([s for s in subnets if self._is_ipv4(s)])
            ipv6s = len([s for s in subnets if self._is_ipv6(s)])
            if ipv4s == 1 and ipv6s == 1:
                # only dualstack subnets use network name as description
                subnet = subnets[0]
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                    db_context.session, subnet['id'])
                params = {
                    'dualstack': True,
                    'network_name': updated_network['name']
                }
                if self._is_l2(subnet_mapping):
                    self.vsdclient.update_l2domain_template(
                        subnet_mapping['nuage_l2dom_tmplt_id'], **params)
                    self.vsdclient.update_l2domain(
                        subnet_mapping['nuage_subnet_id'], **params)
                else:
                    params.update({
                        "subnet_nuage_underlay":
                            subnet.get(constants.NUAGE_UNDERLAY)
                    })
                    self.vsdclient.update_domain_subnet(
                        subnet_mapping['nuage_subnet_id'], params)

    def check_dhcp_agent_alive(self, context):
        get_dhcp_agent = self.get_agents(
            context, filters={"alive": [True],
                              "binary": ['neutron-dhcp-agent']})
        if get_dhcp_agent:
            return True
        return False

    @utils.context_log
    @handle_nuage_api_errorcode
    def create_subnet_precommit(self, context):
        subnet = context.current
        network = context.network.current
        db_context = context._plugin_context
        prefixlen = netaddr.IPNetwork(subnet['cidr']).prefixlen
        nuagenet_set = lib_validators.is_attr_set(subnet.get('nuagenet'))
        net_part_set = lib_validators.is_attr_set(subnet.get('net_partition'))

        if not self.is_network_type_supported(network):
            if nuagenet_set or net_part_set:
                # Nuage attributes set on unsupported network types
                msg = _("Network should have 'provider:network_type' "
                        "vxlan or nuage_hybrid_mpls, or have such a segment")
                raise NuageBadRequest(msg=msg)
            else:
                return  # Not for us

        with db_context.session.begin(subtransactions=True):
            self.create_nuage_subnet_precommit(db_context,
                                               network,
                                               prefixlen, subnet,
                                               nuagenet_set)

    def _validate_create_subnet(self, db_context, network, prefixlen,
                                subnet, vsd_managed, l2bridge):
        for attribute in ('ipv6_ra_mode', 'ipv6_address_mode'):
            if not lib_validators.is_attr_set(subnet.get(attribute)):
                continue
            if subnet[attribute] != os_constants.DHCPV6_STATEFUL:
                msg = _("Attribute %(attribute)s must be '%(allowed)s' or "
                        "not set.")
                raise NuageBadRequest(
                    resource='subnet',
                    msg=msg % {'attribute': attribute,
                               'allowed': os_constants.DHCPV6_STATEFUL})
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
            raise NuageBadRequest(resource='subnet', msg=msg)

        ipv4s = len([s for s in network_subnets if self._is_ipv4(s)])
        ipv6s = len([s for s in network_subnets if self._is_ipv6(s)])

        if ((ipv4s > 1 or ipv6s > 1) and
                self.check_dhcp_agent_alive(db_context) and
                not self.is_external(db_context, network['id'])):
            msg = _("A network with multiple ipv4 or ipv6 subnets is not "
                    "allowed when neutron-dhcp-agent is enabled")
            raise NuageBadRequest(msg=msg)

        # nuage_l2bridge tests
        if l2bridge:
            if self.check_dhcp_agent_alive(db_context):
                msg = _("A network cannot be attached to an l2bridge "
                        "when neutron-dhcp-agent is enabled")
                raise NuageBadRequest(msg=msg)

            if ipv4s > 1 or ipv6s > 1:
                msg = _("A network attached to a nuage_l2bridge cannot have"
                        " more than one ipv4 or more than one ipv6 subnet.")
                raise NuageBadRequest(msg=msg)

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
            for param in constants.L2BRIDGE_SUBNET_EQUAL_ATTRIBUTES:
                self._validate_l2bridge_added_subnet_parameter(
                    ipv_bridged[0], subnet, param, l2bridge)

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_subnet_precommit(self, context):
        self.update_subnet(context)

    @utils.context_log
    @handle_nuage_api_errorcode
    def delete_subnet_precommit(self, context):
        """Get subnet_l2dom_mapping for later.

        In postcommit this nuage_subnet_l2dom_mapping is no longer available
        because it is set to CASCADE with the subnet. So this row will be
        deleted prior to delete_subnet_postcommit
        """
        subnet = context.current
        db_context = context._plugin_context
        context.nuage_mapping = nuagedb.get_subnet_l2dom_by_id(
            db_context.session, subnet['id'])
        context.dual_stack_subnet = self.get_dual_stack_subnet(db_context,
                                                               subnet)
        if not context.nuage_mapping:
            return
        if self._is_l3(context.nuage_mapping) and context.dual_stack_subnet:
            self._validate_vips_in_use(db_context, subnet)

    def _validate_vips_in_use(self, db_context, subnet):
        other_version = 4 if self._is_ipv6(subnet) else 6
        nuage_subnets = (
            nuagedb.get_subnet_mapping_by_network_id_and_ip_version(
                db_context.session, subnet['network_id'],
                ip_version=other_version))
        for nuage_mapping in nuage_subnets:
            vip_filters = {
                'fixed_ips': {'subnet_id': [nuage_mapping['subnet_id']]}
            }
            ports = self.core_plugin.get_ports(db_context,
                                               filters=vip_filters,
                                               fields='allowed_address_pairs')
            ports_with_aap = [p for p in ports if p['allowed_address_pairs']]
            for port in ports_with_aap:
                for aap in port['allowed_address_pairs']:
                    if (netaddr.IPNetwork(aap['ip_address']).size == 1 and
                            netaddr.IPAddress(aap['ip_address']) in
                            netaddr.IPNetwork(subnet['cidr'])):
                        msg = _('IP %s is in use for nuage VIP,'
                                ' hence cannot delete the'
                                ' subnet.') % aap['ip_address']
                        raise NuageBadRequest(msg=msg)

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
                if self._is_ipv4(subnet):
                    self.vsdclient.delete_subnet(mapping=mapping,
                                                 ipv4_subnet=None,
                                                 ipv6_subnet=dual_stack_subnet)
                    return
                else:
                    self.vsdclient.delete_subnet(mapping=mapping,
                                                 ipv4_subnet=dual_stack_subnet,
                                                 ipv6_subnet=None)
                    return
            else:
                l2_id, l3_sub_id = get_l2_and_l3_sub_id(mapping)
                try:
                    self.vsdclient.delete_subnet(l3_vsd_subnet_id=l3_sub_id,
                                                 l2dom_id=l2_id,
                                                 mapping=mapping)
                except restproxy.RESTProxyError as e:
                    vm_exist = (e.code == restproxy.RES_CONFLICT and
                                e.vsd_code in
                                [vsd_constants.VSD_VM_EXIST,
                                 vsd_constants.VSD_VM_EXISTS_ON_VPORT,
                                 vsd_constants.VSD_PG_IN_USE])
                    if vm_exist:
                        if l3_sub_id:
                            vms = self.vsdclient.vms_on_subnet(l3_sub_id)
                        else:
                            vms = self.vsdclient.vms_on_l2domain(l2_id)
                        np = nuagedb.get_net_partition_by_id(
                            db_context.session,
                            id=mapping['net_partition_id'])
                        for vm in vms:
                            LOG.debug('deleting VSD vm %s', vm['ID'])
                            params = {
                                'id': vm['ID'],
                                'tenant': subnet['tenant_id'],
                                'netpart_name': np['name']
                            }
                            self.vsdclient.delete_vm_by_id(params)
                        self.vsdclient.delete_subnet(
                            l3_vsd_subnet_id=l3_sub_id, l2dom_id=l2_id,
                            mapping=mapping)
                    else:
                        raise
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
            'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
        }
        nuage_dhcp_ports = self.core_plugin.get_ports(db_context, filters)
        for nuage_dhcp_port in nuage_dhcp_ports:
            if not nuage_dhcp_port.get('fixed_ips'):
                self.delete_dhcp_nuage_port_by_id(db_context,
                                                  nuage_dhcp_port['id'])

    def _is_port_provisioning_required(self, network, port, host):
        vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)

        if vnic_type not in self._supported_vnic_types():
            LOG.debug('No provisioning block for port %(port_id)s due to '
                      'unsupported vnic_type: %(vnic_type)s',
                      {'port_id': port['id'], 'vnic_type': vnic_type})
            return False

        if port['status'] == os_constants.PORT_STATUS_ACTIVE:
            LOG.debug('No provisioning block for port %s since it is active',
                      port['id'])
            return False

        if not host:
            LOG.debug('No provisioning block for port %s since it does not '
                      'have a host', port['id'])
            return False

        if not self._is_port_supported(port, network):
            LOG.debug('No provisioning block for port %s since it will not '
                      'be handled by driver', port['id'])
            return False

        return True

    def _insert_port_provisioning_block(self, context, port_id):
        # Insert a provisioning block to prevent the port from
        # transitioning to active until Nuage driver reports back
        # that the port is up.
        provisioning_blocks.add_provisioning_component(
            context, port_id, resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY
        )

    def _notify_port_provisioning_complete(self, port_id):
        """Notifies Neutron that the provisioning is complete for port."""
        if provisioning_blocks.is_object_blocked(
                n_context.get_admin_context(), port_id, resources.PORT):
            provisioning_blocks.provisioning_complete(
                n_context.get_admin_context(), port_id, resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_precommit(self, context):
        if self._is_port_provisioning_required(context.network.current,
                                               context.current, context.host):
            self._insert_port_provisioning_block(context._plugin_context,
                                                 context.current['id'])

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_postcommit(self, context):
        self._create_port(context._plugin_context,
                          context.current,
                          context.network.current)
        self._notify_port_provisioning_complete(context.current['id'])

    def _create_port(self, db_context, port, network):
        is_network_external = network.get('router:external')
        # Validate port
        subnet_ids = [ip['subnet_id'] for ip in port['fixed_ips']]
        subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
            db_context.session, subnet_ids)
        if not subnet_mappings:
            LOG.warn('No VSD subnet found for port.')
            return
        if not self._should_act_on_port(port, is_network_external):
            LOG.warn('Port not applicable for Nuage.')
            return

        self._validate_port(db_context, port,
                            is_network_external, subnet_mappings, network)
        self.nuage_callbacks.notify(resources.PORT, constants.BEFORE_CREATE,
                                    self, context=db_context,
                                    request_port=port)

        subnet_mapping = subnet_mappings[0]
        nuage_vport = nuage_vm = np_name = None
        np_id = subnet_mapping['net_partition_id']
        nuage_subnet = self._find_vsd_subnet(db_context, subnet_mapping)
        try:
            if port.get('binding:host_id') and self._port_should_have_vm(port):
                self._validate_vmports_same_netpartition(db_context,
                                                         port, np_id)
                desc = ("device_owner:" + constants.NOVA_PORT_OWNER_PREF +
                        "(please do not edit)")
                nuage_vport = self._create_nuage_vport(port, nuage_subnet,
                                                       desc)
                np_name = self.vsdclient.get_net_partition_name_by_id(np_id)
                require(np_name, "netpartition", np_id)
                nuage_vm = self._create_nuage_vm(
                    db_context, port, np_name, subnet_mapping,
                    nuage_vport, nuage_subnet, network)
            else:
                nuage_vport = self._create_nuage_vport(port, nuage_subnet)

            if (not port[portsecurity.PORTSECURITY] and
                    self._is_os_mgd(subnet_mapping)):
                self._process_port_create_secgrp_for_port_sec(db_context, port)
            self.calculate_vips_for_port_ips(db_context,
                                             port)
        except (restproxy.RESTProxyError, NuageBadRequest) as ex:
            # TODO(gridinv): looks like in some cases we convert 404 to 400
            # so i have to catch both. Question here is - don't we hide
            # valid error with this?
            if nuage_vm:
                if (port.get('device_owner') in
                        [LB_DEVICE_OWNER_V2, DEVICE_OWNER_DHCP]):
                    params = {
                        'externalID': port['id'],
                        'tenant': port['tenant_id'],
                        'netpart_name': np_name
                    }
                    self.vsdclient.delete_vm_by_external_id(params)
                else:
                    self._delete_nuage_vm(db_context, port, np_name,
                                          subnet_mapping, port['device_id'],
                                          network)
            if nuage_vport:
                self.vsdclient.delete_nuage_vport(nuage_vport.get('ID'))
            if self._get_port_from_neutron(db_context, port):
                raise
            else:
                LOG.info(_("Port was deleted concurrently: {}").format(ex))
                return
        except Exception:
            if nuage_vm:
                self._delete_nuage_vm(db_context, port, np_name,
                                      subnet_mapping, port['device_id'],
                                      network)
            if nuage_vport:
                self.vsdclient.delete_nuage_vport(nuage_vport.get('ID'))
            raise
        rollbacks = []
        try:
            self.nuage_callbacks.notify(resources.PORT, constants.AFTER_CREATE,
                                        self, context=db_context, port=port,
                                        vport=nuage_vport, rollbacks=rollbacks,
                                        subnet_mapping=subnet_mapping)
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_port_precommit(self, context):
        db_context = context._plugin_context
        port = context.current
        original = context.original
        network = context.network.current

        if self._is_port_provisioning_required(network,
                                               port, context.host):
            self._insert_port_provisioning_block(db_context,
                                                 port['id'])
        is_network_external = network.get('router:external')
        self._check_fip_on_port_with_multiple_ips(db_context, port)

        currently_actionable = self._should_act_on_port(port,
                                                        is_network_external)
        previously_actionable = self._should_act_on_port(original,
                                                         is_network_external)
        subnet_ids = [ip['subnet_id'] for ip in port['fixed_ips']]
        subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
            db_context.session, subnet_ids)

        if not currently_actionable and previously_actionable:
            # Port no longer needed
            vsd_errors = [(vsd_constants.CONFLICT_ERR_CODE,
                           vsd_constants.VSD_VM_EXISTS_ON_VPORT)]
            utils.retry_on_vsdclient_error(
                self._delete_port, vsd_error_codes=vsd_errors)(db_context,
                                                               original,
                                                               network)
            return

        elif currently_actionable and not previously_actionable:
            # Port creation needed
            self._create_port(db_context, port, network)
            return
        elif not currently_actionable or not subnet_mappings:
            return
        self._validate_port(db_context, port, is_network_external,
                            subnet_mappings)
        # We only need the VSD properties of the subnet mapping, this is equal
        # for all subnet_mappings.
        subnet_mapping = subnet_mappings[0]
        self._check_subport_in_use(original, port)
        vm_if_update_required = self._check_vm_if_update(
            db_context, original, port)

        host_added = host_removed = False
        if not original['binding:host_id'] and port['binding:host_id']:
            host_added = True
        elif original['binding:host_id'] and not port['binding:host_id']:
            host_removed = True
        elif (original['device_owner'] and not port['device_owner'] and
              original['device_owner'] == LB_DEVICE_OWNER_V2):
            host_removed = True

        nuage_vport = self._find_vport(db_context, port, subnet_mapping)
        if not nuage_vport:
            return

        if vm_if_update_required:
            data = {
                'mac': port['mac_address'],
                'ipv4': port['new_ipv4'],
                'ipv6': port['new_ipv6'],
                'nuage_vport_id': nuage_vport['ID'],
            }
            if self._is_trunk_subport(port):
                # (gridinv) : subport can be updated only if port
                # is not in use - so no need for vm resync
                self.vsdclient.update_subport(port, nuage_vport, data)
            else:
                nuage_vip_dict = dict()
                try:
                    self.delete_vips_for_interface_update(data,
                                                          port['new_ipv4'],
                                                          port['new_ipv6'],
                                                          nuage_vip_dict,
                                                          nuage_vport,
                                                          port['orig_ips'],
                                                          subnet_mapping,
                                                          original)
                    self.vsdclient.update_nuage_vm_if(data)
                except restproxy.RESTProxyError as e:
                    if e.vsd_code != vsd_constants.VSD_VM_ALREADY_RESYNC:
                        self.rollback_deleted_vips(data, port['new_ipv4'],
                                                   nuage_vip_dict, nuage_vport,
                                                   port, subnet_mapping)
                        raise

        self._port_device_change(context, db_context, nuage_vport,
                                 original, port,
                                 subnet_mapping, host_added,
                                 host_removed)
        rollbacks = []
        try:
            self.nuage_callbacks.notify(resources.PORT, constants.AFTER_UPDATE,
                                        self.core_plugin, context=db_context,
                                        port=port,
                                        original_port=original,
                                        vport=nuage_vport, rollbacks=rollbacks,
                                        subnet_mapping=subnet_mapping)
            new_sg = port.get('security_groups')
            prt_sec_updt_rqd = (original.get(portsecurity.PORTSECURITY) !=
                                port.get(portsecurity.PORTSECURITY))
            if (self._is_os_mgd(subnet_mapping) and
                    prt_sec_updt_rqd and not new_sg):
                self._process_port_create_secgrp_for_port_sec(db_context,
                                                              port)
            if prt_sec_updt_rqd:
                status = (constants.DISABLED
                          if port.get(portsecurity.PORTSECURITY, True)
                          else constants.ENABLED)
                self.vsdclient.update_mac_spoofing_on_vport(
                    nuage_vport['ID'],
                    status)
        except Exception as e:
            LOG.error('update_port_precommit(): got exception: {}'.format(e))
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_port_postcommit(self, context):
        self._notify_port_provisioning_complete(context.current['id'])

    def rollback_deleted_vips(self, data, new_ipv4_ip, nuage_vip_dict,
                              nuage_vport, port, subnet_mapping):
        for vip in nuage_vip_dict.keys():
            params = {
                'vport_id': nuage_vport['ID'],
                'externalID': port['id'],
                'vip': vip,
                'subnet_id': subnet_mapping['nuage_subnet_id'],
                'mac': data['mac']
            }
            if vip == new_ipv4_ip:
                params['IPType'] = 'IPV4'
            else:
                params['IPType'] = 'IPV6'
            LOG.debug("Rolling back due to update interface failure by"
                      " creating deleted vip ")
            self.vsdclient.create_vip_on_vport(params)

    def delete_vips_for_interface_update(self, data, new_ipv4_ip, new_ipv6_ip,
                                         nuage_vip_dict, nuage_vport, old_ips,
                                         subnet_mapping, original_port):
        if new_ipv4_ip in old_ips[4][:-1] and self._is_l3(subnet_mapping):
            #  New fixed ip is in use as vip, delete ipv4 vip
            nuage_vip_dict[new_ipv4_ip] = data['mac']
        if new_ipv6_ip in old_ips[6][:-1] and self._is_l3(subnet_mapping):
            # New fixed ip is in use as vip, delete ipv6 vip
            nuage_vip_dict[new_ipv6_ip] = data['mac']
        for addrpair in original_port['allowed_address_pairs']:
            if (addrpair['ip_address'] == new_ipv4_ip or
                    addrpair['ip_address'] == new_ipv6_ip):
                # New fixed ip is in use as vip, delete vip
                nuage_vip_dict[addrpair['ip_address']] = (
                    addrpair['mac_address'])
        self.vsdclient.delete_vips(nuage_vport['ID'],
                                   nuage_vip_dict,
                                   nuage_vip_dict)

    def _find_vport(self, db_context, port, subnet_mapping):
        try:
            nuage_vport = self._get_nuage_vport(port,
                                                subnet_mapping,
                                                required=True)
            return nuage_vport
        except (restproxy.ResourceNotFoundException, NuageBadRequest):
            # Get port from db to see if it is deleted concurrently
            port_db = self._get_port_from_neutron(db_context,
                                                  port)
            if not port_db:
                LOG.info("Port %s has been deleted concurrently",
                         port['id'])
                return None
            else:
                # Port was not deleted, it moved l2->l3 or l3->l2
                # Update subnet_mapping with new VSD subnet ID
                for fixed_ip in port_db['fixed_ips']:
                    subnet_db = self._get_subnet_from_neutron(
                        db_context, fixed_ip['subnet_id'])
                    if not subnet_db:
                        LOG.info("Subnet %s has been deleted concurrently",
                                 fixed_ip['subnet_id'])
                        continue
                    subnet_mapping['subnet_id'] = subnet_db['id']
                    LOG.debug("Retrying to get new subnet mapping from vsd")
                    subnet_mapping = self._get_updated_subnet_mapping_from_vsd(
                        db_context, subnet_mapping)
                    return self._get_nuage_vport(port, subnet_mapping,
                                                 required=True)

    def _get_updated_subnet_mapping_from_vsd(self, context, subnet_mapping):
        # The subnet has likely changed from l3 to l2 or vice versa
        vsd_subnet = self._find_vsd_subnet(context, subnet_mapping)
        if vsd_subnet['type'] == constants.L3SUBNET:
            subnet_mapping['nuage_subnet_id'] = vsd_subnet['ID']
            subnet_mapping['nuage_l2dom_tmplt_id'] = None
        else:
            subnet_mapping['nuage_subnet_id'] = vsd_subnet['ID']
            subnet_mapping['nuage_l2dom_tmplt_id'] = vsd_subnet['templateID']
        return subnet_mapping

    def _port_device_change(self, context, db_context, nuage_vport, original,
                            port, subnet_mapping,
                            host_added=False, host_removed=False):
        if not host_added and not host_removed:
            return
        np_name = self.vsdclient.get_net_partition_name_by_id(
            subnet_mapping['net_partition_id'])
        require(np_name, "netpartition",
                subnet_mapping['net_partition_id'])

        if host_removed:
            if self._port_should_have_vm(original):
                self._delete_nuage_vm(db_context, original,
                                      np_name,
                                      subnet_mapping, original['device_id'],
                                      context.network.current,
                                      is_port_device_owner_removed=True)
        elif host_added:
            self._validate_security_groups(context)
            if self._port_should_have_vm(port):
                nuage_subnet = self._find_vsd_subnet(
                    db_context, subnet_mapping)
                self._create_nuage_vm(db_context, port,
                                      np_name, subnet_mapping, nuage_vport,
                                      nuage_subnet, context.network.current)

    @utils.context_log
    def delete_port_postcommit(self, context):
        db_context = context._plugin_context
        network = context.network.current
        port = context.current
        vsd_errors = [(vsd_constants.CONFLICT_ERR_CODE,
                       vsd_constants.VSD_VM_EXISTS_ON_VPORT)]
        utils.retry_on_vsdclient_error(
            self._delete_port, vsd_error_codes=vsd_errors)(db_context,
                                                           port,
                                                           network)

    def _delete_port(self, db_context, port, network):
        subnet_mapping = self.get_subnet_mapping_by_port(db_context, port)
        if not subnet_mapping:
            return

        is_network_external = network.get('router:external')
        if not self._should_act_on_port(port, is_network_external):
            # GW host vport cleanup
            self.delete_gw_host_vport(db_context, port, subnet_mapping)
            return

        # This check is needed because neutron plugin calls delete port
        # after raising a nuage exception when virtio ports are created
        # in nuage_hybrid_mpls networks
        if self.is_nuage_hybrid_mpls_network(network):
            return

        nuage_vport = self._get_nuage_vport(port, subnet_mapping,
                                            required=False)

        if (port.get('binding:host_id') or
                (nuage_vport and nuage_vport.get('hasAttachedInterfaces'))):
            np_name = self.vsdclient.get_net_partition_name_by_id(
                subnet_mapping['net_partition_id'])
            require(np_name, "netpartition",
                    subnet_mapping['net_partition_id'])
            device_id = port['device_id']
            if not device_id:
                # Due to concurrent Create/Update/Delete we do not know the
                # device_id of the port. We get it from VSD vminterface instead
                vm_if = self.vsdclient.get_nuage_vm_if_by_vport_id(
                    nuage_vport['ID'])
                device_id = vm_if['VMUUID']

            self._delete_nuage_vm(
                db_context, port, np_name, subnet_mapping,
                device_id, network,
                is_port_device_owner_removed=not port['device_owner'])
        if nuage_vport and nuage_vport.get('type') == constants.VM_VPORT:
            try:
                self.vsdclient.delete_nuage_vport(
                    nuage_vport['ID'])
            except Exception as e:
                LOG.error("Failed to delete vport from vsd {vport id: %s}",
                          nuage_vport['ID'])
                raise e
            rollbacks = []
            try:
                self.nuage_callbacks.notify(
                    resources.PORT, constants.AFTER_DELETE,
                    self.core_plugin, context=db_context,
                    updated_port=port,
                    port=port,
                    subnet_mapping=subnet_mapping)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for rollback in reversed(rollbacks):
                        rollback[0](*rollback[1], **rollback[2])
        else:
            self.delete_gw_host_vport(db_context, port, subnet_mapping)
            return

    @utils.context_log
    def bind_port(self, context):
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self._supported_vnic_types():
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return
        if not self.is_port_vnic_type_supported(context.current):
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s with "
                      "no switchdev capability", portbindings.VNIC_DIRECT)
            return

        for segment in context.network.network_segments:
            if self._check_segment(segment):
                context.set_binding(segment[api.ID],
                                    portbindings.VIF_TYPE_OVS,
                                    {portbindings.CAP_PORT_FILTER: False})
                break

    @staticmethod
    def _network_no_action(original, update):
        external_change = original.get(
            external_net.EXTERNAL) != update.get(
            external_net.EXTERNAL)
        shared_change = original.get(
            'shared') != update.get('shared')
        physnets_change = (
            (original.get('provider:physical_network') !=
             update.get('provider:physical_network')) or
            (original.get('provider:segmentation_id') !=
             update.get('provider:segmentation_id')) or
            (original.get('provider:network_type') !=
             update.get('provider:network_type')) or
            original.get('segments') != update.get('segments'))
        name_change = original.get('name') != update.get('name')
        return external_change, shared_change, physnets_change, name_change

    def _validate_update_network(self, context, external_change,
                                 shared_change, physnets_change,
                                 original, updated):
        subnets = self.core_plugin.get_subnets(
            context, filters={'network_id': [updated['id']]})
        for subn in subnets:
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                context.session, subn['id'])
            if subnet_l2dom and subnet_l2dom.get('nuage_managed_subnet'):
                msg = _('Network %s has a VSD-Managed subnet associated'
                        ' with it') % updated['id']
                raise NuageBadRequest(msg=msg)
        if (external_change and subnets and not
                updated.get(external_net.EXTERNAL)):
            msg = _('External network with subnets can not be '
                    'changed to non-external network')
            raise NuageBadRequest(msg=msg)
        if external_change:
            self._validate_nuage_sharedresource(updated['id'], subnets, None)

        ports = self.core_plugin.get_ports(context, filters={
            'network_id': [updated['id']]})
        if external_change and updated.get(external_net.EXTERNAL):
            for p in ports:
                if p['device_owner'] not in [constants.DEVICE_OWNER_DHCP_NUAGE,
                                             os_constants.DEVICE_OWNER_DHCP]:
                    # Check if there are ports except nuage and neutron dhcp
                    # ports attached to this network. If there are, then
                    # updating the network router:external is not possible.
                    msg = (_("Network %s cannot be updated. "
                             "There are one or more ports still in"
                             " use on the network.") % updated['id'])
                    raise NuageBadRequest(msg=msg)
        if shared_change:
            for p in ports:
                if p['device_owner'].endswith(resources.ROUTER_INTERFACE):
                    msg = (_("Cannot update the shared attribute value"
                             " since subnet with id %s is attached to a"
                             " router.") % p['fixed_ips']['subnet_id'])
                    raise NuageBadRequest(msg=msg)

        # nuage_l2bridge checks
        if subnets and physnets_change:
            updated_physnets = self._get_l2bridge_physnets(context,
                                                           updated)
            l2bridges = {p['l2bridge_id'] for p in updated_physnets}
            if len(l2bridges) > 1:
                msg = _("It is not allowed to attach a network to multiple"
                        "nuage_l2bridges.")
                raise NuageBadRequest(msg=msg)

            current_physnets = self._get_l2bridge_physnets(context,
                                                           original)
            # Adding or removing the network from a l2bridge
            if len(current_physnets) != len(updated_physnets):
                msg = _("It is not allowed to change the nuage_l2bridge "
                        "this network is attached to.")
                raise NuageBadRequest(msg=msg)
            if (current_physnets and
                    current_physnets[0]['l2bridge_id'] !=
                    updated_physnets[0]['l2bridge_id']):
                msg = _("It is not allowed to change the nuage_l2bridge "
                        "this network is attached to.")
                raise NuageBadRequest(msg=msg)

    @staticmethod
    def _get_l2bridge_physnets(context, network):
        if network.get('provider:physical_network'):
            segments = [{
                'provider:physical_network':
                    network['provider:physical_network'],
                'provider:segmentation_id':
                    network['provider:segmentation_id'],
                'provider:network_type': network['provider:network_type']
            }]
        else:
            segments = network.get('segments', [])
        physnet_list = []
        for segment in segments:
            physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                context.session, physnet=segment['provider:physical_network'],
                segmentation_id=segment['provider:segmentation_id'],
                segmentation_type=segment['provider:network_type'])
            physnet_list.extend(physnets)
        return physnet_list

    @staticmethod
    def _validate_security_groups(context):
        port = context.current
        db_context = context._plugin_context
        sg_ids = port[ext_sg.SECURITYGROUPS]
        if not sg_ids:
            return

        baremetal_ports = nuagedb.get_port_bindings_for_sg(
            db_context.session,
            sg_ids,
            [portbindings.VNIC_BAREMETAL],
            bound_only=True)
        if len(baremetal_ports) > 0:
            msg = ("Security Groups for baremetal and normal ports "
                   "are mutualy exclusive")
            raise NuageBadRequest(msg=msg)

    def _check_vm_if_update(self, db_context, orig_port, port):
        new_ips = self.calculate_vips_for_port_ips(
            db_context, port)
        orig_ips = self.calculate_vips_for_port_ips(
            db_context, orig_port)
        orig_ipv4 = orig_ips[4][-1] if orig_ips[4] else None
        orig_ipv6 = orig_ips[6][-1] if orig_ips[6] else None

        new_ipv4 = new_ips[4][-1] if new_ips[4] else None
        new_ipv6 = new_ips[6][-1] if new_ips[6] else None
        ips_change = (orig_ipv4 != new_ipv4 or
                      orig_ipv6 != new_ipv6)
        port['new_ipv4'] = new_ipv4
        port['new_ipv6'] = new_ipv6
        port['orig_ips'] = orig_ips
        if (ips_change and
                port['device_owner'] == os_constants.DEVICE_OWNER_DHCP):
            return True
        mac_change = orig_port['mac_address'] != port['mac_address']
        vm_if_update = ips_change or mac_change
        vif_type = orig_port.get(portbindings.VIF_TYPE)
        if vm_if_update and vif_type not in PORT_UNPLUGGED_TYPES:
            raise NuagePortBound(port_id=orig_port['id'],
                                 vif_type=vif_type,
                                 old_ips=orig_port['fixed_ips'],
                                 new_ips=port['fixed_ips'])
        if ips_change:
            # Only 1 corresponding VSD subnet allowed
            orig_vsd_subnets = self._get_vsd_subnet_ids_by_port(db_context,
                                                                orig_port)
            new_vsd_subnets = self._get_vsd_subnet_ids_by_port(db_context,
                                                               port)
            if orig_vsd_subnets != new_vsd_subnets:
                msg = _("Updating fixed ip of port {} "
                        "to a different subnet is "
                        "not allowed.").format(port["id"])
                raise NuageBadRequest(msg=msg)

            if len(new_vsd_subnets) != 1:
                msg = _("One neutron port cannot correspond to multiple "
                        "VSD subnets").format(port["id"])
                raise NuageBadRequest(msg=msg)
            subnet_ids = set([x['subnet_id'] for x in port['fixed_ips']])
            subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
                db_context.session, subnet_ids)
            l2dom = next((subnet for subnet in subnet_mappings
                          if self._is_l2(subnet)), None)
            if l2dom and l2dom['nuage_managed_subnet'] and not self.get_subnet(
                    db_context, l2dom['subnet_id'])['enable_dhcp']:
                nuage_subnet, shared_subnet = self._get_nuage_subnet(
                    l2dom['nuage_subnet_id'], subnet_type=constants.L2DOMAIN)
                vsd_l2dom = shared_subnet or nuage_subnet
                return vsd_l2dom['DHCPManaged']
        return vm_if_update

    @staticmethod
    def _get_vsd_subnet_ids_by_port(db_context, port):
        subnet_ids = set([x['subnet_id'] for x in port['fixed_ips']])
        subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
            db_context.session,
            subnet_ids)
        return set([x['nuage_subnet_id'] for x in subnet_mappings])

    @staticmethod
    def _check_subport_in_use(orig_port, port):
        if NuageMechanismDriver._is_trunk_subport(orig_port):
            vif_orig = orig_port.get(portbindings.VIF_TYPE)
            if vif_orig not in PORT_UNPLUGGED_TYPES and port.get('device_id'):
                raise PortInUse(port_id=port['id'],
                                net_id=port['network_id'],
                                device_id='trunk:subport')

    def _check_fip_on_port_with_multiple_ips(self, context, port):
        # Block a port with fip getting multiple ips
        fips = nuagedb.get_floatingips_per_port_id(context.session, port['id'])
        ipv4s, ipv6s = self.count_fixed_ips_per_version(port['fixed_ips'])
        if fips and (ipv4s > 1 or ipv6s > 1):
            msg = _("It is not possible to add multiple ipv4 or multiple ipv6"
                    " addresses on port {} since it has fip {} associated"
                    "to it.").format(port['id'], fips[0]['id'])
            raise NuageBadRequest(msg=msg)

    def _should_act_on_port(self, port, is_network_external=False):
        # Should Nuage create vport for this port

        if not port.get('fixed_ips'):
            return False
        device_owner = port.get('device_owner')
        is_dhcp_port = device_owner == os_constants.DEVICE_OWNER_DHCP
        is_nuage_dhcp_port = device_owner == constants.DEVICE_OWNER_DHCP_NUAGE
        is_router_gw = device_owner == os_constants.DEVICE_OWNER_ROUTER_GW
        is_router_int = device_owner == os_constants.DEVICE_OWNER_ROUTER_INTF

        if is_router_gw or is_router_int:
            # Router can be attached to multiple subnets.
            return False
        if not self.needs_vport_creation(device_owner):
            return False
        if is_dhcp_port and is_network_external:
            return False
        if not self.is_port_vnic_type_supported(port):
            return False
        if is_nuage_dhcp_port:
            return False

        return True

    def _validate_port(self, db_context, port, is_network_external,
                       subnet_mappings, network=None):
        """_validate_port : validating neutron port

        """
        fixed_ips = port.get('fixed_ips', [])
        subnet_list = {4: [], 6: []}
        for fixed_ip in fixed_ips:
            subnet_list[netaddr.IPAddress(
                fixed_ip['ip_address']).version].append(
                fixed_ip['subnet_id'])
        if len(set(subnet_list[4])) > 1:
            msg = "Port can't have multiple IPv4 IPs of different subnets"
            raise NuageBadRequest(msg=msg)
        if len(set(subnet_list[6])) > 1:
            msg = "Port can't have multiple IPv6 IPs of different subnets"
            raise NuageBadRequest(msg=msg)

        if is_network_external:
            msg = "Cannot create port in a FIP pool Subnet"
            raise NuageBadRequest(resource='port', msg=msg)

        self._validate_nuage_l2bridges(db_context, port)

        nuage_managed = []
        vsd_subnet_ids = set()

        for mapping in subnet_mappings:
            nuage_managed.append(mapping['nuage_managed_subnet'])
            vsd_subnet_ids.add(mapping['nuage_subnet_id'])

        if len(vsd_subnet_ids) > 1 and all(nuage_managed):
            msg = _("Port has fixed ips for multiple vsd subnets.")
            raise NuageBadRequest(msg=msg)

        if (not self._is_vsd_mgd(subnet_mappings[0]) and
                port.get(nuagepolicygroup.NUAGE_POLICY_GROUPS)):
            msg = ("Cannot use VSP policy groups on OS managed subnets,"
                   " use neutron security groups instead.")
            raise NuageBadRequest(resource='port', msg=msg)

        if network and self.is_nuage_hybrid_mpls_network(network):
            msg = 'Virtio port is not allowed in nuage_mpls_hybrid networks'
            raise NuageBadRequest(msg=msg)

    @staticmethod
    def get_subnet_mapping_by_port(db_context, port):
        return nuagedb.get_subnet_l2dom_by_port(db_context.session, port)

    @staticmethod
    def _port_should_have_vm(port):
        device_owner = port.get('device_owner')
        return (constants.NOVA_PORT_OWNER_PREF in device_owner or
                device_owner == LB_DEVICE_OWNER_V2 or
                device_owner == DEVICE_OWNER_DHCP or
                constants.DEVICE_OWNER_OCTAVIA_HEALTHMGR in device_owner)

    def _create_nuage_vm(self, db_context, port, np_name, subnet_mapping,
                         nuage_port, nuage_subnet, network):
        if (port.get('device_owner') in
                [LB_DEVICE_OWNER_V2, DEVICE_OWNER_DHCP,
                 constants.DEVICE_OWNER_OCTAVIA_HEALTHMGR]):
            no_of_ports = 1
            vm_id = port['id']
        else:
            vm_id = port['device_id']
            no_of_ports = self.get_num_ports_of_device(
                db_context, vm_id, network)

        fixed_ips = port['fixed_ips']
        subnets = {4: {}, 6: {}}
        ips = {4: [], 6: []}
        for fixed_ip in fixed_ips:
            try:
                subnet = self.core_plugin.get_subnet(db_context,
                                                     fixed_ip['subnet_id'])
            except SubnetNotFound:
                LOG.info("Subnet %s has been deleted concurrently",
                         fixed_ip['subnet_id'])
                return
            subnets[subnet['ip_version']] = subnet
            ips[subnet['ip_version']].append(fixed_ip['ip_address'])
        for key in ips:
            ips[key] = self.sort_ips(ips[key])

        # Only when the tenant who creates the port is different from both
        # ipv4 and ipv6 tenant, we have to add extra permissions on the subnet.
        # If one of the 2 subnet tenants matches, permissions will already
        # exist from subnet-create.
        subnet = subnets[4] or subnets[6]
        if port['tenant_id'] not in (subnets[4].get('tenant_id'),
                                     subnets[6].get('tenant_id')):
            subnet_tenant_id = subnet.get('tenant_id')
        else:
            subnet_tenant_id = port['tenant_id']

        shared = subnet.get('shared') or False

        params = {
            'port_id': port['id'],
            'id': vm_id,
            'mac': port['mac_address'],
            'netpart_name': np_name,
            'ipv4': ips[4][-1] if ips[4] else None,
            'ipv6': ips[6][-1] if ips[6] else None,
            'no_of_ports': no_of_ports,
            'tenant': port['tenant_id'],
            'netpart_id': subnet_mapping['net_partition_id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id'],
            'vport_id': nuage_port.get('ID'),
            'subn_tenant': subnet_tenant_id,
            'portOnSharedSubn': shared,
            'enable_dhcpv4': subnets[4].get('enable_dhcp'),
            'enable_dhcpv6': subnets[6].get('enable_dhcp'),
            'vsd_subnet': nuage_subnet
        }
        network_details = self.core_plugin.get_network(db_context,
                                                       port['network_id'])
        if network_details['shared']:
            self.vsdclient.create_usergroup(
                port['tenant_id'],
                subnet_mapping['net_partition_id'])
        try:
            return self.vsdclient.create_vms(params)
        except restproxy.ResourceNotFoundException as rnf:
            try:
                subnet = self.core_plugin.get_subnet(db_context,
                                                     subnet.get('id'))
            except SubnetNotFound:
                subnet = None
            if not subnet:
                LOG.info("Subnet %s has been deleted concurrently",
                         subnets[4].get('id'))
            else:
                raise rnf

    def get_num_ports_of_device(self, db_context, device_id, network):
        filters = {'device_id': [device_id]}
        ports = self.core_plugin.get_ports(db_context, filters)
        ports = [p for p in ports
                 if self._is_port_supported(p, network) and
                 p['binding:host_id']]
        return len(ports)

    def _process_port_create_secgrp_for_port_sec(self, context, port):
        rtr_id = None
        policygroup_ids = []
        port_id = port['id']

        if not port.get('fixed_ips'):
            return self._make_port_dict(port)

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, port['fixed_ips'][0]['subnet_id'])

        if subnet_mapping:
            l2dom_id, l3dom_id = get_l2_and_l3_sub_id(subnet_mapping)
            if l3dom_id:
                rtr_id = self.vsdclient.get_nuage_domain_id_from_subnet(
                    l3dom_id)

            params = {
                'neutron_port_id': port_id,
                'l2dom_id': l2dom_id,
                'l3dom_id': l3dom_id,
                'rtr_id': rtr_id,
                'type': constants.VM_VPORT,
                'sg_type': constants.SOFTWARE
            }
            nuage_port = self.vsdclient.get_nuage_vport_for_port_sec(params)
            if nuage_port:
                successful = False
                attempt = 1
                max_attempts = 4
                while not successful:
                    try:
                        nuage_vport_id = nuage_port.get('ID')
                        if port.get(portsecurity.PORTSECURITY):
                            self.vsdclient.update_vport_policygroups(
                                nuage_vport_id, policygroup_ids)
                        else:
                            sg_id = (self.vsdclient.
                                     create_nuage_sec_grp_for_no_port_sec(
                                         params))
                            policygroup_ids.append(sg_id)
                            self.vsdclient.update_vport_policygroups(
                                nuage_vport_id, policygroup_ids)
                        successful = True
                    except restproxy.RESTProxyError as e:
                        LOG.debug("Policy group retry %s times.", attempt)
                        msg = str(e).lower()
                        if (e.code not in (404, 409) and
                                'policygroup' not in msg and
                                'policy group' not in msg):
                            raise
                        elif attempt < max_attempts:
                            attempt += 1
                            if (e.vsd_code ==
                                    vsd_constants.PG_VPORT_DOMAIN_CONFLICT):
                                vsd_subnet = self._find_vsd_subnet(
                                    context,
                                    subnet_mapping)
                                if not vsd_subnet:
                                    return
                                if vsd_subnet.get('parentType') == 'zone':
                                    params['l2dom_id'] = None
                                    params['l3dom_id'] = vsd_subnet['ID']
                                    params['rtr_id'] = (
                                        self.vsdclient.
                                        get_nuage_domain_id_from_subnet(
                                            params['l3dom_id']))
                                else:
                                    params['l2dom_id'] = vsd_subnet['ID']
                                    params['l3dom_id'] = None
                                    params['rtr_id'] = None
                        else:
                            LOG.debug("Retry failed %s times.", max_attempts)
                            raise

    def _is_port_supported(self, port, network):
        if not self.is_port_vnic_type_supported(port):
            return False
        return self.is_network_type_supported(network)

    def delete_gw_host_vport(self, context, port, subnet_mapping):
        port_params = {
            'neutron_port_id': port['id']
        }

        # Check if l2domain/subnet exist. In case of router_interface_delete,
        # subnet is deleted and then call comes to delete_port. In that
        # case, we just return
        vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(subnet_mapping)

        if not vsd_subnet:
            return

        port_params['l2dom_id'], port_params['l3dom_id'] = \
            get_l2_and_l3_sub_id(subnet_mapping)
        nuage_vport = self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params, required=False)
        if nuage_vport and (nuage_vport['type'] == constants.HOST_VPORT):
            def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
            netpart = nuagedb.get_default_net_partition(context, def_netpart)
            self.vsdclient.delete_nuage_gateway_vport(
                context,
                nuage_vport.get('ID'),
                netpart['id'])

    def _delete_nuage_vm(self, db_context, port, np_name, subnet_mapping,
                         device_id, network,
                         is_port_device_owner_removed=False):
        if port.get('device_owner') in [LB_DEVICE_OWNER_V2, DEVICE_OWNER_DHCP]:
            no_of_ports = 1
            vm_id = port['id']
        else:
            vm_id = device_id
            no_of_ports = self.get_num_ports_of_device(db_context, vm_id,
                                                       network)
            # In case of device removed, this number should be the amount of
            # vminterfaces on VSD. If it's >1, vsdclient knows there are
            # still other vminterfaces using the VM, and it will not delete the
            # vm. If it's 1 or less. VsdClient will also automatically delete
            # the vm. Because the port count is determined on a database count
            # of ports with device_id X, AND because the update already
            # happened by ml2plugin, AND because we're in the same database
            # transaction, the count here would return 1 less (as the updated
            # port will not be counted because the device_id is already cleared
            if is_port_device_owner_removed:
                no_of_ports += 1

        fixed_ips = port['fixed_ips']
        subnets = {4: {}, 6: {}}
        for fixed_ip in fixed_ips:
            subnet = self.core_plugin.get_subnet(
                db_context, fixed_ip['subnet_id'])
            subnets[subnet['ip_version']] = subnet

        if port['tenant_id'] not in (subnets[4].get('tenant_id'),
                                     subnets[6].get('tenant_id')):
            subnet_tenant_id = subnets[4].get('tenant_id')
        else:
            subnet_tenant_id = port['tenant_id']

        shared = subnets[4].get('shared') or subnets[6].get('shared', False)

        vm_interface = self.vsdclient.get_nuage_vm_interface_by_neutron_id(
            port['id'])
        if not vm_interface:
            return
        params = {
            'no_of_ports': no_of_ports,
            'netpart_name': np_name,
            'tenant': port['tenant_id'],
            'nuage_vif_id': vm_interface['ID'],
            'id': vm_id,
            'subn_tenant': subnet_tenant_id,
            'portOnSharedSubn': shared
        }
        if not vm_interface.get('domainID'):
            params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            params['l3dom_id'] = subnet_mapping['nuage_subnet_id'],
        try:
            self.vsdclient.delete_vms(params)
        except Exception:
            LOG.error("Failed to delete vm from vsd {vm id: %s}",
                      vm_id)
            raise

    def _get_nuage_vport(self, port, subnet_mapping, required=True):
        port_params = {'neutron_port_id': port['id']}
        l2dom_id, l3dom_id = get_l2_and_l3_sub_id(subnet_mapping)
        port_params['l2dom_id'] = l2dom_id
        port_params['l3dom_id'] = l3dom_id
        return self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params, required=required)

    @staticmethod
    def _check_segment(segment):
        network_type = segment[api.NETWORK_TYPE]
        return network_type == os_constants.TYPE_VXLAN

    @staticmethod
    def _supported_vnic_types():
        return [portbindings.VNIC_NORMAL,
                portbindings.VNIC_DIRECT]

    @staticmethod
    def _direct_vnic_supported(port):
        profile = port.get(portbindings.PROFILE)
        capabilities = []
        if profile:
            capabilities = profile.get('capabilities', [])
        return (port.get(portbindings.VNIC_TYPE) ==
                portbindings.VNIC_DIRECT and
                'switchdev' in capabilities)

    @staticmethod
    def is_port_vnic_type_supported(port):
        return (NuageMechanismDriver._direct_vnic_supported(port) or
                port.get(portbindings.VNIC_TYPE, '') ==
                portbindings.VNIC_NORMAL)

    def check_vlan_transparency(self, context):
        """Nuage driver vlan transparency support."""
        return True

    def check_vxlan_mpls_segments_in_network(self, segments):
        if segments:
            segment_types = {segment['provider:network_type'] for segment
                             in segments if
                             segment['provider:network_type'] in
                             self.supported_network_types}
            if len(segment_types) == 2:
                msg = _('It is not allowed to have both vxlan and '
                        'nuage_hybrid_mpls segments in a single network')
                raise NuageBadRequest(msg=msg)
