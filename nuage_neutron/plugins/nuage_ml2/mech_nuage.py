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
import netaddr
import time

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
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
from nuage_neutron.plugins.common.exceptions import \
    NuageDualstackSubnetNotFound
from nuage_neutron.plugins.common.exceptions import NuagePortBound
from nuage_neutron.plugins.common import extensions
from nuage_neutron.plugins.common.extensions import nuage_redirect_target
from nuage_neutron.plugins.common.extensions import nuagefloatingip
from nuage_neutron.plugins.common.extensions import nuagepolicygroup
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import routing_mechanisms
from nuage_neutron.plugins.common import utils
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import ignore_no_update
from nuage_neutron.plugins.common.utils import ignore_not_found
from nuage_neutron.plugins.common.utils import rollback as utils_rollback
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import IsSet
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.plugins.common.validation import validate
from nuage_neutron.plugins.nuage_ml2 import extensions  # noqa
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
        routing_mechanisms.check_routing_mechanisms_config()

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

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_network_precommit(self, context):
        updated_network = context.current
        original_network = context.original
        db_context = context._plugin_context

        (external_change,
         shared_change,
         physnets_change) = self._network_no_action(original_network,
                                                    updated_network)
        if any([external_change, shared_change, physnets_change]):
            self._validate_update_network(db_context, external_change,
                                          shared_change, physnets_change,
                                          original_network,
                                          updated_network)

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_network_postcommit(self, context):
        updated_network = context.current
        original_network = context.original
        db_context = context._plugin_context
        (external_change,
         shared_change,
         physnets_change) = self._network_no_action(original_network,
                                                    updated_network)
        if not any([external_change, shared_change, physnets_change]):
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
                filters = {
                    'fixed_ips': {'subnet_id': [subn['id']]},
                    'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
                }
                dhcp_ports = self.core_plugin.get_ports(db_context,
                                                        filters=filters)
                self._delete_gateway_port(db_context, dhcp_ports)
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
        vsd_managed = nuagenet_set and net_part_set

        if not self.is_vxlan_network(network):
            if nuagenet_set or net_part_set:
                # Nuage attributes set on non-vxlan network ...
                msg = _("Network should have 'provider:network_type' vxlan or "
                        "have such a segment")
                raise NuageBadRequest(msg=msg)
            else:
                return  # Not for us

        with db_context.session.begin(subtransactions=True):
            self._create_nuage_subnet_precommit(db_context, net_part_set,
                                                network, nuagenet_set,
                                                prefixlen, subnet, vsd_managed)

    def _create_nuage_subnet_precommit(self, db_context, net_part_set, network,
                                       nuagenet_set, prefixlen, subnet,
                                       vsd_managed):
        l2bridge = None
        l2bridge_id = subnet.get('nuage_l2bridge')
        if l2bridge_id:
            l2bridge = nuagedb.get_nuage_l2bridge_blocking(db_context.session,
                                                           l2bridge_id)

        self._validate_create_subnet(db_context, net_part_set, nuagenet_set,
                                     network, prefixlen, subnet, vsd_managed,
                                     l2bridge)
        if vsd_managed:
            self._create_vsd_managed_subnet(db_context, subnet)
        else:
            self._create_openstack_managed_subnet(db_context, subnet, l2bridge)

        # take out underlay extension from the json response
        if subnet.get('underlay') == os_constants.ATTR_NOT_SPECIFIED:
            subnet['underlay'] = None
        if 'underlay' not in subnet:
            subnet['underlay'] = None

    def _validate_create_subnet(self, db_context, net_part_set, nuagenet_set,
                                network, prefixlen, subnet, vsd_managed,
                                l2bridge):
        if self._is_ipv6(subnet) and (prefixlen < 64 or prefixlen > 128):
            msg = _("Invalid IPv6 netmask. Netmask can only be "
                    "between a minimum 64 and maximum 128 length.")
            raise NuageBadRequest(resource='subnet', msg=msg)
        if nuagenet_set and not net_part_set:
            msg = _("Parameter net-partition required when "
                    "passing nuagenet")
            raise NuageBadRequest(resource='subnet', msg=msg)
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
        if (ipv4s > 1 and self.check_dhcp_agent_alive(db_context) and
                not self.is_external(db_context, network['id'])):
            msg = _("A network with multiple ipv4 subnets is not "
                    "allowed when neutron-dhcp-agent is enabled")
            raise NuageBadRequest(msg=msg)

        # nuage_l2bridge tests
        if l2bridge:
            ipv6s = len([s for s in network_subnets if self._is_ipv6(s)])

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

    @staticmethod
    def _validate_l2bridge_added_subnet_parameter(
            bridged_subnet, added_subnet, parameter, l2bridge):
        to_check = bridged_subnet.get(parameter)
        new = added_subnet.get(parameter)
        if to_check != new:
            msg = _("The {} associated with nuage_l2bridge {} "
                    "is {}. {} is not compatible. ").format(
                parameter, l2bridge['id'], to_check, new)
            raise NuageBadRequest(msg=msg)

    def _create_vsd_managed_subnet(self, context, subnet):
        nuage_subnet_id = subnet['nuagenet']
        nuage_np_id = self._validate_net_partition(
            subnet['net_partition'], context)['id']
        if not self.vsdclient.check_if_l2_dom_in_correct_ent(
                nuage_subnet_id, {'id': nuage_np_id}):
            msg = ("Provided Nuage subnet not in the provided"
                   " Nuage net-partition")
            raise NuageBadRequest(msg=msg)
        subnet_info = nuagedb.get_subnet_info_by_nuage_id(
            context.session, nuage_subnet_id, ip_type=subnet['ip_version'])
        # retrieve subnet type - it could yield None is not yet known
        subnet_type = subnet_info['subnet_type'] if subnet_info else None
        nuage_subnet, shared_subnet = self._get_nuage_subnet(
            nuage_subnet_id, subnet_type=subnet_type)
        # Check the nuage subnet type is standard if linking to domain subnet
        if (nuage_subnet.get('resourceType') and
                nuage_subnet['resourceType'] != 'STANDARD'):
            msg = (_("The nuage subnet type is {}. Only STANDARD type subnet "
                     "is allowed to be linked.")
                   .format(nuage_subnet['resourceType']))
            raise NuageBadRequest(msg=msg)
        self._validate_cidr(subnet, nuage_subnet, shared_subnet)
        self._validate_allocation_pools(context, subnet, subnet_info)
        match, os_gw_ip, vsd_gw_ip = self._check_gateway_from_vsd(
            nuage_subnet, shared_subnet, subnet)
        if not match:
            msg = ("The specified gateway {} does not match with "
                   "gateway on VSD {}".format(os_gw_ip, vsd_gw_ip))
            raise NuageBadRequest(msg=msg)
        nuage_uid, nuage_gid = self.vsdclient.attach_nuage_group_to_nuagenet(
            context.tenant, nuage_np_id, nuage_subnet_id, subnet.get('shared'),
            context.tenant_name)
        try:
            with context.session.begin(subtransactions=True):
                self.create_dhcp_nuage_port(
                    context, subnet,
                    nuage_subnet=shared_subnet or nuage_subnet)
                l2dom_id = None
                if nuage_subnet["type"] == constants.L2DOMAIN:
                    l2dom_id = nuage_subnet_id
                nuagedb.add_subnetl2dom_mapping(
                    context.session, subnet['id'], nuage_subnet_id,
                    nuage_np_id, subnet['ip_version'],
                    nuage_user_id=nuage_uid, l2dom_id=l2dom_id,
                    nuage_group_id=nuage_gid, managed=True)
                subnet['vsd_managed'] = True
        except Exception:
            self._cleanup_group(context, nuage_np_id, nuage_subnet_id, subnet)
            raise

    def is_external(self, context, net_id):
        return self.core_plugin._network_is_external(context, net_id)

    def _create_openstack_managed_subnet(self, context, subnet, l2bridge):
        if self.is_external(context, subnet['network_id']):
            network_subnets = self.core_plugin.get_subnets_by_network(
                context, subnet['network_id'])
            return self._add_nuage_sharedresource(
                context, subnet, constants.SR_TYPE_FLOATING, network_subnets)
        nuage_np_id = self._get_net_partition_for_entity(context, subnet)['id']
        attempt = 0
        while True:
            try:
                with context.session.begin(subtransactions=True):
                    self._create_nuage_subnet(
                        context, subnet, nuage_np_id, l2bridge)
                return
            except NuageDualstackSubnetNotFound:
                if attempt < 25:
                    LOG.debug("Retrying due to concurrency.")
                    attempt += 1
                    time.sleep(0.2)
                    continue
                msg = "Failed to create subnet on vsd"
                raise Exception(msg)

    @handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def _add_nuage_sharedresource(self, context, subnet, fip_type,
                                  network_subnets):
        subnet['net_partition'] = constants.SHARED_INFRASTRUCTURE
        shared_netpart = self._get_net_partition_for_entity(context, subnet)
        netpart_id = shared_netpart['id']
        net_addr = netaddr.IPNetwork(subnet['cidr'])
        subnet_params = {
            'netaddr': net_addr,
            'resourceType': fip_type
        }

        self.set_nuage_uplink(subnet_params, subnet, network_subnets)

        l3dom_params = {
            'netpart_id': netpart_id,
            'templateID': shared_netpart['l3dom_tmplt_id']
        }

        if subnet.get('underlay') in [True, False]:
            subnet_params['underlay'] = subnet.get('underlay')
            l3dom_params['FIPUnderlay'] = subnet.get('underlay')
        else:
            subnet['underlay'] = cfg.CONF.RESTPROXY.nuage_fip_underlay
            subnet_params['underlay'] = subnet['underlay']
            l3dom_params['FIPUnderlay'] = subnet['underlay']

        zone_id = l3dom_id = None
        if subnet_params.get('nuage_uplink'):
            zone_id = subnet_params['nuage_uplink']
        elif l3dom_params['FIPUnderlay'] is False:
            l3dom_id = self.vsdclient.create_shared_l3domain(l3dom_params)
        else:
            fip_underlay_subnets = nuagedb.get_subnets_by_parameter_value(
                context.session, parameter=constants.NUAGE_UNDERLAY,
                value=constants.NUAGE_UNDERLAY_FIP)
            if fip_underlay_subnets:
                # Underlay subnets are attached to same domain and zone.
                # The first underlay subnet is used to get the uplink zoneID.
                subnet_id = fip_underlay_subnets[0]['subnet_id']
                mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                         subnet_id)
                nuage_subnet = self.vsdclient.get_domain_subnet_by_id(
                    mapping['nuage_subnet_id'])
                zone_id = nuage_subnet['parentID']
            else:
                l3dom_id = (self.vsdclient
                            .get_fip_underlay_enabled_domain_by_netpart(
                                netpart_id))
                if l3dom_id is None:
                    try:
                        l3dom_id = self.vsdclient.create_shared_l3domain(
                            l3dom_params)
                    except restproxy.RESTProxyError as e:
                        msg = ("Shared infrastructure enterprise can have max "
                               "1 Floating IP domains.")
                        if e.msg == msg:
                            LOG.debug("Hit concurrent creation of Floating IP "
                                      "domain in Shared Infrastructure. "
                                      "Obtaining the one created")
                            l3dom_id = (
                                self.vsdclient
                                    .get_fip_underlay_enabled_domain_by_netpart
                                (netpart_id))
                        else:
                            raise

        if zone_id is None and l3dom_id is not None:
            zone_id = self.vsdclient.get_zone_by_domainid(
                l3dom_id)[0]['zone_id']

        if subnet['underlay']:
            with context.session.begin(subtransactions=True):
                nuagedb.add_subnet_parameter(
                    context.session, subnet['id'],
                    constants.NUAGE_UNDERLAY,
                    constants.NUAGE_UNDERLAY_FIP)

        with utils_rollback() as on_exc:
            nuage_subnet = self.vsdclient.create_shared_subnet(zone_id, subnet,
                                                               subnet_params)
            on_exc(self.vsdclient.delete_subnet,
                   l3_vsd_subnet_id=nuage_subnet['ID'])

            subnet['nuage_uplink'] = nuage_subnet['parentID']
            nuage_subnet['nuage_l2template_id'] = None  # L3
            nuage_subnet['nuage_l2domain_id'] = nuage_subnet['ID']

            self._create_subnet_mapping(context, shared_netpart['id'],
                                        subnet, nuage_subnet)

    @staticmethod
    def set_nuage_uplink(params, subnet, network_subnets):
        nuage_uplinks = {s['nuage_uplink'] for s in network_subnets
                         if s['id'] != subnet['id'] and s.get('nuage_uplink')}
        if subnet.get('nuage_uplink'):
            params['nuage_uplink'] = subnet.get('nuage_uplink')
        elif cfg.CONF.RESTPROXY.nuage_uplink:
            params['nuage_uplink'] = cfg.CONF.RESTPROXY.nuage_uplink
        elif nuage_uplinks:
            # Use the same parent of the existing subnets in the network
            params['nuage_uplink'] = list(nuage_uplinks)[0]
        if params.get('nuage_uplink'):
            nuage_uplinks.add(params['nuage_uplink'])
            if len(nuage_uplinks) > 1:
                msg = _("It is not possible for subnets in an "
                        "external network to have different nuage_uplink "
                        "specified: {}.").format(nuage_uplinks)
                raise NuageBadRequest(msg=msg)

    @log_helpers.log_method_call
    def check_if_subnet_is_attached_to_router(self, context, subnet):
        filters = {
            'network_id': [subnet['network_id']],
            'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
        }
        ports = self.core_plugin.get_ports(context, filters)
        for p in ports:
            for ip in p['fixed_ips']:
                if ip['subnet_id'] in subnet['id']:
                    router_id = nuagedb.get_routerport_by_port_id(
                        context.session, p['id'])['router_id']
                    return True, str(router_id)
        return False, None

    @handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def _create_nuage_subnet(self, context, neutron_subnet, netpart_id,
                             l2bridge):
        pnet_binding = None

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, neutron_subnet['id'])
        if subnet_mapping:
            # no-op, already connected
            return

        already_router_attached = False
        r_param = {}
        neutron_net = self.core_plugin.get_network(
            context, neutron_subnet['network_id'])
        is_ipv4 = self._is_ipv4(neutron_subnet)
        dual_stack_subnet = self.get_dual_stack_subnet(context, neutron_subnet)

        if not (dual_stack_subnet or is_ipv4):
            return  # ipv6 without existing ipv4 is no-op.
        elif dual_stack_subnet:
            # ipv6 is already present and now check
            # if router interface is attached or not
            already_router_attached, router_id = \
                self.check_if_subnet_is_attached_to_router(
                    context, dual_stack_subnet)
            if already_router_attached:
                pnet_binding = nuagedb.get_network_binding(
                    context.session,
                    dual_stack_subnet['network_id'])
                r_param['router_attached'] = True
                r_param['pnet_binding'] = pnet_binding
                r_param['router_id'] = router_id

        # If the request is for IPv4, then the dualstack subnet will be IPv6
        # and vice versa
        if is_ipv4:
            ipv4_subnet, ipv6_subnet = neutron_subnet, dual_stack_subnet
        else:
            ipv4_subnet, ipv6_subnet = dual_stack_subnet, neutron_subnet

        if l2bridge and l2bridge['nuage_subnet_id']:
            # There exists already a nuage subnet for this l2bridge
            bridged_subnets = nuagedb.get_subnets_for_nuage_l2bridge(
                context.session, l2bridge['id'])
            # Exclude the current subnet
            if self._is_ipv4(neutron_subnet):
                ipv4s = [s['id'] for s in bridged_subnets
                         if self._is_ipv4(s) and
                         s['id'] != neutron_subnet['id']]
                mappings = nuagedb.get_subnet_l2doms_by_subnet_ids_locking(
                    context.session, ipv4s
                )
                if mappings:
                    # Connecting this ipv4 subnet to the already created vsd
                    # subnet
                    nuage_subnet = {
                        'nuage_l2template_id':
                            mappings[0]['nuage_l2dom_tmplt_id'],
                        'nuage_userid': mappings[0]['nuage_user_id'],
                        'nuage_groupid': mappings[0]['nuage_group_id'],
                        'nuage_l2domain_id': mappings[0]['nuage_subnet_id']
                    }
                    if not already_router_attached:
                        self.create_dhcp_nuage_port(context, neutron_subnet)
                    self._create_subnet_mapping(context,
                                                netpart_id,
                                                neutron_subnet,
                                                nuage_subnet)
                    if dual_stack_subnet:
                        # Link ipv6 if existing
                        self._create_nuage_subnet(
                            context, dual_stack_subnet, netpart_id, l2bridge)
                    return
            else:
                ipv6s = [s['id'] for s in bridged_subnets
                         if self._is_ipv6(s) and
                         s['id'] != neutron_subnet['id']]
                mappings = nuagedb.get_subnet_l2doms_by_subnet_ids_locking(
                    context.session, ipv6s)
                if mappings:
                    # Connecting this ipv6 subnet to the already created vsd
                    # subnet
                    nuage_subnet = {
                        'nuage_l2template_id':
                            mappings[0]['nuage_l2dom_tmplt_id'],
                        'nuage_userid': mappings[0]['nuage_user_id'],
                        'nuage_groupid': mappings[0]['nuage_group_id'],
                        'nuage_l2domain_id': mappings[0]['nuage_subnet_id']
                    }
                    self._create_subnet_mapping(context,
                                                netpart_id,
                                                neutron_subnet,
                                                nuage_subnet)
                    if dual_stack_subnet:
                        # Link ipv6 if existing
                        self._create_nuage_subnet(
                            context, dual_stack_subnet, netpart_id, l2bridge)
                    return

        net = netaddr.IPNetwork(ipv4_subnet['cidr'])
        params = {
            'netpart_id': netpart_id,
            'tenant_id': neutron_subnet['tenant_id'],
            'net': net,
            'pnet_binding': pnet_binding,
            'shared': neutron_net['shared'],
            'dhcp_ip': None,
            'tenant_name': context.tenant_name,
        }

        if is_ipv4:
            if not already_router_attached:
                dhcp_port = self.create_dhcp_nuage_port(context,
                                                        neutron_subnet)
                params['dhcp_ip'] = (dhcp_port['fixed_ips'][0]['ip_address']
                                     if dhcp_port else None)
        else:
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, ipv4_subnet['id'])

            if subnet_mapping is None:
                raise NuageDualstackSubnetNotFound(resource="Subnet")
            params['mapping'] = subnet_mapping
        params.update(r_param)

        is_ipv6 = not is_ipv4

        with utils_rollback() as on_exc:
            nuage_subnet = self.vsdclient.create_subnet(
                ipv4_subnet,
                params=params,
                ipv6_subnet=ipv6_subnet)

            if is_ipv6 and subnet_mapping:
                # ipv6 subnet with ipv4 subnet present
                # -> on rollback, dualstack (L3 and L2) to be rollbacked to
                # ipv4

                # nuage_subnet is None: copy ipv4 mapping for creating ipv6
                # mapping
                nuage_subnet = {
                    'nuage_l2template_id':
                        subnet_mapping['nuage_l2dom_tmplt_id'],
                    'nuage_userid': subnet_mapping['nuage_user_id'],
                    'nuage_groupid': subnet_mapping['nuage_group_id'],
                    'nuage_l2domain_id': subnet_mapping['nuage_subnet_id']
                }

                # mapping_for_rollback is used to delete ipv6 subnet and
                # l2dom_id and l3_vsd_subnet_id should be None. If ipv6 subnet
                # is in l3, nuage_subnet_id is needed in mapping_for_rollback.
                mapping_for_rollback, l2dom_id, l3_subnet_id = (
                    {'nuage_l2dom_tmplt_id':
                        nuage_subnet['nuage_l2template_id'],
                     'nuage_subnet_id':
                         nuage_subnet['nuage_l2domain_id']}, None, None)

            elif already_router_attached:
                # ipv4 subnet added to router-attached ipv6 subnet
                # -> on rollback, ipv4 subnet (L3) to be deleted
                mapping_for_rollback, l2dom_id, l3_subnet_id = (
                    None, None, nuage_subnet['nuage_l2domain_id'])

            else:
                # 1. ipv4 subnet in l2, or
                # 2. ipv4 subnet in l2 with ipv6 subnet present
                # -> on rollback, delete ipv4 l2domain
                mapping_for_rollback, l2dom_id, l3_subnet_id = (
                    None, nuage_subnet['nuage_l2domain_id'], None)

            on_exc(self.vsdclient.delete_subnet, mapping=mapping_for_rollback,
                   l2dom_id=l2dom_id, l3_vsd_subnet_id=l3_subnet_id)

            if nuage_subnet:
                self._create_subnet_mapping(context, netpart_id,
                                            neutron_subnet,
                                            nuage_subnet)
                if dual_stack_subnet and is_ipv4:
                    self._create_subnet_mapping(context, netpart_id,
                                                dual_stack_subnet,
                                                nuage_subnet)
                if l2bridge and not l2bridge['nuage_subnet_id']:
                    l2bridge['nuage_subnet_id'] = nuage_subnet[
                        'nuage_l2domain_id']

    @staticmethod
    def _create_subnet_mapping(context, netpart_id, neutron_subnet,
                               nuage_subnet):
        l2dom_id = nuage_subnet['nuage_l2template_id']
        user_id = nuage_subnet['nuage_userid']
        group_id = nuage_subnet['nuage_groupid']
        nuage_id = nuage_subnet['nuage_l2domain_id']
        with context.session.begin(subtransactions=True):
            nuagedb.add_subnetl2dom_mapping(context.session,
                                            neutron_subnet['id'],
                                            nuage_id,
                                            netpart_id,
                                            neutron_subnet['ip_version'],
                                            l2dom_id=l2dom_id,
                                            nuage_user_id=user_id,
                                            nuage_group_id=group_id)

        neutron_subnet['net_partition'] = netpart_id
        if neutron_subnet.get('vsd_managed'):
            neutron_subnet['nuagenet'] = nuage_id

    def _validate_dhcp_opts_changed(self, original_subnet, updated_subnet):
        if self._is_ipv6(original_subnet):
            return False
        for k in ['dns_nameservers', 'host_routes', 'gateway_ip']:
            if original_subnet.get(k) != updated_subnet.get(k):
                return True
        return False

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_subnet_precommit(self, context):
        updated_subnet = context.current
        original_subnet = context.original
        db_context = context._plugin_context
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        updated_subnet['id'])
        net_id = original_subnet['network_id']
        network_external = self.is_external(db_context, net_id)
        if not subnet_mapping:
            return

        l2bridge_id = nuagedb.get_nuage_l2bridge_id_for_subnet(
            db_context.session, updated_subnet['id'])
        self._validate_update_subnet(db_context, network_external,
                                     subnet_mapping, updated_subnet,
                                     original_subnet, l2bridge_id)
        if subnet_mapping and self._is_vsd_mgd(subnet_mapping):
            # in case of VSD managed subnet, no action on VSD needed
            return

        nuage_subnet_id = subnet_mapping['nuage_subnet_id']
        if network_external:
            return self._update_ext_network_subnet(nuage_subnet_id,
                                                   updated_subnet)
        params = {
            'parent_id': nuage_subnet_id,
            'type': subnet_mapping['nuage_l2dom_tmplt_id']
        }
        if self._is_ipv6(updated_subnet):
            current_gw = netaddr.IPNetwork(
                original_subnet.get('gateway_ip')) if original_subnet.get(
                'gateway_ip') else None
            updated_gw = netaddr.IPNetwork(
                updated_subnet.get('gateway_ip')) if updated_subnet.get(
                'gateway_ip') else None
            if current_gw != updated_gw:
                params["gatewayv6_changed"] = True
            else:
                return
        else:
            # Nuage plugin only updates dhcp in case of ipv4.
            # In case of IPv6, we don't create DHCP opts to correspond
            # to Gateway IP as upstream code takes care of it.
            # The check whether gateway_ip changed for ipv4 is part of the
            # '_validate_dhcp_opts_changed' code.
            curr_enable_dhcp = original_subnet.get('enable_dhcp')
            updated_enable_dhcp = updated_subnet.get('enable_dhcp')
            if not curr_enable_dhcp and updated_enable_dhcp:
                dhcp_port = self.create_dhcp_nuage_port(db_context,
                                                        updated_subnet)
                params['net'] = netaddr.IPNetwork(original_subnet['cidr'])
                params['dhcp_ip'] = dhcp_port['fixed_ips'][0]['ip_address']
            elif curr_enable_dhcp and not updated_enable_dhcp:
                params['dhcp_ip'] = None
                filters = {
                    'fixed_ips': {'subnet_id': [updated_subnet['id']]},
                    'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
                }
                dhcp_ports = self.core_plugin.get_ports(db_context,
                                                        filters=filters)
                self._delete_gateway_port(db_context, dhcp_ports)
            dhcp_opts_changed = self._validate_dhcp_opts_changed(
                original_subnet,
                updated_subnet)
            params['dhcp_opts_changed'] = dhcp_opts_changed
        if self._is_l2(subnet_mapping):
            self.vsdclient.update_subnet(updated_subnet, params)
        else:
            self.vsdclient.update_domain_subnet(updated_subnet, params)
            routing_mechanisms.update_nuage_subnet_parameters(db_context,
                                                              updated_subnet)

    def _validate_update_subnet(self, context, network_external,
                                subnet_mapping, updated_subnet, original,
                                l2bridge_id):
        updated_attributes = set(key for key in updated_subnet if
                                 updated_subnet.get(key) != original.get(key))

        if subnet_mapping and self._is_vsd_mgd(subnet_mapping):
            updatable_attrs = constants.VSD_MANAGED_SUBNET_UPDATABLE_ATTRIBUTES
            if not updated_attributes.issubset(updatable_attrs):
                msg = _("Subnet {} is a VSD-managed subnet. Update is not "
                        "supported for attributes other than {}.")\
                    .format(updated_subnet['id'], ', '.join(updatable_attrs))
                raise NuageBadRequest(resource='subnet', msg=msg)
            if "allocation_pools" in updated_attributes:
                # do a cross-network check that the new pool does not create
                # an overlap with other subnets pointing to the same VSD subnet
                subnet_info = nuagedb.get_subnet_info_by_nuage_id(
                    context.session,
                    updated_subnet['nuagenet'],
                    ip_type=updated_subnet['ip_version'])
                self._validate_allocation_pools(context, updated_subnet,
                                                subnet_info)
            return

        if (self._is_l3(subnet_mapping) and 'gateway_ip' in updated_subnet
                and not updated_subnet.get('gateway_ip')):
            msg = ("Subnet attached to a router interface "
                   "must have a gateway IP")
            raise NuageBadRequest(resource='subnet', msg=msg)

        if not network_external and updated_subnet.get('underlay') is not None:
            msg = _("underlay attribute can not be set for internal subnets")
            raise NuageBadRequest(resource='subnet', msg=msg)

        bridged_subnets = nuagedb.get_subnets_for_nuage_l2bridge(
            context.session, l2bridge_id)
        bridged_subnets = [
            x for x in bridged_subnets if
            x['network_id'] != updated_subnet['network_id']
        ]
        # update only allowed when no other subnets on l2bridge exist.
        if len(bridged_subnets) > 0 and not updated_attributes.isdisjoint(
                set(constants.L2BRIDGE_SUBNET_EQUAL_ATTRIBUTES)):
            msg = _("It is not allowed to update a subnet when it is attached "
                    "to a nuage_l2bridge connected to multiple subnets.")
            raise NuageBadRequest(resource='subnet', msg=msg)

        routing_mechanisms.validate_update_subnet(network_external,
                                                  subnet_mapping,
                                                  updated_subnet)

    def _update_ext_network_subnet(self, nuage_subnet_id, subnet):
        nuage_params = {
            'subnet_name': subnet.get('name'),
            'gateway_ip': subnet.get('gateway_ip')
        }
        self.vsdclient.update_nuage_subnet(nuage_subnet_id, nuage_params)

    @utils.context_log
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
        if not context.nuage_mapping:
            return
        if self._is_l3(context.nuage_mapping) and self._is_ipv6(subnet):
            self._validate_ipv6_vips_in_use(db_context, subnet)

        filters = {
            'network_id': [subnet['network_id']],
            'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
        }
        context.nuage_ports = self.core_plugin.get_ports(db_context, filters)

    def _validate_ipv6_vips_in_use(self, db_context, subnet):
        nuage_ipv4_subnets = (
            nuagedb.get_subnet_mapping_by_network_id_and_ip_version(
                db_context.session, subnet['network_id'], ip_version=4))
        for nuage_mapping in nuage_ipv4_subnets:
            vip_filters = {
                'fixed_ips': {'subnet_id': [nuage_mapping['subnet_id']]}
            }
            ports = self.core_plugin.get_ports(db_context,
                                               filters=vip_filters,
                                               fields='allowed_address_pairs')
            for port in ports:
                for aap in port['allowed_address_pairs']:
                    if (netaddr.IPNetwork(aap['ip_address']).size == 1 and
                            netaddr.IPAddress(aap['ip_address']) in
                            netaddr.IPNetwork(subnet['cidr'])):
                        msg = _('IPV6 IP %s is in use for nuage VIP,'
                                ' hence cannot delete the'
                                ' subnet.') % aap['ip_address']
                        raise NuageBadRequest(msg=msg)

    @handle_nuage_api_errorcode
    def delete_subnet_postcommit(self, context):
        db_context = context._plugin_context
        subnet = context.current
        network = context.network.current
        mapping = context.nuage_mapping
        if not mapping:
            return

        if self._is_os_mgd(mapping):
            l2bridge_id = nuagedb.get_nuage_l2bridge_id_for_network(
                db_context.session, network['id'])
            if l2bridge_id:
                with db_context.session.begin(subtransactions=True):
                    l2bridge = nuagedb.get_nuage_l2bridge_blocking(
                        db_context.session, l2bridge_id)
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
                                   "resource nuage-l2bridge: %s", l2bridge_id)
                            raise Exception(msg)
                    if self._is_ipv4(subnet):
                        ipv4s = [s['id'] for s in bridged_subnets if
                                 self._is_ipv4(s)]
                        mappings = (
                            nuagedb.get_subnet_l2doms_by_subnet_ids_locking(
                                db_context.session, ipv4s))
                        if len(mappings) > 0:
                            return
                        else:
                            l2bridge['nuage_subnet_id'] = None
                    else:
                        ipv6s = [s['id'] for s in bridged_subnets if
                                 self._is_ipv6(s)]
                        mappings = (
                            nuagedb.get_subnet_l2doms_by_subnet_ids_locking(
                                db_context.session, ipv6s))
                        if len(mappings) > 0:
                            return

            if self._is_ipv6(subnet):
                self.vsdclient.delete_subnet(mapping=mapping)
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
                ipv6_subnet = self.get_dual_stack_subnet(db_context, subnet)
                if ipv6_subnet:
                    # normally mappings are deleted by CASCADING but in this
                    # case the ipv6 subnet still exists in neutron; hence now
                    # cleaning up the mapping
                    ipv6_mapping = nuagedb.get_subnet_l2dom_by_id(
                        db_context.session,
                        ipv6_subnet['id'])
                    with db_context.session.begin(subtransactions=True):
                        nuagedb.delete_subnetl2dom_mapping(
                            db_context.session,
                            ipv6_mapping)

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

        self._delete_gateway_port(db_context, context.nuage_ports)

    def _is_port_provisioning_required(self, db_context, port, host):
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

        if not self._is_port_vxlan_supported(port, db_context):
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
        if self._is_port_provisioning_required(context._plugin_context,
                                               context.current, context.host):
            self._insert_port_provisioning_block(context._plugin_context,
                                                 context.current['id'])

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_postcommit(self, context):
        self._create_port(context._plugin_context,
                          context.current,
                          context.network)
        self._notify_port_provisioning_complete(context.current['id'])

    def _create_port(self, db_context, port, network):
        is_network_external = network._network.get('router:external')
        subnet_mapping = self._validate_port(db_context, port,
                                             constants.BEFORE_CREATE,
                                             is_network_external)
        if not subnet_mapping:
            if len(port['fixed_ips']) == 0:
                nuage_attributes = (nuage_redirect_target.REDIRECTTARGETS,
                                    nuagepolicygroup.NUAGE_POLICY_GROUPS,
                                    nuagefloatingip.NUAGE_FLOATINGIP)
                for attribute in nuage_attributes:
                    if attribute in port:
                        del port[attribute]
            LOG.warn('no subnet_mapping')
            return

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
                    nuage_vport, nuage_subnet)
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
                                          subnet_mapping)
            if nuage_vport:
                self.vsdclient.delete_nuage_vport(nuage_vport.get('ID'))
            if self._get_port_from_neutron(db_context, port):
                raise
            else:
                LOG.info("Port was deleted concurrently: %s", ex.message)
                return
        except Exception:
            if nuage_vm:
                self._delete_nuage_vm(db_context, port, np_name,
                                      subnet_mapping)
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

        if self._is_port_provisioning_required(context._plugin_context,
                                               port, context.host):
            self._insert_port_provisioning_block(db_context,
                                             port['id'])
        is_network_external = context.network._network.get('router:external')
        self._check_fip_on_port_with_multiple_ips(db_context, port)

        if (len(port['fixed_ips']) == 0 and len(original['fixed_ips']) != 0 or
                self._ipv4_addr_removed_from_dualstack_dhcp_port(
                    original, port) or
                (self.needs_vport_creation(original.get('device_owner')) and
                 not self.needs_vport_creation(port.get('device_owner')))):
                # TODO(Tom) Octavia
            # port no longer belongs to any subnet or dhcp port has regressed
            # to ipv6 only: delete vport.
            vsd_errors = [(vsd_constants.CONFLICT_ERR_CODE,
                           vsd_constants.VSD_VM_EXISTS_ON_VPORT)]
            utils.retry_on_vsdclient_error(
                self._delete_port, vsd_error_codes=vsd_errors)(db_context,
                                                               original)
            return

        if (len(port['fixed_ips']) != 0 and len(original['fixed_ips']) == 0 or
                self._ip4_addr_added_to_dualstack_dhcp_port(original, port) or
                (not self.needs_vport_creation(
                    original.get('device_owner')) and
                 self.needs_vport_creation(port.get('device_owner')))):
                # TODO(Tom) Octavia
            # port didn't belong to any subnet yet, or dhcp port used to be
            # ipv6 only: create vport
            self._create_port(db_context, port, context.network)
            return

        subnet_mapping = self._validate_port(db_context,
                                             port,
                                             constants.BEFORE_UPDATE,
                                             is_network_external)
        if not subnet_mapping:
            return

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
        except Exception:
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
            port_db = self._get_port_from_neutron(db_context,
                                                  port)
            if not port_db:
                LOG.info("Port %s has been deleted concurrently",
                         port['id'])
                return
            else:
                ipv4_subnet_exists = False
                for fixed_ip in port_db['fixed_ips']:
                    subnet_db = self._get_subnet_from_neutron(
                        db_context,
                        fixed_ip['subnet_id'])
                    if not subnet_db:
                        LOG.info("Subnet %s has been deleted concurrently",
                                 fixed_ip['subnet_id'])
                    elif self._is_ipv4(subnet_db):
                        ipv4_subnet_exists = True
                        subnet_mapping['subnet_id'] = subnet_db['id']
                        LOG.info("found ipv4 address in the port")
                if not ipv4_subnet_exists:
                    LOG.info("VPort does not exist as Ipv4 neutron subnet"
                             "has been concurrently deleted.")
                    return
            LOG.debug("Retrying to get new subnet mapping from vsd")
            subnet_mapping = self._get_updated_subnet_mapping_from_vsd(
                db_context, subnet_mapping)
            return self._get_nuage_vport(port, subnet_mapping, required=True)

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

    def _ip4_addr_added_to_dualstack_dhcp_port(self, original, port):
        original_fixed_ips = original['fixed_ips']
        current_fixed_ips = port['fixed_ips']
        device_owner = port.get('device_owner')
        if device_owner != os_constants.DEVICE_OWNER_DHCP:
            return False  # not a dhcp port

        ipv4s, ipv6s = self.count_fixed_ips_per_version(
            current_fixed_ips)
        original_ipv4s, original_ipv6s = self.count_fixed_ips_per_version(
            original_fixed_ips)

        return (ipv4s == 1 and
                original_ipv4s == 0 and original_ipv6s == 1)

    def _ipv4_addr_removed_from_dualstack_dhcp_port(self, original, port):
        original_fixed_ips = original['fixed_ips']
        current_fixed_ips = port['fixed_ips']
        device_owner = port.get('device_owner')
        if device_owner != os_constants.DEVICE_OWNER_DHCP:
            return False  # not a dhcp port

        ipv4s, ipv6s = self.count_fixed_ips_per_version(
            current_fixed_ips)
        original_ipv4s, original_ipv6s = self.count_fixed_ips_per_version(
            original_fixed_ips)

        return (ipv4s == 0 and ipv6s == 1 and
                original_ipv4s == 1)

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
                                      np_name, subnet_mapping,
                                      is_port_device_owner_removed=True)
        elif host_added:
            self._validate_security_groups(context)
            if self._port_should_have_vm(port):
                nuage_subnet = self._find_vsd_subnet(
                    db_context, subnet_mapping)
                self._create_nuage_vm(db_context, port,
                                      np_name, subnet_mapping, nuage_vport,
                                      nuage_subnet)

    @utils.context_log
    def delete_port_postcommit(self, context):
        db_context = context._plugin_context
        port = context.current
        vsd_errors = [(vsd_constants.CONFLICT_ERR_CODE,
                       vsd_constants.VSD_VM_EXISTS_ON_VPORT)]
        utils.retry_on_vsdclient_error(
            self._delete_port, vsd_error_codes=vsd_errors)(db_context,
                                                           port)

    def _delete_port(self, db_context, port):
        subnet_mapping = self.get_subnet_mapping_by_port(db_context, port)
        if not subnet_mapping:
            return

        if not self.needs_vport_creation(port.get('device_owner')):
            # GW host vport cleanup
            self.delete_gw_host_vport(db_context, port, subnet_mapping)
            return

        if port.get('binding:host_id'):
            np_name = self.vsdclient.get_net_partition_name_by_id(
                subnet_mapping['net_partition_id'])
            require(np_name, "netpartition",
                    subnet_mapping['net_partition_id'])
            self._delete_nuage_vm(db_context, port, np_name,
                                  subnet_mapping,
                                  is_port_device_owner_removed=True)
        nuage_vport = self._get_nuage_vport(port, subnet_mapping,
                                            required=False)
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
        elif not nuage_vport \
                and os_constants.DEVICE_OWNER_DHCP in port.get('device_owner'):
            return
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
        if not self.is_port_supported(context.current):
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
        return external_change, shared_change, physnets_change

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

    def _validate_nuage_sharedresource(self, net_id, network_subnets,
                                       subnet=None):
        if any(map(self._is_ipv6, network_subnets)):
            msg = _("Subnet with ip_version 6 is currently not supported "
                    "for router:external networks.")
            raise NuageBadRequest(msg=msg)

        if subnet:
            fip_underlays = [s['underlay'] for s in network_subnets
                             if s['id'] != subnet['id']]
            subn_underlay = (subnet['underlay'] if subnet.get('underlay')
                             is not None else
                             cfg.CONF.RESTPROXY.nuage_fip_underlay)
            if len(set(fip_underlays + [subn_underlay])) > 1:
                msg = (_('It is not allowed to mix external '
                         'subnets with underlay '
                         'enabled and disabled in the same external '
                         'network {}.').format(net_id))
                raise NuageBadRequest(msg=msg)

    def _validate_create_openstack_managed_subnet(self, context, subnet,
                                                  network_subnets):
        if (lib_validators.is_attr_set(subnet.get('gateway_ip')) and
                netaddr.IPAddress(subnet['gateway_ip']) not in
                netaddr.IPNetwork(subnet['cidr'])):
            msg = "Gateway IP outside of the subnet CIDR "
            raise NuageBadRequest(resource='subnet', msg=msg)

        if self.is_external(context, subnet['network_id']):
            self._validate_nuage_sharedresource(
                subnet['network_id'], network_subnets, subnet)
        else:
            if lib_validators.is_attr_set(subnet.get('net_partition')):
                netpart = self._get_net_partition_for_entity(context, subnet)
                if netpart['name'] == constants.SHARED_INFRASTRUCTURE:
                    msg = (_("It is not allowed to create OpenStack managed "
                             "subnets in the net_partition {}")
                           .format(netpart['name']))
                    raise NuageBadRequest(resource='subnet', msg=msg)
            if lib_validators.is_attr_set(subnet.get('underlay')):
                msg = _("underlay attribute can not be set for "
                        "internal subnets")
                raise NuageBadRequest(resource='subnet', msg=msg)
            if lib_validators.is_attr_set(subnet.get('nuage_uplink')):
                msg = _("nuage_uplink attribute can not be set for "
                        "internal subnets")
                raise NuageBadRequest(resource='subnet', msg=msg)

        ipv4s = len([s for s in network_subnets if self._is_ipv4(s)])
        ipv6s = len([s for s in network_subnets if self._is_ipv6(s)])

        if ipv6s == 1 and ipv4s > 1 or ipv6s > 1:
            msg = _("A network with an ipv6 subnet may only have maximum 1 "
                    "ipv4 and 1 ipv6 subnet")
            raise NuageBadRequest(msg=msg)

    @staticmethod
    def _validate_create_vsd_managed_subnet(network, subnet):
        subnet_validate = {'net_partition': IsSet(),
                           'nuagenet': IsSet()}
        validate("subnet", subnet, subnet_validate)
        net_validate = {'router:external': Is(False)}
        validate("network", network, net_validate)

        # Check that network is not attached to a nuage_l2bridge
        if network.get('nuage_l2bridge'):
            msg = _("The network is attached to nuage_l2bridge {}."
                    "Please consult documentation on how to achieve SRIOV"
                    "duplex for VSD managed subnets.").format(
                network['nuage_l2bridge'])
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

    def _get_nuage_subnet(self, nuage_subnet_id, subnet_db=None,
                          subnet_type=None):
        if subnet_db is None:
            nuage_subnet = self.vsdclient.get_nuage_subnet_by_id(
                nuage_subnet_id, subnet_type=subnet_type)
        else:
            nuage_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                subnet_db)
        require(nuage_subnet, 'subnet or domain', nuage_subnet_id)
        shared = nuage_subnet['associatedSharedNetworkResourceID']
        shared_subnet = None
        if shared:
            shared_subnet = self.vsdclient.get_nuage_subnet_by_id(
                shared,
                subnet_type=subnet_type)
            require(shared_subnet, 'sharednetworkresource', shared)
            shared_subnet['subnet_id'] = shared
        return nuage_subnet, shared_subnet

    def _check_gateway_from_vsd(self, nuage_subnet, shared_subnet, subnet):
        """_check_gateway_from_vsd

        This methods checks the openstack gateway with the VSD gateway and
        returns whether they match, as well as their values which are used in
        the error report when they don't match.

        One side effect of this function is that in case of L2, v4 and
        in OpenStack a GW is specified as the .1 IP, and in VSD no option 3
        is set, we tolerate (so match will be True), but we _clear_ the
        gateway IP in OpenStack also.

        :rtype: (bool, string, string)
        :returns matching_gws: boolean report whether the gateways match
        :returns os_gw_ip: the OpenStack gateway, used for error reporting
        :returns vsd_gw_ip: the VSD gateway, used for error reporting

        """
        gateway_subnet = shared_subnet or nuage_subnet
        is_l2 = nuage_subnet['type'] == constants.L2DOMAIN
        is_v6 = self._is_ipv6(subnet)
        os_gw_ip = subnet['gateway_ip']

        if is_l2:
            if is_v6:
                # Always fine as we are not the dhcp provider we don't know
                # which default route the vm will obtain.
                # Hence we act as good, by acting as if vsd_gw_ip just equals
                # the os_gw_ip. This will make the match check yield True.
                vsd_gw_ip = os_gw_ip

            else:  # v4

                # fetch option 3 from vsd
                vsd_gw_ip = self.vsdclient.get_gw_from_dhcp_l2domain(
                    gateway_subnet['ID'])
                dot_one_ip = netaddr.IPNetwork(subnet['cidr'])[1]

                if not vsd_gw_ip and os_gw_ip:
                    if self._is_equal_ip(os_gw_ip, dot_one_ip):
                        # special case : tolerate but clear gw
                        os_gw_ip = subnet['gateway_ip'] = None

                    else:
                        # improve the error message (better than 'None')
                        vsd_gw_ip = 'not being present'

                        # in other cases, default compare

        # l3
        elif is_v6:
            vsd_gw_ip = gateway_subnet['IPv6Gateway']
        else:
            vsd_gw_ip = gateway_subnet['gateway']

        matching_gws = self._is_equal_ip(os_gw_ip, vsd_gw_ip)

        return matching_gws, os_gw_ip, vsd_gw_ip

    def _cleanup_group(self, db_context, nuage_npid, nuage_subnet_id, subnet):
        try:
            if db_context.tenant == subnet['tenant_id']:
                tenants = [db_context.tenant]
            else:
                tenants = [db_context.tenant, subnet['tenant_id']]
            self.vsdclient.detach_nuage_group_to_nuagenet(
                tenants, nuage_subnet_id,
                subnet.get('shared'))
        except Exception as e:
            LOG.error("Failed to detach group from vsd subnet {tenant: %s,"
                      " netpartition: %s, vsd subnet: %s}",
                      db_context.tenant, nuage_npid, nuage_subnet_id)
            raise e

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
            if l2dom and not self.get_subnet(
                    db_context, l2dom['subnet_id'])['enable_dhcp']:
                return False
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

    def _validate_port(self, db_context, port, event,
                       is_network_external=False):
        """_validate_port : validating neutron port

        :rtype: dict
        """
        fixed_ips = port.get('fixed_ips', [])
        device_owner = port.get('device_owner')
        is_dhcp_port = device_owner == os_constants.DEVICE_OWNER_DHCP
        is_router_gw = device_owner == os_constants.DEVICE_OWNER_ROUTER_GW
        if len(fixed_ips) == 0:
            return False
        if is_dhcp_port and all(map(self._is_v6_ip, fixed_ips)):
            # Delayed creation of vport until dualstack
            return False
        if is_router_gw:
            # Router can be attached to multiple subnets.
            return False
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

        if not self.needs_vport_creation(device_owner):
            return False

        if is_dhcp_port and is_network_external:
            return False

        if all(map(self._is_v6_ip, fixed_ips)):
            msg = _("Port can't be a pure ipv6 port. Need ipv4 fixed ip.")
            raise NuageBadRequest(msg=msg)

        if is_network_external:
            msg = "Cannot create port in a FIP pool Subnet"
            raise NuageBadRequest(resource='port', msg=msg)

        if not self.is_port_supported(port):
            return False
        self._validate_nuage_l2bridges(db_context, port)
        # No update required on port with "network:dhcp:nuage"
        if port.get('device_owner') == constants.DEVICE_OWNER_DHCP_NUAGE:
            return False

        uniq_subnet_ids = set(ip["subnet_id"] for ip in fixed_ips)

        subnet_mappings = nuagedb.get_subnet_l2doms_by_subnet_ids(
            db_context.session,
            uniq_subnet_ids)

        nuage_managed = []
        vsd_subnet_ids = set()

        for mapping in subnet_mappings:
            nuage_managed.append(mapping['nuage_managed_subnet'])
            vsd_subnet_ids.add(mapping['nuage_subnet_id'])

        if not subnet_mappings:
            return False

        if len(vsd_subnet_ids) > 1 and all(nuage_managed):
            msg = _("Port has fixed ips for multiple vsd subnets.")
            raise NuageBadRequest(msg=msg)

        if (not self._is_vsd_mgd(subnet_mappings[0]) and
                port.get(nuagepolicygroup.NUAGE_POLICY_GROUPS)):
            msg = ("Cannot use VSP policy groups on OS managed subnets,"
                   " use neutron security groups instead.")
            raise NuageBadRequest(resource='port', msg=msg)

        # It's okay to just return the first mapping because it's only 1 vport
        # on 1 subnet on VSD that has to be made.
        self.nuage_callbacks.notify(resources.PORT, event,
                                    self, context=db_context,
                                    request_port=port)
        return subnet_mappings[0]

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
                         nuage_port, nuage_subnet):
        if (port.get('device_owner') in
                [LB_DEVICE_OWNER_V2, DEVICE_OWNER_DHCP,
                 constants.DEVICE_OWNER_OCTAVIA_HEALTHMGR]):
            no_of_ports = 1
            vm_id = port['id']
        else:
            no_of_ports, vm_id = self._get_port_num_and_vm_id_of_device(
                db_context, port)

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
        if port['tenant_id'] not in (subnets[4].get('tenant_id'),
                                     subnets[6].get('tenant_id')):
            subnet_tenant_id = subnets[4].get('tenant_id')
        else:
            subnet_tenant_id = port['tenant_id']

        shared = subnets[4].get('shared') or subnets[6].get('shared', False)

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
            'dhcp_enabled': subnets[4].get('enable_dhcp'),
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
                                                     subnets[4].get('id'))
            except SubnetNotFound:
                subnet = None
            if not subnet:
                LOG.info("Subnet %s has been deleted concurrently",
                         subnets[4].get('id'))
            else:
                raise rnf

    def _get_port_num_and_vm_id_of_device(self, db_context, port):
        filters = {'device_id': [port.get('device_id')]}
        ports = self.core_plugin.get_ports(db_context, filters)
        ports = [p for p in ports
                 if self._is_port_vxlan_supported(p, db_context) and
                 p['binding:host_id']]
        return len(ports), port.get('device_id')

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
                                     create_nuage_sec_grp_for_port_sec(params))
                            if sg_id:
                                params['sg_id'] = sg_id
                                (self.vsdclient.
                                 create_nuage_sec_grp_rule_for_port_sec(params)
                                 )
                                policygroup_ids.append(sg_id)
                                self.vsdclient.update_vport_policygroups(
                                    nuage_vport_id, policygroup_ids)
                        successful = True
                    except restproxy.RESTProxyError as e:
                        LOG.debug("Policy group retry %s times.", attempt)
                        msg = e.msg.lower()
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

    def _is_port_vxlan_supported(self, port, db_context):
        if not self.is_port_supported(port):
            return False
        return self.is_vxlan_network_by_id(db_context, port.get('network_id'))

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
                         is_port_device_owner_removed=False):
        if port.get('device_owner') in [LB_DEVICE_OWNER_V2, DEVICE_OWNER_DHCP]:
            no_of_ports = 1
            vm_id = port['id']
        else:
            no_of_ports, vm_id = self._get_port_num_and_vm_id_of_device(
                db_context, port)
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

        nuage_port = self.vsdclient.get_nuage_port_by_id(
            {'neutron_port_id': port['id']})
        if not nuage_port:
            return
        params = {
            'no_of_ports': no_of_ports,
            'netpart_name': np_name,
            'tenant': port['tenant_id'],
            'nuage_vif_id': nuage_port['nuage_vif_id'],
            'id': vm_id,
            'subn_tenant': subnet_tenant_id,
            'portOnSharedSubn': shared
        }
        if not nuage_port['domainID']:
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
    def is_port_supported(port):
        return (NuageMechanismDriver._direct_vnic_supported(port) or
                port.get(portbindings.VNIC_TYPE, '') ==
                portbindings.VNIC_NORMAL)

    def check_vlan_transparency(self, context):
        """Nuage driver vlan transparency support."""
        return True
