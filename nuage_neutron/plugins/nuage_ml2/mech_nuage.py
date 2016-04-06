# Copyright 2015 Alcatel-Lucent USA Inc.
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
import re

from oslo_db.exception import DBDuplicateEntry
from oslo_log import log
from oslo_utils import excutils

from neutron.api import extensions as neutron_extensions
from neutron.api.v2.attributes import UUID_PATTERN
from neutron.callbacks import resources
from neutron.common import constants as os_constants
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import extensions
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import ignore_no_update
from nuage_neutron.plugins.common.utils import ignore_not_found
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import IsSet
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.plugins.common.validation import validate

LB_DEVICE_OWNER_V2 = os_constants.DEVICE_OWNER_LOADBALANCER + 'V2'

LOG = log.getLogger(__name__)


class NuageMechanismDriver(base_plugin.BaseNuagePlugin,
                           api.MechanismDriver):
    def initialize(self):
        LOG.debug('Initializing driver')
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        LOG.debug('Initializing complete')

    def _nuageclient_init(self):
        super(NuageMechanismDriver, self)._nuageclient_init()
        self._wrap_nuageclient()

    def _wrap_nuageclient(self):
        """Wraps nuagecient methods with try-except to ignore certain errors.

        When updating an entity on the VSD and there is nothing to actually
        update because the values don't change, VSD will throw an error. This
        is not needed for neutron so all these exceptions are ignored.

        When VSD responds with a 404, this is sometimes good (for example when
        trying to update an entity). Yet sometimes this is not required to be
        an actual exception. When deleting an entity that does no longer exist
        it is fine for neutron. Also when trying to retrieve something from VSD
        having None returned is easier to work with than RESTProxy exceptions.
        """

        methods = inspect.getmembers(self.nuageclient,
                                     lambda x: inspect.ismethod(x))
        for m in methods:
            wrapped = ignore_no_update(m[1])
            if m[0].startswith('get_') or m[0].startswith('delete_'):
                wrapped = ignore_not_found(wrapped)
            setattr(self.nuageclient, m[0], wrapped)

    @utils.context_log
    def create_subnet_precommit(self, context):
        subnet = context.current
        if not subnet.get('nuagenet') and not subnet.get('net_partition'):
            return
        db_context = context._plugin_context
        core_plugin = context._plugin
        self._validate_create_subnet(core_plugin, db_context, subnet)

    @handle_nuage_api_errorcode
    def create_subnet_postcommit(self, context):
        subnet = context.current
        if not subnet.get('nuagenet') and not subnet.get('net_partition'):
            return
        core_plugin = context._plugin
        db_context = context._plugin_context
        nuage_subnet_id = subnet['nuagenet']
        original_gateway = subnet['gateway_ip']

        nuage_npid = self._validate_net_partition(subnet, db_context)
        nuage_subnet, shared_subnet = self._get_nuage_subnet(nuage_subnet_id)
        self._validate_cidr(subnet, nuage_subnet, shared_subnet)
        self._set_gateway_from_vsd(nuage_subnet, shared_subnet, subnet)

        result = self.nuageclient.attach_nuage_group_to_nuagenet(
            db_context.tenant, nuage_npid, nuage_subnet_id,
            subnet.get('shared'))
        (nuage_uid, nuage_gid) = result
        try:
            with db_context.session.begin(subtransactions=True):
                self._update_gw_and_pools(core_plugin, db_context, subnet,
                                          original_gateway)
                self._reserve_dhcp_ip(core_plugin, db_context, subnet,
                                      nuage_subnet, shared_subnet)
                nuagedb.add_subnetl2dom_mapping(
                    db_context.session, subnet['id'], nuage_subnet_id,
                    nuage_npid, nuage_user_id=nuage_uid,
                    nuage_group_id=nuage_gid, managed=True)
        except DBDuplicateEntry:
            self._cleanup_group(db_context, nuage_npid, nuage_subnet_id,
                                subnet)
            msg = _("Multiple OpenStack Subnets cannot be linked to the same "
                    "Nuage Subnet")
            raise NuageBadRequest(msg=msg)
        except Exception:
            self._cleanup_group(db_context, nuage_npid, nuage_subnet_id,
                                subnet)
            raise

    @utils.context_log
    def update_subnet_precommit(self, context):
        subnet = context.current
        db_context = context._plugin_context
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        subnet['id'])
        if subnet_mapping and subnet_mapping['nuage_managed_subnet']:
            raise NuageBadRequest(
                msg=_("Subnet %s is a VSD-managed subnet. Update is not "
                      "supported") % subnet['id'])

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

    @handle_nuage_api_errorcode
    def delete_subnet_postcommit(self, context):
        db_context = context._plugin_context
        subnet = context.current
        mapping = context.nuage_mapping
        if not mapping or not mapping['nuage_managed_subnet']:
            return

        self._cleanup_group(db_context, mapping['net_partition_id'],
                            mapping['nuage_subnet_id'], subnet)

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_postcommit(self, context):
        db_context = context._plugin_context
        core_plugin = context._plugin
        port = context.current
        request_port = port['request_port']
        if 'request_port' not in port:
            return
        del port['request_port']

        subnet_mapping = self._validate_port(db_context, port)
        if not subnet_mapping:
            return

        nuage_vport = nuage_vm = np_name = None
        try:
            np_id = subnet_mapping['net_partition_id']
            nova_prefix = constants.NOVA_PORT_OWNER_PREF
            if port['device_owner'].startswith(nova_prefix):
                self._validate_vmports_same_netpartition(core_plugin,
                                                         db_context,
                                                         port, np_id)
                desc = ("device_owner:" + constants.NOVA_PORT_OWNER_PREF +
                        "(please do not edit)")
                nuage_vport = self._create_nuage_vport(port, subnet_mapping,
                                                       desc)
                np_name = self.nuageclient.get_net_partition_name_by_id(np_id)
                require(np_name, "netpartition", np_id)
                nuage_vm = self._create_nuage_vm(
                    core_plugin, db_context, port, np_name, subnet_mapping,
                    nuage_vport)
            else:
                nuage_vport = self._create_nuage_vport(port, subnet_mapping)
        except Exception:
            if nuage_vm:
                self._delete_nuage_vm(core_plugin, db_context, port, np_name,
                                      subnet_mapping)
            if nuage_vport:
                self.nuageclient.delete_nuage_vport(
                    nuage_vport.get('nuage_vport_id'))
            raise
        rollbacks = []
        try:
            self.nuage_callbacks.notify(resources.PORT, constants.AFTER_CREATE,
                                        self, context=db_context, port=port,
                                        vport=nuage_vport, rollbacks=rollbacks,
                                        request_port=request_port)
        except Exception:
            with excutils.save_and_reraise_exception():
                    for rollback in reversed(rollbacks):
                        rollback[0](*rollback[1], **rollback[2])

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_port_precommit(self, context):
        db_context = context._plugin_context
        core_plugin = context._plugin
        port = context.current
        original = context.original
        if 'request_port' not in port:
            return
        request_port = port['request_port']
        del port['request_port']

        subnet_mapping = self._validate_port(db_context, port)
        if not subnet_mapping:
            return
        nuage_vport = self._get_nuage_vport(port, subnet_mapping)

        device_added = device_removed = False
        if not original['device_owner'] and port['device_owner']:
            device_added = True
        elif original['device_owner'] and not port['device_owner']:
            device_removed = True

        if device_added or device_removed:
            np_name = self.nuageclient.get_net_partition_name_by_id(
                subnet_mapping['net_partition_id'])
            require(np_name, "netpartition",
                    subnet_mapping['net_partition_id'])

            if device_removed:
                if self._port_should_have_vm(original):
                    self._delete_nuage_vm(core_plugin, db_context, original,
                                          np_name, subnet_mapping)
            elif device_added:
                if port['device_owner'].startswith(
                        constants.NOVA_PORT_OWNER_PREF):
                    self._create_nuage_vm(core_plugin, db_context, port,
                                          np_name, subnet_mapping, nuage_vport)
        rollbacks = []
        try:
            self.nuage_callbacks.notify(resources.PORT, constants.AFTER_UPDATE,
                                        core_plugin, context=db_context,
                                        updated_port=port,
                                        original_port=original,
                                        request_port=request_port,
                                        vport=nuage_vport, rollbacks=rollbacks)
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])

    @utils.context_log
    def delete_port_postcommit(self, context):
        db_context = context._plugin_context
        core_plugin = context._plugin
        port = context.current

        subnet_mapping = self._validate_port(db_context, port)
        if not subnet_mapping:
            return

        if self._port_should_have_vm(port):
            np_name = self.nuageclient.get_net_partition_name_by_id(
                subnet_mapping['net_partition_id'])
            require(np_name, "netpartition",
                    subnet_mapping['net_partition_id'])
            self._delete_nuage_vm(core_plugin, db_context, port, np_name,
                                  subnet_mapping)
        nuage_vport = self._get_nuage_vport(port, subnet_mapping,
                                            required=False)
        if nuage_vport:
            try:
                self.nuageclient.delete_nuage_vport(
                    nuage_vport['nuage_vport_id'])
            except Exception as e:
                LOG.error("Failed to delete vport from vsd {vport id: %s}"
                          % nuage_vport['nuage_vport_id'])
                raise e

    @utils.context_log
    def bind_port(self, context):
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self._supported_vnic_types():
            LOG.debug("Cannot bind due to unsupported vnic_type: %s",
                      vnic_type)
            return
        for segment in context.network.network_segments:
            if self._check_segment(segment):
                context.set_binding(segment[api.ID],
                                    portbindings.VIF_TYPE_OVS,
                                    {portbindings.CAP_PORT_FILTER: False},
                                    os_constants.PORT_STATUS_ACTIVE)

    def _validate_create_subnet(self, core_plugin, db_context, subnet):
        subnet_validate = {'net_partition': IsSet(),
                           'nuagenet': IsSet()}
        validate("subnet", subnet, subnet_validate)
        network = core_plugin.get_network(db_context, subnet['network_id'])
        net_validate = {'router:external': Is(False)}
        validate("network", network, net_validate)

        self._validate_network_segment(network)

    def _validate_network_segment(self, network):
        net_type = 'provider:network_type'
        vxlan_segment = [segment for segment in network.get('segments', [])
                         if str(segment.get(net_type)).lower() == 'vxlan']
        if str(network.get(net_type)).lower() != 'vxlan' and not vxlan_segment:
            msg = _("Network should have 'provider:network_type' vxlan or have"
                    " such a segment")
            raise NuageBadRequest(msg=msg)

    def _validate_net_partition(self, subnet, db_context):
        netpartition_db = nuagedb.get_net_partition_by_name(
            db_context.session, subnet['net_partition'])
        netpartition = self.nuageclient.get_netpartition_by_name(
            subnet['net_partition'])
        require(netpartition, "netpartition", subnet['net_partition'])
        if netpartition_db:
            if netpartition_db['id'] != netpartition['id']:
                net_partdb = nuagedb.get_net_partition_with_lock(
                    db_context.session, netpartition_db['id'])
                nuagedb.delete_net_partition(db_context.session, net_partdb)
                self._add_net_partition(db_context.session, netpartition)
        else:
            self._add_net_partition(db_context.session, netpartition)
        return netpartition['id']

    def _add_net_partition(self, session, netpartition):
        return nuagedb.add_net_partition(
            session, netpartition['id'], None, None,
            netpartition['name'], None, None)

    def _get_nuage_subnet(self, nuage_subnet_id):
        nuage_subnet = self.nuageclient.get_subnet_or_domain_subnet_by_id(
            nuage_subnet_id)
        require(nuage_subnet, 'subnet or domain', nuage_subnet_id)
        shared = nuage_subnet['subnet_shared_net_id']
        shared_subnet = None
        if shared:
            shared_subnet = self.nuageclient.get_nuage_sharedresource(shared)
            require(shared_subnet, 'sharednetworkresource', shared)
            shared_subnet['subnet_id'] = shared
        return nuage_subnet, shared_subnet

    def _set_gateway_from_vsd(self, nuage_subnet, shared_subnet, subnet):
        gateway_subnet = shared_subnet or nuage_subnet
        if subnet['enable_dhcp']:
            if nuage_subnet['type'] == constants.L2DOMAIN:
                gw_ip = self.nuageclient.get_gw_from_dhcp_l2domain(
                    gateway_subnet['subnet_id'])
            else:
                gw_ip = gateway_subnet['subnet_gateway']
            gw_ip = gw_ip or None
        else:
            gw_ip = None
            subnet['dns_nameservers'] = []
            LOG.warn("Nuage ml2 plugin will ignore dns_nameservers.")
        subnet['gateway_ip'] = gw_ip

    def _update_gw_and_pools(self, core_plugin, db_context, subnet,
                             original_gateway):
        if original_gateway == subnet['gateway_ip']:
            # The gateway from vsd is what openstack already had.
            return

        if original_gateway != subnet['gateway_ip']:
            # Gateway from vsd is different, we must recalculate the allocation
            # pools.
            new_pools = self._set_allocation_pools(core_plugin, subnet)
            core_plugin.ipam._update_subnet_allocation_pools(
                db_context, subnet['id'], {'allocation_pools': new_pools,
                                           'id': subnet['id']})
        LOG.warn("Nuage ml2 plugin will overwrite subnet gateway ip "
                 "and allocation pools")
        db_subnet = core_plugin._get_subnet(db_context, subnet['id'])
        update_subnet = {'gateway_ip': subnet['gateway_ip']}
        db_subnet.update(update_subnet)

    def _reserve_dhcp_ip(self, core_plugin, db_context, subnet, nuage_subnet,
                         shared_subnet):
        if (nuage_subnet['type'] != constants.L2DOMAIN
                or not subnet['enable_dhcp']):
            return
        dhcp_ip = (shared_subnet['subnet_gateway']
                   if shared_subnet
                   else nuage_subnet['subnet_gateway'])
        core_plugin.ipam._allocate_specific_ip(db_context,
                                               subnet['id'],
                                               dhcp_ip)

    def _set_allocation_pools(self, core_plugin, subnet):
        pools = core_plugin.ipam.generate_pools(subnet['cidr'],
                                                subnet['gateway_ip'])
        subnet['allocation_pools'] = [
            {'start': str(netaddr.IPAddress(pool.first, pool.version)),
             'end': str(netaddr.IPAddress(pool.last, pool.version))}
            for pool in pools]
        return pools

    def _cleanup_group(self, db_context, nuage_npid, nuage_subnet_id, subnet):
        try:
            self.nuageclient.detach_nuage_group_to_nuagenet(
                db_context.tenant, nuage_npid, nuage_subnet_id,
                subnet.get('shared'))
        except Exception as e:
            LOG.error("Failed to detach group from vsd subnet {tenant: %s,"
                      " netpartition: %s, vsd subnet: %s}"
                      % (db_context.tenant, nuage_npid, nuage_subnet_id))
            raise e

    def _validate_port(self, db_context, port):
        if 'fixed_ips' not in port or len(port.get('fixed_ips', [])) == 0:
            return False
        if port.get('device_owner') in constants.AUTO_CREATE_PORT_OWNERS:
            return False
        if port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL) \
                not in self._supported_vnic_types():
            return False
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        subnet_id)
        if not subnet_mapping or not subnet_mapping['nuage_managed_subnet']:
            return False
        return subnet_mapping

    def _port_should_have_vm(self, port):
        device_owner = port['device_owner']
        return (constants.NOVA_PORT_OWNER_PREF in device_owner
                or LB_DEVICE_OWNER_V2 in device_owner
                or device_owner == constants.APPD_PORT)

    def _create_nuage_vm(self, core_plugin, db_context, port, np_name,
                         subnet_mapping, nuage_port):
        no_of_ports, vm_id = self._get_port_num_and_vm_id_of_device(
            core_plugin, db_context, port)
        subn = core_plugin.get_subnet(
            db_context, port['fixed_ips'][0]['subnet_id'])
        params = {
            'port_id': port['id'],
            'id': vm_id,
            'mac': port['mac_address'],
            'netpart_name': np_name,
            'ip': port['fixed_ips'][0]['ip_address'],
            'no_of_ports': no_of_ports,
            'tenant': port['tenant_id'],
            'netpart_id': subnet_mapping['net_partition_id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id'],
            'vport_id': nuage_port.get('nuage_vport_id'),
            'parent_id': subnet_mapping['nuage_subnet_id'],
            'subn_tenant': subn['tenant_id'],
            'portOnSharedSubn': subn['shared'],
            'dhcp_enabled': subn['enable_dhcp']
        }
        network_details = core_plugin.get_network(db_context,
                                                  port['network_id'])
        if network_details['shared']:
            self.nuageclient.create_usergroup(
                port['tenant_id'],
                subnet_mapping['net_partition_id'])
        return self.nuageclient.create_vms(params)

    def _get_port_num_and_vm_id_of_device(self, core_plugin, db_context, port):
        # upstream neutron_lbaas assigns a constant device_id to all the
        # lbaas_ports (which is a bug), hence we use port ID as vm_id
        # instead of device_id for lbaas dummy VM
        # as get_ports by device_id would return multiple vip_ports,
        # as workaround set no_of_ports = 1
        if port.get('device_owner') == LB_DEVICE_OWNER_V2:
            return 1, port['id']
        filters = {'device_id': [port.get('device_id')]}
        ports = core_plugin.get_ports(db_context, filters)
        ports = [p for p in ports
                 if self._is_port_vxlan_normal(p, core_plugin, db_context)]
        return len(ports), port.get('device_id')

    def _is_port_vxlan_normal(self, port, core_plugin, db_context):
        if port.get('binding:vnic_type') != portbindings.VNIC_NORMAL:
            return False

        network = core_plugin.get_network(db_context, port.get('network_id'))
        try:
            self._validate_network_segment(network)
            return True
        except Exception:
            return False

    def _delete_nuage_vm(self, core_plugin, db_context, port, np_name,
                         subnet_mapping):
        no_of_ports, vm_id = self._get_port_num_and_vm_id_of_device(
            core_plugin, db_context, port)
        subn = core_plugin.get_subnet(db_context, subnet_mapping['subnet_id'])
        nuage_port = self.nuageclient.get_nuage_port_by_id(
            {'neutron_port_id': port['id']})
        if not nuage_port:
            return
        params = {
            'no_of_ports': no_of_ports,
            'netpart_name': np_name,
            'tenant': port['tenant_id'],
            'nuage_vif_id': nuage_port['nuage_vif_id'],
            'id': vm_id,
            'subn_tenant': subn['tenant_id'],
            'portOnSharedSubn': subn['shared']
        }
        if not nuage_port['nuage_domain_id']:
            params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            params['l3dom_id'] = subnet_mapping['nuage_subnet_id'],
        try:
            self.nuageclient.delete_vms(params)
        except Exception as e:
            LOG.error("Failed to delete vm from vsd {vm id: %s}"
                      % vm_id)
            raise e

    def _process_port_redirect_target(self, port, nuage_vport):
        redirect_targets = port['nuage_redirect_targets']
        if redirect_targets is None:
            return
        if len(redirect_targets) == 0:
            self.nuageclient.update_nuage_vport_redirect_target(
                None, nuage_vport.get('nuage_vport_id'))
            return
        if len(redirect_targets) > 1:
            msg = _("Multiple redirect targets on a port not supported.")
            raise NuageBadRequest(msg=msg)

        rtarget = redirect_targets[0]
        uuid_match = re.match(UUID_PATTERN, rtarget)
        if not uuid_match:
            nuage_rtarget = self.nuageclient.get_nuage_redirect_targets(
                {'name': rtarget})
            require(nuage_rtarget, "redirect target", rtarget)
            nuage_rtarget_id = nuage_rtarget[0]['ID']
        else:
            nuage_rtarget = self.nuageclient.get_nuage_redirect_targets(
                {'id': rtarget})
            require(nuage_rtarget, "redirect target", rtarget)
            nuage_rtarget_id = rtarget

        self.nuageclient.update_nuage_vport_redirect_target(
            nuage_rtarget_id, nuage_vport.get('nuage_vport_id'))

        port['nuage_redirect_targets'] = [nuage_rtarget_id]

    def _get_nuage_vport(self, port, subnet_mapping, required=True):
        port_params = {
            'neutron_port_id': port['id'],
            'l2dom_id': subnet_mapping['nuage_subnet_id'],
            'l3dom_id': subnet_mapping['nuage_subnet_id']
        }
        return self.nuageclient.get_nuage_vport_by_id(port_params,
                                                      required=required)

    def _check_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        return network_type == p_constants.TYPE_VXLAN

    def _supported_vnic_types(self):
        return [portbindings.VNIC_NORMAL]
