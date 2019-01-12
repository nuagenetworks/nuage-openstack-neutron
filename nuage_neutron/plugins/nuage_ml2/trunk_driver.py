# Copyright 2017 Nokia.
# All Rights Reserved.
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

import collections
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.db import api as db_api
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import constants as t_consts
from neutron.services.trunk.drivers import base as trunk_base
from neutron.services.trunk import exceptions as t_exc
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_ctx
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import constants as p_consts
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb as db
from nuage_neutron.plugins.common import trunk_db


LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    t_consts.VLAN,
)


class NuageTrunkHandler(object):

    _core_plugin = None

    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    def set_trunk_status(self, context, trunk_id, status):
        with db_api.autonested_transaction(context.session):
            trunk = trunk_objects.Trunk.get_object(context, id=trunk_id)
            if trunk:
                trunk.update(status=status)

    def _trunk_status_change(self, resource, event, trigger, **kwargs):
        updated_port = kwargs['port']
        trunk_details = updated_port.get('trunk_details')
        # If no trunk details port is not parent of a trunk
        if not trunk_details:
            return
        if (updated_port.get(portbindings.VNIC_TYPE) not in
                self.plugin_driver._supported_vnic_types()):
            LOG.debug("Ignoring trunk status change for port"
                      " %s due to unsupported VNIC type",
                      updated_port.get('id'))
            return
        if not self.plugin_driver.is_port_supported(updated_port):
            LOG.debug("Ignoring trunk status change for port "
                      "due to unsupported vnic_type: %s with "
                      "no switchdev capability", portbindings.VNIC_DIRECT)
            return
        context = kwargs['context']
        if trunk_details.get('trunk_id'):
            trunk = trunk_objects.Trunk.get_object(
                context, id=trunk_details.get('trunk_id'))
            if trunk:
                LOG.info("wiring trunk %(tr)s", {'tr': trunk})
                self.wire_trunk(context, trunk)
                return

    def wire_trunk(self, context, trunk):
        updated_ports = self._update_subport_bindings(context,
                                                      trunk.id,
                                                      trunk.sub_ports)
        if len(trunk.sub_ports) != len(updated_ports[trunk.id]):
            LOG.error("Updated: %(up)s, subports: %(sub)s",
                      {'up': len(updated_ports[trunk.id]),
                       'sub': len(trunk.sub_ports)})
            self.set_trunk_status(context, trunk.id, t_consts.DEGRADED_STATUS)

    def _update_subport_bindings(self, context, trunk_id, subports):
        el = context.elevated()
        ports_by_trunk_id = collections.defaultdict(list)
        ports_by_trunk_id[trunk_id] = []
        updated_ports = collections.defaultdict(list)
        for s in subports:
            ports_by_trunk_id[s['trunk_id']].append(s)
        for trunk_id, subports in six.iteritems(ports_by_trunk_id):
            trunk = trunk_objects.Trunk.get_object(el, id=trunk_id)
            if not trunk:
                LOG.debug("Trunk not found. id : %s", trunk_id)
                continue
            trunk_updated_ports = self._process_binding(el,
                                                        trunk,
                                                        subports)
            updated_ports[trunk_id].extend(trunk_updated_ports)
        return updated_ports

    def _validate_port_fixedip(self, port):
        if not port.get('fixed_ips'):
            msg = ("Port %s requires a FixedIP in order to be used" %
                   port.get('id'))
            raise nuage_exc.NuageBadRequest(msg=msg)

    def _validate_same_netpartition(self, context,
                                    trunk_port, trunk_subports):

        parent_netpart = db.get_subnet_l2dom_by_port_id(
            context.session,
            trunk_port['id']).get('net_partition_id')
        bad_subport = next((port for port in trunk_subports
                            if db.get_subnet_l2dom_by_port_id(
                                context.session,
                                port.id).get('net_partition_id') !=
                            parent_netpart), None)
        if bad_subport:
            raise nuage_exc.SubPortNetpartitionConflict(subport=bad_subport.id)

    def _validate_subports_vlan(self, context, trunk):
        """Validates if a subnet only uses a single vlan within a trunk"""
        context = context.elevated()
        all_subports_in_trunk = trunk_db.get_vlan_subports_of_trunk(
            context.session,
            trunk.id)

        vlans_per_subnet = collections.defaultdict(list)
        for port in all_subports_in_trunk:
            self._validate_port_fixedip(port)
            subnet_id = port['fixed_ips'][0]['subnet_id']
            vlans_per_subnet[subnet_id].append(
                port.sub_port.segmentation_id)

        bad_subnet = next((subnet for subnet, vlans in six.iteritems(
            vlans_per_subnet) if len(vlans) > 1), None)
        if bad_subnet:
            raise nuage_exc.TrunkVlanConflict(
                subnet=bad_subnet,
                vlans=vlans_per_subnet[bad_subnet])
        return all_subports_in_trunk

    def _validate_subports_not_trunk_net(self, trunk_port, trunk_subports):
        """Validates if a subport is not in the trunk network"""
        bad_port = next((port for port in trunk_subports
                         if port.network_id == trunk_port['network_id']), None)
        if bad_port:
            raise nuage_exc.SubPortParentPortConflict(subport=bad_port.id)

    def _process_binding(self, context, trunk, subports):
        updated_ports = []
        trunk_port_id = trunk.port_id
        trunk_port = self.core_plugin.get_port(context, trunk_port_id)
        trunk_host = trunk_port.get(portbindings.HOST_ID)
        trunk_profile = trunk_port.get(portbindings.PROFILE)
        trunk.update(status=t_consts.BUILD_STATUS)
        trunk_target_state = (t_consts.ACTIVE_STATUS if trunk_host else
                              t_consts.DOWN_STATUS)
        for port in subports:
            try:
                data = {'port': {portbindings.HOST_ID: trunk_host,
                                 portbindings.PROFILE: trunk_profile,
                                 'device_owner': t_consts.TRUNK_SUBPORT_OWNER}}
                LOG.info("updating port: %(data)s", {'data': data})
                updated_port = self.core_plugin.update_port(
                    context, port.port_id, data)
                vif_type = updated_port.get(portbindings.VIF_TYPE)
                if vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
                    raise t_exc.SubPortBindingError(port_id=port.port_id,
                                                    trunk_id=trunk.id)
                updated_ports.append(updated_port)
            except t_exc.SubPortBindingError as e:
                LOG.error("Failed to bind subport: %s", e)
                trunk.update(status=t_consts.ERROR_STATUS)
                return []
            except Exception as e:
                LOG.error("Failed to bind subport: %s", e)
        if len(subports) != len(updated_ports):
            LOG.debug("Trunk: %s is degraded", trunk.id)
            trunk.update(status=t_consts.DEGRADED_STATUS)
        else:
            trunk.update(status=trunk_target_state)
        return updated_ports

    def _validate_subports_vnic_type(self, context, trunk, trunk_port,
                                     subports):
        LOG.debug("validating vnic types for %(sub)s added subports in "
                  "trunk %(trunk)s",
                  {'sub': len(subports), 'trunk': trunk.id})
        port_ids = [subport.port_id for subport in subports]
        port_bindings = db.get_port_bindings(context.session,
                                             port_ids)
        parent_vnic = trunk_port.get(portbindings.VNIC_TYPE)
        bad_port = next((binding for binding in port_bindings
                         if binding.vnic_type != parent_vnic),
                        None)
        if bad_port:
            raise nuage_exc.TrunkVnicTypeConflict(
                subport=bad_port.port_id,
                vnic_type_sub=bad_port.vnic_type,
                parent=trunk_port['id'],
                vnic_type_parent=parent_vnic)

    def _set_sub_ports(self, trunk_id, subports):
        _vsdclient = self.plugin_driver.vsdclient
        ctx = n_ctx.get_admin_context()
        for port in subports:
            LOG.debug('setting port id %(id)s  vlan %(vlan)s',
                      {'id': port.port_id, 'vlan': port.segmentation_id})
            os_port = self.core_plugin.get_port(ctx, port.port_id)
            subnet_mapping = db.get_subnet_l2dom_by_port_id(ctx.session,
                                                            port.port_id)
            fixed_ips = os_port['fixed_ips']
            subnets = {4: {}, 6: {}}
            ips = {4: None, 6: None}
            for fixed_ip in fixed_ips:
                subnet = self.core_plugin.get_subnet(ctx,
                                                     fixed_ip['subnet_id'])
                subnets[subnet['ip_version']] = subnet
                ips[subnet['ip_version']] = fixed_ip['ip_address']

            network_details = self.core_plugin.get_network(
                ctx,
                os_port['network_id'])
            if network_details['shared']:
                _vsdclient.create_usergroup(
                    os_port['tenant_id'],
                    subnet_mapping['net_partition_id'])

            np_name = _vsdclient.get_net_partition_name_by_id(
                subnet_mapping['net_partition_id'])

            data = {
                'id': os_port['id'],
                'mac': os_port['mac_address'],
                'ipv4': ips[4],
                'ipv6': ips[6],
                'net_partition_id': subnet_mapping['net_partition_id'],
                'net_partition_name': np_name,
                'nuage_subnet_id': subnet_mapping.get('nuage_subnet_id')
            }
            nuage_subnet, _ = self.plugin_driver._get_nuage_subnet(
                subnet_mapping['nuage_subnet_id'], subnet_db=subnet_mapping)
            # TODO(gridinv): should we handle shared network resources
            if nuage_subnet['type'] == p_consts.L2DOMAIN:
                shared_resource_id = nuage_subnet.get(
                    'associatedSharedNetworkResourceID')
                if not subnets[4].get('enable_dhcp'):
                    data['ipv4'] = None
                    data['ipv6'] = None
                elif ((not nuage_subnet['DHCPManaged']) and
                      (not shared_resource_id)):
                    data['ipv4'] = None
                    data['ipv6'] = None
            try:
                _vsdclient.add_subport(trunk_id, port, data)
            except Exception as ex:
                LOG.error("Failed to create subport: %s", ex)
                self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)
        updated_ports = self._update_subport_bindings(ctx,
                                                      trunk_id,
                                                      subports)
        if len(subports) != len(updated_ports[trunk_id]):
            LOG.error("Updated: %(up)s, subports: %(sub)s",
                      {'up': len(updated_ports[trunk_id]),
                       'sub': len(subports)})
            self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)

    def _unset_sub_ports(self, trunk_id, trunk_port, subports):
        _vsdclient = self.plugin_driver.vsdclient
        ctx = n_ctx.get_admin_context()

        trunk_host = trunk_port.get(portbindings.HOST_ID)
        trunk_target_state = (t_consts.ACTIVE_STATUS if trunk_host else
                              t_consts.DOWN_STATUS)

        updated_ports = []
        for port in subports:
            LOG.debug('unset port id : %(id)s', {'id': port.port_id})
            try:
                updated_port = self.core_plugin.update_port(
                    ctx, port.port_id,
                    {'port': {portbindings.HOST_ID: None,
                              portbindings.PROFILE: None,
                              'device_owner': '',
                              'device_id': ''}})
                vif_type = updated_port.get(portbindings.VIF_TYPE)
                if vif_type != portbindings.VIF_TYPE_UNBOUND:
                    raise t_exc.SubPortBindingError(port_id=port.port_id,
                                                    trunk_id=trunk_id)
                updated_ports.append(updated_port)
                subnet_mapping = db.get_subnet_l2dom_by_port_id(ctx.session,
                                                                port.port_id)
                _vsdclient.remove_subport(updated_port, subnet_mapping)
            except t_exc.SubPortBindingError as e:
                LOG.error("Failed to clear binding for subport: %s", e)
                self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)
            except Exception as e:
                LOG.error("Failed to clear binding for subport: %s", e)
        if len(subports) != len(updated_ports):
            self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)
        else:
            self.set_trunk_status(ctx, trunk_id, trunk_target_state)

    def _set_trunk(self, trunk):
        _vsdclient = self.plugin_driver.vsdclient
        ctx = n_ctx.get_admin_context()
        try:
            subnet_mapping = db.get_subnet_l2dom_by_port_id(ctx.session,
                                                            trunk.port_id)
            _vsdclient.create_trunk(trunk, subnet_mapping)
        except Exception as ex:
            LOG.error("Failed to create trunk: %s", ex)
            trunk.update(status=t_consts.ERROR_STATUS)
            raise t_exc.TrunkInErrorState(trunk_id=trunk.id)

    def _unset_trunk(self, trunk):
        _vsdclient = self.plugin_driver.vsdclient
        ctx = n_ctx.get_admin_context()
        try:
            subnet_mapping = db.get_subnet_l2dom_by_port_id(ctx.session,
                                                            trunk.port_id)
            _vsdclient.delete_trunk(trunk, subnet_mapping)
        except Exception as ex:
            LOG.error("Failed to delete trunk: %s", ex)
            trunk.update(status=t_consts.ERROR_STATUS)
            raise t_exc.TrunkInErrorState(trunk_id=trunk.id)

    def trunk_created(self, trunk):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        LOG.debug('trunk_created callback: %(trunk)s', {'trunk': trunk})
        self._set_trunk(trunk)
        if trunk.sub_ports:
            self._set_sub_ports(trunk.id, trunk.sub_ports)

    def trunk_deleted(self, trunk):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        LOG.debug('trunk_deleted callback: %(trunk)s', {'trunk': trunk})
        self._unset_sub_ports(trunk.id, trunk_port, trunk.sub_ports)
        self._unset_trunk(trunk)

    def subports_pre_create(self, context, trunk, subports):
        LOG.debug('subport_pre_create: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        ctx = n_ctx.get_admin_context()
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        trunk_subports = self._validate_subports_vlan(context, trunk)
        self._validate_subports_not_trunk_net(trunk_port, trunk_subports)
        self._validate_same_netpartition(context, trunk_port,
                                         trunk_subports)
        self._validate_subports_vnic_type(context, trunk,
                                          trunk_port, subports)

    def subports_added(self, trunk, subports):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        LOG.debug('subport_added callback: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._set_sub_ports(trunk.id, subports)

    def subports_deleted(self, trunk, subports):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        LOG.debug('subport_deleted callback: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._unset_sub_ports(trunk.id, trunk_port, subports)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

    def trunk_validate(self, resource, event, trunk_plugin, payload):
        ctx = n_ctx.get_admin_context()
        trunk = payload.current_trunk
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if not self.plugin_driver.is_port_supported(trunk_port):
            return
        self._validate_port_fixedip(trunk_port)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.PRECOMMIT_CREATE:
            self.subports_pre_create(payload.context,
                                     payload.original_trunk,
                                     payload.subports)
        if event == events.AFTER_CREATE:
            self.subports_added(payload.original_trunk,
                                payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(payload.original_trunk,
                                  payload.subports)


class NuageTrunkDriver(trunk_base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return (p_consts.NUAGE_ML2_DRIVER_NAME in
                    cfg.CONF.ml2.mechanism_drivers)
        except cfg.NoSuchOptError:
            return False

    @registry.receives(t_consts.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, **kwargs):
        super(NuageTrunkDriver, self).register(
            resource, event, trigger, **kwargs)
        self._handler = NuageTrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               t_consts.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               t_consts.SUBPORTS,
                               event)
        registry.subscribe(self._handler.trunk_validate,
                           t_consts.TRUNK,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self._handler._trunk_status_change,
                           resources.PORT,
                           events.AFTER_UPDATE)
        registry.subscribe(self._handler.subport_event,
                           t_consts.SUBPORTS,
                           events.PRECOMMIT_CREATE)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(p_consts.NUAGE_ML2_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=False)
