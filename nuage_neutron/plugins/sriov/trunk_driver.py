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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import api as db_api
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import constants as t_consts
from neutron.services.trunk.drivers import base as trunk_base
from neutron.services.trunk import exceptions as t_exc
from neutron_lib.api.definitions import portbindings
from neutron_lib import context as n_ctx
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import constants as p_consts
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb as db
from nuage_neutron.plugins.common import trunk_db

LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_HW_VEB,
    portbindings.VIF_TYPE_HOSTDEV_PHY,
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

        context = kwargs['context']
        if trunk_details.get('trunk_id'):
            trunk = trunk_objects.Trunk.get_object(
                context, id=trunk_details.get('trunk_id'))
            if trunk:
                self.wire_trunk(context, trunk)
                return

    def wire_trunk(self, context, trunk):
        updated_ports = self._update_subport_bindings(context,
                                                      trunk.id,
                                                      trunk.sub_ports)
        if len(trunk.sub_ports) != len(updated_ports[trunk.id]):
            LOG.error("Failed to update some of the trunk subports "
                      "updated: %(up)s, subports: %(sub)s",
                      {'up': len(updated_ports[trunk.id]),
                       'sub': len(trunk.sub_ports)})
            self.set_trunk_status(context, trunk.id, t_consts.DEGRADED_STATUS)

    def _update_subport_bindings(self, context, trunk_id, subports):
        el = context.elevated()
        ports_by_trunk_id = collections.defaultdict(list)
        updated_ports = collections.defaultdict(list)
        for s in subports:
            ports_by_trunk_id[s['trunk_id']].append(s)
        for trunk_id, subports in ports_by_trunk_id.items():
            trunk = trunk_objects.Trunk.get_object(el, id=trunk_id)
            if not trunk:
                LOG.debug("Trunk not found. id : %s", trunk_id)
                continue
            trunk_updated_ports = self._process_binding(el,
                                                        trunk,
                                                        subports)
            updated_ports[trunk_id].extend(trunk_updated_ports)
        return updated_ports

    def _process_binding(self, context, trunk, subports):
        updated_ports = []
        trunk_port_id = trunk.port_id
        trunk_port = self.core_plugin.get_port(context, trunk_port_id)
        trunk_host = trunk_port.get(portbindings.HOST_ID)
        trunk_profile = trunk_port.get(portbindings.PROFILE)
        trunk.update(status=t_consts.BUILD_STATUS)
        trunk_target_state = (t_consts.ACTIVE_STATUS if trunk_profile else
                              t_consts.DOWN_STATUS)

        for port in subports:
            try:
                if trunk_profile:
                    trunk_profile['vlan'] = port.segmentation_id
                updated_port = self.core_plugin.update_port(
                    context, port.port_id,
                    {'port': {portbindings.HOST_ID: trunk_host,
                              portbindings.PROFILE: trunk_profile,
                              'device_owner': t_consts.TRUNK_SUBPORT_OWNER}})
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

    def _validate_subports_vlan(self, context, trunk):
        """Validates if a vlan only used by a single subnet within a physnet"""
        LOG.debug("validating vlans in trunk %s", trunk['id'])
        context = context.elevated()

        all_subports_in_physnet = trunk_db.get_vlan_subports_of_trunk_physnet(
            context.session,
            trunk.id)
        subnets_per_vlan = collections.defaultdict(set)
        vlans_per_subnet = collections.defaultdict(set)
        all_subports_in_trunk = []
        for port in all_subports_in_physnet:
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnets_per_vlan[port.sub_port.segmentation_id].add(
                subnet_id)
            vlans_per_subnet[subnet_id].add(
                port.sub_port.segmentation_id)
            if port.sub_port.trunk_id == trunk['id']:
                all_subports_in_trunk.append(port)

        bad_vlan = next((vlan for vlan, subnets in subnets_per_vlan.items()
                         if len(subnets) > 1), None)
        if bad_vlan:
            raise nuage_exc.UniqueSubnetConflict(
                subnets=subnets_per_vlan[bad_vlan],
                vlan=bad_vlan)
        bad_subnet = next((subnet for subnet, vlans in vlans_per_subnet.items()
                           if len(vlans) > 1), None)
        if bad_subnet:
            raise nuage_exc.UniqueVlanConflict(
                subnet=bad_subnet,
                vlans=vlans_per_subnet[bad_subnet]
            )

        return all_subports_in_trunk

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

    def _validate_subports_not_trunk_net(self, trunk_port, trunk_subports):
        """Validates if a subport is not in the trunk network"""
        bad_port = next((port for port in trunk_subports
                         if port.network_id == trunk_port['network_id']), None)
        if bad_port:
            raise nuage_exc.SubPortParentPortConflict(subport=bad_port.id)

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

    def _validate_vlan_allocated_by_net(self, context, trunk, subports):
        LOG.debug("validating vlan allocations in physnet for %(sub)s added "
                  "subports in trunk %(trunk)s",
                  {'sub': len(subports), 'trunk': trunk.id})
        segments = trunk_db.get_segment_allocation_of_subports(
            context.session,
            subports)
        if segments:
            for subport in subports:
                segment = next((segment for segment in segments if
                                segment.segmentation_id ==
                                subport.segmentation_id), None)
                if not segment:
                    continue
                port = self.core_plugin.get_port(context, subport.port_id)
                if segment.network_id != port.get('network_id'):
                    raise nuage_exc.VlanIdInUseByNetwork(
                        vlan=segment.segmentation_id,
                        network=segment.network_id,
                        physnet=segment.physical_network)

    def _validate_vlan_in_net(self, context, subports):
        LOG.debug("validating subport in vlan net uses vlan id of net "
                  "for %(sub)s added subports in trunk",
                  {'sub': len(subports)})
        bad_subport = next((subport for subport in subports if
                            trunk_db.get_subports_in_conflict_with_net(
                                context.session,
                                subports)
                            ), None)
        if bad_subport:
            raise nuage_exc.SubPortNetConflict(subport=bad_subport)

    def _set_sub_ports(self, trunk_id, subports):
        ctx = n_ctx.get_admin_context()
        LOG.debug("updating subport bindings for trunk %s", trunk_id)
        updated_ports = self._update_subport_bindings(ctx,
                                                      trunk_id,
                                                      subports)
        if len(subports) != len(updated_ports[trunk_id]):
            LOG.error("Failed to update some of the trunk subports "
                      "updated: %(up)s, subports: %(sub)s",
                      {'up': len(updated_ports[trunk_id]),
                       'sub': len(subports)})
            self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)

    def _unset_sub_ports(self, trunk_id, subports):
        ctx = n_ctx.get_admin_context()
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
            except t_exc.SubPortBindingError as e:
                LOG.error("Failed to clear binding for subport: %s", e)
                self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)
            except Exception as e:
                LOG.error("Failed to clear binding for subport: %s", e)
        if len(subports) != len(updated_ports):
            self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)

    def trunk_created(self, trunk):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) in
                self.plugin_driver._supported_vnic_types()):
            LOG.debug('trunk_created: %(trunk)s', {'trunk': trunk})
            self._set_sub_ports(trunk.id, trunk.sub_ports)

    def trunk_deleted(self, trunk):
        ctx = n_ctx.get_admin_context()
        # handle trunk with parent port supported by
        # mech driver only
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) in
                self.plugin_driver._supported_vnic_types()):
            LOG.debug('trunk_deleted: %(trunk)s', {'trunk': trunk})
            self._unset_sub_ports(trunk.id, trunk.sub_ports)

    def subports_pre_create(self, context, trunk, subports):
        LOG.debug('subport_pre_create: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        ctx = n_ctx.get_admin_context()
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) in
                self.plugin_driver._supported_vnic_types()):
            self._validate_subports_vnic_type(context, trunk,
                                              trunk_port, subports)
            self._validate_vlan_in_net(context, subports)
            self._validate_vlan_allocated_by_net(context, trunk, subports)
            trunk_subports = self._validate_subports_vlan(context, trunk)
            self._validate_subports_not_trunk_net(trunk_port, trunk_subports)
            self._validate_same_netpartition(context, trunk_port,
                                             trunk_subports)

    def trunk_pre_create(self, context, trunk):
        if trunk.sub_ports:
            self.subports_pre_create(context, trunk, trunk.sub_ports)

    def subports_added(self, trunk, subports):
        LOG.debug('subport_added: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        ctx = n_ctx.get_admin_context()
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) in
                self.plugin_driver._supported_vnic_types()):
            self._set_sub_ports(trunk.id, subports)

    def subports_deleted(self, trunk, subports):
        LOG.debug('subport_deleted: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        ctx = n_ctx.get_admin_context()
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) in
                self.plugin_driver._supported_vnic_types()):
            self._unset_sub_ports(trunk.id, subports)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.PRECOMMIT_CREATE:
            self.trunk_pre_create(payload.context, payload.current_trunk)
        elif event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

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
            return (p_consts.NUAGE_ML2_SRIOV_DRIVER_NAME in
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
        registry.subscribe(self._handler._trunk_status_change,
                           resources.PORT,
                           events.AFTER_UPDATE)
        registry.subscribe(self._handler.subport_event,
                           t_consts.SUBPORTS,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self._handler.trunk_event,
                           t_consts.TRUNK,
                           events.PRECOMMIT_CREATE)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(p_consts.NUAGE_ML2_SRIOV_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)
