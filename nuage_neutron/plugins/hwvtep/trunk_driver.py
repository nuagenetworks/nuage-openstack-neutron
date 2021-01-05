# Copyright 2021 Nokia.
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
from oslo_config import cfg
from oslo_log import log as logging

from nuage_neutron.plugins.common import constants as p_consts
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb as db

LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    t_consts.VLAN,
)


class NuageHwvtepTrunkHandler(object):

    _core_plugin = None

    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @staticmethod
    def set_trunk_status(context, trunk_id, status):
        with db_api.autonested_transaction(context.session):
            trunk = trunk_objects.Trunk.get_object(context, id=trunk_id)
            if trunk:
                trunk.update(status=status)

    def trunk_status_change(self, resource, event, trigger, **kwargs):
        updated_port = kwargs['port']
        trunk_details = updated_port.get('trunk_details')
        # If no trunk details port is not parent of a trunk
        if not trunk_details:
            return
        if (updated_port.get(portbindings.VNIC_TYPE) not in
                self.plugin_driver.get_supported_vnic_types()):
            LOG.debug("Ignoring trunk status change for port"
                      " %s due to unsupported VNIC type",
                      updated_port.get('id'))
            return

        context = kwargs['context']
        if trunk_details.get('trunk_id'):
            trunk = trunk_objects.Trunk.get_object(
                context, id=trunk_details.get('trunk_id'))
            if trunk:
                self.wire_trunk(context, trunk)
                return

    def wire_trunk(self, context, trunk):
        self._update_subport_bindings(context, trunk.id, trunk.sub_ports)

    def _update_subport_bindings(self, context, trunk_id, subports):
        el = context.elevated()
        trunk = trunk_objects.Trunk.get_object(el, id=trunk_id)
        self._process_binding(el, trunk, subports)

    def _process_binding(self, context, trunk, subports):
        updated_ports = []
        trunk_port_id = trunk.port_id
        trunk_port = self.core_plugin.get_port(context, trunk_port_id)
        trunk_host = trunk_port.get(portbindings.HOST_ID)
        trunk.update(status=t_consts.BUILD_STATUS)
        trunk_target_state = (t_consts.ACTIVE_STATUS if trunk_host else
                              t_consts.DOWN_STATUS)

        for port in subports:
            try:
                updated_port = self.core_plugin.update_port(
                    context, port.port_id,
                    {'port': {portbindings.HOST_ID: trunk_host,
                              'device_owner': t_consts.TRUNK_SUBPORT_OWNER}})
                vif_type = updated_port.get(portbindings.VIF_TYPE)
                if vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
                    raise t_exc.SubPortBindingError(port_id=port.port_id,
                                                    trunk_id=trunk.id)
                updated_ports.append(updated_port)
            except t_exc.SubPortBindingError as e:
                LOG.error("Failed to bind subport: %s", e)
            except Exception as e:
                LOG.error("Failed to bind subport: %s", e)
        if len(subports) != len(updated_ports):
            LOG.debug("Trunk: %s is degraded", trunk.id)
            trunk.update(status=t_consts.DEGRADED_STATUS)
        else:
            trunk.update(status=trunk_target_state)

    @staticmethod
    def _validate_port_fixedip(port):
        if not port.get('fixed_ips'):
            msg = ("Port %s requires a FixedIP in order to be used" %
                   port.get('id'))
            raise nuage_exc.NuageBadRequest(msg=msg)

    @staticmethod
    def _validate_same_netpartition(context,
                                    trunk_port, trunk_subports):

        parent_netpart = db.get_subnet_l2dom_by_port_id(
            context.session,
            trunk_port['id']).get('net_partition_id')
        bad_subport = next((port for port in trunk_subports
                            if db.get_subnet_l2dom_by_port_id(
                                context.session,
                                port.port_id).get('net_partition_id') !=
                            parent_netpart), None)
        if bad_subport:
            raise nuage_exc.SubPortNetpartitionConflict(
                subport=bad_subport.port_id)

    @staticmethod
    def _validate_subports_vnic_type(context, trunk, trunk_port,
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
        ctx = n_ctx.get_admin_context()
        LOG.debug("updating subport bindings for trunk %s", trunk_id)
        self._update_subport_bindings(ctx, trunk_id, subports)

    def _unset_sub_ports(self, trunk_id, trunk_port, subports):
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
            except t_exc.SubPortBindingError as e:
                LOG.error("Failed to clear binding for subport: %s", e)
            except Exception as e:
                LOG.error("Failed to clear binding for subport: %s", e)
        if len(subports) != len(updated_ports):
            self.set_trunk_status(ctx, trunk_id, t_consts.DEGRADED_STATUS)
        else:
            self.set_trunk_status(ctx, trunk_id, trunk_target_state)

    def trunk_created(self, trunk):
        LOG.debug('trunk_created: %(trunk)s', {'trunk': trunk})
        if trunk.sub_ports:
            self._set_sub_ports(trunk.id, trunk.sub_ports)

    def trunk_deleted(self, trunk, trunk_port):
        LOG.debug('trunk_deleted: %(trunk)s', {'trunk': trunk})
        self._unset_sub_ports(trunk.id, trunk_port, trunk.sub_ports)

    def subports_pre_create(self, context, trunk, trunk_port, subports):
        LOG.debug('subport_pre_create: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._validate_subports_vnic_type(context, trunk,
                                          trunk_port, subports)
        self._validate_same_netpartition(context, trunk_port,
                                         subports)
        for sp in subports:
            self._validate_port_fixedip(
                self.core_plugin.get_port(context, sp.port_id))

    def trunk_pre_create(self, context, trunk, trunk_port):
        self._validate_port_fixedip(trunk_port)
        if trunk.sub_ports:
            self.subports_pre_create(context, trunk,
                                     trunk_port, trunk.sub_ports)

    def subports_added(self, trunk, subports):
        LOG.debug('subport_added: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._set_sub_ports(trunk.id, subports)

    def subports_deleted(self, trunk, trunk_port, subports):
        LOG.debug('subport_deleted: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._unset_sub_ports(trunk.id, trunk_port, subports)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        ctx = n_ctx.get_admin_context()
        trunk = (payload.original_trunk if event == events.AFTER_DELETE else
                 payload.current_trunk)
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) not in
                self.plugin_driver.get_supported_vnic_types()):
            return
        if event == events.PRECOMMIT_CREATE:
            self.trunk_pre_create(payload.context, trunk, trunk_port)
        elif event == events.AFTER_CREATE:
            self.trunk_created(trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(trunk, trunk_port)

    def subport_event(self, resource, event, trunk_plugin, payload):
        ctx = n_ctx.get_admin_context()
        trunk = payload.original_trunk
        trunk_port = self.core_plugin.get_port(ctx, trunk.port_id)
        if (trunk_port.get(portbindings.VNIC_TYPE) not in
                self.plugin_driver.get_supported_vnic_types()):
            return
        if event == events.PRECOMMIT_CREATE:
            self.subports_pre_create(payload.context,
                                     trunk,
                                     trunk_port,
                                     payload.subports)
        if event == events.AFTER_CREATE:
            self.subports_added(trunk,
                                payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(trunk,
                                  trunk_port,
                                  payload.subports)


class NuageHwvtepTrunkDriver(trunk_base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return (p_consts.NUAGE_ML2_HWVTEP_DRIVER_NAME in
                    cfg.CONF.ml2.mechanism_drivers)
        except cfg.NoSuchOptError:
            return False

    @registry.receives(t_consts.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, **kwargs):
        super(NuageHwvtepTrunkDriver, self).register(
            resource, event, trigger, **kwargs)
        self._handler = NuageHwvtepTrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               t_consts.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               t_consts.SUBPORTS,
                               event)
        registry.subscribe(self._handler.trunk_status_change,
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
        return cls(p_consts.NUAGE_ML2_HWVTEP_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)
