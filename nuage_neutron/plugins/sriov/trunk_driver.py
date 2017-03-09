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
from neutron import context as n_ctx
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron import manager
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import constants as t_consts
from neutron.services.trunk.drivers import base as trunk_base
from neutron.services.trunk import exceptions as t_exc

from nuage_neutron.plugins.common import constants as p_consts

LOG = logging.getLogger(__name__)

# TODO(gridinv): in ocata defines finally moved
# to portbindings
VIF_TYPE_HW_VEB = 'hw_veb'
VIF_TYPE_HOSTDEV_PHY = 'hostdev_physical'

SUPPORTED_INTERFACES = (
    VIF_TYPE_HW_VEB,
    VIF_TYPE_HOSTDEV_PHY,
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
            self._core_plugin = manager.NeutronManager.get_plugin()
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
            LOG.error("Updated: %(up)s, subports: %(sub)s",
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

    def _set_sub_ports(self, trunk_id, subports):
        ctx = n_ctx.get_admin_context()
        LOG.debug("updating subport bindings for trunk %s", trunk_id)
        updated_ports = self._update_subport_bindings(ctx,
                                                      trunk_id,
                                                      subports)
        if len(subports) != len(updated_ports):
            LOG.error("Updated: %(up)s, subports: %(sub)s",
                      {'up': len(updated_ports), 'sub': len(subports)})
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
        LOG.debug('trunk_created: %(trunk)s', {'trunk': trunk})
        self._set_sub_ports(trunk.id, trunk.sub_ports)

    def trunk_deleted(self, trunk):
        LOG.debug('trunk_deleted: %(trunk)s', {'trunk': trunk})
        self._unset_sub_ports(trunk.id, trunk.sub_ports)

    def subports_added(self, trunk, subports):
        LOG.debug('subport_added: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._set_sub_ports(trunk.id, subports)

    def subports_deleted(self, trunk, subports):
        LOG.debug('subport_deleted: %(trunk)s subports : %(sp)s',
                  {'trunk': trunk, 'sp': subports})
        self._unset_sub_ports(trunk.id, subports)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
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

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(p_consts.NUAGE_ML2_SRIOV_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)
