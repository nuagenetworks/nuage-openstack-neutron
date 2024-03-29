# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron_lib.db import model_query as lib_model_query
from neutron_lib.db import utils as lib_db_utils

from oslo_db.sqlalchemy import utils as sa_utils
from oslo_utils import uuidutils
import six
from sqlalchemy.orm import exc as sql_exc
from sqlalchemy import sql

from nuage_neutron.plugins.common.extensions import net_topology as _ext
from nuage_neutron.plugins.common import nuage_models


def get_switchport_by_host_slot(context, record_dict):
    """Get switchport that matches the supplied host_id and pci_slot."""
    try:
        query = context.session.query(nuage_models.NuageSwitchportMapping)
        gateway_port = query.filter_by(
            host_id=record_dict['host_id'],
            pci_slot=record_dict['pci_slot']).one()
    except sql_exc.NoResultFound:
        return None
    return gateway_port


def get_switchports_by_host_bridge(context, host_id, bridge):
    """Get switchports that matches the supplied host_id and bridge."""
    query = context.session.query(nuage_models.NuageSwitchportMapping)
    return query.filter_by(
        host_id=host_id,
        bridge=bridge).all()


def get_switchport_bindings_by_switchport_vlan(context,
                                               switchport_uuid,
                                               segmentation_id):
    """Get switch port bindings that matches seg_id and switchport"""
    query = context.session.query(nuage_models.NuageSwitchportBinding)
    return query.filter_by(switchport_uuid=switchport_uuid,
                           segmentation_id=segmentation_id).all()


def get_switchport_bindings_by_switchport(context, switchport_uuid):
    """Get switch port bindings that matches seg_id and switchport"""
    query = context.session.query(nuage_models.NuageSwitchportBinding)
    return query.filter_by(switchport_uuid=switchport_uuid).all()


def get_switchport_bindings_by_switchport_mapping(context,
                                                  switchport_mapping_id):
    """Get switch port bindings that matches id of nuage_switchport_mapping"""
    query = context.session.query(nuage_models.NuageSwitchportBinding)
    return query.filter_by(switchport_mapping_id=switchport_mapping_id).all()


def get_switchport_binding_by_neutron_port(context,
                                           port_id,
                                           segmentation_id=None):
    """Get switch port binding that matches neutron port """
    query = (
        context.session.query(nuage_models.NuageSwitchportBinding)
        .filter_by(neutron_port_id=port_id)
    )
    if segmentation_id:
        query = query.filter_by(segmentation_id=segmentation_id)
    return query.all()


def add_switchport_binding(context, binding):
    """Add switch port to neutron net mapping."""
    session = context.session
    with session.begin(subtransactions=True):
        port_map = nuage_models.NuageSwitchportBinding(
            id=uuidutils.generate_uuid(),
            neutron_port_id=binding['neutron_port_id'],
            nuage_vport_id=binding['nuage_vport_id'],
            switchport_uuid=binding['switchport_uuid'],
            segmentation_id=binding['segmentation_id'],
            switchport_mapping_id=binding['switchport_mapping_id']
            )
        session.add(port_map)


def delete_switchport_binding(context, neutron_port_id, segmentation_id=None):
    """Delete mappings that matches neutron_port_id."""
    session = context.session
    with session.begin(subtransactions=True):
        if neutron_port_id:
            query = (
                session.query(nuage_models.NuageSwitchportBinding).filter_by(
                    neutron_port_id=neutron_port_id)
            )
            if segmentation_id:
                query = query.filter_by(segmentation_id=segmentation_id)
            query.delete()


class NuageGwPortMappingDbMixin(_ext.NuageNetTopologyPluginBase):
    """Mixin class to add switchport mapping."""

    __native_bulk_support = False

    def _ensure_switchport_mapping_not_in_use(self, context, id, mapping=None):
        switchport = self._get_switchport_mapping(context, id)
        bindings = get_switchport_bindings_by_switchport_mapping(
            context,
            switchport.get('id'))
        if bindings:
            if (mapping and
                    switchport.get('switch_id') == mapping.get('switch_id') and
                    switchport.get('port_id') == mapping.get('port_id')):
                return switchport
            raise _ext.SwitchportInUse(id=id)
        return switchport

    @staticmethod
    def _make_switchport_mapping_dict(gw_map_db, fields=None):
        res = {'id': gw_map_db['id'],
               'switch_info': gw_map_db['switch_info'],
               'switch_id': gw_map_db['switch_id'],
               'port_id': gw_map_db['port_id'],
               'port_uuid': gw_map_db['port_uuid'],
               'redundant_port_uuid': gw_map_db['redundant_port_uuid'],
               'pci_slot': gw_map_db['pci_slot'],
               'bridge': gw_map_db['bridge'],
               'host_id': gw_map_db['host_id']
               }
        return lib_db_utils.resource_fields(res, fields)

    @staticmethod
    def _get_switchport_mapping(context, resource_id):
        try:
            gw_map_db = lib_model_query.get_by_id(
                context,
                nuage_models.NuageSwitchportMapping,
                resource_id)
        except sql_exc.NoResultFound:
            raise _ext.SwitchportNotFound(id=resource_id)
        return gw_map_db

    @staticmethod
    def _get_switchport_binding(context, resource_id):
        try:
            gw_bind_db = lib_model_query.get_by_id(
                context,
                nuage_models.NuageSwitchportBinding, resource_id)
            query = context.session.query(
                nuage_models.NuageSwitchportMapping.switch_id,
                nuage_models.NuageSwitchportMapping.port_id)
            query = query.filter(
                nuage_models.NuageSwitchportMapping.port_uuid ==
                gw_bind_db['switchport_uuid']).distinct()
            switch, port = query.one()
            gw_bind_db['port_id'] = port
            gw_bind_db['switch_id'] = switch

        except sql_exc.NoResultFound:
            raise _ext.SwitchportBindingNotFound(id=resource_id)
        return gw_bind_db

    @staticmethod
    def _make_switchport_binding_dict(gw_bind_db, fields=None):
        res = {'id': gw_bind_db['id'],
               'neutron_port_id': gw_bind_db['neutron_port_id'],
               'switch_id': gw_bind_db.get('switch_id'),
               'port_id': gw_bind_db.get('port_id'),
               'port_uuid': gw_bind_db['switchport_uuid'],
               'nuage_vport_id': gw_bind_db['nuage_vport_id'],
               'segmentation_id': gw_bind_db['segmentation_id']
               }
        return lib_db_utils.resource_fields(res, fields)

    @staticmethod
    def _make_switchport_binding_dict_from_tuple(binding, fields=None):
        gw_bind_db = binding[0]
        res = {'id': gw_bind_db['id'],
               'neutron_port_id': gw_bind_db['neutron_port_id'],
               'switch_id': binding[1],
               'port_id': binding[2],
               'port_uuid': gw_bind_db['switchport_uuid'],
               'nuage_vport_id': gw_bind_db['nuage_vport_id'],
               'segmentation_id': gw_bind_db['segmentation_id']
               }
        return lib_db_utils.resource_fields(res, fields)

    @staticmethod
    def _validate_host_pci(context, switchport_mapping):
        port_map = get_switchport_by_host_slot(context, switchport_mapping)
        if port_map:
            raise _ext.SwitchportParamDuplicate(
                param_name='pci_slot',
                param_value=switchport_mapping['pci_slot'])

    def create_switchport_mapping(self, context, switchport_mapping):
        s = switchport_mapping['switchport_mapping']
        self._validate_host_pci(context, s)
        with context.session.begin(subtransactions=True):
            gw_map_db = nuage_models.NuageSwitchportMapping(
                id=uuidutils.generate_uuid(),
                switch_info=s['switch_info'],
                switch_id=s['switch_id'],
                port_id=s['port_id'],
                port_uuid=s['port_uuid'],
                redundant_port_uuid=s['redundant_port_uuid'],
                pci_slot=s['pci_slot'],
                bridge=s['bridge'],
                host_id=s['host_id'])
            context.session.add(gw_map_db)
        return self._make_switchport_mapping_dict(gw_map_db)

    def delete_switchport_mapping(self, context, id):
        gw_map = self._ensure_switchport_mapping_not_in_use(context, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(gw_map)

    def get_switchport_mappings(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        marker_obj = lib_db_utils.get_marker_obj(self, context,
                                                 'switchport_mappings',
                                                 limit, marker)
        return lib_model_query.get_collection(
            context,
            nuage_models.NuageSwitchportMapping,
            self._make_switchport_mapping_dict,
            filters=filters, fields=fields,
            sorts=sorts, limit=limit, marker_obj=marker_obj,
            page_reverse=page_reverse)

    def get_switchport_mapping(self, context, id, fields=None):
        gw_map = self._get_switchport_mapping(context, id)
        return self._make_switchport_mapping_dict(gw_map, fields)

    def update_switchport_mapping(self, context, id, switchport_mapping):
        s = switchport_mapping['switchport_mapping']
        gw_map_db = self._ensure_switchport_mapping_not_in_use(context, id, s)
        with context.session.begin(subtransactions=True):
            if s:
                gw_map_db.update(s)
        context.session.refresh(gw_map_db)
        return self._make_switchport_mapping_dict(gw_map_db)

    def get_switchport_bindings(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        query = context.session.query(
            nuage_models.NuageSwitchportBinding,
            nuage_models.NuageSwitchportMapping.switch_id,
            nuage_models.NuageSwitchportMapping.port_id)
        query = query.outerjoin(
            nuage_models.NuageSwitchportMapping,
            nuage_models.NuageSwitchportMapping.port_uuid ==
            nuage_models.NuageSwitchportBinding.switchport_uuid)
        query = query.distinct()

        if filters:
            for key, value in six.iteritems(filters):
                column = getattr(
                    nuage_models.NuageSwitchportBinding, key, None)
                if column is None:
                    column = getattr(
                        nuage_models.NuageSwitchportMapping, key, None)
                if column is not None:
                    if not value:
                        query = query.filter(sql.false())
                    else:
                        query = query.filter(column.in_(value))

        if sorts:
            marker_obj = lib_db_utils.get_marker_obj(self, context,
                                                     'switchport_bindings',
                                                     limit, marker)
            sort_dirs = ['asc' if s[1] else 'desc' for s in sorts]
            query = sa_utils.paginate_query(
                query,
                nuage_models.NuageSwitchportBinding,
                limit,
                marker=marker_obj,
                sort_keys=sorts,
                sort_dirs=sort_dirs)
        items = [self._make_switchport_binding_dict_from_tuple(c, fields)
                 for c in query]
        if limit and page_reverse:
            items.reverse()
        return items

    def get_switchport_binding(self, context, id, fields=None):
        gw_binding = self._get_switchport_binding(context, id)
        return self._make_switchport_binding_dict(gw_binding, fields)
