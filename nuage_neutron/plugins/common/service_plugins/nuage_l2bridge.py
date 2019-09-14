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
from neutron._i18n import _
from neutron.db.models.plugins.ml2.vlanallocation import VlanAllocation
from neutron_lib import constants as lib_constants
from neutron_lib.db import model_query as lib_model_query
from neutron_lib.db import utils as lib_db_utils

from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import nuage_models
from nuage_neutron.plugins.common import nuagedb


class NuageL2BridgePlugin(BaseNuagePlugin):

    supported_extension_aliases = ['nuage-l2bridge']
    supported_segmentation_types = ['vlan']

    def __init__(self):
        super(NuageL2BridgePlugin, self).__init__()

    def get_plugin_type(self):
        return constants.NUAGE_L2BRIDGE_SERVICE_PLUGIN

    def get_plugin_description(self):
        return "Nuage Neutron L2Bridge Service plugin"

    def get_nuage_l2bridges(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        marker_obj = lib_db_utils.get_marker_obj(self, context,
                                                 'nuage_l2bridges',
                                                 limit, marker)
        l2bridges = lib_model_query.get_collection(
            context,
            nuage_models.NuageL2bridge,
            self._make_l2bridges_dict,
            filters=filters, fields=fields,
            sorts=sorts,
            limit=limit, marker_obj=marker_obj,
            page_reverse=page_reverse)
        if not fields or 'physnets' in fields:
            for l2bridge in l2bridges:
                physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                    context.session,
                    l2bridge_id=l2bridge['id'])
                l2bridge['physnets'] = self._make_physnet_mapping_dict(
                    physnets)
        if not fields or 'networks' in fields:
            for l2bridge in l2bridges:
                networks = nuagedb.get_networks_for_nuage_l2bridge(
                    context.session, l2bridge['id'])
                networks = [n['id'] for n in networks]
                l2bridge['networks'] = networks
        return l2bridges

    def get_nuage_l2bridge(self, context, nuage_l2bridge_id, fields=None):
        bridge = nuagedb.get_nuage_l2bridge(context.session,
                                            l2bridge_id=nuage_l2bridge_id)
        if not bridge:
            raise exceptions.NuageNotFound(resource='nuage_l2bridge',
                                           resource_id=nuage_l2bridge_id)
        bridge = self._make_l2bridges_dict(bridge, fields)
        if not fields or 'physnets' in fields:
            physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                context.session,
                l2bridge_id=bridge['id'])
            bridge['physnets'] = self._make_physnet_mapping_dict(physnets)
        if not fields or 'networks' in fields:
            networks = nuagedb.get_networks_for_nuage_l2bridge(
                context.session, nuage_l2bridge_id)
            networks = [n['id'] for n in networks]
            bridge['networks'] = networks
        return bridge

    def create_nuage_l2bridge(self, context, nuage_l2bridge):
        bridge = nuage_l2bridge['nuage_l2bridge']

        db_physnets = []
        with context.session.begin(subtransactions=True):
            # lock first
            db_bridge = nuage_models.NuageL2bridge(
                name=bridge.get('name'), tenant_id=bridge.get('tenant_id'))
            context.session.add(db_bridge)
            if bridge.get('physnets') != lib_constants.ATTR_NOT_SPECIFIED:
                for physnet in bridge['physnets']:
                    self._validate_physnet(
                        context, physnet_name=physnet['physnet_name'],
                        segmentation_id=physnet['segmentation_id'],
                        segmentation_type=physnet['segmentation_type'])
                    db_physnet = nuage_models.NuageL2bridgePhysnetMapping(
                        l2bridge_id=db_bridge['id'],
                        physnet=physnet['physnet_name'],
                        segmentation_id=physnet['segmentation_id'],
                        segmentation_type=physnet['segmentation_type'])
                    context.session.add(db_physnet)
                    db_physnets.append(db_physnet)

        bridge = self._make_l2bridges_dict(db_bridge)
        bridge['physnets'] = self._make_physnet_mapping_dict(db_physnets)
        return bridge

    def update_nuage_l2bridge(self, context, l2bridge_id, nuage_l2bridge):
        nuage_l2bridge = nuage_l2bridge['nuage_l2bridge']
        with context.session.begin(subtransactions=True):
            current = nuagedb.get_nuage_l2bridge_blocking(context.session,
                                                          l2bridge_id)
            if not current:
                raise exceptions.NuageNotFound(resource='nuage_l2bridge',
                                               resource_id=l2bridge_id)
            physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                context.session,
                l2bridge_id=current['id'])
            if nuage_l2bridge.get('physnets') is not None:
                current_keyset = {(p['physnet'], p['segmentation_id'],
                                   p['segmentation_type']) for p
                                  in physnets}
                future_keyset = {(p['physnet_name'], p['segmentation_id'],
                                  p['segmentation_type'])
                                 for p in nuage_l2bridge['physnets']}
                # Check deleted physnets
                deleted = current_keyset - future_keyset
                for to_delete in deleted:
                    db_physnet = nuagedb.get_nuage_l2bridge_physnet_mappings(
                        context.session,
                        l2bridge_id=current['id'], physnet=to_delete[0],
                        segmentation_id=to_delete[1],
                        segmentation_type=to_delete[2]
                    )[0]
                    msg = _("Physical network {} with segmentation_id {} and "
                            "segmentation_type {} is currently in use. It is "
                            "not allowed to remove a physical network that is "
                            "in use from a nuage_l2bridge.")
                    self._check_physnet_not_in_use_by_network(
                        context.session, db_physnet['physnet'],
                        db_physnet['segmentation_id'],
                        db_physnet['segmentation_type'], msg=msg)
                    context.session.delete(db_physnet)
                # Check added subnets
                added = future_keyset - current_keyset
                for to_add in added:
                    self._validate_physnet(
                        context, to_add[0],
                        to_add[1], to_add[2])
                    db_physnet = nuage_models.NuageL2bridgePhysnetMapping(
                        l2bridge_id=current['id'],
                        physnet=to_add[0],
                        segmentation_id=to_add[1],
                        segmentation_type=to_add[2]
                    )
                    context.session.add(db_physnet)
                physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                    context.session, l2bridge_id=current['id'])

            if (nuage_l2bridge.get('name') and
                    current['name'] != nuage_l2bridge['name']):
                current['name'] = nuage_l2bridge['name']
                if current['nuage_subnet_id']:
                    subnet_mapping = nuagedb.get_subnet_l2doms_by_nuage_id(
                        context.session, current['nuage_subnet_id'])[0]
                    self.vsdclient.update_l2domain_template(
                        nuage_l2dom_tmplt_id=(
                            subnet_mapping["nuage_l2dom_tmplt_id"]),
                        description=nuage_l2bridge['name'])
                    self.vsdclient.update_l2domain(
                        nuage_l2dom_id=current['nuage_subnet_id'],
                        description=nuage_l2bridge['name'])
        current['physnets'] = self._make_physnet_mapping_dict(physnets)
        return current

    def delete_nuage_l2bridge(self, context, nuage_l2bridge_id):
        with context.session.begin(subtransactions=True):
            bridge = nuagedb.get_nuage_l2bridge_blocking(context.session,
                                                         nuage_l2bridge_id)
            physnets = nuagedb.get_nuage_l2bridge_physnet_mappings(
                context.session,
                l2bridge_id=bridge['id'])
            for physnet in physnets:
                msg = _("Physical network {} with segmentation_id {} and "
                        "segmentation_type {} belonging to this nuage_l2bridge"
                        " is currently in use. It is not allowed to delete "
                        "it from this nuage_l2bridge.")
                self._check_physnet_not_in_use_by_network(
                    context.session,
                    physnet['physnet'],
                    physnet['segmentation_id'],
                    physnet['segmentation_type'], msg=msg)
            context.session.delete(bridge)

    def _validate_physnet(self, context,
                          physnet_name, segmentation_id, segmentation_type):
        if segmentation_type not in self.supported_segmentation_types:
            msg = ("Segmentation_type {} not in supported types "
                   "({})").format(segmentation_type,
                                  self.supported_segmentation_types)
            raise exceptions.NuageBadRequest(msg=msg)
        msg = _("Physical network {} with segmentation_id {} and "
                "segmentation_type {} is currently in use. It is "
                "not allowed to add a physical network that is "
                "in use to this nuage_l2bridge.")
        self._check_physnet_not_in_use_by_network(
            context.session, physnet_name,
            segmentation_id, segmentation_type, msg=msg)
        self._check_physnet_not_in_use_by_l2bridge(
            context.session, physnet_name,
            segmentation_id, segmentation_type)

    @staticmethod
    def _make_physnet_mapping_dict(db_physnets):
        physnets = []
        for db_physnet in db_physnets:
            physnets.append({
                'physnet': db_physnet['physnet'],
                'segmentation_id': db_physnet['segmentation_id'],
                'segmentation_type': db_physnet['segmentation_type']
            })
        return physnets

    def _make_l2bridges_dict(self, db_l2bridge, fields=None):
        res = {'id': db_l2bridge['id'],
               'name': db_l2bridge['name'],
               'nuage_subnet_id': db_l2bridge['nuage_subnet_id'],
               'tenant_id': db_l2bridge['project_id']
               }
        return self._fields(res, fields)

    @staticmethod
    def _check_physnet_not_in_use_by_network(session, physnet_name,
                                             segmentation_id,
                                             segmentation_type, msg=None):
        if segmentation_type == 'vlan':
            vlan_alloc = session.query(VlanAllocation).filter_by(
                physical_network=physnet_name,
                vlan_id=segmentation_id,
            ).first()
            if vlan_alloc and vlan_alloc.allocated:
                msg = (msg or ("Physical network {} with segmentation_id "
                               "{} and segmentation_type {} is "
                               "currently in use.")).format(
                    physnet_name, segmentation_id, segmentation_type)
                raise exceptions.NuageBadRequest(msg=msg)

    @staticmethod
    def _check_physnet_not_in_use_by_l2bridge(session, physnet_name,
                                              segmentation_id,
                                              segmentation_type):
        in_db = nuagedb.get_nuage_l2bridge_physnet_mappings(
            session,
            physnet=physnet_name,
            segmentation_id=segmentation_id,
            segmentation_type=segmentation_type)
        if in_db:
            msg = _("Physnet {}, segmentation_id {}"
                    " and segmentation_type {} "
                    "are already "
                    "in use by l2bridge {}").format(
                physnet_name,
                segmentation_id,
                segmentation_type,
                in_db[0]['l2bridge_id']
            )
            raise exceptions.NuageBadRequest(msg=msg)
