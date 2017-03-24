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

import binascii
import six

from networking_sfc.db import sfc_db
from nuage_neutron.flow_classifier import nuage_flowclassifier_db as fc_db
from nuage_neutron.plugins.common import nuage_models


class NuageSfcDbPlugin(sfc_db.SfcDbPlugin):

    def __init__(self):
        super(NuageSfcDbPlugin, self).__init__()

    @staticmethod
    def get_subnet_vlan_bit_map_with_lock(session, subnet_id=None):
        query = session.query(nuage_models.NuageSfcVlanSubnetMapping)
        if subnet_id:
            vlan_mapping = query.filter_by(
                subnet_id=subnet_id).with_for_update().first()
        else:
            vlan_mapping = None
        return vlan_mapping

    @staticmethod
    def add_subnet_vlan_bit_map(session, vlan_bit_map, subnet_id):
        with session.begin(subtransactions=True):
            vlan_mapping = nuage_models.NuageSfcVlanSubnetMapping(
                subnet_id=subnet_id,
                vlan_bit_map=vlan_bit_map)
            session.add(vlan_mapping)
            return vlan_mapping

    @staticmethod
    def update_subnet_vlan_bit_map_unset(session, vlan_id, subnet_id):
        with session.begin(subtransactions=True):
            mask = 1 << (vlan_id - 1)
            query = session.query(nuage_models.NuageSfcVlanSubnetMapping)
            vlan_mapping = query.filter_by(
                subnet_id=subnet_id).with_for_update().first()
            if vlan_mapping:
                int_vlan_map = int(binascii.hexlify(
                    vlan_mapping['vlan_bit_map']), 16)
                int_vlan_map |= mask
                vlan_mapping.update(
                    {'vlan_bit_map': binascii.unhexlify('%x' % int_vlan_map)})

    @staticmethod
    def delete_subnet_vlan_bit_map(session, subnet_id):
        with session.begin(subtransactions=True):
            query = session.query(nuage_models.NuageSfcVlanSubnetMapping)
            query.filter_by(subnet_id=subnet_id).delete()

    def _validate_flow_classifiers(self, context, fc_ids, pc_id=None):
        with context.session.begin(subtransactions=True):
            fcs = [
                self._get_flow_classifier(context, fc_id)
                for fc_id in fc_ids
                ]
            for fc in fcs:
                fc_assoc = fc.chain_classifier_association
                if fc_assoc and fc_assoc['portchain_id'] != pc_id:
                    raise sfc_db.ext_fc.FlowClassifierInUse(id=fc.id)

            query = self._model_query(context, sfc_db.PortChain)
            for port_chain_db in query.all():
                if port_chain_db['id'] == pc_id:
                    continue
                pc_fc_ids = [
                    assoc['flowclassifier_id']
                    for assoc in
                    port_chain_db.chain_classifier_associations
                    ]
                pc_fcs = [
                    self._get_flow_classifier(context, pc_fc_id)
                    for pc_fc_id in pc_fc_ids
                    ]
                for pc_fc in pc_fcs:
                    for fc in fcs:
                        fc_cls = fc_db.NuageFlowClassifierDbPlugin
                        if fc_cls.flowclassifier_basic_conflict(
                            pc_fc, fc
                        ):
                            raise (
                                sfc_db.ext_sfc.
                                PortChainFlowClassifierInConflict(
                                    fc_id=fc['id'],
                                    pc_id=port_chain_db['id'],
                                    pc_fc_id=pc_fc['id'])
                            )

    @sfc_db.log_helpers.log_method_call
    def create_port_chain(self, context, port_chain):
        """Create a port chain."""
        pc = port_chain['port_chain']
        tenant_id = pc['tenant_id']
        chain_id = pc['chain_id']
        with context.session.begin(subtransactions=True):
            chain_parameters = {
                key: sfc_db.ChainParameter(keyword=key,
                                           value=sfc_db.jsonutils.dumps(val))
                for key, val in six.iteritems(pc['chain_parameters'])}

            pg_ids = pc['port_pair_groups']
            fc_ids = pc['flow_classifiers']
            self._validate_flow_classifiers(context, fc_ids)
            assigned_chain_ids = {}
            query = context.session.query(sfc_db.PortChain)
            for port_chain_db in query.all():
                assigned_chain_ids[port_chain_db['chain_id']] = (
                    port_chain_db['id']
                )
            if not chain_id:
                available_chain_id = 1
                while available_chain_id:
                    if available_chain_id not in assigned_chain_ids:
                        chain_id = available_chain_id
                        break
                    available_chain_id += 1
                if not chain_id:
                    raise sfc_db.ext_sfc.PortChainUnavailableChainId()
            else:
                if chain_id in assigned_chain_ids:
                    raise sfc_db.ext_sfc.PortChainChainIdInConflict(
                        chain_id=chain_id, pc_id=assigned_chain_ids[chain_id])
            port_chain_db = sfc_db.PortChain(
                id=sfc_db.uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                description=pc['description'],
                name=pc['name'],
                chain_parameters=chain_parameters,
                chain_id=chain_id)
            self._setup_chain_group_associations(
                context, port_chain_db, pg_ids)
            self._setup_chain_classifier_associations(
                context, port_chain_db, fc_ids)
            context.session.add(port_chain_db)

            return self._make_port_chain_dict(port_chain_db)

    @sfc_db.log_helpers.log_method_call
    def update_port_chain(self, context, id, port_chain):
        pc = port_chain['port_chain']
        with context.session.begin(subtransactions=True):
            pc_db = self._get_port_chain(context, id)
            for k, v in six.iteritems(pc):
                if k == 'flow_classifiers':
                    self._validate_flow_classifiers(
                        context, v, pc_id=id)
                    self._setup_chain_classifier_associations(
                        context, pc_db, v)
                elif k == 'port_pair_groups':
                    self._setup_chain_group_associations(
                        context, pc_db, v)
                else:
                    pc_db[k] = v
            return self._make_port_chain_dict(pc_db)
