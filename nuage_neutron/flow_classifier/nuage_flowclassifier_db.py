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

from networking_sfc.db import flowclassifier_db
from networking_sfc.extensions import flowclassifier as fc_ext
from neutron.db import api as db_api

from oslo_utils import uuidutils


class NuageFlowClassifierDbPlugin(flowclassifier_db.FlowClassifierDbPlugin):

    @classmethod
    def _vlan_range_conflict(cls, first_vlan_dict, second_vlan_dict):
        first_vlan_range_min = first_vlan_dict.get('vlan_range_min')
        first_vlan_range_max = first_vlan_dict.get('vlan_range_max')
        second_vlan_range_min = second_vlan_dict.get('vlan_range_min')
        second_vlan_range_max = second_vlan_dict.get('vlan_range_max')

        cls._port_range_conflict(first_vlan_range_min, first_vlan_range_max,
                                 second_vlan_range_min, second_vlan_range_max)

    @classmethod
    def flowclassifier_basic_conflict(cls,
                                      first_flowclassifier,
                                      second_flowclassifier):
        initial_validation = (
            super(NuageFlowClassifierDbPlugin, cls).
            flowclassifier_basic_conflict(first_flowclassifier,
                                          second_flowclassifier))
        return initial_validation and (
            cls._vlan_range_conflict(first_flowclassifier['l7_parameters'],
                                     second_flowclassifier['l7_parameters']))

    def _get_ports_in_use_for_fc(self, context, filters):
        query = self._model_query(context, flowclassifier_db.FlowClassifier)
        result = self._apply_filters_to_query(query,
                                              flowclassifier_db.FlowClassifier,
                                              filters)
        return result.all()

    def create_flow_classifier(self, context, flow_classifier):
        fc = flow_classifier['flow_classifier']
        project_id = fc['project_id']
        l7_parameters = {
            # Overriding the method due to change of below line only
            key: flowclassifier_db.L7Parameter(keyword=key, value=val)
            for key, val in fc['l7_parameters'].items()}
        ethertype = fc['ethertype']
        protocol = fc['protocol']
        source_port_range_min = fc['source_port_range_min']
        source_port_range_max = fc['source_port_range_max']
        self._check_port_range_valid(source_port_range_min,
                                     source_port_range_max,
                                     protocol)
        destination_port_range_min = fc['destination_port_range_min']
        destination_port_range_max = fc['destination_port_range_max']
        self._check_port_range_valid(destination_port_range_min,
                                     destination_port_range_max,
                                     protocol)
        source_ip_prefix = fc['source_ip_prefix']
        self._check_ip_prefix_valid(source_ip_prefix, ethertype)
        destination_ip_prefix = fc['destination_ip_prefix']
        self._check_ip_prefix_valid(destination_ip_prefix, ethertype)
        logical_source_port = fc['logical_source_port']
        logical_destination_port = fc['logical_destination_port']
        with db_api.context_manager.writer.using(context):
            if logical_source_port is not None:
                self._get_port(context, logical_source_port)
            if logical_destination_port is not None:
                self._get_port(context, logical_destination_port)
            query = self._model_query(context,
                                      flowclassifier_db.FlowClassifier)
            for flow_classifier_db in query.all():
                if self.flowclassifier_conflict(
                    fc,
                    flow_classifier_db
                ):
                    raise fc_ext.FlowClassifierInConflict(
                        id=flow_classifier_db['id']
                    )
            flow_classifier_db = flowclassifier_db.FlowClassifier(
                id=uuidutils.generate_uuid(),
                project_id=project_id,
                name=fc['name'],
                description=fc['description'],
                ethertype=ethertype,
                protocol=protocol,
                source_port_range_min=source_port_range_min,
                source_port_range_max=source_port_range_max,
                destination_port_range_min=destination_port_range_min,
                destination_port_range_max=destination_port_range_max,
                source_ip_prefix=source_ip_prefix,
                destination_ip_prefix=destination_ip_prefix,
                logical_source_port=logical_source_port,
                logical_destination_port=logical_destination_port,
                l7_parameters=l7_parameters
            )
            context.session.add(flow_classifier_db)
            return self._make_flow_classifier_dict(flow_classifier_db)
