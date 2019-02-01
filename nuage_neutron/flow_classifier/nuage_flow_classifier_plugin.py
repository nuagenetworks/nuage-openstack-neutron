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

from neutron_lib.db import api as db_api
from neutron_lib import constants as lib_constants
# This loads in the extensions for flow classifier.
from nuage_neutron.flow_classifier import extensions  # noqa
from nuage_neutron.flow_classifier import nuage_flowclassifier_db
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from networking_sfc.services.flowclassifier import plugin as flow_plugin

LOG = logging.getLogger(__name__)


class NuageFlowClassifierPlugin(
        base_plugin.BaseNuagePlugin,
        flow_plugin.FlowClassifierPlugin,
        nuage_flowclassifier_db.NuageFlowClassifierDbPlugin):
    supported_extension_aliases = ['nuage-flow-classifier']

    def __init__(self):
        LOG.debug("Initializing Nuage SFC Flow Classifier Plugin.")
        super(NuageFlowClassifierPlugin, self).__init__()

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_flow_classifier(self, context, flow_classifier):
        flow_classifier_dict = flow_classifier['flow_classifier']

        vlan_min_specified = (flow_classifier_dict.get('vlan_range_min') is not
                              lib_constants.ATTR_NOT_SPECIFIED)
        vlan_max_specified = (flow_classifier_dict.get('vlan_range_max') is not
                              lib_constants.ATTR_NOT_SPECIFIED)
        if vlan_min_specified or vlan_max_specified:
            vlan_min_value = flow_classifier_dict.get('vlan_range_min')
            vlan_max_value = flow_classifier_dict.get('vlan_range_max')
            if (vlan_min_specified and vlan_max_specified and
                    vlan_min_value != vlan_max_value):
                msg = ("Currently nuage only supports flow classifier where,"
                       " the minimum and maximum VLAN range values are equal.")
                raise nuage_exc.NuageBadRequest(msg=msg)
            flow_classifier['flow_classifier']['l7_parameters'] = {
                'vlan_range_min': vlan_min_value,
                'vlan_range_max': vlan_max_value
            }
        src_prt_details, dst_prt_details = self._validate_flow_classifier(
            context,
            flow_classifier_dict)
        with db_api.CONTEXT_WRITER.using(context):
            fc_db = (nuage_flowclassifier_db.NuageFlowClassifierDbPlugin.
                     create_flow_classifier(self, context, flow_classifier))
        with nuage_utils.rollback() as on_exc:
            on_exc(super(
                NuageFlowClassifierPlugin, self).delete_flow_classifier,
                context, fc_db['id'])
            src_prt_details['externalID'] = 'fc' + '_' + src_prt_details['id']
            dst_prt_details['externalID'] = 'fc' + '_' + dst_prt_details['id']
            l2dom_id, l3subnet_id, rtr_id = (
                self.get_logical_port_subnet_mapping(context, src_prt_details))
            self._create_nuage_flow_classifier(on_exc,
                                               l2dom_id,
                                               l3subnet_id,
                                               rtr_id,
                                               src_prt_details)
            if src_prt_details['id'] != dst_prt_details['id']:
                self._create_nuage_flow_classifier(on_exc,
                                                   l2dom_id,
                                                   l3subnet_id,
                                                   rtr_id,
                                                   dst_prt_details)
        return fc_db

    def _validate_flow_classifier(self, context, fc_info):
        port_list = []
        logical_source_port = fc_info['logical_source_port']
        logical_destination_port = fc_info['logical_destination_port']
        if not logical_source_port or not logical_destination_port:
            msg = ("Nuage does not support port chain without"
                   " logical-source-port and"
                   " logical-destination-port.")
            raise nuage_exc.NuageBadRequest(msg=msg)
        src_prt_details = self._get_logical_port_details(context,
                                                         logical_source_port,
                                                         port_list, 'source')
        dst_prt_details = self._get_logical_port_details(
            context,
            logical_destination_port,
            port_list,
            'destination')
        subnet_ids = {}
        for port in port_list:
            if subnet_ids:
                subnet_ids.add(port['fixed_ips'][0]['subnet_id'])
            else:
                subnet_ids = {port['fixed_ips'][0]['subnet_id']}
        if len(subnet_ids) != 1:
                msg = ('Nuage only supports logical ports'
                       ' belonging to one subnet.')
                raise nuage_exc.NuageBadRequest(msg=msg)
        return src_prt_details, dst_prt_details

    def _get_logical_port_details(self, context, logical_port,
                                  port_list, port_type):
        prt_details = self.core_plugin.get_port(
            context,
            id=logical_port)
        if (prt_details['device_owner'] in
                self.get_auto_create_port_owners()):
            msg = ("Do not support port chain where"
                   " logical %s port has port device owner as %s."
                   % port_type % prt_details['device_owner'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        port_list.append(prt_details)
        return prt_details

    def _create_nuage_flow_classifier(self, on_exc, l2dom_id, l3subnet_id,
                                      rtr_id,
                                      port_info):
        params = {'l2dom_id': l2dom_id}
        params['rtr_id'] = rtr_id
        params['l3dom_id'] = rtr_id
        params['externalID'] = port_info['externalID']
        params['type'] = constants.VM_VPORT
        params['sg_type'] = constants.SOFTWARE
        params['name'] = port_info['externalID']
        params['description'] = port_info['externalID']
        nuage_sg_id = (self.vsdclient.
                       create_nuage_sec_grp_for_sfc(params))
        params['redundancy_enabled'] = 'false'
        params['insertion_mode'] = 'VIRTUAL_WIRE'
        params['subnet_id'] = port_info['externalID']  # for external_id
        get_param = {'name': port_info['externalID']}
        rt_list = self.vsdclient.get_nuage_redirect_targets(get_param)
        if not rt_list:
            on_exc(self.vsdclient.delete_nuage_policy_group,
                   nuage_sg_id)
            rt = self.vsdclient.create_nuage_redirect_target(
                params, l2dom_id=l2dom_id, domain_id=rtr_id)
            on_exc(self.vsdclient.delete_nuage_redirect_target, rt['ID'])
            port_details = {'neutron_port_id': port_info['id'],
                            'l2dom_id': l2dom_id,
                            'rtr_id': rtr_id,
                            'l3dom_id': l3subnet_id}
            nuage_port = self.vsdclient.get_nuage_vport_for_port_sec(
                port_details)
            self.vsdclient.update_vports_in_policy_group(nuage_sg_id,
                                                         [nuage_port['ID']])
            on_exc(self.vsdclient.update_vports_in_policy_group, nuage_sg_id,
                   [])
            self.vsdclient.update_redirect_target_vports(rt['ID'],
                                                         [nuage_port['ID']])
            on_exc(self.vsdclient.update_redirect_target_vports, rt['ID'], [])

    def get_logical_port_subnet_mapping(self, context, port_info):
        l2dom_id = None
        rtr_id = None
        l3subnet_id = None
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session,
            port_info['fixed_ips'][0]['subnet_id'])
        if subnet_mapping:
            if self._is_l2(subnet_mapping):
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3subnet_id = subnet_mapping['nuage_subnet_id']
                rtr_id = self.vsdclient.get_nuage_domain_id_from_subnet(
                    l3subnet_id)
        else:
            msg = ('Cannot find subnet mapping for'
                   ' the port-id %s ' % port_info['id'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        return l2dom_id, l3subnet_id, rtr_id

    def _delete_nuage_flow_classifier_for_port(self, port_id):
        param = {'name': 'fc_' + port_id}
        rt = self.vsdclient.get_nuage_redirect_targets(param)
        if rt:
            self.vsdclient.update_redirect_target_vports(rt[0]['ID'], [])
            pg = self.vsdclient.get_nuage_policy_groups(
                required=False, externalID=rt[0]['externalID'])
            if pg:
                self.vsdclient.update_vports_in_policy_group(pg[0]['ID'], [])
                self.vsdclient.delete_nuage_policy_group(pg[0]['ID'])
            self.vsdclient.delete_nuage_redirect_target(rt[0]['ID'])

    @staticmethod
    def _check_port_use_in_fc(delete_dst, delete_src, fc_info,
                              port_in_fcs, logical_port_type):
        for fc in port_in_fcs:
            if fc[logical_port_type] == fc_info['logical_source_port']:
                delete_src = False
            elif (fc[logical_port_type] ==
                  fc_info['logical_destination_port']):
                delete_dst = False
        return delete_dst, delete_src

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_flow_classifier(self, context, id):
        fc_info = self.get_flow_classifier(context, id)
        super(NuageFlowClassifierPlugin, self).delete_flow_classifier(context,
                                                                      id)
        filters = {
            'logical_source_port': [fc_info['logical_source_port'],
                                    fc_info['logical_destination_port']]}
        port_in_fcs_src = self._get_ports_in_use_for_fc(context, filters)

        filters = {
            'logical_destination_port': [fc_info['logical_source_port'],
                                         fc_info['logical_destination_port']]}
        port_in_fcs_dst = self._get_ports_in_use_for_fc(context, filters)
        delete_src = True
        delete_dst = True
        delete_dst, delete_src = self._check_port_use_in_fc(
            delete_dst,
            delete_src,
            fc_info,
            port_in_fcs_src,
            'logical_source_port')
        if delete_src or delete_dst:
            delete_dst, delete_src = self._check_port_use_in_fc(
                delete_dst,
                delete_src,
                fc_info,
                port_in_fcs_dst,
                'logical_destination_port')
        if delete_src:
            self._delete_nuage_flow_classifier_for_port(
                fc_info['logical_source_port'])
        if delete_dst:
            self._delete_nuage_flow_classifier_for_port(
                fc_info['logical_destination_port'])
