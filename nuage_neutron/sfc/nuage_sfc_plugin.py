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
import copy
import random

from networking_sfc.services.sfc import plugin as sfc_plugin
from neutron.services.trunk import constants as t_consts
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.sfc import nuage_sfc_db
from nuage_neutron.vsdclient.common import cms_id_helper
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NuageSFCPlugin(sfc_plugin.SfcPlugin,
                     base_plugin.BaseNuagePlugin,
                     nuage_sfc_db.NuageSfcDbPlugin):

    def __init__(self):
        LOG.debug("Initializing Nuage SFC Plugin.")
        super(NuageSFCPlugin, self).__init__()

    @log_helpers.log_method_call
    def create_port_pair(self, context, port_pair):
        # need to deep copy to override correlation value with vlan since
        # currently lib.validators is giving value error when overriding
        # value using the provided port pair.
        port_pair_copy = copy.deepcopy(port_pair)
        port_pair_dict = port_pair_copy['port_pair']
        correlation = port_pair_dict[constants.SFC_PARAMS].get('correlation')
        if not correlation or correlation == 'vlan':
            port_pair_dict[constants.SFC_PARAMS]['correlation'] = 'vlan'
            pp = super(NuageSFCPlugin, self).create_port_pair(
                context,
                port_pair_copy)
        else:
            msg = ('Nuage only supports VLAN as correlation'
                   ' parameter. Does not support %s' % correlation)
            raise nuage_exc.NuageBadRequest(msg=msg)
        return pp

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_port_pair_group(self, context, port_pair_group):
        # if more than one port-pair then raise error

        port_pair_group_dict = port_pair_group['port_pair_group']
        values = self._validate_create_port_pair_group(context,
                                                       port_pair_group_dict)
        ingress_ports = values[0]
        egress_ports = values[1]
        one_ingress_egress = values[2]
        with nuage_utils.rollback() as on_exc:
            ppg = super(NuageSFCPlugin, self).create_port_pair_group(
                context, port_pair_group)
            on_exc(super(NuageSFCPlugin, self).delete_port_pair_group,
                   context,
                   ppg['id'])
            self._create_nuage_port_pair_group(context, on_exc,
                                               ingress_ports, ppg,
                                               one_ingress_egress)
            if not one_ingress_egress:
                self._create_nuage_port_pair_group(context, on_exc,
                                                   egress_ports, ppg)
        return ppg

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_port_pair_group(self, context, port_pair_group_id,
                               port_pair_group):
        original_ppg = self.get_port_pair_group(context, port_pair_group_id)
        original_values = self._validate_ppg(context, original_ppg)
        ppg_dict = port_pair_group['port_pair_group']
        updated_values = self._validate_create_port_pair_group(context,
                                                               ppg_dict)
        if original_values[-1] != updated_values[-1]:
            if original_values[-1]:
                msg = ("Nuage does not support updating port pair group when"
                       " the existing port pairs have one ingress and"
                       " egress port and the new port pairs have different"
                       " port for ingress and egress.")
            else:
                msg = ("Nuage does not support updating port pair group when"
                       " the existing port pairs have different"
                       " ports for ingress and egress and the new port pairs"
                       " have same ingress and egress port.")
            raise nuage_exc.NuageBadRequest(msg=msg)
        with nuage_utils.rollback() as on_exc:
            updated_ppg = super(
                NuageSFCPlugin, self).update_port_pair_group(
                context,
                port_pair_group_id,
                port_pair_group)
            del original_ppg['port_pair_group_parameters']
            on_exc(super(NuageSFCPlugin, self).update_port_pair_group,
                   context, port_pair_group_id,
                   {'port_pair_group': original_ppg})
            self._update_nuage_port_pair_group(context, on_exc,
                                               updated_values[0],
                                               original_values[0],
                                               updated_ppg,
                                               updated_values[-1])
            if not updated_values[-1]:
                self._update_nuage_port_pair_group(context, on_exc,
                                                   updated_values[1],
                                                   original_values[1],
                                                   updated_ppg,
                                                   updated_values[-1])
            return updated_ppg

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_port_pair_group(self, context, port_pair_group):
        port_pair_group_dict = self.get_port_pair_group(context,
                                                        port_pair_group)
        with nuage_utils.rollback() as on_exc:
            values = self._validate_ppg(context, port_pair_group_dict)
            ingress_ports = values[0]
            egress_ports = values[1]
            one_ingress_egress = values[2]

            self._delete_nuage_port_pair_group(context, on_exc, ingress_ports,
                                               port_pair_group_dict,
                                               one_ingress_egress)
            if not one_ingress_egress:
                self._delete_nuage_port_pair_group(context, on_exc,
                                                   egress_ports,
                                                   port_pair_group_dict)

            super(NuageSFCPlugin, self).delete_port_pair_group(context,
                                                               port_pair_group)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_port_chain(self, context, port_chain):
        port_chain_copy = copy.deepcopy(port_chain)
        port_chain_dict = port_chain_copy['port_chain']
        self._validate_port_chain_correlation(port_chain_dict)
        port_chain_dict['chain_parameters']['correlation'] = 'vlan'
        LOG.warning("Nuage will override correlation value to vlan")
        port_pair_groups = port_chain_dict['port_pair_groups']
        pg_filter, redirect_filter, port_for_parent_validation = (
            self._map_ppg_names_for_filtering(context, port_pair_groups))
        domain_id, fc_filter, flow_classifiers = (
            self._map_port_chain_fc_filter(
                context, port_chain_dict['flow_classifiers'],
                port_for_parent_validation))
        nuage_pgs = self.vsdclient.get_policy_groups_by_single_filter(
            required=True,
            filters=pg_filter)
        rdts = self.vsdclient.get_nuage_redirect_targets_by_single_filter(
            filters=redirect_filter,
            required=True)
        fc_port_pgs, fc_port_rts = self._validate_port_chain_fc_on_vsd(
            fc_filter)
        with nuage_utils.rollback() as on_exc:
            vlan_subnet_mapping = self.get_subnet_vlan_bit_map_with_lock(
                context,
                subnet_id=domain_id)
            if vlan_subnet_mapping:
                vlan_label_id = self._set_vlanid(domain_id,
                                                 vlan_subnet_mapping)
                on_exc(self.update_subnet_vlan_bit_map_unset,
                       context,
                       vlan_label_id,
                       domain_id)
            else:
                vlan_bit_map = (1 << 4094) - 1
                vlan_label_id = 1
                mask = 1 << 0
                vlan_bit_map &= ~mask
                self.add_subnet_vlan_bit_map(
                    context,
                    subnet_id=domain_id,
                    vlan_bit_map=binascii.unhexlify('%x' % vlan_bit_map))
                on_exc(self.delete_subnet_vlan_bit_map,
                       context, domain_id)
            port_chain_dict['chain_parameters']['correlation_id'] = (
                vlan_label_id)
            pc = nuage_sfc_db.NuageSfcDbPlugin.create_port_chain(
                self,
                context,
                port_chain_copy)
            on_exc(super(NuageSFCPlugin, self).delete_port_chain,
                   context, pc['id'])
            fwd_template = {"active": True,
                            "priority": pc['chain_id'],
                            "name": "pc_" + pc['id'],
                            "description": "pc_" + pc['id'],
                            "externalID": pc['id']}
            pc_fwd_policy = self.vsdclient.create_in_adv_fwd_policy_template(
                nuage_pgs[0]['parentType'], nuage_pgs[0]['parentID'],
                fwd_template)
            on_exc(self.vsdclient.delete_in_adv_fwd_policy_template,
                   pc_fwd_policy['ID'])
            if flow_classifiers:
                flow_classifiers.reverse()
            else:
                return pc
            self._create_nuage_port_chain_rules(on_exc, pc_fwd_policy,
                                                flow_classifiers,
                                                port_pair_groups,
                                                nuage_pgs, rdts, fc_port_pgs,
                                                fc_port_rts,
                                                vlan_label=vlan_label_id)
            if port_chain_dict['chain_parameters'].get('symmetric') is True:
                ppgs = copy.deepcopy(port_pair_groups)
                ppgs.reverse()
                self._create_nuage_port_chain_rules(
                    on_exc, pc_fwd_policy,
                    flow_classifiers,
                    port_pair_groups=ppgs,
                    nuage_pgs=nuage_pgs,
                    rdts=rdts,
                    fc_pgs=fc_port_pgs,
                    fc_port_rdts=fc_port_rts,
                    vlan_label=vlan_label_id,
                    direction='reverse')
            return pc

    def _set_vlanid(self, domain_id, vlan_subnet_mapping):
        vlan_bit_map = int(binascii.hexlify(
            vlan_subnet_mapping['vlan_bit_map']), 16)
        vlan_label_id = self._get_next_available_vlan_id(
            vlan_bit_map)
        if vlan_label_id > 4093:
            msg = ("Cannot create port chain since all"
                   " 'vlan' values are in use by other"
                   " port chains for"
                   " the subnet %s " % domain_id)
            raise nuage_exc.NuageBadRequest(msg=msg)
        mask = 1 << vlan_label_id
        vlan_bit_map &= ~mask
        vlan_subnet_mapping.update(
            {'vlan_bit_map': binascii.unhexlify('%x' % vlan_bit_map)})
        vlan_label_id += 1
        return vlan_label_id

    def _map_port_chain_fc_filter(self, context, pc_fcs,
                                  port_for_parent_validation):
        flow_classifiers = []
        fc_filter = []
        domain_id = None
        for flow_classifier in pc_fcs:
            fc_info = self._get_flow_classifier(context, flow_classifier)
            domain_id = self._validate_port_chain_flow_classifier(
                context,
                fc_info,
                port_for_parent_validation)
            fc_filter += ['fc_' + fc_info['logical_source_port'],
                          'fc_' + fc_info['logical_destination_port']]

            flow_classifiers.append(fc_info)

        if not domain_id and not pc_fcs:
            port = self.core_plugin.get_port(context,
                                             id=port_for_parent_validation)
            domain_id = self._check_ports_on_same_l2_or_l3_domain([port], '')
        return domain_id, fc_filter, flow_classifiers

    def _map_ppg_names_for_filtering(self, context, port_pair_groups):
        ppg_redirect_targets = []
        ppg_policy_groups = []
        ports = []
        for port_pair_group in port_pair_groups:
            ppg_redirect_targets += ["ingress_" + port_pair_group,
                                     "egress_" + port_pair_group,
                                     "ingress_egress_" + port_pair_group]
            ppg_policy_groups += ["ingress_" + port_pair_group,
                                  "egress_" + port_pair_group,
                                  "ingress_egress_" + port_pair_group]
            ppg = self.get_port_pair_group(context, port_pair_group)
            for pp_id in ppg['port_pairs']:
                pp = self.get_port_pair(context, pp_id)
                ports.append(self.core_plugin.get_port(
                    context,
                    id=pp['ingress']))
                ports.append(self.core_plugin.get_port(
                    context,
                    id=pp['egress']))
        msg = ('Nuage only supports port chains of ports'
               ' belonging to one subnet')
        self._check_ports_on_same_l2_or_l3_domain(ports, msg)
        pg_filter = {"name": ppg_policy_groups}
        redirect_filter = {"name": ppg_redirect_targets}
        return pg_filter, redirect_filter, ports[0]['id']

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_port_chain(self, context, portchain_id, port_chain):
        original_port_chain = self.get_port_chain(context, portchain_id)
        port_chain_dict = port_chain['port_chain']
        if (port_chain_dict.get('chain_parameters') and
                port_chain_dict['chain_parameters'].get(
                    'correlation') != 'vlan'):
            msg = "Nuage only supports 'vlan' correlation for port chain."
            raise nuage_exc.NuageBadRequest(msg=msg)
        ppg_value_changed = (True if port_chain_dict.get(
            'port_pair_groups') and port_chain_dict['port_pair_groups'] !=
            original_port_chain['port_pair_groups'] else False)
        flws_value_changed = (True if port_chain_dict.get(
            'flow_classifiers') is not None and
            port_chain_dict['flow_classifiers'] !=
            original_port_chain['flow_classifiers'] else False)
        symtric_value_changed = (True if port_chain_dict.get(
            'chain_parameters') is not None and port_chain_dict.get(
            'chain_parameters').get('symmetric') is not None and
            port_chain_dict['chain_parameters']['symmetric'] !=
            original_port_chain['chain_parameters']['symmetric'] else False)
        if (not symtric_value_changed and
                not flws_value_changed and not ppg_value_changed):
            return super(NuageSFCPlugin, self).update_port_chain(context,
                                                                 portchain_id,
                                                                 port_chain)

        port_pair_groups = (port_chain_dict['port_pair_groups']
                            if ppg_value_changed
                            else original_port_chain['port_pair_groups'])
        fl_classifier_list = (port_chain_dict['flow_classifiers']
                              if flws_value_changed
                              else original_port_chain.get('flow_classifiers'))

        symmetric_val = (port_chain_dict['chain_parameters']['symmetric'] if
                         symtric_value_changed else
                         original_port_chain['chain_parameters']['symmetric'])

        pg_filter, redirect_filter, port_for_parent_validation = (
            self._map_ppg_names_for_filtering(context, port_pair_groups))
        domain_id, fc_filter, flow_classifiers = (
            self._map_port_chain_fc_filter(
                context, fl_classifier_list, port_for_parent_validation))
        if flow_classifiers:
            flow_classifiers.reverse()
        vlan_label_id = (
            original_port_chain['chain_parameters']['correlation_id'])
        nuage_pgs = self.vsdclient.get_policy_groups_by_single_filter(
            required=True,
            filters=pg_filter)
        rdts = self.vsdclient.get_nuage_redirect_targets_by_single_filter(
            filters=redirect_filter,
            required=True)
        fc_port_pgs, fc_port_rts = self._validate_port_chain_fc_on_vsd(
            fc_filter)
        with nuage_utils.rollback() as on_exc:
            existing_adv_fwds = self.vsdclient.get_in_adv_fwd_policy_by_cmsid(
                nuage_pgs[0]['parentType'], nuage_pgs[0]['parentID'])
            adv_fwd_tmpl = None
            for fwd_tmplt in existing_adv_fwds:
                if ((portchain_id in fwd_tmplt['name']) and
                        (portchain_id in fwd_tmplt['description'])):
                    adv_fwd_tmpl = fwd_tmplt
                    break
            if adv_fwd_tmpl:
                name_param = {'name': 'updating_' + adv_fwd_tmpl['name']}
                self.vsdclient.update_in_adv_fwd_policy_template(
                    adv_fwd_tmpl['ID'],
                    name_param)
                name_param = {'name': adv_fwd_tmpl['name']}
                on_exc(self.vsdclient.update_in_adv_fwd_policy_template,
                       adv_fwd_tmpl['ID'], name_param)
            pc = nuage_sfc_db.NuageSfcDbPlugin.update_port_chain(
                self,
                context,
                portchain_id,
                port_chain)
            del original_port_chain['chain_parameters']
            on_exc(nuage_sfc_db.NuageSfcDbPlugin.update_port_chain,
                   self,
                   context, original_port_chain['id'],
                   {'port_chain': original_port_chain})
            fwd_template = {"active": False,
                            "name": "pc_" + pc['id'],
                            "description": "pc_" + pc['id'],
                            "externalID": pc['id'],
                            "priority": random.randint(
                                constants.MAX_VSD_PRIORITY // 10,
                                constants.MAX_VSD_PRIORITY)}
            pc_fwd_policy = self.vsdclient.create_in_adv_fwd_policy_template(
                nuage_pgs[0]['parentType'], nuage_pgs[0]['parentID'],
                fwd_template)
            on_exc(self.vsdclient.delete_in_adv_fwd_policy_template,
                   pc_fwd_policy['ID'])
            self._create_nuage_port_chain_rules(on_exc, pc_fwd_policy,
                                                flow_classifiers,
                                                port_pair_groups,
                                                nuage_pgs, rdts,
                                                fc_port_pgs,
                                                fc_port_rts,
                                                vlan_label=vlan_label_id)
            if symmetric_val:
                self._create_nuage_port_chain_rules(
                    on_exc, pc_fwd_policy,
                    flow_classifiers,
                    port_pair_groups,
                    nuage_pgs, rdts,
                    fc_port_pgs,
                    fc_port_rts,
                    vlan_label=vlan_label_id,
                    direction='reverse')
            self.vsdclient.update_in_adv_fwd_policy_template(
                pc_fwd_policy['ID'],
                {"active": True})
            if adv_fwd_tmpl:
                self.vsdclient.delete_in_adv_fwd_policy_template(
                    adv_fwd_tmpl['ID'])
            self.vsdclient.update_in_adv_fwd_policy_template(
                pc_fwd_policy['ID'],
                {"priority": original_port_chain['chain_id']})
            return pc

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_port_chain(self, context, portchain_id):
        pc = self.get_port_chain(context, portchain_id)
        parent_id = None
        if not pc['flow_classifiers']:
            port_pair_group = pc['port_pair_groups'][0]
            ppg_policy_groups = ["ingress_" + port_pair_group,
                                 "egress_" + port_pair_group,
                                 "ingress_egress_" + port_pair_group]
            pg_filter = {"name": ppg_policy_groups}
            nuage_pgs = self.vsdclient.get_policy_groups_by_single_filter(
                required=True,
                filters=pg_filter)
            if nuage_pgs:
                existing_adv_fwds = (
                    self.vsdclient.get_in_adv_fwd_policy_by_cmsid(
                        nuage_pgs[0]['parentType'],
                        nuage_pgs[0]['parentID']))
                for fwd_tmplt in existing_adv_fwds:
                    if ((portchain_id in fwd_tmplt['name']) and
                            (portchain_id in fwd_tmplt['description'])):
                        parent_id = fwd_tmplt['ID']
                        break
        for flow_classifier in pc['flow_classifiers']:
            rdts = (
                self.vsdclient.get_nuage_redirect_target_rules_by_external_id(
                    flow_classifier))
            for rd_rule in rdts:
                parent_id = rd_rule['parentID']
                self.vsdclient.delete_nuage_redirect_target_rule(rd_rule['ID'])
        self.vsdclient.delete_in_adv_fwd_policy_template(parent_id)
        super(NuageSFCPlugin, self).delete_port_chain(context, portchain_id)
        ppg = self.get_port_pair_group(context, pc['port_pair_groups'][0])
        pp = self.get_port_pair(context, ppg['port_pairs'][0])
        port_info = self.core_plugin.get_port(context, id=pp['ingress'])
        if port_info:
            self.update_subnet_vlan_bit_map_unset(
                context,
                pc['chain_parameters']['correlation_id'],
                port_info['fixed_ips'][0]['subnet_id'])

    @staticmethod
    def _get_next_available_vlan_id(vlan_bit_map):
        return (vlan_bit_map & -vlan_bit_map).bit_length() - 1

    def _validate_ppg(self, context, ppg):
        ingress_ports = []
        egress_ports = []
        one_ingress_egress_port = False
        for pp_id in ppg['port_pairs']:
            pp = self.get_port_pair(context, pp_id)
            if ppg['port_pairs'].index(pp_id) == 0:
                if pp['ingress'] == pp['egress']:
                    one_ingress_egress_port = True
            elif one_ingress_egress_port != (pp['ingress'] == pp['egress']):
                msg = ("Do not support having port pair group where"
                       " in one port pair has"
                       " one ingress and egress port and the"
                       " other port pair have different port for"
                       " ingress and egress.")
                raise nuage_exc.NuageBadRequest(msg=msg)
            ingress_port_details = self.core_plugin.get_port(
                context,
                id=pp['ingress'])
            self._validate_port_config(context, ingress_port_details)
            ingress_port_details['direction'] = 'ingress'
            egress_port_details = self.core_plugin.get_port(
                context,
                id=pp['egress'])
            self._validate_port_config(context, egress_port_details)
            egress_port_details['direction'] = 'egress'
            ingress_ports.append(ingress_port_details)
            egress_ports.append(egress_port_details)
        return ingress_ports, egress_ports, one_ingress_egress_port

    def _validate_port_config(self, context, port_details):
        non_supported_ports = (self.get_auto_create_port_owners() +
                               [t_consts.TRUNK_SUBPORT_OWNER])
        if port_details['device_owner'] in non_supported_ports:
            msg = ("Do not support having port pair group where"
                   " in port device owner is %s." %
                   port_details['device_owner'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session,
            port_details['fixed_ips'][0]['subnet_id'])
        if not subnet_mapping:
            msg = ('Cannot find subnet mapping for'
                   ' the port-id %s ' % port_details['id'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        if (port_details['port_security_enabled'] and
                self._is_os_mgd(subnet_mapping)):
            msg = ("Nuage do not support having port pair group when"
                   " port security is enabled, port-id: %s" %
                   port_details['id'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        elif self._is_vsd_mgd(subnet_mapping):
            LOG.warning("Nuage requires spoofing to be enabled on VSD for"
                        " port-id: %s", port_details['id'])

    @staticmethod
    def _validate_port_chain_correlation(port_chain_dict):
        if (port_chain_dict['chain_parameters'].get('correlation')
                not in [None, 'mpls', 'vlan']):
            msg = "Nuage only supports 'vlan' correlation for port chain."
            raise nuage_exc.NuageBadRequest(msg=msg)

    def _validate_port_chain_fc_on_vsd(self, fc_fltr):
        fc_port_pgs = []
        fc_port_rts = []
        if fc_fltr:
            fc_filter = {"name": fc_fltr}
            fc_port_pgs = self.vsdclient.get_policy_groups_by_single_filter(
                required=True,
                filters=fc_filter)
            if len(fc_port_pgs) != len(set(fc_fltr)):
                msg = ('Cannot find policy groups on VSD for logical'
                       ' ports in the flow classifers')
                raise nuage_exc.NuageBadRequest(msg=msg)
            fc_port_rts = (
                self.vsdclient.get_nuage_redirect_targets_by_single_filter(
                    filters=fc_filter,
                    required=True))
            if len(fc_port_rts) != len(set(fc_fltr)):
                msg = ('Cannot find redirect targets on VSD for logical'
                       ' ports in them flow classifers')
                raise nuage_exc.NuageBadRequest(msg=msg)
        return fc_port_pgs, fc_port_rts

    def _validate_port_chain_flow_classifier(self, context, fc_info,
                                             port_for_parent_validation):
        port_list = []
        logical_source_port = fc_info['logical_source_port']
        logical_destination_port = fc_info['logical_destination_port']
        src_prt_details = self.core_plugin.get_port(
            context,
            id=logical_source_port)
        port_list.append(src_prt_details)
        dst_prt_details = self.core_plugin.get_port(
            context,
            id=logical_destination_port)
        port_list.append(dst_prt_details)
        port_list.append(self.core_plugin.get_port(
            context,
            id=port_for_parent_validation))
        msg = ('Nuage only supports port chain where ports'
               ' should belong to one subnet')
        return self._check_ports_on_same_l2_or_l3_domain(port_list, msg)

    @staticmethod
    def _check_ports_on_same_l2_or_l3_domain(port_list, msg):
        subnet_ids = {}
        for port in port_list:
            if subnet_ids:
                subnet_ids.add(port['fixed_ips'][0]['subnet_id'])
            else:
                subnet_ids = {port['fixed_ips'][0]['subnet_id']}
        if len(subnet_ids) != 1:
            raise nuage_exc.NuageBadRequest(msg=msg)
        return list(subnet_ids)[0]

    def _create_nuage_port_chain_rules(self,
                                       on_exc,
                                       adv_fwd_tmplt,
                                       flow_classifiers,
                                       port_pair_groups,
                                       nuage_pgs,
                                       rdts,
                                       fc_pgs,
                                       fc_port_rdts,
                                       vlan_label,
                                       direction='forward'):
        ppg_pg_map = self._sfc_map_vsd_resource(nuage_pgs)
        ppg_rdts_map = self._sfc_map_vsd_resource(rdts)
        chain_links = list(zip(port_pair_groups[:-1], port_pair_groups[1:]))
        if not chain_links and port_pair_groups:
            chain_links = [(port_pair_groups[0], port_pair_groups[0])]
        if adv_fwd_tmplt['parentType'] == constants.L2DOMAIN:
            fields = ['parentID', 'DHCPManaged']
            l2dom_fields = self.vsdclient.get_l2domain_fields_for_pg(
                adv_fwd_tmplt['parentID'],
                fields)
            np_id = l2dom_fields['parentID']
        else:
            np_id = self.vsdclient.get_l3domain_np_id(
                adv_fwd_tmplt['parentID'])
        fc_pg_map = self._sfc_map_vsd_resource(fc_pgs)
        fc_rdts_map = self._sfc_map_vsd_resource(fc_port_rdts)
        for flow_classifier in flow_classifiers:
            src_pg = fc_pg_map[flow_classifier['logical_source_port']][0]
            dst_pg = (
                fc_pg_map[flow_classifier['logical_destination_port']][0])
            src_rd = fc_rdts_map[flow_classifier['logical_source_port']][0]
            dst_rd = (
                fc_rdts_map[flow_classifier['logical_destination_port']][0])
            links = []
            if chain_links:
                if direction == 'forward':
                    links = ([(src_pg['ID'], chain_links[0][0])] +
                             chain_links +
                             [(chain_links[-1][1], dst_rd['ID'])])
                else:
                    links = ([(dst_pg['ID'], chain_links[0][0])] +
                             chain_links +
                             [(chain_links[-1][1], src_rd['ID'])])
            neutron_id = flow_classifier['id']
            for link in links:
                if links.index(link) == 0:
                    policy_group_id = link[0]
                    ppg_rdts = ppg_rdts_map.get(link[1])
                    if direction == 'forward':
                        redirect_target_id = (ppg_rdts[0]['ID']
                                              if 'ingress' in
                                                 ppg_rdts[0]['name']
                                              else ppg_rdts[1]['ID'])
                    else:
                        redirect_target_id = (ppg_rdts[0]['ID']
                                              if 'egress' in
                                                 ppg_rdts[0]['name']
                                              else ppg_rdts[1]['ID'])
                    nuage_match_info = {
                        'description': direction + '_' + neutron_id,
                        'action': 'REDIRECT',
                        'DSCP': '*',
                        'locationType': "POLICYGROUP",
                        'locationID': policy_group_id,
                        'redirectVPortTagID': redirect_target_id,
                        'externalID': neutron_id
                    }
                    if flow_classifier['ethertype'] == 'IPv4':
                        nuage_match_info['etherType'] = '0x0800'
                        if (direction == 'forward' and
                                flow_classifier.get('source_ip_prefix')):
                            nuage_match_info['addressOverride'] = (
                                flow_classifier.get('source_ip_prefix'))
                        elif (direction == 'reverse' and flow_classifier.get(
                                'destination_ip_prefix')):
                            nuage_match_info['addressOverride'] = (
                                flow_classifier.get(
                                    'destination_ip_prefix'))
                    else:
                        nuage_match_info['etherType'] = '0x86DD'
                        if (direction == 'forward' and
                                flow_classifier.get('source_ip_prefix')):
                            nuage_match_info['IPv6AddressOverride'] = (
                                flow_classifier.get('source_ip_prefix'))
                        elif (direction == 'reverse' and flow_classifier.get(
                                'destination_ip_prefix')):
                            nuage_match_info['IPv6AddressOverride'] = (
                                flow_classifier.get('destination_ip_prefix'))
                    if flow_classifier.get('protocol'):
                        nuage_match_info['protocol'] = flow_classifier.get(
                            'protocol')
                        if flow_classifier.get('source_port_range_min'):
                            if direction == 'forward':
                                nuage_match_info['sourcePort'] = (
                                    str(flow_classifier.get(
                                        'source_port_range_min')) +
                                    "-" + str(flow_classifier.get(
                                        'source_port_range_max')))
                            else:
                                nuage_match_info['sourcePort'] = (
                                    str(flow_classifier.get(
                                        'destination_port_range_min')) +
                                    "-" + str(flow_classifier.get(
                                        'destination_port_range_max')))
                        elif nuage_match_info['protocol'].lower() != 'icmp':
                            nuage_match_info['sourcePort'] = '*'
                        if flow_classifier.get('destination_port_range_min'):
                            if direction == 'forward':
                                nuage_match_info['destinationPort'] = (
                                    str(flow_classifier.get(
                                        'destination_port_range_min')) +
                                    "-" + str(flow_classifier.get(
                                        'destination_port_range_max')))
                            else:
                                nuage_match_info['destinationPort'] = (
                                    str(flow_classifier.get(
                                        'source_port_range_min')) +
                                    "-" + str(flow_classifier.get(
                                        'source_port_range_max')))
                        elif nuage_match_info['protocol'].lower() != 'icmp':
                            nuage_match_info['destinationPort'] = '*'
                    else:
                        nuage_match_info['protocol'] = 'ANY'
                    if (flow_classifier['l7_parameters'] and
                            flow_classifier['l7_parameters'].get(
                                'vlan_range_min')):
                        nuage_match_info['vlanRange'] = (
                            flow_classifier['l7_parameters']
                            ['vlan_range_min']['value'])
                    else:
                        nuage_match_info['vlanRange'] = '*'
                    if direction == 'forward':
                        nuage_match_info['networkType'] = (
                            'ENTERPRISE_NETWORK' if flow_classifier.get(
                                'destination_ip_prefix') else "ANY")
                    else:
                        nuage_match_info['networkType'] = (
                            'ENTERPRISE_NETWORK' if flow_classifier.get(
                                'source_ip_prefix') else "ANY")
                    if nuage_match_info['networkType'] == 'ENTERPRISE_NETWORK':
                        if direction == 'forward':
                            nuage_match_info['destination_ip_prefix'] = (
                                flow_classifier.get('destination_ip_prefix'))
                        else:
                            nuage_match_info['destination_ip_prefix'] = (
                                flow_classifier.get('source_ip_prefix'))
                    nuage_match_info['redirectRewriteType'] = 'VLAN'
                    nuage_match_info['redirectRewriteValue'] = vlan_label
                    rule = self.vsdclient.add_nuage_sfc_rule(adv_fwd_tmplt,
                                                             nuage_match_info,
                                                             np_id)
                    on_exc(self.vsdclient.delete_nuage_redirect_target_rule,
                           rule['ID'])
                elif links.index(link) == len(links) - 1:
                    pgs = ppg_pg_map.get(link[0])
                    if direction == 'forward':
                        policy_group_id = (
                            pgs[0]['ID'] if 'egress' in pgs[0]['name']
                            else pgs[1]['ID'])
                    else:
                        policy_group_id = (
                            pgs[0]['ID'] if 'ingress' in pgs[0]['name']
                            else pgs[1]['ID'])
                    nuage_match_info = {
                        'description': direction + '_' + neutron_id,
                        'action': 'REDIRECT',
                        'DSCP': '*',
                        'locationType': "POLICYGROUP",
                        'locationID': policy_group_id,
                        'externalID': neutron_id,
                        'protocol': 'ANY',
                        'redirectVPortTagID': link[1]
                    }
                    if flow_classifier['ethertype'] == 'IPv4':
                        nuage_match_info['etherType'] = '0x0800'
                    else:
                        nuage_match_info['etherType'] = '0x86DD'
                    nuage_match_info['networkType'] = "ANY"
                    nuage_match_info['redirectRewriteType'] = 'VLAN'
                    nuage_match_info['vlanRange'] = vlan_label
                    if (flow_classifier['l7_parameters'] and
                            flow_classifier['l7_parameters'].get(
                                'vlan_range_min') and
                            flow_classifier['l7_parameters']
                            ['vlan_range_min']['value'] ==
                            flow_classifier['l7_parameters']
                            ['vlan_range_max']['value']):
                        new_vlan_value = (flow_classifier['l7_parameters']
                                          ['vlan_range_min']['value'])
                    else:
                        new_vlan_value = 0
                    nuage_match_info['redirectRewriteValue'] = new_vlan_value
                    rule = self.vsdclient.add_nuage_sfc_rule(adv_fwd_tmplt,
                                                             nuage_match_info,
                                                             np_id)
                    on_exc(self.vsdclient.delete_nuage_redirect_target_rule,
                           rule['ID'])
                elif (link[0] != link[1] and
                      flow_classifiers.index(flow_classifier) == 0):
                    pgs = ppg_pg_map.get(link[0])
                    rdts = ppg_rdts_map.get(link[1])
                    if direction == 'forward':
                        policy_group_id = (pgs[0]['ID'] if 'egress' in
                                                           pgs[0]['name']
                                           else pgs[1]['ID'])
                        redirect_target_id = (rdts[0]['ID'] if 'ingress' in
                                                               rdts[0]['name']
                                              else rdts[1]['ID'])
                    else:
                        policy_group_id = (pgs[0]['ID'] if 'ingress' in
                                                           pgs[0]['name']
                                           else pgs[1]['ID'])
                        redirect_target_id = (rdts[0]['ID'] if 'egress' in
                                                               rdts[0]['name']
                                              else rdts[1]['ID'])
                    nuage_match_info = {
                        'description': direction + '_' + neutron_id,
                        'action': 'REDIRECT',
                        'DSCP': '*',
                        'locationType': "POLICYGROUP",
                        'locationID': policy_group_id,
                        'redirectVPortTagID': redirect_target_id,
                        'externalID': neutron_id,
                        'networkType': 'ANY',
                        'protocol': 'ANY',
                    }
                    if flow_classifier['ethertype'] == 'IPv4':
                        nuage_match_info['etherType'] = '0x0800'
                    else:
                        nuage_match_info['etherType'] = '0x86DD'
                    nuage_match_info['redirectRewriteType'] = 'VLAN'
                    nuage_match_info['redirectRewriteValue'] = vlan_label
                    nuage_match_info['vlanRange'] = vlan_label
                    rule = self.vsdclient.add_nuage_sfc_rule(adv_fwd_tmplt,
                                                             nuage_match_info,
                                                             np_id)
                    on_exc(self.vsdclient.delete_nuage_redirect_target_rule,
                           rule['ID'])

    @staticmethod
    def _sfc_map_vsd_resource(nuage_resources):
        nuage_map = {}
        for nuage_resource in nuage_resources:
            resource_id = nuage_resource['name'].split('_')[-1]
            if nuage_map.get(resource_id):
                resource_list = nuage_map.get(resource_id)
                resource_list.append(nuage_resource)
                nuage_map[resource_id] = resource_list
            else:
                nuage_map[resource_id] = [nuage_resource]
        return nuage_map

    def _create_nuage_port_pair_group(self, context, on_exc,
                                      ports, ppg, one_ingress_egress=False):
        l2dom_id = None
        rtr_id = None
        l3subnet_id = None
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session,
            ports[0]['fixed_ips'][0]['subnet_id'])
        if subnet_mapping:
            if self._is_l2(subnet_mapping):
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3subnet_id = subnet_mapping['nuage_subnet_id']
                rtr_id = self.vsdclient.get_nuage_domain_id_from_subnet(
                    l3subnet_id)
        else:
            msg = ('Cannot find subnet mapping for'
                   ' the port-id %s ' % ports[0]['id'])
            raise nuage_exc.NuageBadRequest(msg=msg)
        insertion_mode = 'VIRTUAL_WIRE'
        if one_ingress_egress:
            dir_ppg = 'ingress_egress' + '_' + ppg['id']
        else:
            dir_ppg = ports[0]['direction'] + '_' + ppg['id']
        params = {'l2dom_id': l2dom_id,
                  'rtr_id': rtr_id,
                  'l3dom_id': rtr_id,
                  'dir_ppg': dir_ppg}
        nuage_sg_id = self._create_port_pair_policy_group(params)
        on_exc(self.vsdclient.delete_nuage_policy_group,
               nuage_sg_id)
        params['name'] = dir_ppg
        params['redundancy_enabled'] = 'false'
        params['insertion_mode'] = insertion_mode
        params['external_id'] = dir_ppg
        rt = self.vsdclient.create_nuage_redirect_target(
            params, l2dom_id=l2dom_id, domain_id=rtr_id)
        on_exc(self.vsdclient.delete_nuage_redirect_target, rt['ID'])
        nuage_port_ids = self._get_vports_for_ports(l2dom_id,
                                                    l3subnet_id,
                                                    ports)
        self.vsdclient.update_redirect_target_vports(rt['ID'],
                                                     nuage_port_ids)
        on_exc(self.vsdclient.update_redirect_target_vports,
               rt['ID'], [])

        self.vsdclient.update_vports_in_policy_group(nuage_sg_id,
                                                     nuage_port_ids)
        on_exc(self.vsdclient.update_vports_in_policy_group, nuage_sg_id, [])

    def _update_nuage_port_pair_group(self, context, on_exc, new_ports,
                                      old_ports,
                                      ppg, one_ingress_egress=False):
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session,
            new_ports[0]['fixed_ips'][0]['subnet_id'])
        if subnet_mapping:
            l2dom_id = None
            l3subnet_id = None
            if self._is_l2(subnet_mapping):
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3subnet_id = subnet_mapping['nuage_subnet_id']
            if one_ingress_egress:
                name = 'ingress_egress' + '_' + ppg['id']
            else:
                name = new_ports[0]['direction'] + '_' + ppg['id']
            param = {'name': name}
            rt = self.vsdclient.get_nuage_redirect_targets(param)
            external_id = cms_id_helper.get_vsd_external_id(name)
            pp_pg = self.vsdclient.get_nuage_policy_groups(
                required=False, externalID=external_id)
            if rt and pp_pg:
                new_nuage_port_ids = []
                old_nuage_port_ids = []
                common_ports = ([i for i in new_ports for j
                                 in old_ports if i['id'] == j['id']])
                if (len(common_ports) == len(new_ports) and
                        len(common_ports) == len(old_ports)):
                    return
                if common_ports:
                    diff_new_ports = ([i for i in new_ports for j
                                       in common_ports if i['id'] != j['id']])
                    diff_old_ports = ([i for i in old_ports for j
                                       in common_ports if i['id'] != j['id']])
                    new_nuage_port_ids = self._get_vports_for_ports(
                        l2dom_id,
                        l3subnet_id,
                        common_ports)
                    old_nuage_port_ids = copy.deepcopy(new_nuage_port_ids)
                else:
                    diff_new_ports = new_ports
                    diff_old_ports = old_ports
                new_nuage_port_ids += self._get_vports_for_ports(
                    l2dom_id,
                    l3subnet_id,
                    diff_new_ports)
                old_nuage_port_ids += self._get_vports_for_ports(
                    l2dom_id,
                    l3subnet_id,
                    diff_old_ports)
                self.vsdclient.update_redirect_target_vports(
                    rt[0]['ID'],
                    new_nuage_port_ids)
                on_exc(self.vsdclient.update_redirect_target_vports,
                       rt[0]['ID'], old_nuage_port_ids)
                self.vsdclient.update_vports_in_policy_group(
                    pp_pg[0]['ID'],
                    new_nuage_port_ids)
                on_exc(self.vsdclient.update_vports_in_policy_group,
                       pp_pg[0]['ID'], old_nuage_port_ids)
            else:
                msg = ("Cannot find rt or ppg mapping for"
                       " this port pair group on VSD")
                nuage_exc.NuageBadRequest(msg=msg)

    def _delete_nuage_port_pair_group(self, context, on_exc, ports,
                                      port_pair_group_dict,
                                      one_ingress_egress_port=False):
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session,
            ports[0]['fixed_ips'][0]['subnet_id'])
        if subnet_mapping:
            l2dom_id = None
            l3subnet_id = None
            if self._is_l2(subnet_mapping):
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3subnet_id = subnet_mapping['nuage_subnet_id']
            nuage_port_list = self._get_vports_for_ports(l2dom_id,
                                                         l3subnet_id, ports,
                                                         required=False)
            if one_ingress_egress_port:
                name = 'ingress_egress' + '_' + port_pair_group_dict['id']
            else:
                name = ports[0]['direction'] + '_' + port_pair_group_dict['id']
            param = {'name': name}
            rt = self.vsdclient.get_nuage_redirect_targets(param)
            if rt:
                self.vsdclient.update_redirect_target_vports(rt[0]['ID'], [])
                on_exc(self.vsdclient.update_redirect_target_vports,
                       rt[0]['ID'], nuage_port_list)
            external_id = cms_id_helper.get_vsd_external_id(name)
            pp_pg = self.vsdclient.get_nuage_policy_groups(
                required=False, externalID=external_id)
            if pp_pg:
                self.vsdclient.update_vports_in_policy_group(pp_pg[0]['ID'],
                                                             [])
                on_exc(self.vsdclient.update_vports_in_policy_group,
                       pp_pg[0]['ID'], nuage_port_list)
            if rt:
                self.vsdclient.delete_nuage_redirect_target(
                    rt[0]['ID'])
            if pp_pg:
                self.vsdclient.delete_nuage_policy_group(
                    pp_pg[0]['ID'])

    def _get_vports_for_ports(self, l2_dom_id, l3subnet_id,
                              ports, required=True):
        nuage_port_list = []
        params = {'l2dom_id': l2_dom_id}
        for port in ports:
            params['neutron_port_id'] = port['id']
            params['l3dom_id'] = l3subnet_id
            nuage_port = (self.vsdclient.get_nuage_vport_for_port_sec(
                params, required=required))
            if nuage_port:
                nuage_port_list.append(nuage_port['ID'])
        return nuage_port_list

    def _validate_create_port_pair_group(self, context, port_pair_group_dict):
        if len(port_pair_group_dict['port_pairs']) != 1:
            msg = 'Nuage only supports one port pair per port pair group'
            raise nuage_exc.NuageBadRequest(msg=msg)
        ingress_ports, egress_ports, one_ingress_egress_port = (
            self._validate_ppg(context, port_pair_group_dict))
        if one_ingress_egress_port:
            all_ports = ingress_ports
        else:
            all_ports = ingress_ports + egress_ports
        msg = ('Nuage only supports grouping of ports'
               ' belonging to one subnet')
        self._check_ports_on_same_l2_or_l3_domain(all_ports, msg)
        return ingress_ports, egress_ports, one_ingress_egress_port

    def _create_port_pair_policy_group(self, policy_group_details):
        params = {
            'externalID': policy_group_details['dir_ppg'],
            'l2dom_id': policy_group_details['l2dom_id'],
            'rtr_id': policy_group_details['rtr_id'],
            'type': constants.VM_VPORT,
            'sg_type': constants.SOFTWARE,
            'name': policy_group_details['dir_ppg'],
            'description': policy_group_details['dir_ppg']
        }
        nuage_sg_id = (self.vsdclient.
                       create_nuage_sec_grp_for_sfc(params))
        return nuage_sg_id
