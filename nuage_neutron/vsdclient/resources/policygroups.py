# Copyright 2016 NOKIA
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

import logging
import random

from oslo_config import cfg

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.common import pg_helper
from nuage_neutron.vsdclient import restproxy

from oslo_utils import excutils

VSD_RESP_OBJ = constants.VSD_RESP_OBJ
PROTO_NAME_TO_NUM = constants.PROTO_NAME_TO_NUM
NUAGE_NOTSUPPORTED_ETHERTYPE = constants.NUAGE_NOTSUPPORTED_ETHERTYPE
NUAGE_NOTSUPPORTED_ACL_MATCH = constants.NUAGE_NOTSUPPORTED_ACL_MATCH
NOT_SUPPORTED_ACL_ATTR_MSG = constants.NOT_SUPPORTED_ACL_ATTR_MSG
NUAGE_ACL_PROTOCOL_ANY_MAPPING = constants.NUAGE_ACL_PROTOCOL_ANY_MAPPING
RES_POLICYGROUPS = constants.RES_POLICYGROUPS
NOTHING_TO_UPDATE_ERR_CODE = constants.VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE
MIN_SG_PRI = 0
MAX_SG_PRI = 1000000000
STATEFUL_ICMP_TYPES = [8, 13, 15, 17]

LOG = logging.getLogger(__name__)


class NuagePolicyGroups(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy
        self.flow_logging_enabled = cfg.CONF.PLUGIN.flow_logging_enabled
        self.stats_collection_enabled = (cfg.CONF.PLUGIN.
                                         stats_collection_enabled)

    def _create_nuage_secgroup(self, params):
        rtr_id = params['nuage_router_id']
        l2dom_id = params['nuage_l2dom_id']

        req_params = {
            'name': params['name'],
            'sg_id': params.get('sg_id'),
            'externalID': params.get('externalID',
                                     get_vsd_external_id(params.get('sg_id')))
        }
        if rtr_id:
            req_params['domain_id'] = rtr_id
        elif l2dom_id:
            req_params['domain_id'] = l2dom_id
        if params.get('sg_type') == 'HARDWARE':
            req_params['sg_type'] = 'HARDWARE'

        nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
        if rtr_id:
            response = self.restproxy.rest_call(
                'POST', nuage_policygroup.post_resource(),
                nuage_policygroup.post_data())
        elif l2dom_id:
            response = self.restproxy.rest_call(
                'POST', nuage_policygroup.post_resource_l2dom(),
                nuage_policygroup.post_data())
        if not nuage_policygroup.validate(response):
            if response[0] != constants.CONFLICT_ERR_CODE:
                raise restproxy.RESTProxyError(nuage_policygroup.error_msg)
            else:
                LOG.debug(nuage_policygroup.error_msg)
                # Return already existing policygroup id
                # router
                if rtr_id:
                    nuage_policygroup_id = (
                        pg_helper.get_l3dom_policygroup_by_sgid(
                            self.restproxy, rtr_id, params.get('sg_id')))
                # l2 domain
                else:
                    nuage_policygroup_id = (
                        pg_helper.get_l2dom_policygroup_by_sgid(
                            self.restproxy,
                            l2dom_id, params.get('sg_id')))
                return nuage_policygroup_id

        nuage_policygroup_id = nuage_policygroup.get_policygroup_id(response)
        return nuage_policygroup_id

    def _delete_policy_group(self, id):
        nuage_policygroup = nuagelib.NuagePolicygroup()
        self.restproxy.delete(nuage_policygroup.delete_resource(id))

    def delete_policy_group(self, id):
        nuage_policygroup = self.get_sg_policygroup_mapping(id)
        if nuage_policygroup:
            l3dom_policygroup_list = nuage_policygroup['l3dom_policygroups']
            l2dom_policygroup_list = nuage_policygroup['l2dom_policygroups']

            for l3dom_policygroup in l3dom_policygroup_list:
                self._delete_policy_group(
                    l3dom_policygroup['policygroup_id'])

            for l2dom_policygroup in l2dom_policygroup_list:
                self._delete_policy_group(
                    l2dom_policygroup['policygroup_id'])

    def _validate_nuage_port_range(self, rule):
        if not rule['protocol']:
            msg = "protocol type required when port range is specified"
            raise restproxy.RESTProxyError(msg)
        ip_proto = rule['protocol']
        if ip_proto in ['tcp', 'udp']:
            if (rule['port_range_min'] is not None and
                    rule['port_range_min'] == 0):
                msg = ("Invalid port range, Port Number(0) must be between 1 "
                       "and 65535")
                raise restproxy.RESTProxyError(msg)

    def validate_nuage_sg_rule_definition(self, sg_rule):
        if 'ethertype' in sg_rule.keys():
            if str(sg_rule['ethertype']) in NUAGE_NOTSUPPORTED_ETHERTYPE:
                raise restproxy.RESTProxyError(NOT_SUPPORTED_ACL_ATTR_MSG)
        if (sg_rule['port_range_min'] is None and
                sg_rule['port_range_max'] is None):
            return
        self._validate_nuage_port_range(sg_rule)

    def _map_nuage_sgrule(self, params):
        sg_rule = params['neutron_sg_rule']
        np_id = params['np_id']
        policygroup_id = params['policygroup_id']
        l2dom_dhcp_managed = params.get('dhcp_managed')
        network_type = 'ENDPOINT_DOMAIN'
        if l2dom_dhcp_managed == 'unmanaged':
            network_type = 'ANY'
        nuage_match_info = {
            'etherType': '0x0800',
            'protocol': 'ANY',
            'networkType': network_type,
            'locationType': 'POLICYGROUP',
            'locationID': policygroup_id,
            'action': 'FORWARD',
            'stateful': True,
            'DSCP': '*',
            'flowLoggingEnabled': self.flow_logging_enabled,
            'statsLoggingEnabled': self.stats_collection_enabled,
            'priority': random.randint(MIN_SG_PRI, MAX_SG_PRI)
        }
        min_port = max_port = None
        for key in sg_rule.keys():
            if sg_rule[key] is not None:
                if str(key) == 'ethertype':
                    nuage_match_info['etherType'] = '0x0800'
                elif str(key) == 'protocol':
                    try:
                        # protocol passed in rule create is integer
                        # representation
                        float(sg_rule[key])
                        nuage_match_info['protocol'] = int(sg_rule[key])
                        if nuage_match_info['protocol'] in (
                                [PROTO_NAME_TO_NUM['tcp'],
                                 PROTO_NAME_TO_NUM['udp']]):
                            nuage_match_info['sourcePort'] = '*'
                            nuage_match_info['destinationPort'] = '*'
                    except (ValueError, TypeError):
                        # protocol passed in rule create is string
                        # representation
                        if sg_rule[key] == "ANY":
                            continue
                        nuage_match_info['protocol'] = \
                            PROTO_NAME_TO_NUM[str(sg_rule[key])]
                        if sg_rule[key] in ['tcp', 'udp']:
                            nuage_match_info['sourcePort'] = '*'
                            nuage_match_info['destinationPort'] = '*'
                elif str(key) == 'remote_ip_prefix':
                    netid = pg_helper._create_nuage_prefix_macro(
                        self.restproxy, sg_rule, np_id)
                    nuage_match_info['networkID'] = netid
                    nuage_match_info['networkType'] = "ENTERPRISE_NETWORK"
                elif str(key) == 'remote_group_id':
                    rtr_id = params.get('l3dom_id')
                    l2dom_id = params.get('l2dom_id')
                    if rtr_id:
                        remote_policygroup_id = (
                            pg_helper._get_remote_policygroup_id(
                                self.restproxy,
                                sg_rule[key], 'l3domain', rtr_id,
                                params.get('remote_group_name')))
                    else:
                        remote_policygroup_id = (
                            pg_helper._get_remote_policygroup_id(
                                self.restproxy,
                                sg_rule[key], constants.L2DOMAIN, l2dom_id,
                                params.get('remote_group_name')))
                    nuage_match_info['networkID'] = remote_policygroup_id
                    nuage_match_info['networkType'] = "POLICYGROUP"
                elif str(key) == 'remote_external_group':
                    nuage_match_info['networkID'] = sg_rule[key]
                    nuage_match_info['networkType'] = "POLICYGROUP"
                elif str(key) == 'port_range_max':
                    max_port = str(sg_rule[key])
                elif str(key) == 'port_range_min':
                    min_port = str(sg_rule[key])
        if min_port and max_port:
            if nuage_match_info['protocol'] in \
                    [PROTO_NAME_TO_NUM['tcp'], PROTO_NAME_TO_NUM['udp']]:
                port_str = min_port
                if int(min_port) != int(max_port):
                    port_str = port_str + '-' + max_port
                nuage_match_info['sourcePort'] = '*'
                nuage_match_info['destinationPort'] = port_str
        if nuage_match_info['protocol'] in [PROTO_NAME_TO_NUM['icmp']]:
            if min_port:
                nuage_match_info['ICMPType'] = min_port
            if max_port:
                nuage_match_info['ICMPCode'] = max_port
            if ((not min_port and not max_port) or
                    int(min_port) not in STATEFUL_ICMP_TYPES):
                nuage_match_info['stateful'] = False
        if params.get('sg_type') == 'HARDWARE':
            nuage_match_info['stateful'] = False

        return nuage_match_info

    def _create_nuage_sgrules_bulk(self, params):
        rtr_id = params['nuage_router_id']
        l2dom_id = params['nuage_l2dom_id']
        nuage_policygroup_id = params.get('nuage_policygroup_id')
        l3dom_policygroup_list = []
        l2dom_policygroup_list = []

        if rtr_id:
            l3dom_policygroup = {
                'l3dom_id': rtr_id,
                'policygroup_id': nuage_policygroup_id
            }
            l3dom_policygroup_list.append(l3dom_policygroup)
        elif l2dom_id:
            l2dom_policygroup = {
                'l2dom_id': l2dom_id,
                'policygroup_id': nuage_policygroup_id
            }
            l2dom_policygroup_list.append(l2dom_policygroup)

        policygroup = {
            'l3dom_policygroups': l3dom_policygroup_list,
            'l2dom_policygroups': l2dom_policygroup_list
        }
        sg_rules = params.get('sg_rules')

        if sg_rules:
            for rule in sg_rules:
                try:
                    params = {
                        'policygroup': policygroup,
                        'neutron_sg_rule': rule,
                    }
                    if 'ethertype' in rule.keys() and str(rule['ethertype']) \
                            in NUAGE_NOTSUPPORTED_ETHERTYPE:
                        continue
                    self.create_nuage_sgrule(params)
                except Exception:
                    raise

    def create_nuage_sgrule(self, params):
        neutron_sg_rule = params['neutron_sg_rule']
        policygroup_list = params['policygroup']
        l3dom_policygroup_list = policygroup_list['l3dom_policygroups']
        l2dom_policygroup_list = policygroup_list['l2dom_policygroups']
        sg_type = params.get('sg_type')
        remote_group_name = params.get('remote_group_name')
        external_id = params.get('externalID')

        for l3dom_policygroup in l3dom_policygroup_list:
            nuage_ibacl_id = pg_helper.get_l3dom_inbound_acl_id(
                self.restproxy,
                l3dom_policygroup['l3dom_id'])
            nuage_obacl_id = pg_helper.get_l3dom_outbound_acl_id(
                self.restproxy,
                l3dom_policygroup['l3dom_id'])

            if not nuage_ibacl_id and not nuage_obacl_id:
                msg = ("Router %s does not have ACL mapping"
                       % l3dom_policygroup['l3dom_id'])
                raise restproxy.RESTProxyError(msg)

            np_id = helper.get_l3domain_np_id(self.restproxy,
                                              l3dom_policygroup['l3dom_id'])
            if not np_id:
                msg = "Net Partition not found for l3domain %s " \
                      % l3dom_policygroup['l3dom_id']
                raise restproxy.RESTProxyError(msg)

            acl_mapping = {
                'nuage_iacl_id': nuage_ibacl_id,
                'nuage_oacl_id': nuage_obacl_id
            }

            sg_rule = dict(neutron_sg_rule)
            params = {
                'direction': sg_rule.get('direction'),
                'acl_mapping': acl_mapping,
                'neutron_sg_rule': sg_rule,
                'np_id': np_id,
                'policygroup_id': l3dom_policygroup['policygroup_id'],
                'rule_id': sg_rule.get('id'),
                'l3dom_id': l3dom_policygroup['l3dom_id'],
                'externalID': external_id
            }
            if sg_type:
                params['sg_type'] = sg_type
            if remote_group_name:
                params['remote_group_name'] = remote_group_name
            self._create_nuage_sgrule_process(params)

        for l2dom_policygroup in l2dom_policygroup_list:
            nuage_ibacl_id = pg_helper.get_l2dom_inbound_acl_id(
                self.restproxy,
                l2dom_policygroup['l2dom_id'])
            nuage_obacl_id = pg_helper.get_l2dom_outbound_acl_id(
                self.restproxy,
                l2dom_policygroup['l2dom_id'])

            if not nuage_ibacl_id and not nuage_obacl_id:
                msg = ("L2Domain of Security Group %s does not have ACL "
                       "mapping") % l2dom_policygroup['l2dom_id']
                raise

            fields = ['parentID', 'DHCPManaged']
            l2dom_fields = helper.get_l2domain_fields_for_pg(
                self.restproxy, l2dom_policygroup['l2dom_id'], fields)
            np_id = l2dom_fields['parentID']
            dhcp_managed = l2dom_fields['DHCPManaged']
            if not dhcp_managed:
                dhcp_managed = "unmanaged"
            if not np_id:
                msg = "Net Partition not found for l3domain %s " \
                      % l3dom_policygroup['l3dom_id']
                raise restproxy.RESTProxyError(msg)
            acl_mapping = {
                'nuage_iacl_id': nuage_ibacl_id,
                'nuage_oacl_id': nuage_obacl_id
            }

            sg_rule = dict(neutron_sg_rule)
            params = {
                'direction': sg_rule.get('direction'),
                'acl_mapping': acl_mapping,
                'neutron_sg_rule': sg_rule,
                'np_id': np_id,
                'policygroup_id': l2dom_policygroup['policygroup_id'],
                'rule_id': sg_rule.get('id'),
                'dhcp_managed': dhcp_managed,
                'l2dom_id': l2dom_policygroup['l2dom_id']
            }
            if sg_type:
                params['sg_type'] = sg_type
            if remote_group_name:
                params['remote_group_name'] = remote_group_name
            self._create_nuage_sgrule_process(params)

    def _create_nuage_sgrule_process(self, params):
        if params.get('sg_type') == 'HARDWARE':
            self._create_nuage_sgrule(params)
        else:
            if (not params['neutron_sg_rule'].get('remote_group_id') and
                    not params['neutron_sg_rule'].get('remote_ip_prefix')):
                params['neutron_sg_rule']['remote_ip_prefix'] = '0.0.0.0/0'
            if not params['neutron_sg_rule'].get('protocol'):
                params['neutron_sg_rule']['protocol'] = "ANY"
            # As VSP does not support stateful icmp with ICMPtype not in
            # [8,13,15,17], to be compatible with upstream openstack, create 2
            # non stateful icmp rules in egress and ingress direction for such
            # #types, for valid icmptypes create single stateful icmp rule
            if params['neutron_sg_rule'].get('protocol') == 'icmp':
                port_min = params['neutron_sg_rule'].get('port_range_min')
                port_max = params['neutron_sg_rule'].get('port_range_max')
                if ((not port_min and not port_max) or
                        port_min not in STATEFUL_ICMP_TYPES):
                    self._create_nuage_sgrule(params)
                    if params['neutron_sg_rule']['direction'] == 'ingress':
                        params['neutron_sg_rule']['direction'] = 'egress'
                        params['direction'] = 'egress'
                        self._create_nuage_sgrule(params)
                    elif params['neutron_sg_rule']['direction'] == 'egress':
                        params['neutron_sg_rule']['direction'] = 'ingress'
                        params['direction'] = 'ingress'
                        self._create_nuage_sgrule(params)
                elif port_min in STATEFUL_ICMP_TYPES:
                    self._create_nuage_sgrule(params)
            else:
                self._create_nuage_sgrule(params)

    def _create_nuage_sgrule(self, params):
        # neutron ingress is nuage egress and vice versa
        if params['neutron_sg_rule']['direction'] == 'ingress':
            acl_id = params['acl_mapping']['nuage_oacl_id']
        else:
            acl_id = params['acl_mapping']['nuage_iacl_id']
        req_params = {
            'acl_id': acl_id,
        }
        nuage_aclrule = nuagelib.NuageACLRule(create_params=req_params)
        nuage_match_info = self._map_nuage_sgrule(params)
        nuage_match_info['externalID'] = get_vsd_external_id(
            params.get('rule_id')) if params.get('rule_id') else params.get(
            'externalID')

        # neutron ingress is nuage egress and vice versa
        if params['neutron_sg_rule']['direction'] == 'ingress':
            url = nuage_aclrule.eg_post_resource()
        else:
            url = nuage_aclrule.in_post_resource()

        attempts = 3
        for i in range(attempts):
            try:
                return self.restproxy.post(url, nuage_match_info)[0]['ID']
            except restproxy.RESTProxyError as e:
                if (e.code == restproxy.REST_CONFLICT and
                        e.vsd_code ==
                        constants.VSD_PRIORITY_CONFLICT_ERR_CODE):
                    nuage_match_info['priority'] = random.randint(MIN_SG_PRI,
                                                                  MAX_SG_PRI)
                else:
                    raise
        raise restproxy.RESTProxyError("Failed to create aclentrytemplate "
                                       "after %s attempts due to priority "
                                       "conflict" % attempts)

    def _delete_nuage_sgrule(self, id, direction):
        nuage_aclrule = nuagelib.NuageACLRule()
        # neutron ingress is nuage egress and vice versa
        if direction == 'ingress':
            self.restproxy.rest_call('DELETE',
                                     nuage_aclrule.eg_delete_resource(id), '')
        else:
            self.restproxy.rest_call('DELETE',
                                     nuage_aclrule.in_delete_resource(id), '')

    def delete_nuage_sgrule(self, sg_rules):
        for rule in sg_rules:
            params = {
                'rule_id': rule['id'],
                'direction': rule['direction']
            }
            sgrule_acl = self.get_sgrule_acl_mapping_for_ruleid(params)
            if sgrule_acl:
                for acl_id in sgrule_acl:
                    self._delete_nuage_sgrule(acl_id, rule['direction'])
            # this handles the case where, rule with protocol icmp and
            # ICMPTYpe not in [8,13,15,17] with ingress direction
            # has an icmp rule in egress and vice versa
            if (rule.get('protocol') == 'icmp' and
                    rule.get('port_range_min') not in STATEFUL_ICMP_TYPES):
                if rule['direction'] == 'egress':
                    params = {
                        'rule_id': rule['id'],
                        'direction': 'ingress'
                    }
                else:
                    params = {
                        'rule_id': rule['id'],
                        'direction': 'egress'
                    }
                sgrule_acl = self.get_sgrule_acl_mapping_for_ruleid(params)
                # To do(Divya): try to use rule['direction'] instead of
                # params['direction']
                if sgrule_acl:
                    for acl_id in sgrule_acl:
                        self._delete_nuage_sgrule(acl_id, params['direction'])

    def update_vport_policygroups(self, vport_id, policygroup_ids):
        policygroups = nuagelib.NuagePolicygroup()
        self.restproxy.put(
            policygroups.put_child_resource(nuagelib.NuageVPort.resource,
                                            vport_id),
            policygroup_ids)

    def get_rate_limit(self, vport_id, neutron_fip_id):
        create_params = {'vport_id': vport_id,
                         'externalID': get_vsd_external_id(neutron_fip_id)}
        qos = nuagelib.NuageVportQOS(create_params)
        response = self.restproxy.rest_call(
            'GET',
            qos.get_all_resource(), '',
            extra_headers=qos.extra_headers_get())
        if not qos.get_validate(response):
            raise restproxy.RESTProxyError(qos.error_msg)
        fip_rate_values = {}
        egress_value = qos.get_response_obj(
            response).get('FIPPeakInformationRate')
        ingress_value = qos.get_response_obj(
            response).get('EgressFIPPeakInformationRate')
        fip_rate_values["egress_value"] = float(
            egress_value) * 1000 if egress_value != (
                '%s' % constants.INFINITY) else -1
        if ingress_value:
            fip_rate_values["ingress_value"] = float(
                ingress_value) * 1000 if ingress_value != (
                '%s' % constants.INFINITY) else -1
        return fip_rate_values

    def create_update_rate_limiting(self, fip_rate_values, vport_id,
                                    neutron_fip_id):
        data = {}
        for direction, value in fip_rate_values.iteritems():
            if float(value) == -1:
                value = constants.INFINITY
            elif 'kbps' in direction:
                value = float(value) / 1000
            if 'ingress' in direction:
                data["EgressFIPPeakInformationRate"] = value
            elif 'egress' in direction:
                data["FIPPeakInformationRate"] = value
        create_params = {'vport_id': vport_id,
                         'externalID': get_vsd_external_id(neutron_fip_id)}
        qos = nuagelib.NuageVportQOS(create_params)
        response = self.restproxy.rest_call(
            'GET',
            qos.get_all_resource(), '',
            extra_headers=qos.extra_headers_get())
        if not qos.validate(response):
            raise restproxy.RESTProxyError(qos.error_msg)
        if not response[3]:
            self.add_rate_limiting(data, vport_id, neutron_fip_id)
            return
        qos_obj = qos.get_response_obj(response)

        create_params = {'qos_id': qos_obj['ID']}
        qos = nuagelib.NuageVportQOS(create_params)
        response = self.restproxy.rest_call('PUT', qos.put_resource(), data)

        if (not qos.validate(response) and
                qos.vsd_error_code != NOTHING_TO_UPDATE_ERR_CODE):
            raise restproxy.RESTProxyError(qos.error_msg)

    def add_rate_limiting(self, rate_limit_values, vport_id, neutron_fip_id):
        data = {"FIPPeakBurstSize": 100,
                "EgressFIPPeakBurstSize": 100,
                "FIPRateLimitingActive": True,
                "active": True,
                "externalID": get_vsd_external_id(neutron_fip_id)}
        data.update(rate_limit_values)
        qos = nuagelib.NuageVportQOS({"name": "FIP Rate Limiting",
                                      "vport_id": vport_id}, data)
        response = self.restproxy.rest_call('POST',
                                            qos.post_resource(),
                                            qos.post_data())
        if not qos.validate(response):
            raise restproxy.RESTProxyError(qos.error_msg)

    def delete_rate_limiting(self, vport_id, neutron_fip_id):
        create_params = {'vport_id': vport_id,
                         'externalID': get_vsd_external_id(neutron_fip_id)}
        qos = nuagelib.NuageVportQOS(create_params)
        response = self.restproxy.rest_call(
            'GET', qos.get_all_resource(), '',
            extra_headers=qos.extra_headers_get())
        if not qos.validate(response):
            raise restproxy.RESTProxyError(qos.error_msg)
        if not response[3]:
            return

        qos_obj = qos.get_response_obj(response)

        create_params = {'qos_id': qos_obj['ID']}
        qos = nuagelib.NuageVportQOS(create_params)
        response = self.restproxy.rest_call('DELETE', qos.delete_resource(),
                                            '')
        if not qos.validate(response):
            raise restproxy.RESTProxyError(qos.error_msg)

    def get_sg_policygroup_mapping(self, sg_id):
        req_params = {
            'externalID': get_vsd_external_id(sg_id)
        }
        nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
        nuage_policygroup_extra_headers = nuage_policygroup.extra_headers_get()
        response = self.restproxy.rest_call(
            'GET',
            nuage_policygroup.get_all_resources(),
            '',
            extra_headers=nuage_policygroup_extra_headers)

        if not nuage_policygroup.validate(response):
            raise restproxy.RESTProxyError(nuage_policygroup.error_msg)

        l3dom_policygroup_list = []
        l2dom_policygroup_list = []
        if response[3]:
            for policygroup in response[3]:
                if policygroup['parentType'] == 'domain':
                    l3dom_policygroup = {
                        'l3dom_id': policygroup['parentID'],
                        'policygroup_id': policygroup['ID']
                    }
                    l3dom_policygroup_list.append(l3dom_policygroup)
                elif policygroup['parentType'] == constants.L2DOMAIN:
                    l2dom_policygroup = {
                        'l2dom_id': policygroup['parentID'],
                        'policygroup_id': policygroup['ID']
                    }
                    l2dom_policygroup_list.append(l2dom_policygroup)

        if not l3dom_policygroup_list and not l2dom_policygroup_list:
            result = None
        else:
            result = {
                'l3dom_policygroups': l3dom_policygroup_list,
                'l2dom_policygroups': l2dom_policygroup_list
            }

        return result

    def get_sgrule_acl_mapping_for_ruleid(self, params):
        acl_list = []
        # neutron ingress is egress on nuage and vice versa
        if params['direction'] == 'ingress':
            req_params = {
                'externalID': get_vsd_external_id(params['rule_id'])
            }
            nuage_aclrule = nuagelib.NuageACLRule(create_params=req_params)
            nuage_aclrule_extra_headers = nuage_aclrule.extra_headers_get()

            response = self.restproxy.rest_call(
                'GET', nuage_aclrule.eg_get_all_resources(), '',
                nuage_aclrule_extra_headers)
            if not nuage_aclrule.validate(response):
                raise restproxy.RESTProxyError(nuage_aclrule.error_msg)

            if response[3]:
                for nuage_acl in response[3]:
                    nuage_acl_id = nuage_acl['ID']
                    acl_list.append(nuage_acl_id)
        else:
            req_params = {
                'externalID': get_vsd_external_id(params['rule_id'])
            }
            nuage_aclrule = nuagelib.NuageACLRule(create_params=req_params)
            nuage_aclrule_extra_headers = nuage_aclrule.extra_headers_get()

            response = self.restproxy.rest_call(
                'GET', nuage_aclrule.in_get_all_resources(), '',
                nuage_aclrule_extra_headers)
            if not nuage_aclrule.validate(response):
                raise restproxy.RESTProxyError(nuage_aclrule.error_msg)

            if response[3]:
                for nuage_acl in response[3]:
                    nuage_acl_id = nuage_acl['ID']
                    acl_list.append(nuage_acl_id)

        return acl_list

    def _get_ingressacl_by_policygroup_id(self, inaclid, policygroup_id):
        req_params = {
            'acl_id': inaclid
        }
        nuage_acl = nuagelib.NuageACLRule(create_params=req_params)
        in_acls = self.restproxy.rest_call(
            'GET', nuage_acl.in_post_resource(), '',
            nuage_acl.extra_headers_get_locationID(policygroup_id))
        if not nuage_acl.validate(in_acls):
            raise restproxy.RESTProxyError(nuage_acl.error_msg)

        return in_acls

    def _get_egressacl_by_policygroup_id(self, egaclid, policygroup_id):
        req_params = {
            'acl_id': egaclid
        }
        nuage_acl = nuagelib.NuageACLRule(create_params=req_params)
        eg_acls = self.restproxy.rest_call(
            'GET', nuage_acl.eg_post_resource(), '',
            nuage_acl.extra_headers_get_locationID(policygroup_id))
        if not nuage_acl.validate(eg_acls):
            raise restproxy.RESTProxyError(nuage_acl.error_msg)

        return eg_acls

    def _get_ingressacl_by_remote_policygroup_id(self, inaclid,
                                                 policygroup_id):
        req_params = {
            'acl_id': inaclid
        }
        nuage_acl = nuagelib.NuageACLRule(create_params=req_params)
        in_acls = self.restproxy.rest_call(
            'GET', nuage_acl.in_post_resource(), '',
            nuage_acl.extra_headers_get_network_id(policygroup_id))
        if not nuage_acl.validate(in_acls):
            raise restproxy.RESTProxyError(nuage_acl.error_msg)

        return in_acls

    def _get_egressacl_by_remote_policygroup_id(self, egaclid, policygroup_id):
        req_params = {
            'acl_id': egaclid
        }
        nuage_acl = nuagelib.NuageACLRule(create_params=req_params)
        eg_acls = self.restproxy.rest_call(
            'GET', nuage_acl.eg_post_resource(), '',
            nuage_acl.extra_headers_get_network_id(policygroup_id))
        if not nuage_acl.validate(eg_acls):
            raise restproxy.RESTProxyError(nuage_acl.error_msg)

        return eg_acls

    def _check_policygroup_is_empty(self, policygroup_id, resource_type,
                                    resource_id):
        # get ingress/egress acl template
        if resource_type == constants.L2DOMAIN:
            nuage_ibacl_id = pg_helper.get_l2dom_inbound_acl_id(
                self.restproxy, resource_id)
            nuage_obacl_id = pg_helper.get_l2dom_outbound_acl_id(
                self.restproxy, resource_id)
        else:
            nuage_ibacl_id = pg_helper.get_l3dom_inbound_acl_id(
                self.restproxy, resource_id)
            nuage_obacl_id = pg_helper.get_l3dom_outbound_acl_id(
                self.restproxy, resource_id)

        # get ingress/egress aclrules for policygroup_id
        in_acls = self._get_ingressacl_by_policygroup_id(nuage_ibacl_id,
                                                         policygroup_id)
        eg_acls = self._get_egressacl_by_policygroup_id(nuage_obacl_id,
                                                        policygroup_id)

        if len(in_acls[VSD_RESP_OBJ]) > 0 or len(eg_acls[VSD_RESP_OBJ]) > 0:
            return False
        else:
            return True

    def _map_security_group_to_policygroup(self, security_group):
        return {
            'description': security_group['name'],
            'name': security_group['id'],
            'externalID': get_vsd_external_id(security_group['id']),
        }

    def create_security_group(self, parent_resource, parent_id,
                              security_group, sg_type=constants.SOFTWARE):
        vsd_data = self._map_security_group_to_policygroup(security_group)
        vsd_data['type'] = sg_type
        resource = nuagelib.Policygroup()
        return self.restproxy.post(resource.post_url(parent_resource.resource,
                                                     parent_id),
                                   vsd_data)[0]

    def process_port_create_security_group(self, params):
        to_rollback = []
        vsd_subnet = params['vsd_subnet']
        sg = params['sg']
        sg_rules = params['sg_rules']
        l3dom_id = None

        if vsd_subnet['type'] == constants.SUBNET:
            zone = helper.get_nuage_zone_by_id(
                self.restproxy, vsd_subnet['parentID'])
            l3dom_id = zone['nuage_parent_id']
            nuage_policygroup_id = pg_helper.get_l3dom_policygroup_by_sgid(
                self.restproxy, l3dom_id, sg['id'])
        else:
            nuage_policygroup_id = pg_helper.get_l2dom_policygroup_by_sgid(
                self.restproxy, vsd_subnet['ID'], sg['id'])

        create_params = {
            'nuage_router_id': l3dom_id,
            'nuage_l2dom_id': vsd_subnet['ID'],
            'name': sg['name'],
            'sg_id': sg['id'],
            'sg_rules': sg_rules
        }
        if not nuage_policygroup_id:
            try:
                nuage_policygroup_id = self._create_nuage_secgroup(
                    create_params)
                rollback_resource = {
                    'resource': RES_POLICYGROUPS,
                    'resource_id': nuage_policygroup_id
                }
                to_rollback.append(rollback_resource)
                create_params['nuage_policygroup_id'] = nuage_policygroup_id
                self._create_nuage_sgrules_bulk(create_params)
            except Exception:
                with excutils.save_and_reraise_exception():
                    helper.process_rollback(self.restproxy, to_rollback)
        return nuage_policygroup_id

    def get_policygroup_vport_mapping_by_port_id(self, vport_id):
        nuage_vport = nuagelib.NuageVPort()

        response = self.restproxy.rest_call(
            'GET',
            nuage_vport.get_vport_policygroup_resource(vport_id),
            '')

        if not nuage_vport.validate(response):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        policygroups = []
        if response[3]:
            for policygroup in response[3]:
                policygroup = {
                    'nuage_policygroup_id': policygroup['ID']
                }
                policygroups.append(policygroup)

        return policygroups

    # deprecated
    def delete_port_security_group_bindings(self, params):
        try:
            nuage_port = helper.get_nuage_vport_by_neutron_id(self.restproxy,
                                                              params)
        except restproxy.RESTProxyError as e:
            if e.code == 404:
                return
            else:
                raise e

        if nuage_port and nuage_port.get('ID'):
            nuage_vport_id = nuage_port['ID']
            policygroup_vport_list = (
                self.get_policygroup_vport_mapping_by_port_id(nuage_vport_id))
            if policygroup_vport_list:
                self.update_vport_policygroups(nuage_vport_id, [])
                # check for eager cleanup
                for pg_vport in policygroup_vport_list:
                    params = {"policygroup_id":
                              pg_vport['nuage_policygroup_id']}
                    nuage_vport = nuagelib.NuageVPort(create_params=params)
                    response = self.restproxy.rest_call(
                        'GET', nuage_vport.get_vports_for_policygroup(), '')
                    if (nuage_vport.validate(response) and
                            not nuage_vport.get_response_objlist(response)):
                        # pg no longer in use - delete it
                        self._delete_policy_group(
                            pg_vport['nuage_policygroup_id'])

    def check_unused_policygroups(self, securitygroup_ids):
        if not securitygroup_ids:
            return
        vsd_policygroup = nuagelib.NuagePolicygroup()
        filters = ["externalID IS '%s'" % get_vsd_external_id(sg_id)
                   for sg_id in securitygroup_ids]
        header = {'X-Nuage-Filter': " or ".join(filters)}

        policygroups = self.restproxy.get(vsd_policygroup.get_all_resources(),
                                          extra_headers=header)
        for policygroup in policygroups:
            pg_vports = self.restproxy.get(
                nuagelib.NuageVPort().get_child_resource(
                    vsd_policygroup.resource,
                    policygroup['ID']))
            if not pg_vports:
                # pg no longer in use - delete it
                self._delete_policy_group(policygroup['ID'])

    def create_policygroup_default_allow_any_rule(self, l2dom_id, rtr_id,
                                                  neutron_subnet_id, gw_type,
                                                  pg_name=None):
        sg_type = "SOFTWARE"
        if gw_type == "VSG":
            sg_type = "HARDWARE"
        params = {
            'nuage_router_id': rtr_id,
            'nuage_l2dom_id': l2dom_id,
            'name': 'defaultPG-' + neutron_subnet_id,
            'sg_id': None,
            'sg_type': sg_type,
            'externalID': get_vsd_external_id(neutron_subnet_id)
        }

        if pg_name:
            params['name'] = pg_name

        nuage_policygroup_id = self._create_nuage_secgroup(params)

        l3dom_policygroup_list = []
        l2dom_policygroup_list = []

        if rtr_id:
            l3dom_policygroup = {
                'l3dom_id': rtr_id,
                'policygroup_id': nuage_policygroup_id
            }
            l3dom_policygroup_list.append(l3dom_policygroup)
        elif l2dom_id:
            l2dom_policygroup = {
                'l2dom_id': l2dom_id,
                'policygroup_id': nuage_policygroup_id
            }
            l2dom_policygroup_list.append(l2dom_policygroup)

        # create default ingress and egress acl rule
        policygroup = {
            'l3dom_policygroups': l3dom_policygroup_list,
            'l2dom_policygroups': l2dom_policygroup_list
        }
        neutron_sg_rule = {
            'direction': 'ingress',
            'ethertype': 'ipv4'
        }
        params = {
            'policygroup': policygroup,
            'neutron_sg_rule': neutron_sg_rule,
            'sg_type': 'HARDWARE',
            'externalID': get_vsd_external_id(neutron_subnet_id)
        }
        self.create_nuage_sgrule(params)

        neutron_sg_rule = {
            'direction': 'egress',
            'ethertype': 'ipv4'
        }
        params = {
            'policygroup': policygroup,
            'neutron_sg_rule': neutron_sg_rule,
            'sg_type': 'HARDWARE',
            'externalID': get_vsd_external_id(neutron_subnet_id)
        }
        self.create_nuage_sgrule(params)

        return nuage_policygroup_id

    def create_nuage_external_security_group(self, params):
        l2dom_id = params.get('l2dom_id')
        l3dom_id = params.get('l3dom_id')

        req_params = {
            'name': params['name'],
            'description': params.get('description'),
            'extended_community': params.get('extended_community'),
            'externalID': get_vsd_external_id(params.get('externalID'))
        }
        if l3dom_id:
            req_params['domain_id'] = l3dom_id
        elif l2dom_id:
            req_params['domain_id'] = l2dom_id

        nuage_policygroup = nuagelib.NuagePolicygroup(create_params=req_params)
        if l3dom_id:
            response = self.restproxy.post(
                nuage_policygroup.post_resource(),
                nuage_policygroup.post_data_ext_sg())
        elif l2dom_id:
            response = self.restproxy.post(
                nuage_policygroup.post_resource_l2dom(),
                nuage_policygroup.post_data_ext_sg())
        return response

    def get_nuage_external_security_group(self, ext_sg_id):
        ext_policygroup = nuagelib.NuagePolicygroup()
        is_external = "true"
        extra_headers = ext_policygroup.extra_headers_get_external(is_external)

        ext_policygroup_resp = self.restproxy.rest_call(
            'GET', ext_policygroup.get_resource(ext_sg_id), '',
            extra_headers=extra_headers)
        if not ext_policygroup.get_validate(ext_policygroup_resp):
            raise restproxy.RESTProxyError(ext_policygroup.error_msg)

        return ext_policygroup_resp[3][0]

    def get_nuage_external_security_groups(self, params):
        ext_policygroup = nuagelib.NuagePolicygroup()
        is_external = "true"
        extra_headers = ext_policygroup.extra_headers_get_external(is_external)
        if not params:
            ext_policygroup_resp = self.restproxy.rest_call(
                'GET', ext_policygroup.get_all_resources(), '',
                extra_headers=extra_headers)
            if not ext_policygroup.validate(ext_policygroup_resp):
                raise restproxy.RESTProxyError(ext_policygroup.error_msg)
            return ext_policygroup_resp[3]
        if params.get('name'):
            extra_headers = (
                ext_policygroup.extra_headers_get_name_and_external(
                    params.get('name'), is_external))
            ext_policygroup_resp = self.restproxy.rest_call(
                'GET', ext_policygroup.get_all_resources(), '',
                extra_headers=extra_headers)
            if not ext_policygroup.get_validate(ext_policygroup_resp):
                raise restproxy.RESTProxyError(ext_policygroup.error_msg)
        elif params.get('id'):
            ext_policygroup_id = params.get('id')
            ext_policygroup_resp = self.restproxy.rest_call(
                'GET', ext_policygroup.get_resource(ext_policygroup_id), '',
                extra_headers=extra_headers)
            if not ext_policygroup.get_validate(ext_policygroup_resp):
                raise restproxy.RESTProxyError(ext_policygroup.error_msg)
        elif params.get('subnet'):
            subnet_mapping = params.get('subnet_mapping')
            l2dom_id = helper.get_nuage_subnet(
                self.restproxy, subnet_mapping)['ID']
            req_params = {
                'domain_id': l2dom_id
            }
            ext_policygroup.create_params = req_params
            ext_policygroup_resp = self.restproxy.rest_call(
                'GET', ext_policygroup.post_resource_l2dom(), '',
                extra_headers=extra_headers)
        elif params.get('router'):
            l3dom_id = helper.get_l3domid_by_router_id(self.restproxy,
                                                       params.get('router'))
            req_params = {
                'domain_id': l3dom_id
            }
            ext_policygroup.create_params = req_params
            ext_policygroup_resp = self.restproxy.rest_call(
                'GET', ext_policygroup.post_resource(), '',
                extra_headers=extra_headers)

        if not ext_policygroup.validate(ext_policygroup_resp):
            raise restproxy.RESTProxyError(ext_policygroup.error_msg)

        return ext_policygroup_resp[3]

    def delete_nuage_external_security_group(self, ext_sg_id):
        self._delete_policy_group(ext_sg_id)

    def _process_external_sg_rule(self, ext_sg_rule):
        nuage_policygroup = nuagelib.NuagePolicygroup()
        if ext_sg_rule['locationID']:
            policygroup_resp = self.restproxy.rest_call(
                'GET',
                nuage_policygroup.get_resource(ext_sg_rule['locationID']),
                '')
            if not nuage_policygroup.validate(policygroup_resp):
                raise restproxy.RESTProxyError(nuage_policygroup.error_msg)
            ext_sg_rule['origin_group_id'] = policygroup_resp[3][0]['name']
        if ext_sg_rule['networkType'] == 'POLICYGROUP' and (
                ext_sg_rule['networkID']):
            policygroup_resp = self.restproxy.rest_call(
                'GET',
                nuage_policygroup.get_resource(ext_sg_rule['networkID']),
                '')
            if not nuage_policygroup.validate(policygroup_resp):
                raise restproxy.RESTProxyError(nuage_policygroup.error_msg)
            ext_sg_rule['remote_group_id'] = policygroup_resp[3][0]['name']

        return ext_sg_rule

    def _create_nuage_external_sg_rule_params(self, ext_sg_rule, parent,
                                              parent_type):
        if parent_type == 'domain':
            if ext_sg_rule['direction'] == 'ingress':
                acl_id = pg_helper.get_l3dom_inbound_acl_id(
                    self.restproxy, parent)
            else:
                acl_id = pg_helper.get_l3dom_outbound_acl_id(
                    self.restproxy, parent)
            np_id = helper.get_l3domain_np_id(self.restproxy, parent)
            parent_type = 'l3domain'
        elif parent_type == constants.L2DOMAIN:
            if ext_sg_rule['direction'] == 'ingress':
                acl_id = pg_helper.get_l2dom_inbound_acl_id(
                    self.restproxy, parent)
            else:
                acl_id = pg_helper.get_l2dom_outbound_acl_id(
                    self.restproxy, parent)
            fields = ['parentID', 'DHCPManaged']
            l2dom_fields = helper.get_l2domain_fields_for_pg(
                self.restproxy, parent, fields)
            np_id = l2dom_fields['parentID']
            if not l2dom_fields['DHCPManaged']:
                l2dom_fields['DHCPManaged'] = "unmanaged"

        origin_policygroup_id = pg_helper._get_remote_policygroup_id(
            self.restproxy,
            ext_sg_rule['origin_group_id'], parent_type,
            parent,
            None)
        params = {
            'acl_id': acl_id,
            'direction': ext_sg_rule.get('direction'),
            'neutron_sg_rule': ext_sg_rule,
            'policygroup_id': origin_policygroup_id,
            'np_id': np_id
        }
        if parent_type == constants.L2DOMAIN:
            params['l2dom_id'] = parent
            params['dhcp_managed'] = l2dom_fields['DHCPManaged']
        else:
            params['l3dom_id'] = parent
        return params

    def create_nuage_external_sg_rule(self, params):
        external_sg_id = params['remote_external_group_id']
        external_sg = self.get_nuage_external_security_group(external_sg_id)
        params['remote_external_group'] = external_sg_id
        parent = external_sg['parentID']
        parent_type = external_sg['parentType']

        rule_params = self._create_nuage_external_sg_rule_params(
            params, parent, parent_type)
        rule_params['remote_external_group_name'] = external_sg['name']
        req_params = {
            'acl_id': rule_params['acl_id'],
        }
        nuage_aclrule = nuagelib.NuageACLRule(create_params=req_params)
        nuage_match_info = self._map_nuage_sgrule(rule_params)
        nuage_match_info['externalID'] = external_sg['externalID']

        # neutron ingress is nuage egress and vice versa
        if params['direction'] == 'ingress':
            response = self.restproxy.rest_call(
                'POST',
                nuage_aclrule.in_post_resource(),
                nuage_match_info)
        else:
            response = self.restproxy.rest_call(
                'POST',
                nuage_aclrule.eg_post_resource(),
                nuage_match_info)
        if not nuage_aclrule.validate(response):
            raise restproxy.RESTProxyError(nuage_aclrule.error_msg)

        if response[3]:
            rule = self._process_external_sg_rule(response[3][0])

        return rule

    def get_nuage_external_sg_rules(self, params):
        in_acl_id = None
        ob_acl_id = None
        external_sg_id = params['external_group']
        external_sg = self.get_nuage_external_security_group(external_sg_id)

        parent = external_sg['parentID']
        parent_type = external_sg['parentType']
        if parent_type == 'domain':
            in_acl_id = pg_helper.get_l3dom_inbound_acl_id(self.restproxy,
                                                           parent)
            ob_acl_id = pg_helper.get_l3dom_outbound_acl_id(self.restproxy,
                                                            parent)
        elif parent_type == constants.L2DOMAIN:
            in_acl_id = pg_helper.get_l2dom_inbound_acl_id(
                self.restproxy, parent)
            ob_acl_id = pg_helper.get_l2dom_outbound_acl_id(
                self.restproxy, parent)

        # get ingress/egress aclrules for policygroup_id
        in_acls = self._get_ingressacl_by_remote_policygroup_id(
            in_acl_id, external_sg_id)
        eg_acls = self._get_egressacl_by_remote_policygroup_id(
            ob_acl_id, external_sg_id)
        rules = []
        for in_acl in in_acls[3]:
            rule = self._process_external_sg_rule(in_acl)
            rule['direction'] = 'ingress'
            rules.append(rule)
        for eg_acl in eg_acls[3]:
            rule = self._process_external_sg_rule(eg_acl)
            rule['direction'] = 'egress'
            rules.append(rule)
        return rules

    def get_nuage_external_sg_rule(self, ext_rule_id):
        nuage_aclrule = nuagelib.NuageACLRule()
        in_acl = self.restproxy.rest_call(
            'GET', nuage_aclrule.in_delete_resource(ext_rule_id), '')
        if not nuage_aclrule.get_validate(in_acl):
            eg_acl = self.restproxy.rest_call(
                'GET', nuage_aclrule.eg_delete_resource(ext_rule_id), '')
            if not nuage_aclrule.get_validate(eg_acl):
                raise restproxy.RESTProxyError(nuage_aclrule.error_msg)
            eg_acl
            ext_rule = eg_acl
            ext_rule[3][0]['direction'] = 'egress'
        else:
            ext_rule = in_acl
            ext_rule[3][0]['direction'] = 'ingress'

        rule = self._process_external_sg_rule(ext_rule[3][0])
        return rule

    def delete_nuage_external_sg_rule(self, ext_rule_id):
        nuage_aclrule = nuagelib.NuageACLRule()
        del_resp = self.restproxy.rest_call(
            'DELETE', nuage_aclrule.in_delete_resource(ext_rule_id), '')
        if not nuage_aclrule.delete_validate(del_resp):
            del_resp = self.restproxy.rest_call(
                'DELETE', nuage_aclrule.eg_delete_resource(ext_rule_id), '')
            if not nuage_aclrule.delete_validate(del_resp):
                raise restproxy.RESTProxyError(nuage_aclrule.error_msg)

    def create_nuage_sec_grp_for_port_sec(self, params):
        l2dom_id = params['l2dom_id']
        rtr_id = params['rtr_id']
        append_str = ((l2dom_id or rtr_id) +
                      '_' + params.get('type'))
        params_sg = {
            'nuage_l2dom_id': l2dom_id,
            'nuage_router_id': rtr_id,
            'description': constants.NUAGE_PLCY_GRP_FOR_SPOOFING,
            'name': (constants.NUAGE_PLCY_GRP_FOR_SPOOFING +
                     '_' + append_str),
            'sg_id': (constants.NUAGE_PLCY_GRP_FOR_SPOOFING +
                      '_' + append_str),
            'sg_type': params['sg_type']
        }
        return self._create_nuage_secgroup(params_sg)

    def create_nuage_sec_grp_rule_for_port_sec(self, params):
        nuage_ibacl_details = {}
        nuage_obacl_id = None
        pg_id = params['sg_id']
        l2dom_id = params['l2dom_id']
        rtr_id = params['rtr_id']
        in_parameters = {
            'rule_id': None,
            'direction': 'ingress',
        }
        out_parameters = {
            'rule_id': None,
            'direction': 'egress',
        }
        if l2dom_id:
            nuage_ibacl_details = pg_helper.get_inbound_acl_details(
                self.restproxy, l2dom_id, type=constants.L2DOMAIN)
            nuage_obacl_id = pg_helper.get_l2dom_outbound_acl_id(
                self.restproxy, l2dom_id)
        elif rtr_id:
            nuage_ibacl_details = pg_helper.get_inbound_acl_details(
                self.restproxy, rtr_id)
            nuage_obacl_id = pg_helper.get_l3dom_outbound_acl_id(
                self.restproxy, rtr_id)
        nuage_ibacl_id = nuage_ibacl_details.get('ID')
        external_id = nuage_ibacl_details.get('externalID')
        if external_id:
            in_parameters['rule_id'] = external_id.split('@')[0]
            out_parameters['rule_id'] = external_id.split('@')[0]
        in_sec_rule = self.get_sgrule_acl_mapping_for_ruleid(in_parameters)
        out_sec_rule = self.get_sgrule_acl_mapping_for_ruleid(
            out_parameters)
        req_params = {'acl_id': nuage_ibacl_id}
        extra_params = {'locationID': pg_id,
                        'externalID': external_id,
                        'flowLoggingEnabled': self.flow_logging_enabled,
                        'statsLoggingEnabled': self.stats_collection_enabled}
        if len(in_sec_rule) == 0:
            nuage_ib_aclrule = nuagelib.NuageACLRule(create_params=req_params,
                                                     extra_params=extra_params)
            self.restproxy.post(nuage_ib_aclrule.in_post_resource(),
                                nuage_ib_aclrule.post_data_for_spoofing())
        req_params = {'acl_id': nuage_obacl_id}
        if len(out_sec_rule) == 0:
            nuage_ob_aclrule = nuagelib.NuageACLRule(create_params=req_params,
                                                     extra_params=extra_params)
            self.restproxy.post(nuage_ob_aclrule.eg_post_resource(),
                                nuage_ob_aclrule.post_data_for_spoofing())

    def get_policy_group(self, id, required=False, **filters):
        policy_group = nuagelib.NuagePolicygroup()
        policy_groups = self.restproxy.get(
            policy_group.get_resource(id),
            extra_headers=policy_group.extra_header_filter(**filters),
            required=required)
        if policy_groups:
            return policy_groups[0]

    def get_policy_groups(self, required=False, **filters):
        policy_group = nuagelib.NuagePolicygroup()
        return self.restproxy.get(
            policy_group.get_all_resources(),
            extra_headers=policy_group.extra_header_filter(**filters),
            required=required)

    def get_child_policy_groups(self, parent_resource, parent_id,
                                required=False, **filters):
        policy_group = nuagelib.NuagePolicygroup()
        return self.restproxy.get(
            policy_group.get_child_resource(parent_resource, parent_id),
            extra_headers=policy_group.extra_header_filter(**filters),
            required=required)


class NuageRedirectTargets(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy
        self.flow_logging_enabled = cfg.CONF.PLUGIN.flow_logging_enabled
        self.stats_collection_enabled = (cfg.CONF.PLUGIN.
                                         stats_collection_enabled)

    def create_nuage_redirect_target(self, redirect_target, subnet_id=None,
                                     domain_id=None):
        rtarget = nuagelib.NuageRedirectTarget()
        if subnet_id:
            try:
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('subnet_id'))
                return self.restproxy.post(
                    rtarget.post_resource_l2dom(subnet_id),
                    rtarget.post_rtarget_data(redirect_target))[0]
            except restproxy.ResourceNotFoundException:
                domain_id = helper._get_nuage_domain_id_from_subnet(
                    self.restproxy, subnet_id)
        if domain_id:
            if redirect_target.get('router_id'):
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('router_id'))
            else:
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('subnet_id'))
            return self.restproxy.post(
                rtarget.post_resource_l3dom(domain_id),
                rtarget.post_rtarget_data(redirect_target))[0]

    def create_virtual_ip(self, rtarget_id, vip, vip_port_id):
        rtarget = nuagelib.NuageRedirectTarget()
        vip_resp = self.restproxy.rest_call(
            'POST',
            rtarget.post_virtual_ip(rtarget_id),
            rtarget.post_virtualip_data(vip, vip_port_id))
        if not rtarget.validate(vip_resp):
            raise restproxy.RESTProxyError(rtarget.error_msg)

        return vip_resp

    def get_nuage_redirect_target(self, rtarget_id):
        rtarget = nuagelib.NuageRedirectTarget()
        rtarget_resp = self.restproxy.get(
            rtarget.get_redirect_target(rtarget_id))
        if rtarget_resp:
            return rtarget_resp[0]

    def get_nuage_redirect_targets(self, filters):
        rtarget = nuagelib.NuageRedirectTarget()
        extra_headers = rtarget.extra_header_filter(**filters)
        url = rtarget.get_all_redirect_targets()
        return self.restproxy.get(url, extra_headers=extra_headers)

    def get_child_redirect_targets(self, parent_resource, parent_id,
                                   required=False, **filters):
        redirect_target = nuagelib.NuageRedirectTarget()
        return self.restproxy.get(
            redirect_target.get_child_resource(parent_resource, parent_id),
            extra_headers=redirect_target.extra_header_filter(**filters),
            required=required)

    def delete_nuage_redirect_target(self, rtarget_id):
        rtarget = nuagelib.NuageRedirectTarget()
        del_resp = self.restproxy.rest_call(
            'DELETE', rtarget.delete_redirect_target(rtarget_id), '')
        if not rtarget.validate(del_resp):
            raise restproxy.RESTProxyError(rtarget.error_msg)

    def delete_nuage_redirect_target_vip(self, rtarget_vip_id):
        rtarget = nuagelib.NuageRedirectTarget()
        vip_resp = self.restproxy.rest_call(
            'DELETE',
            rtarget.post_virtual_ip(rtarget_vip_id), '')
        if not rtarget.validate(vip_resp):
            raise restproxy.RESTProxyError(rtarget.error_msg)

    def update_nuage_vport_redirect_target(self, rtarget_id, vport_id):
        rtarget = nuagelib.NuageRedirectTarget()
        response = self.restproxy.rest_call(
            'PUT',
            rtarget.get_vport_redirect_target(vport_id),
            rtarget.put_vport_data(rtarget_id))
        if not rtarget.validate(response):
            raise restproxy.RESTProxyError(rtarget.error_msg,
                                           rtarget.vsd_error_code)

    def delete_port_redirect_target_bindings(self, params):
        nuage_port = helper.get_nuage_vport_by_neutron_id(self.restproxy,
                                                          params)
        if nuage_port and nuage_port.get('ID'):
            nuage_vport_id = nuage_port['ID']
            rtarget_id = (
                self.get_rtarget_vport_mapping_by_port_id(nuage_vport_id))
            if rtarget_id:
                rtarget_id = None
                self.update_nuage_vport_redirect_target(rtarget_id,
                                                        nuage_vport_id)

    def get_rtarget_vport_mapping_by_port_id(self, vport_id):
        nuage_vport = nuagelib.NuageVPort()

        response = self.restproxy.rest_call(
            'GET',
            nuage_vport.get_vport_redirect_target_resource(vport_id), '')

        if not nuage_vport.validate(response):
            raise restproxy.RESTProxyError(nuage_vport.error_msg)

        if response[3]:
            return response[3][0]['ID']

    def create_nuage_redirect_target_rule(self, params):
        rtarget_id = params['redirect_target_id']
        rtarget = self.get_nuage_redirect_target(rtarget_id)

        parent = rtarget['parentID']
        parent_type = rtarget['parentType']

        fwd_policy_id = helper.get_in_adv_fwd_policy(self.restproxy,
                                                     parent_type,
                                                     parent)

        if parent_type == 'domain':
            if not fwd_policy_id:
                msg = ("Router %s does not have policy mapping") \
                    % parent
                raise restproxy.RESTProxyError(msg)

            np_id = helper.get_l3domain_np_id(self.restproxy,
                                              parent)
            if not np_id:
                msg = "Net Partition not found for l3domain %s " % parent
                raise restproxy.RESTProxyError(msg)
        elif parent_type == constants.L2DOMAIN:
            if not fwd_policy_id:
                msg = ("L2Domain of redirect target %s does not have policy "
                       "mapping") % parent
                raise restproxy.RESTProxyError(msg)

            fields = ['parentID', 'DHCPManaged']
            l2dom_fields = helper.get_l2domain_fields_for_pg(self.restproxy,
                                                             parent,
                                                             fields)
            np_id = l2dom_fields['parentID']
            dhcp_managed = l2dom_fields['DHCPManaged']
            if not dhcp_managed:
                dhcp_managed = "unmanaged"
            if not np_id:
                msg = "Net Partition not found for l2domain %s " \
                      % parent
                raise restproxy.RESTProxyError(msg)

        if (not params.get('remote_group_id') and
                not params.get('remote_ip_prefix')):
            params['remote_ip_prefix'] = '0.0.0.0/0'

        rule_params = {
            'rtarget_rule': params,
            'np_id': np_id,
            'parent_type': parent_type,
            'parent': parent
        }
        nuage_fwdrule = nuagelib.NuageAdvFwdRule()
        nuage_match_info = self._map_nuage_redirect_target_rule(rule_params)
        nuage_match_info['externalID'] = rtarget['externalID']

        # neutron ingress is nuage egress and vice versa
        response = self.restproxy.rest_call(
            'POST', nuage_fwdrule.in_post_resource(fwd_policy_id),
            nuage_match_info)
        if not nuage_fwdrule.validate(response):
            raise restproxy.RESTProxyError(nuage_fwdrule.error_msg)

        if response[3]:
            rule = self._process_redirect_target_rule(response[3][0])

        return rule

    def _map_nuage_redirect_target_rule(self, params):
        np_id = params['np_id']
        rtarget_rule = params.get('rtarget_rule')

        # rtarget_id = rtarget_rule.get('remote_target_id')
        # network_type = 'ENDPOINT_DOMAIN'
        nuage_match_info = {
            'etherType': '0x0800',
            'action': rtarget_rule.get('action'),
            'DSCP': '*',
            'protocol': 'ANY',
            'priority': rtarget_rule.get('priority'),
            'flowLoggingEnabled': self.flow_logging_enabled,
            'statsLoggingEnabled': self.stats_collection_enabled,
        }
        min_port = max_port = None
        for key in rtarget_rule.keys():
            if rtarget_rule[key] is None:
                continue
            if str(key) == 'protocol':
                nuage_match_info['protocol'] = int(rtarget_rule[key])
                if nuage_match_info['protocol'] in (
                        [PROTO_NAME_TO_NUM['tcp'],
                         PROTO_NAME_TO_NUM['udp']]):
                    nuage_match_info['reflexive'] = True
                    nuage_match_info['sourcePort'] = '*'
                    nuage_match_info['destinationPort'] = '*'
            elif str(key) == 'remote_ip_prefix':
                netid = pg_helper._create_nuage_prefix_macro(
                    self.restproxy, rtarget_rule, np_id)
                nuage_match_info['networkID'] = netid
                nuage_match_info['networkType'] = "ENTERPRISE_NETWORK"
            elif str(key) == 'remote_group_id':
                if params.get('parent_type') == 'domain':
                    remote_policygroup_id = (
                        pg_helper._get_remote_policygroup_id(
                            self.restproxy,
                            rtarget_rule[key], 'l3domain',
                            params.get('parent'),
                            rtarget_rule.get('remote_group_name')))
                else:
                    remote_policygroup_id = (
                        pg_helper._get_remote_policygroup_id(
                            self.restproxy,
                            rtarget_rule[key], constants.L2DOMAIN,
                            params.get('parent'),
                            rtarget_rule.get('remote_group_name')))
                nuage_match_info['networkID'] = remote_policygroup_id
                nuage_match_info['networkType'] = "POLICYGROUP"
            elif str(key) == 'origin_group_id':
                if params.get('parent_type') == 'domain':
                    origin_policygroup_id = (
                        pg_helper._get_remote_policygroup_id(
                            self.restproxy,
                            rtarget_rule[key], 'l3domain',
                            params.get('parent'),
                            rtarget_rule.get('remote_group_name')))
                else:
                    origin_policygroup_id = (
                        pg_helper._get_remote_policygroup_id(
                            self.restproxy,
                            rtarget_rule[key], constants.L2DOMAIN,
                            params.get('parent'),
                            rtarget_rule.get('remote_group_name')))
                nuage_match_info['locationID'] = origin_policygroup_id
                nuage_match_info['locationType'] = "POLICYGROUP"
            elif str(key) == 'port_range_max':
                max_port = str(rtarget_rule[key])
            elif str(key) == 'port_range_min':
                min_port = str(rtarget_rule[key])
            elif str(key) == 'redirect_target_id':
                nuage_match_info['redirectVPortTagID'] = rtarget_rule[key]
        if min_port and max_port:
            if nuage_match_info['protocol'] in [6, 17]:
                port_str = min_port
                if int(min_port) != int(max_port):
                    port_str = port_str + '-' + max_port
                nuage_match_info['sourcePort'] = '*'
                nuage_match_info['destinationPort'] = port_str
        return nuage_match_info

    def _process_redirect_target_rule(self, rtarget_rule):
        nuage_policygroup = nuagelib.NuagePolicygroup()
        if rtarget_rule['locationID']:
            policygroup_resp = self.restproxy.rest_call(
                'GET',
                nuage_policygroup.get_resource(rtarget_rule['locationID']),
                '')
            if not nuage_policygroup.validate(policygroup_resp):
                raise restproxy.RESTProxyError(nuage_policygroup.error_msg)
            rtarget_rule['origin_group_id'] = policygroup_resp[3][0]['name']
        if rtarget_rule['networkType'] == 'POLICYGROUP' and (
                rtarget_rule['networkID']):
            policygroup_resp = self.restproxy.rest_call(
                'GET',
                nuage_policygroup.get_resource(rtarget_rule['networkID']),
                '')
            if not nuage_policygroup.validate(policygroup_resp):
                raise restproxy.RESTProxyError(nuage_policygroup.error_msg)
            rtarget_rule['remote_group_id'] = policygroup_resp[3][0]['name']

        return rtarget_rule

    def get_nuage_redirect_target_rules(self, params):
        rtarget_rule = nuagelib.NuageAdvFwdRule()
        if params.get('subnet'):
            subnet_mapping = params.get('subnet_mapping')
            parent = helper.get_nuage_subnet(
                self.restproxy, subnet_mapping)['ID']
            parent_type = constants.L2DOMAIN
        elif params.get('router'):
            parent = helper.get_l3domid_by_router_id(self.restproxy,
                                                     params.get('router'))
            parent_type = 'domain'

        fwd_policy_id = helper.get_in_adv_fwd_policy(self.restproxy,
                                                     parent_type,
                                                     parent)
        rtarget_rules_resp = self.restproxy.rest_call(
            'GET', rtarget_rule.in_post_resource(fwd_policy_id), '')

        if not rtarget_rule.get_validate(rtarget_rules_resp):
            raise restproxy.RESTProxyError(rtarget_rule.error_msg)

        rules = []
        for rtarget_rule in rtarget_rules_resp[3]:
            rule = self._process_redirect_target_rule(rtarget_rule)
            rules.append(rule)

        return rules

    def get_nuage_redirect_target_rule(self, rtarget_rule_id):
        rtarget_rule = nuagelib.NuageAdvFwdRule()

        rtarget_rule_resp = self.restproxy.rest_call(
            'GET', rtarget_rule.in_get_resource(rtarget_rule_id), '')
        if not rtarget_rule.get_validate(rtarget_rule_resp):
            raise restproxy.RESTProxyError(rtarget_rule.error_msg)

        rule = self._process_redirect_target_rule(rtarget_rule_resp[3][0])
        return rule

    def delete_nuage_redirect_target_rule(self, rtarget_rule_id):
        rtarget_rule = nuagelib.NuageAdvFwdRule()
        del_resp = self.restproxy.rest_call(
            'DELETE', rtarget_rule.in_delete_resource(rtarget_rule_id), '')
        if not rtarget_rule.validate(del_resp):
            raise restproxy.RESTProxyError(rtarget_rule.error_msg)

    def nuage_redirect_targets_on_l2domain(self, l2domid):
        nuagel2dom = nuagelib.NuageL2Domain()
        response = self.restproxy.rest_call(
            'GET',
            nuagel2dom.nuage_redirect_target_get_resource(l2domid),
            '')
        found = response[VSD_RESP_OBJ] and len(response[VSD_RESP_OBJ]) > 0
        return found

    def get_redirect_target_vports(self, rtarget_id, required=False):
        vport = nuagelib.NuageVPort(create_params={'rtarget_id': rtarget_id})
        return self.restproxy.get(
            vport.get_vport_for_redirectiontargets(),
            required=False)
