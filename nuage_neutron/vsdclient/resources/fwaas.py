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
import netaddr

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common.helper import get_by_field_values
from nuage_neutron.vsdclient.common.nuagelib import FirewallAcl
from nuage_neutron.vsdclient.common.nuagelib import FirewallRule
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)

OS_ACTION_TO_VSD_ACTION = {
    'allow': 'FORWARD',
    'deny': 'DROP'
}
OS_ACTION_TO_VSD_STATEFUL = {
    'allow': True,
    'deny': False
}
OS_IPVERSION_TO_VSD_ETHERTYPE = {
    4: constants.IPV4_ETHERTYPE,
    6: constants.IPV6_ETHERTYPE
}


def copy(value):
    return value


class NuageFwaasBase(object):

    def __init__(self, restproxy):
        super(NuageFwaasBase, self).__init__()
        self.restproxy = restproxy

    def _vsd_fw_rule_by_os_id(self, enterprise_id, id, required=False):
        return self._get_by_openstack_id(
            FirewallRule, id, parent='enterprises', parent_id=enterprise_id,
            required=required)

    def _vsd_fw_acl_by_os_id(self, enterprise_id, id, required=False):
        return self._get_by_openstack_id(
            FirewallAcl, id, parent='enterprises', parent_id=enterprise_id,
            required=required)

    def _get_by_openstack_id(self, resource, id, parent=None, parent_id=None,
                             required=False):
        external_id = get_vsd_external_id(id)
        filter_header = FirewallRule.extra_header_filter(
            externalID=external_id)
        objects = self.get(resource, parent=parent, parent_id=parent_id,
                           extra_headers=filter_header)
        if not objects and required:
            raise restproxy.ResourceNotFoundException(
                "Can not find %s with externalID %s on vsd"
                % (resource.resource, external_id))
        return objects[0] if objects else None

    def get(self, resource, parent=None, parent_id=None, extra_headers=None):
        return self.restproxy.get(
            resource.get_url(parent=parent, parent_id=parent_id),
            extra_headers=extra_headers)

    def post(self, resource, data, extra_headers=None, on_res_exists=None,
             parent=None, parent_id=None):
        if on_res_exists is None:
            on_res_exists = self.restproxy.retrieve_by_external_id
        return self.restproxy.post(
            resource.post_url(parent=parent, parent_id=parent_id),
            data, extra_headers=extra_headers, on_res_exists=on_res_exists)[0]

    def put(self, resource, id, data, extra_headers=None):
        return self.restproxy.put(resource.put_url() % id, data,
                                  extra_headers=extra_headers)

    def delete(self, resource, id, extra_headers=None, required=False):
        return self.restproxy.delete(resource.delete_url() % id,
                                     extra_headers=extra_headers,
                                     required=required)


class NuageFwaasMapper(NuageFwaasBase):

    os_fwrule_to_vsd_fwrule = {
        'source_ip_address': [
            ('addressOverride',
             lambda x: str(netaddr.IPNetwork(x).cidr) if x else None)
        ],
        'name': [('description', copy)],
        'destination_ip_address': [
            ('networkID',
                lambda x: str(netaddr.IPNetwork(x).cidr) if x else None),
            ('networkType', lambda x: 'NETWORK' if x else None)
        ],
        'source_port': [
            ('sourcePort', lambda x: x.replace(':', '-') if x else None)
        ],
        'protocol': [
            ('protocol', lambda x: constants.PROTO_NAME_TO_NUM.get(x, 'ANY'))
        ],
        'destination_port': [
            ('destinationPort', lambda x: x.replace(':', '-') if x else None)
        ],
        'action': [('action', lambda x: OS_ACTION_TO_VSD_ACTION[x]),
                   ('stateful', lambda x: OS_ACTION_TO_VSD_STATEFUL[x])],
        'id': [('externalID', lambda x: get_vsd_external_id(x))],
        'ip_version': [
            ('etherType', lambda x: OS_IPVERSION_TO_VSD_ETHERTYPE.get(x))
        ]
    }

    os_fwpolicy_to_vsd_fwpolicy = {
        'name': [('name', copy)],
        'description': [('description', copy)],
        'id': [('externalID', lambda x: get_vsd_external_id(x))],
    }

    def do_mapping(self, mapping, object):
        result = {}
        for key in object:
            if key in mapping and key in object:
                for attr_mapping in mapping[key]:
                    result_key, method = attr_mapping
                    result[result_key] = method(object[key])
        return result

    def map_rule_os_to_vsd(self, os_rule, post=False):
        vsd_dict = self.do_mapping(self.os_fwrule_to_vsd_fwrule, os_rule)
        if post:
            vsd_dict.update({
                'locationType': 'ANY',
                'DSCP': '*'
            })
        return vsd_dict

    def map_policy_os_to_vsd(self, enterprise_id, os_policy, post=False):
        vsd_dict = self.do_mapping(self.os_fwpolicy_to_vsd_fwpolicy, os_policy)
        if os_policy.get('firewall_rules') is not None:
            external_ids = [get_vsd_external_id(os_rule_id)
                            for os_rule_id in os_policy['firewall_rules']]

            # build a list of VSD rules with the same order as the list of
            # os rules
            vsd_rules_ext_id_to_id = {
                rule['externalID']: rule['ID']
                for rule in get_by_field_values(self.restproxy, FirewallRule,
                                                'externalID', external_ids,
                                                parent='enterprises',
                                                parent_id=enterprise_id)
            }
            vsd_dict['ruleIds'] = [vsd_rules_ext_id_to_id[external_id]
                                   for external_id in external_ids
                                   if external_id in vsd_rules_ext_id_to_id]
        if post:
            vsd_dict.update({
                "defaultAllowIP": False,
                "defaultAllowNonIP": False,
            })
        return vsd_dict

    def map_rule_info_os_to_vsd(self, enterprise_id, os_rule_info,
                                insert=False):
        vsd_dict = {
            'type': 'firewallrules',
            'ids': [
                self._vsd_fw_rule_by_os_id(
                    enterprise_id,
                    os_rule_info.get('firewall_rule_id'),
                    required=True)['ID']
            ]
        }

        if insert:
            if os_rule_info.get('insert_before'):
                vsd_dict['insertLocation'] = 'BEFORE'
                vsd_dict['insertPositionID'] = self._vsd_fw_rule_by_os_id(
                    enterprise_id,
                    os_rule_info.get('insert_before'),
                    required=True)['ID']
            elif os_rule_info.get('insert_after'):
                vsd_dict['insertLocation'] = 'AFTER'
                vsd_dict['insertPositionID'] = self._vsd_fw_rule_by_os_id(
                    enterprise_id,
                    os_rule_info.get('insert_after'),
                    required=True)['ID']
            else:
                vsd_dict['insertLocation'] = 'START'

        return vsd_dict


class NuageFwaas(NuageFwaasMapper):

    # Firewall Rule

    def create_firewall_rule(self, enterprise_id, os_rule):
        data = self.map_rule_os_to_vsd(os_rule, post=True)
        return self.post(FirewallRule, data, parent='enterprises',
                         parent_id=enterprise_id)

    def update_firewall_rule(self, enterprise_id, id, os_rule):
        fw_rule = self._vsd_fw_rule_by_os_id(enterprise_id, id, required=True)
        data = self.map_rule_os_to_vsd(os_rule)
        if data:
            self.put(FirewallRule, fw_rule['ID'], data)

    def delete_firewall_rule(self, enterprise_id, id):
        fw_rule = self._vsd_fw_rule_by_os_id(enterprise_id, id)
        if fw_rule:
            self.delete(FirewallRule, fw_rule['ID'])

    def delete_vsd_firewallrule(self, id):
        self.delete(FirewallRule, id)

    # Firewall Policy

    def create_firewall_policy(self, enterprise_id, os_policy):
        data = self.map_policy_os_to_vsd(enterprise_id, os_policy, post=True)
        return self.post(FirewallAcl, data, parent='enterprises',
                         parent_id=enterprise_id)

    def update_firewall_policy(self, enterprise_id, id, os_policy):
        fw_acl = self._vsd_fw_acl_by_os_id(enterprise_id, id, required=True)
        data = self.map_policy_os_to_vsd(enterprise_id, os_policy)
        if data:
            self.put(FirewallAcl, fw_acl['ID'], data)

    def delete_firewall_policy(self, enterprise_id, id):
        fw_acl = self._vsd_fw_acl_by_os_id(enterprise_id, id)
        if fw_acl:
            self.delete(FirewallAcl, fw_acl['ID'])

    def insert_rule(self, enterprise_id, os_policy_id, os_rule_info):
        fw_acl = self._vsd_fw_acl_by_os_id(
            enterprise_id, os_policy_id, required=True)
        data = self.map_rule_info_os_to_vsd(enterprise_id, os_rule_info,
                                            insert=True)
        self.restproxy.put(FirewallAcl.insert_url() % fw_acl['ID'], data)

    def remove_rule(self, enterprise_id, os_policy_id, os_rule_info):
        fw_acl = self._vsd_fw_acl_by_os_id(
            enterprise_id, os_policy_id, required=True)
        data = self.map_rule_info_os_to_vsd(enterprise_id, os_rule_info)
        self.restproxy.put(FirewallAcl.remove_url() % fw_acl['ID'], data)

    def _create_drop_all_fw_acl(self, enterprise_id, firewall_id):
        policy = {'name': 'DROP_ALL_ACL_%s' % firewall_id,
                  'description': 'Drop all acl for firewall %s '
                                 'when admin_state_up=False'
                                 % firewall_id,
                  'id': firewall_id}
        return self.create_firewall_policy(enterprise_id, policy)

    def _delete_drop_all_fw_acl(self, enterprise_id, firewall_id):
        try:
            fw_acl = self._vsd_fw_acl_by_os_id(enterprise_id,
                                               firewall_id)
            self.restproxy.put(FirewallAcl.domains_url() % fw_acl['ID'],
                               [])
            self.delete(FirewallAcl, fw_acl['ID'])
        except restproxy.ResourceNotFoundException:
            pass

    # Firewall

    def create_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        handle_block_acl = os_firewall.get('admin_state_up', True) is False
        self._firewall_update(enterprise_id, os_firewall, l3domain_ids,
                              handle_block_acl=handle_block_acl)

    def update_firewall(self, enterprise_id, os_firewall, l3domain_ids,
                        admin_state_updated, routers_updated):
        if (os_firewall.get('admin_state_up') is False and
                admin_state_updated is False and routers_updated is False):
            return
        self._firewall_update(enterprise_id, os_firewall, l3domain_ids,
                              handle_block_acl=admin_state_updated)

    def delete_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        if os_firewall.get('admin_state_up', True) is False:
            self._delete_drop_all_fw_acl(enterprise_id, os_firewall['id'])
        else:
            self._firewall_update(enterprise_id, os_firewall, l3domain_ids)

    def _firewall_update(self, enterprise_id, os_firewall, l3domain_ids,
                         handle_block_acl=False):
        if os_firewall.get('admin_state_up', True):
            if handle_block_acl:
                self._delete_drop_all_fw_acl(enterprise_id, os_firewall['id'])
            if not os_firewall['firewall_policy_id']:
                return
            fw_acl = self._vsd_fw_acl_by_os_id(
                enterprise_id,
                os_firewall['firewall_policy_id'],
                required=True)
        else:
            if handle_block_acl:
                fw_acl = self._create_drop_all_fw_acl(enterprise_id,
                                                      os_firewall['id'])
            else:
                fw_acl = self._vsd_fw_acl_by_os_id(enterprise_id,
                                                   os_firewall['id'],
                                                   required=True)
        self.restproxy.put(FirewallAcl.domains_url() % fw_acl['ID'],
                           l3domain_ids)
