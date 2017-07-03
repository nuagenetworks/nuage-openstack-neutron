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
        objects = self.get(resource, parent=parent, parent_id=parent_id,
                           externalID=external_id)
        if not objects and required:
            raise restproxy.ResourceNotFoundException(
                "Can not find %s with externalID %s on vsd"
                % (resource.resource, external_id))
        return objects[0] if objects else None

    def get(self, resource, parent=None, parent_id=None, **filters):
        headers = resource.extra_header_filter(**filters)
        return self.restproxy.get(
            resource.get_url(parent=parent, parent_id=parent_id),
            extra_headers=headers)

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
            vsd_rules = self.get(FirewallRule, parent='enterprises',
                                 parent_id=enterprise_id)
            rule_map = {rule.get('externalID', '').split('@')[0]: rule['ID']
                        for rule in vsd_rules}
            vsd_dict['ruleIds'] = []
            for os_rule_id in os_policy.get('firewall_rules'):
                try:
                    vsd_dict['ruleIds'].append(rule_map[os_rule_id])
                except KeyError:
                    # A rule can not exist on VSD when it's disabled.
                    pass
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

    # Firewall

    def create_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self._firewall_update(enterprise_id, os_firewall, l3domain_ids)

    def update_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self._firewall_update(enterprise_id, os_firewall, l3domain_ids)

    def delete_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self._firewall_update(enterprise_id, os_firewall, l3domain_ids)

    def _firewall_update(self, enterprise_id, os_firewall, l3domain_ids):
        if not os_firewall['firewall_policy_id']:
            return
        fw_acl = self._vsd_fw_acl_by_os_id(enterprise_id,
                                           os_firewall['firewall_policy_id'],
                                           required=True)
        self.restproxy.put(FirewallAcl.domains_url() % fw_acl['ID'],
                           l3domain_ids)
