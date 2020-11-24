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
import collections
import copy
import ipaddress
import logging

import netaddr

from neutron_lib import constants as lib_constants
from oslo_config import cfg

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.common import pg_helper
from nuage_neutron.vsdclient import restproxy

PROTO_NAME_TO_NUM = lib_constants.IP_PROTOCOL_MAP
VSD_RESP_OBJ = constants.VSD_RESP_OBJ
NUAGE_SUPPORTED_ETHERTYPES = constants.NUAGE_SUPPORTED_ETHERTYPES
NOT_SUPPORTED_ACL_ATTR_MSG = constants.NOT_SUPPORTED_ACL_ATTR_MSG
NUAGE_ACL_PROTOCOL_ANY_MAPPING = constants.NUAGE_ACL_PROTOCOL_ANY_MAPPING
RES_POLICYGROUPS = constants.RES_POLICYGROUPS
NOTHING_TO_UPDATE_ERR_CODE = constants.VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE
MIN_SG_PRI = 0
MAX_SG_PRI = 1000000000
ICMP_PROTOCOL_NUMS = [PROTO_NAME_TO_NUM['icmp'],
                      PROTO_NAME_TO_NUM['ipv6-icmp'],
                      PROTO_NAME_TO_NUM['icmpv6']]
STATEFUL_ICMP_V4_TYPES = [8, 13, 15, 17]
STATEFUL_ICMP_V6_TYPES = [128]

ANY_IPV4_IP = constants.ANY_IPV4_IP
ANY_IPV6_IP = constants.ANY_IPV6_IP

LOG = logging.getLogger(__name__)


class NuagePolicyGroups(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy
        self.flow_logging_enabled = cfg.CONF.PLUGIN.flow_logging_enabled
        self.stats_collection_enabled = (cfg.CONF.PLUGIN.
                                         stats_collection_enabled)
        self.policygroup_obj = nuagelib.Policygroup()

    @staticmethod
    def _get_vsd_external_id(neutron_id, pg_type):
        if pg_type == constants.HARDWARE:
            prefix = 'hw:'
        else:
            prefix = ''
        return get_vsd_external_id(prefix + neutron_id)

    @staticmethod
    def _get_resource_type(resource_type):
        if resource_type == constants.DOMAIN:
            return nuagelib.NuageL3Domain().resource
        elif resource_type == constants.L2DOMAIN:
            return nuagelib.NuageL2Domain().resource
        elif resource_type == constants.VPORT:
            return nuagelib.NuageVPort().resource

    def get_policygroup(self, pg_id, required=False, **filters):
        policy_groups = self.restproxy.get(
            self.policygroup_obj.show_url() % pg_id,
            extra_headers=self.policygroup_obj.extra_header_filter(**filters),
            required=required)
        if policy_groups:
            return policy_groups[0]

    def get_policygroups(self, required=False, parent_type=None,
                         parent_id=None, **filters):
        parent_type = self._get_resource_type(parent_type)
        return self.restproxy.get(
            self.policygroup_obj.get_url(parent=parent_type,
                                         parent_id=parent_id),
            extra_headers=self.policygroup_obj.extra_header_filter(**filters),
            required=required)

    def _get_policygroups_by_neutron_id(self, neutron_id):
        filters = {
            'externalID': [self._get_vsd_external_id(neutron_id, pg_type)
                           for pg_type in
                           (constants.HARDWARE, constants.SOFTWARE)]
        }
        return self.restproxy.get(
            self.policygroup_obj.get_url(),
            extra_headers=self.policygroup_obj.extra_header_filter(**filters))

    def get_vports_in_policygroup(self, pg_id):
        vport_obj = nuagelib.NuageVPort()
        return self.restproxy.get(
            vport_obj.get_url(parent=self.policygroup_obj.resource,
                              parent_id=pg_id),
            required=True)

    def find_security_groups_in_domain(self, sgs, domain_type, domain_id,
                                       domain_sg_pg_mapping,
                                       pg_type=constants.SOFTWARE):
        for sg_id in sgs:
            if sg_id in domain_sg_pg_mapping[domain_id]:
                # Already found
                continue
            pg = self.get_policygroup_in_domain(sg_id, domain_type,
                                                domain_id, pg_type)
            if pg:
                domain_sg_pg_mapping[domain_id][sg_id] = pg

    def find_create_security_groups(self, sgs, domain_type, domain_id,
                                    domain_enterprise_mapping,
                                    domain_sg_pg_mapping,
                                    domain_acl_mapping, on_exception,
                                    pg_type=constants.SOFTWARE,
                                    allow_non_ip=False):
        # Find PGs
        # If not found: create PGs
        # If not found: Create ACLs for created PGs
        # Result is stored in domain_sg_pg_mapping
        sgs_to_create = []
        for sg in sgs:
            if sg['id'] in domain_sg_pg_mapping[domain_id]:
                # Already found
                continue
            pg = self.get_policygroup_in_domain(sg['id'], domain_type,
                                                domain_id, pg_type)
            if not pg:
                sgs_to_create.append(sg)
            else:
                domain_sg_pg_mapping[domain_id][sg['id']] = pg
        # Create PG for all SG that where not found on domain
        sgs_to_create_rules_for = []
        for sg in sgs_to_create:
            try:
                pg = self._create_policygroup_for_securitygroup(
                    sg, domain_type, domain_id, pg_type)
                domain_sg_pg_mapping[domain_id][sg['id']] = pg
                sgs_to_create_rules_for.append(sg)
                on_exception(self.delete_policygroup, pg['ID'])
            except restproxy.RESTProxyError as e:
                if e.vsd_code == restproxy.REST_PG_EXISTS_ERR_CODE:
                    # PG is being concurrently created, do not create rules
                    pg = self.get_policygroup_in_domain(sg['id'], domain_type,
                                                        domain_id, pg_type)
                    domain_sg_pg_mapping[domain_id][sg['id']] = pg
        # Create ACL for the created PGs
        # This step does not need rollback, as it automatically deletes upon
        # PG deletion
        for sg in sgs_to_create_rules_for:
            pg = domain_sg_pg_mapping[domain_id][sg['id']]
            for sg_rule in sg['security_group_rules']:
                acl_entries = self.calculate_acl_entries(
                    sg_rule, pg['ID'], pg['parentType'], pg['parentID'],
                    sg['stateful'], domain_enterprise_mapping,
                    domain_sg_pg_mapping[domain_id], pg_type=pg['type'])
                for acl_entry in acl_entries:
                    self.create_acl_entry(acl_entry, domain_type, domain_id,
                                          domain_acl_mapping,
                                          on_exception=None)
        # Ensure default deny all rule is in place for HW
        if pg_type == constants.HARDWARE:
            deny_all_acl_template = self._find_or_create_deny_all_acl_template(
                domain_type, domain_id, allow_non_ip, direction='egress')
            for sg in sgs_to_create_rules_for:
                # Create deny all egress ACLEntryTemplate
                pg = domain_sg_pg_mapping[domain_id][sg['id']]
                acl_entry = {
                    'direction': 'egress',
                    'etherType': '0x0800',
                    'protocol': 'ANY',
                    'networkType': 'ANY',
                    'locationType': 'POLICYGROUP',
                    'locationID': pg['ID'],
                    'action': 'DROP',
                    'stateful': False,
                    'DSCP': '*',
                    'flowLoggingEnabled': False,
                    'statsLoggingEnabled': False,
                }
                self.create_acl_entry(acl_entry, domain_type, domain_id,
                                      domain_acl_mapping,
                                      on_exception,
                                      acl_template_id=deny_all_acl_template)

    def _find_or_create_deny_all_acl_template(self, domain_type, domain_id,
                                              allow_non_ip, direction):
        acltemplate_obj = nuagelib.ACLTemplate(direction)
        external_id = self._get_vsd_external_id(domain_id,
                                                constants.HARDWARE)
        filters = {'externalID': external_id}
        domain_resource_type = self._get_resource_type(domain_type)
        acltemplates = self.restproxy.get(
            acltemplate_obj.get_url(domain_resource_type, domain_id),
            extra_headers=acltemplate_obj.extra_header_filter(**filters),
            required=True)
        acl_template_id = acltemplates[0]['ID'] if acltemplates else None
        if not acl_template_id:
            name = 'hw:%s' % domain_id
            data = acltemplate_obj.post_data(
                name=name, external_id=external_id, allow_non_ip=allow_non_ip,
                priority=1)
            acl_template = self.restproxy.post(
                acltemplate_obj.post_url(domain_resource_type, domain_id),
                data,
                on_res_exists=self.restproxy.retrieve_by_cms_id_and_priority,
                ignore_err_codes=[restproxy.REST_DUPLICATE_ACL_PRIORITY])[0]
            acl_template_id = acl_template['ID']
        return acl_template_id

    def _create_policygroup_for_securitygroup(self, sg, domain_type, domain_id,
                                              pg_type):
        suffix = '_HARDWARE' if pg_type == constants.HARDWARE else ''
        data = {
            'description': sg['name'],
            'name': sg['id'] + suffix,
            'externalID': self._get_vsd_external_id(sg['id'], pg_type),
            'type': pg_type
        }
        return self.create_policygroup(domain_type, domain_id, data)

    def create_policygroup(self, domain_type, domain_id, pg_data,
                           raise_on_pg_exists=True):
        domain_resource_type = self._get_resource_type(domain_type)
        return self.restproxy.post(
            self.policygroup_obj.post_url(domain_resource_type, domain_id),
            pg_data,
            ignore_err_codes=(None if raise_on_pg_exists else
                              [restproxy.REST_PG_EXISTS_ERR_CODE]))[0]

    def get_policygroup_in_domain(self, sg_id, domain_type, domain_id,
                                  pg_type):
        filters = {
            'externalID': self._get_vsd_external_id(sg_id, pg_type)
        }
        domain_resource_type = self._get_resource_type(domain_type)
        pgs = self.restproxy.get(
            self.policygroup_obj.get_url(domain_resource_type, domain_id),
            extra_headers=self.policygroup_obj.extra_header_filter(**filters),
            required=True)
        return pgs[0] if pgs else None

    def update_security_group(self, security_group_id, updates):
        # Update PGs corresponding to SG
        pgs = self._get_policygroups_by_neutron_id(security_group_id)
        data = [dict(ID=pg['ID'], **updates) for pg in pgs]
        self.restproxy.bulk_put(self.policygroup_obj.bulk_url(), data)

    def delete_security_group(self, security_group_id):
        # Delete PGs corresponding to SG
        pgs = self._get_policygroups_by_neutron_id(security_group_id)
        self.restproxy.bulk_delete(self.policygroup_obj.bulk_url(),
                                   data=[pg['ID'] for pg in pgs])

    def delete_policygroup(self, policygroup_id):
        self.restproxy.delete(
            self.policygroup_obj.delete_url() % policygroup_id)

    def create_security_group_rule(self, sg, sg_rule, on_exception,
                                   remote_sgs=None):
        pgs = self._get_policygroups_by_neutron_id(sg['id'])
        domain_enterprise_mapping = {}
        # domainID -> {'ingress': ACL_ID, 'egress': ACL_ID}
        domain_acl_mapping = collections.defaultdict(
            lambda: {'ingress': None, 'egress': None})
        # domainID -> SG_ID -> PG
        domain_sg_pg_mapping = collections.defaultdict(dict)

        for pg in pgs:
            # Handle creation of remote security groups
            if remote_sgs:
                # All remote_sgs are of SOFTWARE type as remote_group_id is
                # not supported in HARDWARE environment
                self.find_create_security_groups(
                    remote_sgs, pg['parentType'], pg['parentID'],
                    domain_enterprise_mapping, domain_sg_pg_mapping,
                    domain_acl_mapping,
                    on_exception)
            # Handle rule creation domain per domain
            acl_entries = self.calculate_acl_entries(
                sg_rule, pg['ID'], pg['parentType'], pg['parentID'],
                sg['stateful'], domain_enterprise_mapping,
                domain_sg_pg_mapping[pg['parentID']], pg_type=pg['type'])
            for acl_entry in acl_entries:
                self.create_acl_entry(acl_entry, pg['parentType'],
                                      pg['parentID'], domain_acl_mapping,
                                      on_exception)

    def calculate_acl_entries(self, sg_rule, pg_id, domain_type, domain_id,
                              stateful, domain_enterprise_mapping,
                              sg_pg_mapping,
                              pg_type=constants.SOFTWARE):
        # domain_enterprise_mapping: cache for domain -> enterprise ID
        # sg_pg_mapping: cache for sg -> PG in the relevant domain

        # Calculate the acl entries that need to be created
        is_ipv6 = (sg_rule.get('ethertype',
                               constants.OS_IPV4) == constants.OS_IPV6)
        is_hardware = pg_type == constants.HARDWARE
        # Simulate stateful experience with stateless rules in two directions
        needs_reverse_rule = False
        # Hardware rules are always stateless
        stateful = stateful if not is_hardware else False
        acl_values = {
            'locationType': 'POLICYGROUP',
            'locationID': pg_id,
            'action': 'FORWARD',
            'DSCP': '*',
            'stateful': stateful,
            'flowLoggingEnabled': self.flow_logging_enabled
            if not is_hardware else False,
            'statsLoggingEnabled': self.stats_collection_enabled
            if not is_hardware else False,
            'direction': constants.DIRECTIONS_OS_VSD[sg_rule.get('direction')],
        }

        if sg_rule.get('id'):
            acl_values['externalID'] = self._get_vsd_external_id(
                sg_rule['id'], constants.SOFTWARE)

        # VSD etherType in hex value: 4 or 6
        if not is_ipv6:
            acl_values['etherType'] = constants.IPV4_ETHERTYPE
        else:
            acl_values['etherType'] = constants.IPV6_ETHERTYPE

        # VSD protocol in numerical value or ANY
        if not sg_rule.get('protocol'):
            acl_values['protocol'] = 'ANY'
        else:
            # Neutron Protocol can be numerical or string
            protocol = sg_rule['protocol']
            try:
                acl_values['protocol'] = int(protocol)
            except (ValueError, TypeError):
                if protocol == 'icmp' and is_ipv6:
                    protocol = 'ipv6-icmp'  # Change 1 to 58
                acl_values['protocol'] = lib_constants.IP_PROTOCOL_MAP[
                    protocol]

        # networkType
        if (sg_rule.get('remote_group_id') or
                sg_rule.get('remote_external_group_id')):
            acl_values['networkType'] = 'POLICYGROUP'
        elif sg_rule.get('remote_ip_prefix'):
            acl_values['networkType'] = 'ENTERPRISE_NETWORK'
        else:
            acl_values['networkType'] = 'ANY'

        # networkID
        if sg_rule.get('remote_external_group_id'):
            acl_values['networkID'] = sg_rule['remote_external_group_id']
        elif sg_rule.get('remote_ip_prefix'):
            # Create / fetch network macro
            ent_nw = self._create_enterprise_network_for_pg_sg_rule(
                domain_type, domain_id, sg_rule, domain_enterprise_mapping)
            acl_values['networkID'] = ent_nw['ID']
        elif sg_rule.get('remote_group_id'):
            # Remote PG are created first
            remote_pg_id = sg_pg_mapping[sg_rule['remote_group_id']]['ID']
            acl_values['networkID'] = remote_pg_id

        # sourcePort & destinationPort only applicable for tcp/udp
        if acl_values['protocol'] in [lib_constants.IP_PROTOCOL_MAP['tcp'],
                                      lib_constants.IP_PROTOCOL_MAP['udp']]:
            acl_values['sourcePort'] = '*'
            min_port = sg_rule.get('port_range_min')
            max_port = sg_rule.get('port_range_max')
            if min_port and max_port:
                if int(min_port) != int(max_port):
                    port_range = str(min_port) + '-' + str(max_port)
                else:
                    port_range = str(min_port)
            else:
                port_range = '*'
            acl_values['destinationPort'] = port_range

        # When a rule is ICMP: some redefinition is needed
        if acl_values['protocol'] in ICMP_PROTOCOL_NUMS:
            icmp_type = sg_rule.get('port_range_min')
            icmp_code = sg_rule.get('port_range_max')
            if icmp_type:
                acl_values['ICMPType'] = icmp_type
            if icmp_code:
                acl_values['ICMPCode'] = icmp_code
            # Redefine stateful parameter if necessary,
            # only when SG is stateful.
            # VSP supports stateful icmp only on very specific types
            if icmp_type not in (STATEFUL_ICMP_V4_TYPES +
                                 STATEFUL_ICMP_V6_TYPES):
                if stateful:
                    acl_values['stateful'] = False
                    needs_reverse_rule = True

        rules = [acl_values]
        if needs_reverse_rule:
            acl2_values = copy.deepcopy(acl_values)
            acl2_values['direction'] = sg_rule.get('direction')
            rules.append(acl2_values)
        return rules

    def _create_enterprise_network_for_pg_sg_rule(
            self, domain_type, domain_id, sg_rule, domain_enterprise_mapping):
        enterprise_id = domain_enterprise_mapping.get(domain_id)
        if not enterprise_id:
            # Find enterprise by fetching parent of PG
            enterprise_id = self._get_enterprise_id_by_domain(
                domain_type, domain_id)
            domain_enterprise_mapping[domain_id] = enterprise_id
        # Create / Fetch network macro
        params = {
            'externalID': enterprise_id + '@openstack'
        }
        remote_network = netaddr.IPNetwork(sg_rule['remote_ip_prefix'])
        if sg_rule['ethertype'] == constants.OS_IPV4:
            params['address'] = remote_network.ip
            params['netmask'] = remote_network.netmask
            params['IPType'] = constants.IPV4
        else:
            params['IPv6Address'] = str(remote_network)
            params['IPType'] = constants.IPV6

        # Name format: 'IPV4|6' _ 'longhand notation :/. -> -' _ 'prefixlength'
        params['name'] = (
            str(sg_rule['ethertype'] + '_' +
                ipaddress.ip_address(remote_network.ip).exploded.
                replace(':', '-').replace('.', '-') + '_' +
                str(remote_network.prefixlen)))
        # Assumption: enterprise network is going to exist more often than not
        enterprise_networks = self._get_enterprise_network(
            enterprise_id=enterprise_id, ip_type=params['IPType'],
            address=params.get('address'), netmask=params.get('netmask'),
            ipv6_address=params.get('IPv6Address'))
        if not enterprise_networks:
            enterprise_network_obj = nuagelib.EnterpriseNetwork()
            enterprise_networks = self.restproxy.post(
                enterprise_network_obj.post_url(parent='enterprises',
                                                parent_id=enterprise_id),
                data=params,
                on_res_exists=None,
                ignore_err_codes=[
                    restproxy.REST_NW_MACRO_EXISTS_INTERNAL_ERR_CODE])
        if not enterprise_networks:
            # Concurrent Create
            enterprise_networks = self._get_enterprise_network(
                enterprise_id=enterprise_id, ip_type=params['IPType'],
                address=params.get('address'), netmask=params.get('netmask'),
                ipv6_address=params.get('IPv6Address'), required=True)
        return enterprise_networks[0]

    def _get_enterprise_network(self, enterprise_id, ip_type,
                                address=None, netmask=None, ipv6_address=None,
                                required=False):
        ent_nw_obj = nuagelib.EnterpriseNetwork()
        if ip_type == constants.IPV4:
            filters = {'address': str(address), 'netmask': str(netmask)}
        else:
            filters = {'IPv6Address': str(ipv6_address)}

        return self.restproxy.get(
            ent_nw_obj.get_url(parent='enterprises',
                               parent_id=enterprise_id),
            extra_headers=ent_nw_obj.extra_header_filter(**filters),
            required=required)

    def _get_enterprise_id_by_domain(self, domain_type, domain_id):
        if domain_type == constants.DOMAIN:
            create_params = {'domain_id': domain_id}
            domain_obj = nuagelib.NuageL3Domain(create_params=create_params)
            return self.restproxy.get(
                domain_obj.get_resource(), required=True)[0]['parentID']
        else:
            domain_obj = nuagelib.NuageL2Domain()
            return self.restproxy.get(
                domain_obj.get_resource(domain_id),
                required=True)[0]['parentID']

    def create_acl_entry(self, acl_entry, domain_type, domain_id,
                         domain_acl_mapping,
                         on_exception, acl_template_id=None):
        direction = acl_entry.pop('direction')
        acl_template_id = acl_template_id or domain_acl_mapping[
            domain_id][direction]
        if not acl_template_id:
            acl_template_id = self._get_default_acl_template_by_domain(
                direction, domain_type, domain_id)['ID']
            domain_acl_mapping[domain_id][direction] = acl_template_id

        parent_type = nuagelib.ACLTemplate(direction).resource
        acl_entry_tmpl_obj = nuagelib.ACLEntryTemplate(direction)

        acl_entry = self.restproxy.post(
            acl_entry_tmpl_obj.post_url(parent=parent_type,
                                        parent_id=acl_template_id),
            acl_entry)
        if on_exception:
            on_exception(self.restproxy.delete,
                         acl_entry_tmpl_obj.delete_url() % acl_entry[0]['ID'])
        return acl_entry[0]

    def _get_default_acl_template_by_domain(self, direction, domain_type,
                                            domain_id):
        acltemplate_obj = nuagelib.ACLTemplate(direction)
        if domain_type == constants.DOMAIN:
            if direction == 'egress':
                name_suffix = constants.NUAGE_DEFAULT_L3_EGRESS_ACL
            else:
                name_suffix = constants.NUAGE_DEFAULT_L3_INGRESS_ACL
        else:
            if direction == 'egress':
                name_suffix = constants.NUAGE_DEFAULT_L2_EGRESS_ACL
            else:
                name_suffix = constants.NUAGE_DEFAULT_L2_INGRESS_ACL

        filters = {
            'name': domain_id + name_suffix
        }
        domain_resource_type = self._get_resource_type(domain_type)
        acltemplates = self.restproxy.get(
            acltemplate_obj.get_url(domain_resource_type, domain_id),
            extra_headers=acltemplate_obj.extra_header_filter(**filters),
            required=True)
        if not acltemplates:
            msg = ("No ACL mapping found for direction %s "
                   "in %s %s" % (direction, domain_type, domain_id))
            raise restproxy.ResourceConflictException(msg)
        return acltemplates[0]

    def update_vport_policygroups(self, vport_id, add_policygroups,
                                  remove_policygroups):
        resource = self.policygroup_obj.post_url(
            parent=nuagelib.NuageVPort().resource, parent_id=vport_id)
        if add_policygroups:
            self.restproxy.patch(resource, add_policygroups,
                                 constants.PATCH_ADD)
        if remove_policygroups:
            self.restproxy.patch(resource, remove_policygroups,
                                 constants.PATCH_REMOVE)

    def set_vports_in_policygroup(self, pg_id, vport_list):
        self.restproxy.put(
            self.policygroup_obj.show_url() % pg_id + '/vports' +
            '?responseChoice=1',
            vport_list)

    def delete_security_group_rule(self, sg_rule):
        filters = {
            'externalID': self._get_vsd_external_id(sg_rule['id'],
                                                    constants.SOFTWARE)}
        for _, vsd_direction in constants.DIRECTIONS_OS_VSD.items():
            acl_entry_tmpl_obj = nuagelib.ACLEntryTemplate(vsd_direction)
            # Get all acl entries corresponding to external ID
            acl_entries = self.restproxy.get(
                acl_entry_tmpl_obj.get_url(),
                extra_headers=acl_entry_tmpl_obj.extra_header_filter(
                    **filters))
            if acl_entries:
                # bulk delete
                self.restproxy.bulk_delete(
                    acl_entry_tmpl_obj.bulk_url(),
                    data=[acl_entry['ID'] for acl_entry in acl_entries])

    def delete_acl_entry(self, acl_id):
        for _, vsd_direction in constants.DIRECTIONS_OS_VSD.items():
            acl_entry_tmpl_obj = nuagelib.ACLEntryTemplate(vsd_direction)
            # Get all acl entries corresponding to external ID
            self.restproxy.delete(
                acl_entry_tmpl_obj.delete_url() % acl_id)

    def get_nuage_external_sg_rule(self, ext_rule_id):
        try:
            nuage_aclrule = nuagelib.ACLEntryTemplate('ingress')
            acl = self.restproxy.get(
                nuage_aclrule.show_url() % ext_rule_id,
                required=True)[0]
            acl['direction'] = 'ingress'
        except restproxy.ResourceNotFoundException:
            nuage_aclrule = nuagelib.ACLEntryTemplate('egress')
            acl = self.restproxy.get(
                nuage_aclrule.show_url() % ext_rule_id,
                required=True)[0]
            acl['direction'] = 'egress'
        return self._process_external_sg_rule(acl)

    def get_nuage_external_sg_rules(self, params):
        external_sg_id = params['external_group']
        external_sg = self.get_policygroup(external_sg_id, required=True)

        parent = external_sg['parentID']
        parent_type = external_sg['parentType']
        in_acl_id = self._get_default_acl_template_by_domain(
            'ingress', parent_type, parent)['ID']
        ob_acl_id = self._get_default_acl_template_by_domain(
            'egress', parent_type, parent)['ID']

        # get ingress/egress aclrules for policygroup_id
        in_acls = self._get_acl_by_remote_policygroup_id(
            in_acl_id, external_sg_id, direction='ingress')
        eg_acls = self._get_acl_by_remote_policygroup_id(
            ob_acl_id, external_sg_id, direction='egress')
        rules = []
        for in_acl in in_acls:
            rule = self._process_external_sg_rule(in_acl)
            rule['direction'] = 'ingress'
            rules.append(rule)
        for eg_acl in eg_acls:
            rule = self._process_external_sg_rule(eg_acl)
            rule['direction'] = 'egress'
            rules.append(rule)
        return rules

    def _get_acl_by_remote_policygroup_id(self, inaclid, policygroup_id,
                                          direction):
        acl_obj = nuagelib.ACLTemplate(direction)
        aclentry_obj = nuagelib.ACLEntryTemplate(direction)
        filters = {
            'networkID': policygroup_id
        }
        return self.restproxy.get(
            aclentry_obj.get_url(parent=acl_obj.resource, parent_id=inaclid),
            extra_headers=aclentry_obj.extra_header_filter(**filters),
            required=True)

    def _process_external_sg_rule(self, ext_sg_rule):
        if ext_sg_rule['locationID']:
            pol_group = self.get_policygroup(ext_sg_rule['locationID'],
                                             required=True)
            ext_sg_rule['origin_group_id'] = pol_group['name']
        if ext_sg_rule['networkType'] == 'POLICYGROUP' and (
                ext_sg_rule['networkID']):
            pol_group = self.get_policygroup(ext_sg_rule['networkID'],
                                             required=True)
            ext_sg_rule['remote_group_id'] = pol_group['name']

        return ext_sg_rule


class NuageRedirectTargets(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy
        self.flow_logging_enabled = cfg.CONF.PLUGIN.flow_logging_enabled
        self.stats_collection_enabled = (cfg.CONF.PLUGIN.
                                         stats_collection_enabled)

    def create_nuage_redirect_target(self, redirect_target, l2dom_id=None,
                                     domain_id=None):
        rtarget = nuagelib.NuageRedirectTarget()
        if l2dom_id:
            try:
                # Only the subnet redirect target's externalID is
                # network_id@cms_id.
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('external_id'))
                return self.restproxy.post(
                    rtarget.post_resource_l2dom(l2dom_id),
                    rtarget.post_rtarget_data(redirect_target))[0]
            except restproxy.ResourceNotFoundException:
                domain_id = helper._get_nuage_domain_id_from_subnet(
                    self.restproxy, l2dom_id)
        if domain_id:
            if redirect_target.get('router_id'):
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('router_id'))
            else:
                redirect_target['externalID'] = get_vsd_external_id(
                    redirect_target.get('external_id'))
            return self.restproxy.post(
                rtarget.post_resource_l3dom(domain_id),
                rtarget.post_rtarget_data(redirect_target))[0]

    def create_virtual_ip(self, rtarget_id, vip, vip_port_id):
        rtarget = nuagelib.NuageRedirectTarget()
        return self.restproxy.post(
            rtarget.post_virtual_ip(rtarget_id),
            rtarget.post_virtualip_data(vip, vip_port_id))

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

    def get_nuage_redirect_targets_by_single_filter(self, filters,
                                                    required=False):
        rtarget = nuagelib.NuageRedirectTarget()
        extra_headers = rtarget.single_filter_header(**filters)
        url = rtarget.get_all_redirect_targets()
        return self.restproxy.get(url, extra_headers=extra_headers,
                                  required=required)

    def get_child_redirect_targets(self, parent_resource, parent_id,
                                   required=False, **filters):
        redirect_target = nuagelib.NuageRedirectTarget()
        return self.restproxy.get(
            redirect_target.get_child_resource(parent_resource, parent_id),
            extra_headers=redirect_target.extra_header_filter(**filters),
            required=required)

    def delete_nuage_redirect_target(self, rtarget_id):
        rtarget = nuagelib.NuageRedirectTarget()
        self.restproxy.delete(rtarget.delete_redirect_target(rtarget_id))

    def delete_nuage_redirect_target_vip(self, rtarget_vip_id):
        rtarget = nuagelib.NuageRedirectTarget()
        self.restproxy.delete(rtarget.post_virtual_ip(rtarget_vip_id))

    def update_nuage_vport_redirect_target(self, rtarget_id, vport_id):
        rtarget = nuagelib.NuageRedirectTarget()
        self.restproxy.put(rtarget.get_vport_redirect_target(vport_id),
                           rtarget.put_vport_data(rtarget_id))

    def update_redirect_target_vports(self, redirect_target_id,
                                      nuage_port_id_list):
        rtarget = nuagelib.NuageRedirectTarget()
        self.restproxy.put(
            rtarget.get_redirect_target(redirect_target_id) + '/vports',
            nuage_port_id_list)

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
        vports = self.restproxy.get(
            nuage_vport.get_vport_redirect_target_resource(vport_id),
            required=True)
        return vports[0]['ID'] if vports else None

    def create_nuage_redirect_target_rule(self, params, rtarget=None):
        if not rtarget:
            rtarget_id = params['redirect_target_id']
            rtarget = self.get_nuage_redirect_target(rtarget_id)

        parent = rtarget['parentID']
        parent_type = rtarget['parentType']

        fwd_policy_id = helper.get_in_adv_fwd_policy(self.restproxy,
                                                     parent_type,
                                                     parent)
        np_id = None
        if parent_type == constants.DOMAIN:
            if not fwd_policy_id:
                msg = ("Router %s does not have policy mapping") \
                    % parent
                raise restproxy.ResourceConflictException(msg)

            np_id = helper.get_l3domain_np_id(self.restproxy,
                                              parent)
            if not np_id:
                msg = "Net Partition not found for l3domain %s " % parent
                raise restproxy.ResourceNotFoundException(msg)
        elif parent_type == constants.L2DOMAIN:
            if not fwd_policy_id:
                msg = ("L2Domain of redirect target %s does not have policy "
                       "mapping") % parent
                raise restproxy.ResourceConflictException(msg)

            fields = ['parentID', 'DHCPManaged']
            l2dom_fields = helper.get_l2domain_fields_for_pg(self.restproxy,
                                                             parent,
                                                             fields)
            np_id = l2dom_fields['parentID']
            if not np_id:
                msg = "Net Partition not found for l2domain %s " \
                      % parent
                raise restproxy.ResourceNotFoundException(msg)

        if (not params.get('remote_group_id') and
                not params.get('remote_ip_prefix')):
            if params.get('ethertype') == constants.OS_IPV6:
                params['remote_ip_prefix'] = ANY_IPV6_IP
            else:
                params['remote_ip_prefix'] = ANY_IPV4_IP

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
        fwd_rules = self.restproxy.post(
            nuage_fwdrule.in_post_resource(fwd_policy_id),
            nuage_match_info,
            on_res_exists=self.restproxy.retrieve_by_ext_id_and_priority,
            ignore_err_codes=[restproxy.REST_DUPLICATE_POLICY_ENTRY_PRIORITY]
        )
        return (self._process_redirect_target_rule(fwd_rules[0])
                if fwd_rules else None)

    def add_nuage_sfc_rule(self, fwd_policy, rule_params, np_id):
        fwd_policy_id = fwd_policy['ID']
        if rule_params.get('destination_ip_prefix'):
            netid = pg_helper.create_nuage_prefix_macro(
                self.restproxy, {'remote_ip_prefix': rule_params.get(
                    'destination_ip_prefix')}, np_id)
            rule_params['networkID'] = netid
        nuage_fwdrule = nuagelib.NuageAdvFwdRule()
        if rule_params['protocol'] != "ANY":
            rule_params['protocol'] = (PROTO_NAME_TO_NUM
                                       [rule_params['protocol']])
        rule_params['externalID'] = get_vsd_external_id(
            rule_params['externalID'])
        rule_params['flowLoggingEnabled'] = self.flow_logging_enabled
        rule_params['statsLoggingEnabled'] = self.stats_collection_enabled
        rule = self.restproxy.post(
            nuage_fwdrule.in_post_resource(fwd_policy_id),
            rule_params)
        return rule[0]

    def _map_nuage_redirect_target_rule(self, params):
        np_id = params['np_id']
        rtarget_rule = params.get('rtarget_rule')

        # rtarget_id = rtarget_rule.get('remote_target_id')
        # network_type = 'ENDPOINT_DOMAIN'
        nuage_match_info = {
            'etherType': constants.IPV4_ETHERTYPE,
            'action': rtarget_rule.get('action'),
            'DSCP': '*',
            'protocol': 'ANY',
            'priority': rtarget_rule.get('priority'),
            'flowLoggingEnabled': self.flow_logging_enabled,
            'statsLoggingEnabled': self.stats_collection_enabled,
        }
        min_port = max_port = None
        for key in list(rtarget_rule):
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
                netid = pg_helper.create_nuage_prefix_macro(
                    self.restproxy, rtarget_rule, np_id)
                nuage_match_info['networkID'] = netid
                nuage_match_info['networkType'] = "ENTERPRISE_NETWORK"
            elif str(key) == 'remote_group_id':
                nuage_match_info['networkID'] = (
                    rtarget_rule['remote_policygroup_id'])
                nuage_match_info['networkType'] = "POLICYGROUP"
            elif str(key) == 'origin_group_id':
                nuage_match_info['locationID'] = (
                    rtarget_rule['origin_policygroup_id'])
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
        nuage_policygroup = nuagelib.Policygroup()
        if rtarget_rule['locationID']:
            pol_groups = self.restproxy.get(
                nuage_policygroup.show_url() % rtarget_rule['locationID'],
                required=True)
            rtarget_rule['origin_group_id'] = pol_groups[0]['name']
        if rtarget_rule['networkType'] == 'POLICYGROUP' and (
                rtarget_rule['networkID']):
            pol_groups = self.restproxy.get(
                nuage_policygroup.show_url() % rtarget_rule['networkID'],
                required=True)
            rtarget_rule['remote_group_id'] = pol_groups[0]['name']

        return rtarget_rule

    def get_nuage_redirect_target_rules(self, params):
        rtarget_rule = nuagelib.NuageAdvFwdRule()
        parent = parent_type = None
        if params.get('subnet'):
            subnet_mapping = params.get('subnet_mapping')
            parent = helper.get_nuage_subnet(
                self.restproxy, subnet_mapping)['ID']
            parent_type = constants.L2DOMAIN
        elif params.get('router'):
            parent = helper.get_l3domid_by_router_id(self.restproxy,
                                                     params.get('router'))
            parent_type = constants.DOMAIN

        fwd_policy_id = helper.get_in_adv_fwd_policy(self.restproxy,
                                                     parent_type,
                                                     parent)
        adw_rules = self.restproxy.get(
            rtarget_rule.in_post_resource(fwd_policy_id),
            required=True)
        if not adw_rules:
            msg = "Could not find ingressadvfwdentrytemplates for " \
                  "ingressadvfwdtemplate %s "
            raise restproxy.ResourceNotFoundException(msg % fwd_policy_id)
        return [self._process_redirect_target_rule(r)
                for r in adw_rules]

    def get_nuage_redirect_target_rules_by_external_id(self, neutron_id):
        create_params = {'externalID': neutron_id}
        rtarget_rule = nuagelib.NuageAdvFwdRule(create_params=create_params)
        rtarget_rules_resp = self.restproxy.get(
            rtarget_rule.in_get_all_resources(),
            extra_headers=rtarget_rule.extra_headers_get())
        return rtarget_rules_resp

    def get_nuage_redirect_target_rule(self, rtarget_rule_id):
        rtarget_rule = nuagelib.NuageAdvFwdRule()
        adw_rules = self.restproxy.get(
            rtarget_rule.in_get_resource(rtarget_rule_id),
            required=True)
        return self._process_redirect_target_rule(adw_rules[0])

    def delete_nuage_redirect_target_rule(self, rtarget_rule_id):
        rtarget_rule = nuagelib.NuageAdvFwdRule()
        self.restproxy.delete(rtarget_rule.in_delete_resource(rtarget_rule_id))

    def nuage_redirect_targets_on_l2domain(self, l2domid):
        nuagel2dom = nuagelib.NuageL2Domain()
        rts = self.restproxy.get(
            nuagel2dom.nuage_redirect_target_get_resource(l2domid),
            required=True)
        return len(rts) > 0

    def get_redirect_target_vports(self, rtarget_id, required=False):
        vport = nuagelib.NuageVPort(create_params={'rtarget_id': rtarget_id})
        return self.restproxy.get(
            vport.get_vport_for_redirectiontargets(), required=required)
