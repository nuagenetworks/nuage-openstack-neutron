# Copyright 2015 Alcatel-Lucent USA Inc.
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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils

LOG = logging.getLogger(__name__)


class NuageexternalsgMixin(object):

    @log_helpers.log_method_call
    def _make_external_security_group_dict(self, redirect_target,
                                           context=None, fields=None):
        res = {
            'id': redirect_target['ID'],
            'name': redirect_target['name'],
            'description': redirect_target['description'],
            'extended_community_id': redirect_target['EVPNCommunityTag']
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_nuage_external_security_group(self, context,
                                             nuage_external_security_group):
        external_sg = nuage_external_security_group[
            'nuage_external_security_group']
        subnet_id = external_sg.get('subnet_id')
        router_id = external_sg.get('router_id')

        l2dom_id = None
        l3dom_id = None
        if subnet_id:
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, subnet_id)
            if subnet_mapping:
                if subnet_mapping['nuage_l2dom_tmplt_id']:
                    l2dom_id = subnet_mapping['nuage_subnet_id']
        elif router_id:
            nuage_router = self.nuageclient.get_router_by_external(
                router_id)
            if nuage_router:
                l3dom_id = nuage_router['ID']
        params = {
            'l2dom_id': l2dom_id,
            'l3dom_id': l3dom_id,
            'name': external_sg.get('name'),
            'description': external_sg.get('description'),
            'extended_community': external_sg.get('extended_community_id')
        }
        ext_sg_resp = (
            self.nuageclient.create_nuage_external_security_group(
                params))
        return self._make_external_security_group_dict(ext_sg_resp[3][0],
                                                       context=context)

    @log_helpers.log_method_call
    def get_nuage_external_security_group(self, context, ext_sg_id,
                                          fields=None):
        try:
            ext_sg_resp = self.nuageclient.get_nuage_external_security_group(
                ext_sg_id)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group',
                resource_id=ext_sg_id)
        return self._make_external_security_group_dict(ext_sg_resp,
                                                       context=context,
                                                       fields=fields)

    @log_helpers.log_method_call
    def get_nuage_external_security_groups(self, context, filters=None,
                                           fields=None):
        # get all redirect targets
        resource_id = None
        params = {}
        if filters.get('subnet'):
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, filters['subnet'][0])
            if subnet_mapping:
                if not subnet_mapping['nuage_l2dom_tmplt_id']:
                    message = ("Subnet %s doesn't have mapping l2domain on "
                               "VSD " % filters['subnet'][0])
                    raise nuage_exc.NuageBadRequest(msg=message)
                params['subnet'] = filters.get('subnet')[0]
            else:
                message = ("Subnet %s doesn't have mapping l2domain on "
                           "VSD " % filters['subnet'][0])
                raise nuage_exc.NuageBadRequest(msg=message)
        elif filters.get('router'):
            params['router'] = filters.get('router')[0]
        elif filters.get('id'):
            params['id'] = filters.get('id')[0]
            resource_id = params['id']
        elif filters.get('name'):
            params['name'] = filters.get('name')[0]
            resource_id = params['name']

        try:
            ext_sgs = self.nuageclient.get_nuage_external_security_groups(
                params)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group',
                resource_id=resource_id)
        return [self._make_external_security_group_dict(sg, context, fields)
                for sg in ext_sgs]

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_nuage_external_security_group(self, context, ext_sg_id):
        self.nuageclient.delete_nuage_external_security_group(ext_sg_id)

    @log_helpers.log_method_call
    def get_nuage_external_security_groups_count(self, context, filters=None):
        return 0

    @log_helpers.log_method_call
    def _make_external_security_group_rule_dict(self, ext_sg_rule,
                                                context=None, fields=None):
        port_range_min = None
        port_range_max = None
        remote_group_id = None
        if ext_sg_rule['networkType'] == 'POLICYGROUP':
            remote_group_id = ext_sg_rule['remote_group_id']

        if ext_sg_rule['destinationPort']:
            port_range_min = '*'
            port_range_max = '*'
            if ext_sg_rule['destinationPort'] != port_range_max:
                destination_port = ext_sg_rule['destinationPort']
                port_range = destination_port.split('-')
                port_range_min = port_range[0]
                port_range_max = port_range[1]

        res = {
            'id': ext_sg_rule['ID'],
            'protocol': ext_sg_rule['protocol'],
            'direction': ext_sg_rule['direction'],
            'port_range_min': port_range_min,
            'port_range_max': port_range_max,
            'remote_external_group_id': remote_group_id,
            'origin_group_id': ext_sg_rule['origin_group_id']
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_nuage_external_security_group_rule(
            self, context, nuage_external_security_group_rule):
        external_sg_rule = (
            nuage_external_security_group_rule[
                'nuage_external_security_group_rule'])
        self._validate_redirect_target_port_range(external_sg_rule)
        rule_resp = self.nuageclient.create_nuage_external_sg_rule(
            external_sg_rule)
        rule_resp['direction'] = external_sg_rule['direction']
        return self._make_external_security_group_rule_dict(rule_resp,
                                                            context=context)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_nuage_external_security_group_rule(self, context, external_rule_id,
                                               fields=None):
        try:
            ext_rule_resp = (
                self.nuageclient.get_nuage_external_sg_rule(external_rule_id))
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group-rule',
                resource_id=external_rule_id)
        return self._make_external_security_group_rule_dict(ext_rule_resp,
                                                            context=context,
                                                            fields=fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_nuage_external_security_group_rule(self, context,
                                                  external_rule_id):
        self.nuageclient.delete_nuage_external_sg_rule(external_rule_id)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_nuage_external_security_group_rules(self, context, filters=None,
                                                fields=None):
        params = {}
        resource_id = None
        if filters.get('subnet'):
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, filters['subnet'][0])
            if subnet_mapping:
                if not subnet_mapping['nuage_l2dom_tmplt_id']:
                    message = ("Subnet %s doesn't have mapping l2domain on "
                               "VSD " % filters['subnet'][0])
                    raise nuage_exc.NuageBadRequest(msg=message)
                params['subnet'] = filters.get('subnet')[0]
            else:
                message = ("Subnet %s doesn't have mapping l2domain on "
                           "VSD " % filters['subnet'][0])
                raise nuage_exc.NuageBadRequest(msg=message)
        elif filters.get('router'):
            params['router'] = filters.get('router')[0]
        elif filters.get('external_group'):
            params['external_group'] = filters.get('external_group')[0]
            resource_id = params['external_group']
        try:
            ext_rules = self.nuageclient.get_nuage_external_sg_rules(
                params)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group-rule',
                resource_id=resource_id)

        return [self._make_external_security_group_rule_dict(ext_rule, context,
                                                             fields) for
                ext_rule in ext_rules]

    @log_helpers.log_method_call
    def get_nuage_external_security_group_rules_count(self, context,
                                                      filters=None):
        return 0
