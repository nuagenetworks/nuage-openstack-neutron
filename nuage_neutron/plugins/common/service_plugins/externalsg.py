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
import collections

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron._i18n import _
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common import constants as vsd_constants


LOG = logging.getLogger(__name__)


class NuageexternalsgMixin(nuage_utils.SubnetUtilsBase):

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

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_external_security_group(self, context,
                                             nuage_external_security_group):
        external_sg = nuage_external_security_group[
            'nuage_external_security_group']
        subnet_id = external_sg.get('subnet_id')
        router_id = external_sg.get('router_id')

        if not subnet_id and not router_id:
            msg = _("Either router_id or subnet_id must be specified")
            raise n_exc.BadRequest(resource='nuage_external_security_group',
                                   msg=msg)

        domain_type = None
        domain_id = None
        external_id = None
        if subnet_id:
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, subnet_id)
            if subnet_mapping and self._is_l2(subnet_mapping):
                domain_type = vsd_constants.L2DOMAIN
                domain_id = subnet_mapping['nuage_subnet_id']
                external_id = subnet_id
            else:
                msg = _("VSD L2Domain not found for subnet %s") % subnet_id
                raise n_exc.BadRequest(
                    resource='nuage_external_security_group', msg=msg)
        elif router_id:
            nuage_router = self.vsdclient.get_l3domain_by_external_id(
                router_id)
            if nuage_router:
                domain_type = vsd_constants.DOMAIN
                domain_id = nuage_router['ID']
                external_id = router_id
            else:
                msg = _("VSD domain not found for router %s") % router_id
                raise n_exc.BadRequest(
                    resource='nuage_external_security_group', msg=msg)

        pg_data = {
            'name': external_sg.get('name'),
            'description': external_sg.get('description'),
            'EVPNCommunityTag': external_sg.get('extended_community_id'),
            'externalID': cms_id_helper.get_vsd_external_id(external_id),
            'type': constants.SOFTWARE,
            'external': 'true'
        }
        ext_pg = self.vsdclient.create_policygroup(domain_type, domain_id,
                                                   pg_data)

        return self._make_external_security_group_dict(ext_pg,
                                                       context=context)

    @log_helpers.log_method_call
    def get_nuage_external_security_group(self, context, ext_sg_id,
                                          fields=None):
        try:
            filters = {
                'external': 'true'
            }
            ext_pg = self.vsdclient.get_policygroup(ext_sg_id, required=True,
                                                    **filters)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group',
                resource_id=ext_sg_id)
        return self._make_external_security_group_dict(ext_pg,
                                                       context=context,
                                                       fields=fields)

    @log_helpers.log_method_call
    def get_nuage_external_security_groups(self, context, filters=None,
                                           fields=None):
        # get all redirect targets
        domain_type = None
        domain_id = None
        vsd_filters = {
            'external': 'true'
        }
        if filters.get('subnet'):
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, filters['subnet'][0])
            if subnet_mapping:
                if self._is_l3(subnet_mapping):
                    message = ("Subnet %s doesn't have mapping l2domain on "
                               "VSD " % filters['subnet'][0])
                    raise nuage_exc.NuageBadRequest(msg=message)
                domain_type = vsd_constants.L2DOMAIN
                domain_id = subnet_mapping['nuage_subnet_id']
            else:
                message = ("Subnet %s doesn't have mapping l2domain on "
                           "VSD " % filters['subnet'][0])
                raise nuage_exc.NuageBadRequest(msg=message)
        elif filters.get('router'):
            router_id = filters.get('router')[0]
            nuage_router = self.vsdclient.get_l3domain_by_external_id(
                router_id)
            if nuage_router:
                domain_type = vsd_constants.DOMAIN
                domain_id = nuage_router['ID']
            else:
                msg = _("VSD domain not found for router %s") % router_id
                raise n_exc.BadRequest(
                    resource='nuage_external_security_group', msg=msg)
        elif filters.get('id'):
            return self.get_nuage_external_security_group(context,
                                                          filters.get('id')[0])
        elif filters.get('name'):
            vsd_filters['name'] = filters.get('name')[0]

        try:
            ext_sgs = self.vsdclient.get_policygroups(parent_type=domain_type,
                                                      parent_id=domain_id,
                                                      **vsd_filters)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group')
        return [self._make_external_security_group_dict(sg, context, fields)
                for sg in ext_sgs]

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_external_security_group(self, context, ext_sg_id):
        self.vsdclient.delete_policygroup(ext_sg_id)

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

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_external_security_group_rule(
            self, context, nuage_external_security_group_rule):

        rule = nuage_external_security_group_rule[
            'nuage_external_security_group_rule']
        self.get_port_attributes_plugin()._validate_redirect_target_port_range(
            rule)

        filters = {
            'external': 'true'
        }
        # External group id: External Security Group
        ext_pg = self.vsdclient.get_policygroup(
            rule['remote_external_group_id'], required=True, **filters)
        # Origin Group id: Neutron security group
        try:
            sg = self.core_plugin.get_security_group(context,
                                                     rule['origin_group_id'])
        except n_exc.NotFound:
            raise nuage_exc.NuageBadRequest(
                msg="Could not find Securitygroup "
                    "for external security group rule")

        domain_enterprise_mapping = {}
        # domainID -> {'ingress': ACL_ID, 'egress': ACL_ID}
        domain_acl_mapping = collections.defaultdict(
            lambda: {'ingress': None, 'egress': None})
        # domainID -> SG_ID -> PG
        domain_sg_pg_mapping = collections.defaultdict(dict)
        with nuage_utils.rollback() as on_exception:
            self.vsdclient.find_create_security_groups(
                [sg], ext_pg['parentType'], ext_pg['parentID'],
                domain_enterprise_mapping,
                domain_sg_pg_mapping, domain_acl_mapping, on_exception,
                pg_type=vsd_constants.SOFTWARE,
                allow_non_ip=config.default_allow_non_ip_enabled())
            domain_id = ext_pg['parentID']
            domain_type = ext_pg['parentType']
            pg_for_rule = domain_sg_pg_mapping[
                ext_pg['parentID']][sg['id']]['ID']
            # Reverse direction for the rule, as here it means VSD direction
            vsd_direction = rule['direction']
            rule['direction'] = vsd_constants.DIRECTIONS_OS_VSD[vsd_direction]
            acl_entry = self.vsdclient.calculate_acl_entries(
                sg_rule=rule, pg_id=pg_for_rule, domain_type=domain_type,
                domain_id=domain_id, stateful=True,
                domain_enterprise_mapping=domain_enterprise_mapping,
                sg_pg_mapping=domain_sg_pg_mapping[domain_id])[0]
            acl_entry['externalID'] = ext_pg['externalID']
            acl_entry = self.vsdclient.create_acl_entry(
                acl_entry, domain_type, domain_id, domain_acl_mapping,
                on_exception)

        # Reverse direction for the rule, as here it means VSD direction
        acl_entry['direction'] = vsd_direction
        acl_entry['origin_group_id'] = pg_for_rule
        acl_entry['remote_group_id'] = rule['remote_external_group_id']
        return self._make_external_security_group_rule_dict(acl_entry,
                                                            context=context)

    def get_port_attributes_plugin(self):
        return directory.get_plugin(
            constants.NUAGE_PORT_ATTRIBUTES_SERVICE_PLUGIN)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_external_security_group_rule(self, context, external_rule_id,
                                               fields=None):
        try:
            ext_rule_resp = (
                self.vsdclient.get_nuage_external_sg_rule(external_rule_id))
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-external-security-group-rule',
                resource_id=external_rule_id)
        return self._make_external_security_group_rule_dict(ext_rule_resp,
                                                            context=context,
                                                            fields=fields)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_external_security_group_rule(self, context,
                                                  external_rule_id):
        self.vsdclient.delete_acl_entry(external_rule_id)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_external_security_group_rules(self, context, filters=None,
                                                fields=None):
        params = {}
        resource_id = None
        if filters.get('subnet'):
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, filters['subnet'][0])
            if subnet_mapping:
                if self._is_l3(subnet_mapping):
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
            ext_rules = self.vsdclient.get_nuage_external_sg_rules(
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
