# Copyright 2020 NOKIA
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
import re

import netaddr
from neutron._i18n import _
from neutron.ipam import utils as ipam_utils
from neutron_lib.api.validators import is_attr_set
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers

from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common.extensions import (
    nuage_redirect_target as ext_rtarget)
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import port_security
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id


class NuageRedirectTarget(BaseNuagePlugin):

    @property
    def core_plugin(self):
        if not hasattr(self, '_core_plugin'):
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    def __init__(self):
        super(NuageRedirectTarget, self).__init__()
        self.psec_handler = port_security.NuagePortSecurityHandler(
            self.vsdclient, self)
        self.nuage_callbacks.subscribe(self.post_port_update_redirect_target,
                                       resources.PORT, constants.AFTER_UPDATE)
        self.nuage_callbacks.subscribe(self.post_port_create_redirect_target,
                                       resources.PORT, constants.AFTER_CREATE)

    @log_helpers.log_method_call
    def get_nuage_redirect_target(self, context, rtarget_id, fields=None):
        rtarget_resp = self.vsdclient.get_nuage_redirect_target(rtarget_id)
        if not rtarget_resp:
            raise nuage_exc.NuageNotFound(resource='nuage_redirect_target',
                                          resource_id=rtarget_id)
        vports = self.vsdclient.get_redirect_target_vports(rtarget_id) or []
        port_ids = [vport['externalID'].split('@')[0] for vport in vports]
        rtarget_resp['ports'] = port_ids
        return self._make_redirect_target_dict(rtarget_resp, context=context,
                                               fields=fields)

    def get_nuage_redirect_targets_by_port(self, port_id, context):
        port_params = {'neutron_port_id': port_id}
        vsd_mapping = nuagedb.get_subnet_l2dom_by_port_id(
            context.session, port_id)
        if vsd_mapping['nuage_l2dom_tmplt_id']:
            port_params['l2dom_id'] = vsd_mapping['nuage_subnet_id']
        else:
            port_params['l3dom_id'] = vsd_mapping['nuage_subnet_id']
        vport = self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params, required=True)
        return self.vsdclient.get_nuage_vport_redirect_targets(
            vport_id=vport['ID'], required=False) or []

    @log_helpers.log_method_call
    def get_nuage_redirect_targets(self, context, filters=None, fields=None):
        rtargets = []

        if filters.get('subnet'):
            params = {}

            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, filters['subnet'][0])
            if not subnet_mapping:
                return []
            if self._is_vsd_mgd(subnet_mapping) or self._is_l3(subnet_mapping):
                domain_id = self.vsdclient.get_l3domain_id_by_domain_subnet_id(
                    subnet_mapping['nuage_subnet_id'])
                if domain_id:
                    params['parentID'] = domain_id
                elif self._is_vsd_mgd(subnet_mapping):
                    params['parentID'] = subnet_mapping['nuage_subnet_id']
                else:
                    return []
            else:
                params['parentID'] = subnet_mapping['nuage_subnet_id']

            rtargets = self.vsdclient.get_nuage_redirect_targets(params)

        elif filters.get('router'):
            router_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                context.session, filters['router'][0])
            if not router_mapping:
                msg = (_("No router mapping found for router %s")
                       % filters['router'][0])
                raise nuage_exc.NuageBadRequest(msg=msg)

            rtargets = self.vsdclient.get_nuage_redirect_targets(
                {'parentID': router_mapping['nuage_router_id']})

        elif filters.get('id'):
            rtargets = self.vsdclient.get_nuage_redirect_targets(
                {'ID': filters.get('id')[0]})

        elif filters.get('name'):
            rtargets = self.vsdclient.get_nuage_redirect_targets(
                {'name': filters.get('name')[0]})

        elif filters.get('ports'):
            rtargets = (rtarget for port_id in filters['ports'] for rtarget in
                        self.get_nuage_redirect_targets_by_port(port_id,
                                                                context))

        return [self._make_redirect_target_dict(rtarget, context, fields)
                for rtarget in rtargets]

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_redirect_target(self, context, rtarget_id):
        filters = {'device_id': [rtarget_id]}
        ports = self.core_plugin.get_ports(context, filters=filters)
        for vip_port in ports:
            self.core_plugin.delete_port(context, vip_port['id'])
        self.vsdclient.delete_nuage_redirect_target(rtarget_id)

    @log_helpers.log_method_call
    def get_nuage_redirect_targets_count(self, context, filters=None):
        return 0

    @log_helpers.log_method_call
    def _make_redirect_target_dict(self, redirect_target,
                                   context=None, fields=None):
        res = {
            'id': redirect_target['ID'],
            'name': redirect_target['name'],
            'description': redirect_target['description'],
            'insertion_mode': redirect_target['endPointType'],
            'redundancy_enabled': redirect_target['redundancyEnabled']
        }
        if 'ports' in redirect_target:
            res['ports'] = redirect_target['ports']
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_redirect_target(self, context, nuage_redirect_target):
        redirect_target = nuage_redirect_target['nuage_redirect_target']
        has_subnet_id = is_attr_set(redirect_target.get('subnet_id'))
        has_router_id = is_attr_set(redirect_target.get('router_id'))

        if not has_subnet_id and not has_router_id:
            msg = _('subnet_id or router_id should be specified')
            raise n_exc.BadRequest(resource='subnets', msg=msg)

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, redirect_target.get('subnet_id')) or {}
        router_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, redirect_target.get('router_id')) or {}
        if not subnet_mapping and not router_mapping:
            raise ext_rtarget.RedirectTargetNoDomainOrL2Domain()
        if has_subnet_id:
            subnet = self.core_plugin.get_subnet(context,
                                                 redirect_target['subnet_id'])
            if subnet:
                redirect_target['external_id'] = \
                    cms_id_helper.get_vsd_external_id(subnet['network_id'])
        try:
            nuage_redirect_target = self.vsdclient\
                .create_nuage_redirect_target(
                    redirect_target,
                    l2dom_id=subnet_mapping.get('nuage_subnet_id'),
                    domain_id=router_mapping.get('nuage_router_id'))
        except Exception as e:
            if getattr(e, "vsd_code", None) == '7016':
                msg = _("A Nuage redirect target with name '%s' already "
                        "exists") % redirect_target['name']
                raise nuage_exc.NuageBadRequest(msg=msg)
            raise
        return self._make_redirect_target_dict(nuage_redirect_target,
                                               context=context)

    @log_helpers.log_method_call
    def _make_redirect_target_vip_dict(self, rtarget_vip,
                                       context=None, fields=None):
        res = {
            'id': rtarget_vip['ID'],
            'virtualIP': rtarget_vip['virtualIP']
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_redirect_target_vip(self, context,
                                         nuage_redirect_target_vip):
        redirect_target = nuage_redirect_target_vip[
            'nuage_redirect_target_vip']
        nuage_redirect_target = self.get_nuage_redirect_target(
            context, redirect_target['redirect_target_id'])
        subnet_id = redirect_target.get('subnet_id')
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)

        vip = redirect_target.get('virtual_ip_address')
        self._validate_create_redirect_target_vip(
            context, nuage_redirect_target, subnet_mapping, vip)
        # Port has no 'tenant-id', as it is hidden from user
        subnet = self.core_plugin.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        fixed_ips = {'ip_address': vip}
        vip_port = self.core_plugin.create_port(
            context,
            {'port': {
                'tenant_id': redirect_target['tenant_id'],
                'network_id': network_id,
                'mac_address': lib_constants.ATTR_NOT_SPECIFIED,
                'fixed_ips': [fixed_ips],
                'device_id': '',
                'device_owner': constants.DEVICE_OWNER_VIP_NUAGE,
                'admin_state_up': True,
                'name': ''
            }}
        )
        if not vip_port['fixed_ips']:
            self.core_plugin.delete_port(context, vip_port['id'])
            msg = 'No IPs available for VIP %s' % network_id
            raise n_exc.BadRequest(
                resource='nuage-redirect-target', msg=msg)

        vip_resp = self.vsdclient.create_virtual_ip(
            redirect_target['redirect_target_id'],
            redirect_target['virtual_ip_address'],
            vip_port['id'])

        self.core_plugin.update_port(
            context, vip_port['id'],
            {'port':
                {'device_id': redirect_target['redirect_target_id']}})
        return self._make_redirect_target_vip_dict(vip_resp[0],
                                                   context=context)

    @log_helpers.log_method_call
    def get_nuage_redirect_target_vips_count(self, context, filters=None):
        # neutron call this count function when creating a resource, to see
        # if it is within the quota limit, as this is VSD specific resource
        # and VSD doesn't have any quota limit, returning zero here
        return 0

    @log_helpers.log_method_call
    def _make_redirect_target_rule_dict(self, redirect_target_rule,
                                        context=None, fields=None):
        port_range_min = None
        port_range_max = None
        remote_ip_prefix = None
        remote_group_id = None
        if redirect_target_rule['networkType'] == 'ENTERPRISE_NETWORK':
            nuage_net_macro = self.vsdclient.get_nuage_prefix_macro(
                redirect_target_rule['networkID'])
            remote_ip_prefix = netaddr.IPNetwork(nuage_net_macro['address'] +
                                                 '/' +
                                                 nuage_net_macro['netmask'])
        elif redirect_target_rule['networkType'] == 'POLICYGROUP':
            remote_group_id = redirect_target_rule['remote_group_id']

        if redirect_target_rule['destinationPort']:
            port_range_min = '*'
            port_range_max = '*'
            if redirect_target_rule['destinationPort'] != port_range_max:
                destination_port = redirect_target_rule['destinationPort']
                port_range = destination_port.split('-')
                port_range_min = port_range[0]
                port_range_max = port_range[1]

        res = {
            'id': redirect_target_rule['ID'],
            'priority': redirect_target_rule['priority'],
            'protocol': redirect_target_rule['protocol'],
            'port_range_min': port_range_min,
            'port_range_max': port_range_max,
            'action': redirect_target_rule['action'],
            'redirect_target_id': redirect_target_rule['redirectVPortTagID'],
            'remote_ip_prefix': remote_ip_prefix,
            'remote_group_id': remote_group_id,
            'origin_group_id': redirect_target_rule.get('origin_group_id')
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @log_helpers.log_method_call
    def _validate_nuage_redirect_target_rule(self, rule):
        self._validate_redirect_target_rule_priority(rule['priority'])
        self._validate_redirect_target_port_range(rule)

    @staticmethod
    @log_helpers.log_method_call
    def _validate_redirect_target_rule_priority(priority):
        try:
            val = int(priority)
        except (ValueError, TypeError):
            message = _("Invalid value for priority.")
            raise nuage_exc.NuageAPIException(msg=message)

        # VSD requires port number 0 not valid
        if 0 <= val <= 999999999:
            return
        else:
            message = _("Priority should be >=0 and <= 999999999")
            raise nuage_exc.NuageAPIException(msg=message)

    @log_helpers.log_method_call
    def _validate_redirect_target_port_range(self, rule):
        # Check that port_range is valid.
        if (rule['port_range_min'] is None and
                rule['port_range_max'] is None):
            return
        if not rule['protocol']:
            raise ext_rtarget.RedirectTargetRuleProtocolRequiredWithPorts()
        try:
            port_min = int(rule['port_range_min'])
            port_max = int(rule['port_range_max'])
        except (ValueError, TypeError):
            message = (_("Invalid value for port_min %(port_min)s or "
                         "port_max %(port_max)s")
                       % {port_min: port_min, port_max: port_max})
            raise n_exc.InvalidInput(error_message=message)

        ip_proto = self.core_plugin._get_ip_proto_number(rule['protocol'])
        if ip_proto in [lib_constants.PROTO_NUM_TCP,
                        lib_constants.PROTO_NUM_UDP]:
            if (rule['port_range_min'] is not None and
                    rule['port_range_min'] <= rule['port_range_max']):
                pass
            else:
                raise ext_rtarget.RedirectTargetRuleInvalidPortRange()

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_redirect_target_rule(self, context,
                                          nuage_redirect_target_rule):
        remote_sg = None
        origin_sg = None
        rtarget_rule = nuage_redirect_target_rule['nuage_redirect_target_rule']
        if rtarget_rule.get('remote_group_id'):
            remote_sg = self.core_plugin.get_security_group(
                context, rtarget_rule.get('remote_group_id'))
        if (rtarget_rule.get('origin_group_id') and rtarget_rule.get(
                'origin_group_id') != rtarget_rule.get('remote_group_id')):
            origin_sg = self.core_plugin.get_security_group(
                context, rtarget_rule.get('origin_group_id'))
        self._validate_nuage_redirect_target_rule(rtarget_rule)
        rtarget = self.vsdclient.get_nuage_redirect_target(
            rtarget_rule['redirect_target_id'])
        if not rtarget:
            raise nuage_exc.NuageNotFound(
                resource='nuage_redirect_target',
                resource_id=rtarget_rule['redirect_target_id'])
        if rtarget['parentType'] == constants.L2DOMAIN:
            domain = self.vsdclient.get_l2domain_by_id(rtarget['parentID'])
        else:
            domain = self.vsdclient.get_l3domain_by_id(rtarget['parentID'],
                                                       True)
        vsd_managed = False if domain['externalID'] else True
        if remote_sg:
            rtarget_rule['remote_group_name'] = remote_sg['name']
            remote_pg_id = self._find_or_create_policygroup_using_rt(
                context, remote_sg['id'], rtarget, vsd_managed)
            rtarget_rule['remote_policygroup_id'] = remote_pg_id
            rtarget_rule['origin_policygroup_id'] = remote_pg_id
        if origin_sg:
            rtarget_rule['origin_group_name'] = origin_sg['name']
            origin_pg_id = self._find_or_create_policygroup_using_rt(
                context, origin_sg['id'], rtarget, vsd_managed)
            rtarget_rule['origin_policygroup_id'] = origin_pg_id
        rtarget_rule_resp = self.vsdclient.create_nuage_redirect_target_rule(
            rtarget_rule, rtarget)

        return self._make_redirect_target_rule_dict(rtarget_rule_resp,
                                                    context=context)

    def _find_or_create_policygroup_using_rt(self, context, security_group_id,
                                             redirect_target, vsd_managed):
        domain_id = redirect_target['parentID']
        domain_type = redirect_target['parentType']

        return self.psec_handler.process_create_security_group_in_domain(
            context,
            security_group_id,
            domain_id, domain_type, vsd_managed)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_redirect_target_rule(self, context, rtarget_rule_id,
                                       fields=None):
        try:
            rtarget_rule_resp = (
                self.vsdclient.get_nuage_redirect_target_rule(
                    rtarget_rule_id))
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-redirect-target-rule',
                resource_id=rtarget_rule_id)
        return self._make_redirect_target_rule_dict(rtarget_rule_resp,
                                                    context=context,
                                                    fields=fields)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_redirect_target_rule(self, context, rtarget_rule_id):
        self.vsdclient.delete_nuage_redirect_target_rule(rtarget_rule_id)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_redirect_target_rules(self, context, filters=None,
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
                params['subnet_mapping'] = subnet_mapping
            else:
                message = ("Subnet %s doesn't have mapping l2domain on "
                           "VSD " % filters['subnet'][0])
                raise nuage_exc.NuageBadRequest(msg=message)
        elif filters.get('router'):
            params['router'] = filters.get('router')[0]
        elif filters.get('id'):
            params['id'] = filters.get('id')[0]
            resource_id = params['id']

        try:
            rtarget_rules = self.vsdclient.get_nuage_redirect_target_rules(
                params)
        except Exception:
            raise nuage_exc.NuageNotFound(
                resource='nuage-redirect-target-rule',
                resource_id=resource_id)

        return [self._make_redirect_target_rule_dict(
            rtarget_rule, context, fields) for rtarget_rule in rtarget_rules]

    @log_helpers.log_method_call
    def get_nuage_redirect_target_rules_count(self, context, filters=None):
        return 0

    @log_helpers.log_method_call
    def _validate_port_redirect_target(self, context, port, rtargets):
        if not is_attr_set(rtargets):
            return
        if len(rtargets) > 1:
            msg = (_("Multiple redirect targets on a port not supported "))
            raise nuage_exc.NuageBadRequest(msg=msg)
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, port['fixed_ips'][0]['subnet_id'])
        nuage_rtargets_ids = []
        for rtarget in rtargets:
            uuid_match = re.match(lib_constants.UUID_PATTERN, rtarget)
            if not uuid_match:
                nuage_rtarget = self._resource_finder(
                    context, 'port', 'nuage_redirect_target', rtarget)
                nuage_rtarget_id = nuage_rtarget['id']
                nuage_rtargets_ids.append(nuage_rtarget_id)
            else:
                nuage_rtarget_id = rtarget
                nuage_rtargets_ids.append(rtarget)
            # validate rtarget is in the same subnet as port
            rtarget_resp = self.vsdclient.get_nuage_redirect_target(
                nuage_rtarget_id)
            if not rtarget_resp:
                msg = (_("Redirect target %s does not exist on VSD ") %
                       nuage_rtarget_id)
                raise nuage_exc.NuageBadRequest(msg=msg)
            parent_type = rtarget_resp['parentType']
            parent = rtarget_resp['parentID']
            validate_params = {
                'parent': parent,
                'parent_type': parent_type,
                'nuage_subnet_id': subnet_mapping['nuage_subnet_id']
            }
            if subnet_mapping and (
                    not self.vsdclient.validate_port_create_redirect_target(
                        validate_params)):
                msg = ("Redirect Target belongs to subnet %s that is "
                       "different from port subnet %s" %
                       (subnet_mapping['subnet_id'],
                        port['fixed_ips'][0]['subnet_id']))
                raise nuage_exc.NuageBadRequest(msg=msg)

        return nuage_rtargets_ids

    @log_helpers.log_method_call
    def process_port_redirect_target(self, context, port, rtargets,
                                     n_rtargets_ids):
        if not is_attr_set(rtargets):
            port[ext_rtarget.REDIRECTTARGETS] = []
            return
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, port['fixed_ips'][0]['subnet_id'])
        for n_rtarget_id in n_rtargets_ids:
            l2dom_id = subnet_mapping['nuage_subnet_id']
            l3dom_id = subnet_mapping['nuage_subnet_id']
            try:
                params = {'neutron_port_id': port['id']}

                l2_id, l3_id = get_l2_and_l3_sub_id(subnet_mapping)
                params['l2dom_id'] = l2_id
                params['l3dom_id'] = l3_id

                nuage_port = self.vsdclient.get_nuage_vport_by_neutron_id(
                    params)
                nuage_port['l2dom_id'] = l2dom_id
                nuage_port['l3dom_id'] = l3dom_id
                if nuage_port and nuage_port.get('ID'):
                    self.vsdclient.update_nuage_vport_redirect_target(
                        n_rtarget_id, nuage_port.get('ID'))
            except Exception:
                raise

        port[ext_rtarget.REDIRECTTARGETS] = (list(n_rtargets_ids)
                                             if n_rtargets_ids else [])

    @log_helpers.log_method_call
    def _delete_port_redirect_target_bindings(self, context, port_id):
        port = self.core_plugin.get_port(context, port_id)
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if subnet_mapping:
            l2dom_id, l3dom_id = get_l2_and_l3_sub_id(subnet_mapping)

            params = {
                'neutron_port_id': port_id,
                'l2dom_id': l2dom_id,
                'l3dom_id': l3dom_id
            }
            self.vsdclient.delete_port_redirect_target_bindings(params)

    def _validate_create_redirect_target_vip(self, context, redirect_target,
                                             subnet_mapping, vip):
        # VIP not allowed if redudancyEnabled is False
        if redirect_target.get('redundancy_enabled') == "False":
            if redirect_target.get('virtual_ip_address'):
                msg = (_("VIP can be addded to a redirect target only "
                         "when redundancyEnabled is True"))
                raise nuage_exc.NuageBadRequest(msg=msg)

        # VIP should be in the same subnet as redirect_target['subnet_id']
        if vip:
            subnet = self.core_plugin.get_subnet(context,
                                                 subnet_mapping['subnet_id'])
            if not ipam_utils.check_subnet_ip(subnet['cidr'], vip):
                msg = ("VIP should be in the same subnet as subnet %s " %
                       subnet_mapping['subnet_id'])
                raise nuage_exc.NuageBadRequest(msg=msg)

    def post_port_update_redirect_target(self, resource, event, trigger,
                                         payload):
        port = payload.latest_state
        original_port = payload.states[0]
        if ext_rtarget.REDIRECTTARGETS not in port:
            return
        if (port[ext_rtarget.REDIRECTTARGETS] == original_port.get(
                ext_rtarget.REDIRECTTARGETS)):
            return
        nuage_rtargets_ids = self._validate_port_redirect_target(
            payload.context,
            port,
            port[ext_rtarget.REDIRECTTARGETS]
        )
        self._delete_port_redirect_target_bindings(payload.context,
                                                   port['id'])
        self.process_port_redirect_target(
            payload.context, port, port[ext_rtarget.REDIRECTTARGETS],
            nuage_rtargets_ids)

    def post_port_create_redirect_target(self, resource, event, trigger,
                                         payload):
        port = payload.latest_state
        if ext_rtarget.REDIRECTTARGETS not in port:
            port[ext_rtarget.REDIRECTTARGETS] = []
            return

        n_rtarget_ids = self._validate_port_redirect_target(
            payload.context, port, port[ext_rtarget.REDIRECTTARGETS])
        self.process_port_redirect_target(
            payload.context, port, port[ext_rtarget.REDIRECTTARGETS],
            n_rtarget_ids)
