# Copyright 2016 Alcatel-Lucent USA Inc.
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

from neutron.callbacks import resources
from neutron import policy
from neutron_lib.api.validators import is_attr_set

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common.extensions.nuagepolicygroup \
    import NUAGE_POLICY_GROUPS
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.service_plugins \
    import vsd_passthrough_resource
from nuage_neutron.plugins.common import utils as nuage_utils
from nuagenetlib.restproxy import ResourceNotFoundException


def external_to_scope(vsd, os):
    os['scope'] = 'external' if vsd['external'] else 'internal'


def scope_to_external(vsd, os_filters):
    vsd['external'] = os_filters['scope'][0] == 'external'


def pg_id_to_policygroupid(vsd, os_filters):
    vsd['policyGroupID'] = int(os_filters['pg_id'][0])


class NuagePolicyGroup(vsd_passthrough_resource.VsdPassthroughResource):
    vsd_to_os = {
        'ID': 'id',
        'name': 'name',
        'description': 'description',
        'type': 'type',
        'EVPNCommunityTag': 'evpn_tag',
        'policyGroupID': 'pg_id',
        'external': external_to_scope,
        'ports': 'ports',
    }
    os_to_vsd = {
        'id': 'ID',
        'name': 'name',
        'description': 'description',
        'type': 'type',
        'evpn_tag': 'EVPNCommunityTag',
        'pg_id': pg_id_to_policygroupid,
        'scope': scope_to_external,
        'ports': 'ports',
    }
    vsd_filterables = ['id', 'name', 'type', 'scope', 'pg_id']
    extra_filters = ['ports', 'for_port', 'for_subnet']

    def __init__(self):
        super(NuagePolicyGroup, self).__init__()
        self.nuage_callbacks.subscribe(self.post_port_update,
                                       resources.PORT, constants.AFTER_UPDATE)
        self.nuage_callbacks.subscribe(self.post_port_create,
                                       resources.PORT, constants.AFTER_CREATE)
        self.nuage_callbacks.subscribe(self.post_port_show,
                                       resources.PORT, constants.AFTER_SHOW)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_policy_group(self, context, id, fields=None):
        try:
            policy_group = self.nuageclient.get_nuage_policy_group(
                id, externalID=None)
            if not policy_group:
                raise exceptions.NuageNotFound(resource="nuage-policy-group",
                                               resource_id=id)
            vports = self.nuageclient.get_nuage_policy_group_vports(id) or []
            port_ids = [vport['externalID'].split('@')[0] for vport in vports]
            policy_group['ports'] = port_ids
            return self.map_vsd_to_os(policy_group, fields=fields)
        except ResourceNotFoundException:
            raise exceptions.NuageNotFound(resource='nuage_policy_group',
                                           resource_id=id)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_policy_groups(self, context, filters=None, fields=None):
        unique_filters = ['ports', 'for_port', 'for_subnet']
        if len([x for x in unique_filters if x in filters]) > 1:
            msg = _("The filters %s can't be combined") % unique_filters
            raise exceptions.NuageBadRequest(msg=msg)

        if 'ports' in filters:
            getter = self.get_ports_nuage_policy_groups
        elif 'for_port' in filters:
            getter = self.get_port_available_nuage_policy_groups
        elif 'for_subnet' in filters:
            getter = self.get_subnet_available_nuage_policy_groups
        else:
            policy.enforce(context, 'get_nuage_policy_group_all', None)
            getter = self.get_all_nuage_policy_groups
        policy_groups = getter(context, filters=filters)
        return [self.map_vsd_to_os(policy_group, fields=fields)
                for policy_group in policy_groups]

    def get_all_nuage_policy_groups(self, context, filters=None):
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        return self.nuageclient.get_nuage_policy_groups(externalID=None,
                                                        **vsd_filters)

    def get_ports_nuage_policy_groups(self, context, filters=None):
        ports = filters.pop('ports')
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        policy_groups = []
        for port in ports:
            pgs = self._get_port_nuage_policy_groups(
                context, port, vsd_filters)
            if not policy_groups:
                policy_groups = pgs
            else:
                # multiple ports, take intersection of policy_groups of each
                # port
                policy_groups = [pg for pg in pgs if pg in policy_groups]
        return policy_groups

    def _get_port_nuage_policy_groups(self, context, port_id,
                                      vsd_filters):
        vsd_mapping = nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                          port_id)
        vport = self.nuageclient.get_nuage_vport_by_neutron_id(
            {'neutron_port_id': port_id,
             'l2dom_id': vsd_mapping['nuage_subnet_id'],
             'l3dom_id': vsd_mapping['nuage_subnet_id']})
        return self.nuageclient.get_nuage_vport_policy_groups(
            vport['ID'], externalID=None, **vsd_filters)

    def get_port_available_nuage_policy_groups(self, context, filters=None):
        port_id = filters.pop('for_port')[0]
        vsd_mapping = nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                          port_id)
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        return self._get_available_nuage_policy_groups(vsd_mapping,
                                                       vsd_filters)

    def get_subnet_available_nuage_policy_groups(self, context, filters=None):
        subnet_id = filters.pop('for_subnet')[0]
        vsd_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                     subnet_id)
        if not vsd_mapping:
            raise exceptions.SubnetMappingNotFound(resource='subnet',
                                                   id=subnet_id)
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        return self._get_available_nuage_policy_groups(vsd_mapping,
                                                       vsd_filters)

    def _get_available_nuage_policy_groups(self, vsd_mapping, vsd_filters):
        vsd_filters['externalID'] = None
        vsd_id = vsd_mapping['nuage_subnet_id']
        vsd_subnet = self.nuageclient.get_subnet_or_domain_subnet_by_id(vsd_id)
        if not vsd_subnet:
            raise exceptions.VsdSubnetNotFound(id=vsd_id)
        if vsd_subnet['type'] == constants.L2DOMAIN:
            return self.nuageclient.get_nuage_l2domain_policy_groups(
                vsd_subnet['ID'], **vsd_filters)
        else:
            domain_id = self.nuageclient.get_router_by_domain_subnet_id(
                vsd_subnet['ID'])
            return self.nuageclient.get_nuage_domain_policy_groups(
                domain_id, **vsd_filters)

    def post_port_update(self, resource, event, trigger, **kwargs):
        return self.process_port_nuage_policy_group(resource,
                                                    event,
                                                    trigger,
                                                    **kwargs)

    def post_port_create(self, resource, event, trigger, **kwargs):
        self.process_port_nuage_policy_group(
            resource, event, trigger, **kwargs)
        request_port = kwargs['request_port']
        if kwargs['vport'] and \
                is_attr_set(request_port.get(NUAGE_POLICY_GROUPS)):
            kwargs['port'][NUAGE_POLICY_GROUPS] = request_port.get(
                NUAGE_POLICY_GROUPS)
        else:
            kwargs['port'][NUAGE_POLICY_GROUPS] = None

    def process_port_nuage_policy_group(self, resource, event,
                                        trigger, **kwargs):
        request_port = kwargs.get('request_port')
        vport = kwargs.get('vport')
        if not vport or not is_attr_set(request_port.get(NUAGE_POLICY_GROUPS)):
            return
        self._process_port_nuage_policy_group(
            event, kwargs.get('original_port'), request_port,
            kwargs['rollbacks'], vport)

    @nuage_utils.handle_nuage_api_errorcode
    def _process_port_nuage_policy_group(self, event, original_port,
                                         request_port, rollbacks, vport):
        policy_group_ids = request_port[NUAGE_POLICY_GROUPS]
        [self.validate_policy_group(pg_id) for pg_id in policy_group_ids]
        if (event == constants.AFTER_UPDATE and
                NUAGE_POLICY_GROUPS in original_port):
            rollbacks.append(
                (self.nuageclient.update_vport_policygroups,
                 [vport['ID'], original_port[NUAGE_POLICY_GROUPS]], {})
            )
        self.nuageclient.update_vport_policygroups(vport['ID'],
                                                   policy_group_ids)

    def validate_policy_group(self, policy_group_id):
        policy_group = self.nuageclient.get_nuage_policy_group(policy_group_id,
                                                               required=True)
        if policy_group['externalID']:
            msg = _("Policy group %s has externalID, it can't be used with "
                    "this API.") % policy_group['ID']
            raise exceptions.NuageBadRequest(msg=msg)

    def post_port_show(self, resource, event, trigger, **kwargs):
        port = kwargs.get('port')
        fields = kwargs.get('fields')
        vport = kwargs.get('vport')
        if fields and NUAGE_POLICY_GROUPS not in fields:
            return
        if not vport:
            port[NUAGE_POLICY_GROUPS] = None
            return

        policy_groups = self.nuageclient.get_nuage_vport_policy_groups(
            vport['ID'], externalID=None)
        port[NUAGE_POLICY_GROUPS] = [policy_group['ID']
                                     for policy_group in policy_groups]
