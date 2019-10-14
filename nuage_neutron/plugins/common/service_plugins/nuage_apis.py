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

import functools

import netaddr
from neutron._i18n import _
from neutron.api import extensions as neutron_extensions
from neutron.db import _model_query as model_query
from neutron.db import _utils as db_utils
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db as sg_db
from neutron_lib.api import validators
from neutron_lib import context as n_ctx
from neutron_lib import exceptions as n_exc
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import externalsg
from nuage_neutron.plugins.common import gateway
from nuage_neutron.plugins.common import nuage_models
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.plugins.nuage_ml2 import extensions
from nuage_neutron.vsdclient.restproxy import RESTProxyError

LOG = logging.getLogger(__name__)


class NuageApi(base_plugin.BaseNuagePlugin,
               service_base.ServicePluginBase,
               externalsg.NuageexternalsgMixin,
               gateway.NuagegatewayMixin,
               sg_db.SecurityGroupDbMixin):
    supported_extension_aliases = ['net-partition', 'nuage-gateway',
                                   'vsd-resource',
                                   'nuage-external-security-group',
                                   'nuage-security-group']

    def __init__(self):
        super(NuageApi, self).__init__()
        # Prepare default and shared netpartitions
        self._prepare_netpartitions()
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
            'security_groups', [self._extend_resource_dict])

    def get_plugin_type(self):
        return constants.NUAGE_APIS

    def get_plugin_description(self):
        return "Plugin providing Nuage-specific APIs."

    def get_default_np_id(self):
        return self._default_np_id

    def _make_net_partition_dict(self, net_partition,
                                 context=None, fields=None):
        res = {
            'id': net_partition['id'],
            'name': net_partition['name'],
            'l3dom_tmplt_id': net_partition['l3dom_tmplt_id'],
            'l2dom_tmplt_id': net_partition['l2dom_tmplt_id'],
            'isolated_zone': net_partition['isolated_zone'],
            'shared_zone': net_partition['shared_zone']
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    def _make_project_net_partition_mapping(self, context, mapping,
                                            fields=None):
        res = {
            'project': mapping['project'],
            'net_partition_id': mapping['net_partition_id'],
        }
        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @log_helpers.log_method_call
    def _create_net_partition(self, session, net_part_name):
        params = {
            'name': net_part_name,
            'fp_quota': str(cfg.CONF.RESTPROXY.default_floatingip_quota),
            'externalID': net_part_name + '@openstack'
        }
        nuage_net_partition = self.vsdclient.create_net_partition(params)
        net_partitioninst = None
        if nuage_net_partition:
            with session.begin(subtransactions=True):
                net_partitioninst = NuageApi._add_net_partition(
                    session,
                    nuage_net_partition,
                    net_part_name)
        if not net_partitioninst:
            return {}
        return self._make_net_partition_dict(net_partitioninst)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def _validate_create_net_partition(self, context, net_part_name):
        """Sync net partition configuration between plugin and VSD"""
        # About parallelism: This method could be executed in parallel
        # by different neutron instances. The decorator
        # retry_if_session_inactive makes sure that that the method will be
        # retried when database transaction errors occur like deadlock and
        # duplicate inserts.
        self._validate_net_partition_name(net_part_name)
        session = context.session
        with session.begin(subtransactions=True):
            netpart_db = nuagedb.get_net_partition_by_name(session,
                                                           net_part_name)
            nuage_netpart = self.vsdclient.get_netpartition_data(net_part_name)
            if nuage_netpart:
                if netpart_db:
                    # Net-partition exists in neutron and vsd
                    def_netpart = (
                        cfg.CONF.RESTPROXY.default_net_partition_name)
                    share_netpart = constants.SHARED_INFRASTRUCTURE
                    if (def_netpart == net_part_name or
                            share_netpart == net_part_name):
                        if nuage_netpart['np_id'] != netpart_db['id']:
                            msg = ("Net-partition %s exists in "
                                   "Neutron and VSD, but the id is different"
                                   % net_part_name)
                            raise n_exc.BadRequest(resource='net_partition',
                                                   msg=msg)
                        self._update_net_partition(session,
                                                   net_part_name,
                                                   netpart_db,
                                                   nuage_netpart)
                        LOG.info("Net-partition %s already exists,"
                                 " so will just use it", net_part_name)
                        return self._make_net_partition_dict(netpart_db)
                    else:
                        if nuage_netpart['np_id'] != netpart_db['id']:
                            msg = (('Net-partition %s already exists in '
                                    'Neutron and VSD, but the id is '
                                    'different') % net_part_name)
                        else:
                            msg = (('Net-partition %s already exists in '
                                    'Neutron and VSD with same id') %
                                   net_part_name)

                        raise n_exc.BadRequest(resource='net_partition',
                                               msg=msg)

                # Net-partition exists in vsd and not in neutron
                netpart_db = NuageApi._add_net_partition(session,
                                                         nuage_netpart,
                                                         net_part_name)
                return self._make_net_partition_dict(netpart_db)
            else:
                if netpart_db:
                    # Net-partition exists in neutron and not VSD
                    LOG.info("Existing net-partition %s will be deleted and "
                             "re-created in db", net_part_name)
                    nuagedb.delete_net_partition(session, netpart_db)

                # Net-partition does not exist in neutron and VSD
                return self._create_net_partition(session, net_part_name)

    @staticmethod
    def _validate_net_partition_name(name):
        try:
            name.encode('ascii')
        except UnicodeEncodeError:
            msg = _('Invalid netpartition name: Only ascii names are allowed')
            raise n_exc.BadRequest(resource='net_partition', msg=msg)

    @staticmethod
    @log_helpers.log_method_call
    def _add_net_partition(session, netpart, netpart_name):
        l3dom_id = netpart['l3dom_tid']
        if netpart_name == constants.SHARED_INFRASTRUCTURE:
            l3isolated = None
            l3shared = constants.SHARED_ZONE_TEMPLATE
        else:
            l3isolated = constants.DEF_NUAGE_ZONE_PREFIX + '-' + l3dom_id
            l3shared = constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' + l3dom_id
        return nuagedb.add_net_partition(session,
                                         netpart['np_id'],
                                         l3dom_id,
                                         netpart['l2dom_tid'],
                                         netpart_name,
                                         l3isolated,
                                         l3shared)

    @log_helpers.log_method_call
    def _update_net_partition(self, session,
                              netpart_name,
                              net_partition_db,
                              vsd_net_partition):
        l3dom_id = vsd_net_partition['l3dom_tid']
        if netpart_name == constants.SHARED_INFRASTRUCTURE:
            l3isolated = None
            l3shared = constants.SHARED_ZONE_TEMPLATE
        else:
            l3isolated = constants.DEF_NUAGE_ZONE_PREFIX + '-' + l3dom_id
            l3shared = constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' + l3dom_id
        with session.begin(subtransactions=True):
            nuagedb.update_netpartition(net_partition_db, {
                'l3dom_tmplt_id': l3dom_id,
                'l2dom_tmplt_id': vsd_net_partition['l2dom_tid'],
                'isolated_zone': l3isolated,
                'shared_zone': l3shared,
            })

    @log_helpers.log_method_call
    def _link_default_netpartition(self, netpart_name,
                                   l2template, l3template,
                                   l3isolated, l3shared):
        params = {
            'name': netpart_name,
            'l3template': l3template,
            'l2template': l2template
        }
        (np_id, l3dom_tid,
         l2dom_tid) = self.vsdclient.link_default_netpartition(params)
        # verify that the provided zones have been created already
        shared_match, isolated_match = self.vsdclient.validate_zone_create(
            l3dom_tid, l3isolated, l3shared)
        if not shared_match or not isolated_match:
            msg = ('Default zone names must be provided for '
                   'default net-partiton')
            raise n_exc.BadRequest(resource='net_partition', msg=msg)

        # basic verifications passed. add default netpartition to the DB
        session = db.get_writer_session()
        netpartition = nuagedb.get_net_partition_by_name(session,
                                                         netpart_name)

        with session.begin():
            if netpartition:
                nuagedb.delete_net_partition(session, netpartition)
            nuagedb.add_net_partition(session,
                                      np_id,
                                      l3dom_tid,
                                      l2dom_tid,
                                      netpart_name,
                                      l3isolated,
                                      l3shared)
        self._default_np_id = np_id

    @log_helpers.log_method_call
    def _prepare_netpartitions(self):
        # prepare shared netpartition
        shared_netpart_name = constants.SHARED_INFRASTRUCTURE
        self._validate_create_net_partition(n_ctx.get_admin_context(),
                                            shared_netpart_name)
        # prepare default netpartition
        default_netpart_name = cfg.CONF.RESTPROXY.default_net_partition_name
        l3template = cfg.CONF.RESTPROXY.default_l3domain_template
        l2template = cfg.CONF.RESTPROXY.default_l2domain_template
        l3isolated = cfg.CONF.RESTPROXY.default_isolated_zone
        l3shared = cfg.CONF.RESTPROXY.default_shared_zone

        # if templates are not provided, create default templates
        if l2template or l3template or l3isolated or l3shared:
            if (not l2template or not l3template or not l3isolated or
                    not l3shared):
                msg = 'Configuration of default net-partition not complete'
                raise n_exc.BadRequest(resource='net_partition',
                                       msg=msg)
            '''NetPartition and templates already created. Just sync the
            neutron DB. They must all be in VSD. If not, its an error
            '''
            self._link_default_netpartition(default_netpart_name,
                                            l2template,
                                            l3template,
                                            l3isolated,
                                            l3shared)
        else:
            default_netpart = self._validate_create_net_partition(
                n_ctx.get_admin_context(),
                default_netpart_name)
            self._default_np_id = default_netpart['id']

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_net_partition(self, context, net_partition):
        ent = net_partition['net_partition']
        return self._validate_create_net_partition(context, ent['name'])

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def _validate_delete_net_partition(self, context, id, net_partition_name):
        if net_partition_name == constants.SHARED_INFRASTRUCTURE:
            msg = _("Can't delete net_partition {}").format(net_partition_name)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_entid(
            context.session, id)
        ent_l2dom_mapping = nuagedb.get_ent_l2dom_mapping_by_entid(
            context.session, id)
        if ent_rtr_mapping:
            msg = (_("One or more router still attached to "
                     "net_partition %s.") % net_partition_name)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)
        if ent_l2dom_mapping:
            msg = (_("One or more L2 Domain Subnet present in the "
                     "net_partition %s.") % net_partition_name)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_net_partition(self, context, id):
        net_partition = nuagedb.get_net_partition_by_id(context.session, id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        self._validate_delete_net_partition(context, id, net_partition['name'])
        self.vsdclient.delete_net_partition(net_partition['id'])
        with context.session.begin(subtransactions=True):
            nuagedb.delete_net_partition(context.session,
                                         net_partition)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_net_partition(self, context, id, fields=None):
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        return self._make_net_partition_dict(net_partition, context=context,
                                             fields=fields)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_net_partitions(self, context, filters=None, fields=None):
        net_partitions = nuagedb.get_net_partitions(context.session,
                                                    filters=filters,
                                                    fields=fields)
        return [self._make_net_partition_dict(net_partition, context, fields)
                for net_partition in net_partitions]

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def create_project_net_partition_mapping(self, context,
                                             project_net_partition_mapping):
        session = context.session
        p2n = project_net_partition_mapping['project_net_partition_mapping']
        project = p2n['project']
        net_partition_id = p2n['net_partition_id']

        err = validators.validate_uuid(project)
        if err:
            raise nuage_exc.NuageBadRequest(resource='net_partition', msg=err)
        # Validate netpartition
        netpart = nuagedb.get_net_partition_by_id(session, net_partition_id)
        if not netpart:
            msg = _('Net partition {} is not a valid netpartition '
                    'ID.').format(net_partition_id)
            raise nuage_exc.NuageBadRequest(
                resource='project_net_partition_mapping', msg=msg)

        with session.begin(subtransactions=True):
            existing_mapping = nuagedb.get_project_net_partition_mapping(
                session, project)
            if existing_mapping:
                session.delete(existing_mapping)
            mapping = nuagedb.add_project_net_partition_mapping(
                session, net_partition_id, project)
        return self._make_project_net_partition_mapping(context, mapping)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_project_net_partition_mapping(self, context,
                                             project_id):
        session = context.session
        err = validators.validate_uuid(project_id)
        if err:
            raise nuage_exc.NuageBadRequest(
                resource='project_net_partition_mapping', msg=err)
        with session.begin(subtransactions=True):
            existing_mapping = nuagedb.get_project_net_partition_mapping(
                session, project_id)
            if existing_mapping:
                session.delete(existing_mapping)
            else:
                msg = _('Project {} does not currently '
                        'have a default net-partition associated.').format(
                    project_id)
                raise nuage_exc.NuageBadRequest(
                    resource='project_net_partition_mapping', msg=msg)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_project_net_partition_mapping(self, context, id, fields=None):
        mapping = nuagedb.get_project_net_partition_mapping(context.session,
                                                            id)
        if not mapping:
            raise nuage_exc.NuageNotFound(
                resource='project_net_partition_mapping', resource_id=id)
        return self._make_project_net_partition_mapping(context, mapping,
                                                        fields)

    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_project_net_partition_mappings(
            self, context, filters=None, fields=None, sorts=None,
            limit=None, marker=None, page_reverse=False):
        marker_obj = db_utils.get_marker_obj(
            self, context, 'project_net_partition_mapping', limit, marker)
        return model_query.get_collection(
            context, nuage_models.NetPartitionProject,
            functools.partial(self._make_project_net_partition_mapping,
                              context),
            filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker_obj=marker_obj, page_reverse=page_reverse)

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_vsd_subnet(self, context, id, fields=None):
        subnet = self.vsdclient.get_nuage_subnet_by_id(
            id, required=True)
        vsd_subnet = {'id': subnet['ID'],
                      'name': subnet['name'],
                      'cidr': self._calc_cidr(subnet),
                      'ipv6_cidr': self._calc_ipv6_cidr(subnet),
                      'gateway': subnet['gateway'],
                      'ipv6_gateway': subnet['IPv6Gateway'],
                      'ip_version': subnet['IPType'],
                      'enable_dhcpv4': subnet['enableDHCPv4'],
                      'enable_dhcpv6': subnet['enableDHCPv6'],
                      }
        if subnet['type'] == constants.L3SUBNET:
            domain_id = self.vsdclient.get_router_by_domain_subnet_id(
                vsd_subnet['id'])
            netpart_id = self.vsdclient.get_router_np_id(domain_id)
        else:
            netpart_id = subnet['parentID']

        net_partition = self.vsdclient.get_net_partition_name_by_id(
            netpart_id)
        vsd_subnet['net_partition'] = net_partition
        return self._fields(vsd_subnet, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_subnets(self, context, filters=None, fields=None):
        if 'vsd_zone_id' not in filters:
            msg = _('vsd_zone_id is a required filter parameter for this API.')
            raise n_exc.BadRequest(resource='vsd-subnets', msg=msg)
        l3subs = self.vsdclient.get_domain_subnet_by_zone_id(
            filters['vsd_zone_id'][0])
        vsd_to_os = {
            'ID': 'id',
            'name': 'name',
            self._calc_cidr: 'cidr',
            self._calc_ipv6_cidr: 'ipv6_cidr',
            'gateway': 'gateway',
            'IPv6Gateway': 'ipv6_gateway',
            'IPType': 'ip_version',
            'enableDHCPv4': 'enable_dhcpv4',
            'enableDHCPv6': 'enable_dhcpv6',
            functools.partial(
                self._return_val, filters['vsd_zone_id'][0]): 'vsd_zone_id'
        }
        return self._trans_vsd_to_os(l3subs, vsd_to_os, filters, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_domains(self, context, filters=None, fields=None):

        l3domains = []
        l2domains = []

        if 'vsd_organisation_id' in filters:
            # get domains by enterprise id
            l3domains.extend(self.vsdclient.get_routers_by_netpart(
                filters['vsd_organisation_id'][0]))
            l2domains.extend(self.vsdclient.get_subnet_by_netpart(
                filters['vsd_organisation_id'][0]))
        elif 'os_router_ids' in filters:
            # get domain by Openstack router id
            l3domains.extend(self.vsdclient.get_router_by_external(os_id)
                             for os_id in filters['os_router_ids'])
        else:
            msg = _('vsd_organisation_id or os_router_ids is a required filter'
                    ' parameter for this API.')
            raise n_exc.BadRequest(resource='vsd-domains', msg=msg)

        # add type to the domains (used by horizon linkedselect)
        for domain in l3domains:
            domain.update({'type': 'L3'})
        for domain in l2domains:
            domain.update({'type': 'L2'})

        vsd_to_os = {
            'ID': 'id',
            'name': 'name',
            'type': 'type',

            # L2
            'net_partition_id': 'net_partition_id',
            'dhcp_managed': 'dhcp_managed',
            'IPType': 'ip_version',
            'ipv4_cidr': 'cidr',
            'IPv6Address': 'ipv6_cidr',
            'ipv4_gateway': 'gateway',
            'IPv6Gateway': 'ipv6_gateway',
            'enableDHCPv4': 'enable_dhcpv4',
            'enableDHCPv6': 'enable_dhcpv6',

            # L3
            'parentID': 'net_partition_id',
            'routeDistinguisher': 'rd',
            'routeTarget': 'rt',
            'backHaulVNID': 'backhaul_vnid',
            'backHaulRouteDistinguisher': 'backhaul_rd',
            'backHaulRouteTarget': 'backhaul_rt',
            'templateID': 'router_template_id',
            'tunnelType': 'tunnel_type',
            'ECMPCount': 'ecmp_count'
        }
        return self._trans_vsd_to_os(l3domains + l2domains, vsd_to_os,
                                     filters, fields)

    def _calc_cidr(self, subnet):
        if (not subnet['address']) and (
                not subnet['associatedSharedNetworkResourceID']):
            return None

        shared_id = subnet['associatedSharedNetworkResourceID']
        if shared_id:
            subnet = self.vsdclient.get_nuage_subnet_by_id(shared_id)
        if subnet.get('address'):
            ip = netaddr.IPNetwork(subnet['address'] + '/' +
                                   subnet['netmask'])
            return str(ip)

    def _calc_ipv6_cidr(self, subnet):
        if (not subnet['IPv6Address']) and (
                not subnet['associatedSharedNetworkResourceID']):
            return None

        shared_id = subnet['associatedSharedNetworkResourceID']
        if shared_id:
            subnet = self.vsdclient.get_nuage_subnet_by_id(shared_id)
        return subnet.get('IPv6Address')

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_zones(self, context, filters=None, fields=None):
        if 'vsd_domain_id' not in filters:
            msg = _('vsd_domain_id is a required filter parameter for this '
                    'API.')
            raise n_exc.BadRequest(resource='vsd-zones', msg=msg)
        try:
            vsd_zones = self.vsdclient.get_zone_by_domainid(
                filters['vsd_domain_id'][0])
        except RESTProxyError as e:
            if e.code == 404:
                return []
            else:
                raise e

        vsd_zones = [self._update_dict(zone, 'vsd_domain_id',
                                       filters['vsd_domain_id'][0])
                     for zone in vsd_zones]
        vsd_to_os = {
            'zone_id': 'id',
            'zone_name': 'name',
            'vsd_domain_id': 'vsd_domain_id'
        }
        return self._trans_vsd_to_os(vsd_zones, vsd_to_os, filters, fields)

    def _update_dict(self, dict, key, val):
        dict[key] = val
        return dict

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_organisations(self, context, filters=None, fields=None):
        netpartitions = self.vsdclient.get_net_partitions()
        vsd_to_os = {
            'net_partition_id': 'id',
            'net_partition_name': 'name'
        }
        return self._trans_vsd_to_os(netpartitions, vsd_to_os, filters, fields)

    def _trans_vsd_to_os(self, vsd_list, mapping, filters, fields):
        os_list = []
        if not filters:
            filters = {}
        for filter in filters:
            filters[filter] = [value.lower() for value in filters[filter]]

        for vsd_obj in vsd_list:
            os_obj = {}
            for vsd_key in mapping:
                if callable(vsd_key):
                    os_obj[mapping[vsd_key]] = vsd_key(vsd_obj)
                elif vsd_key in vsd_obj:
                    os_obj[mapping[vsd_key]] = vsd_obj[vsd_key]

            if self._passes_filters(os_obj, filters):
                self._fields(os_obj, fields)
                os_list.append(os_obj)

        return os_list

    @staticmethod
    def _passes_filters(obj, filters):
        for filter in filters:
            if (filter in obj and
                    str(obj[filter]).lower() not in filters[filter]):
                return False
        return True

    @staticmethod
    def _return_val(val, dummy):  # this must be the dummiest method ever
        return val

    @staticmethod
    def _filter_fields(subnet, fields):
        for key in subnet:
            if key not in fields:
                del subnet[key]
        return subnet

    def _extend_resource_dict(self, resource_res, resource_db):
        if resource_db:
            sg_id = resource_res['id']
            resource_res['stateful'] = self.get_sg_stateful_value(sg_id)

    @staticmethod
    def get_sg_stateful_value(sg_id):
        session = db.get_reader_session()
        value = nuagedb.get_nuage_sg_parameter(session, sg_id, 'STATEFUL')
        session.close()
        return not (value and value.parameter_value == '0')
