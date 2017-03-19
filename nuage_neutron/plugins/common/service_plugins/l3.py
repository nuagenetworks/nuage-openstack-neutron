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

import copy
from logging import handlers

import netaddr
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common.extensions import nuage_router
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from oslo_config import cfg
from oslo_log.formatters import ContextFormatter
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.callbacks import resources
from neutron.db import api as db
from neutron.db.common_db_mixin import CommonDbMixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.utils import helpers

LOG = logging.getLogger(__name__)


class NuageL3Plugin(base_plugin.BaseNuagePlugin,
                    service_base.ServicePluginBase,
                    CommonDbMixin,
                    extraroute_db.ExtraRoute_db_mixin,
                    l3_gwmode_db.L3_NAT_db_mixin):
    supported_extension_aliases = ['router',
                                   'nuage-router',
                                   'nuage-floatingip',
                                   'extraroute',
                                   'ext-gw-mode']

    def __init__(self):
        super(NuageL3Plugin, self).__init__()
        self._l2_plugin = None
        self._default_np_id = None
        self.init_fip_rate_log()

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    @property
    def default_np_id(self):
        if self._default_np_id is None:
            self._default_np_id = directory.get_plugin(
                constants.NUAGE_APIS).default_np_id
        return self._default_np_id

    def get_plugin_type(self):
        return lib_constants.L3

    def get_plugin_description(self):
        return "Plugin providing support for routers and floatingips."

    def init_fip_rate_log(self):
        self.def_fip_rate = cfg.CONF.FIPRATE.default_fip_rate
        self.def_ingress_rate_kbps = (
            cfg.CONF.FIPRATE.default_ingress_fip_rate_kbps)
        self.def_egress_rate_kbps = (
            cfg.CONF.FIPRATE.default_egress_fip_rate_kbps)

        self._validate_fip_rate_value(self.def_fip_rate, 'default_fip_rate')
        self._validate_fip_rate_value(self.def_ingress_rate_kbps,
                                      'default_ingress_fip_rate_kbps',
                                      units='kbps')
        if cfg.CONF.FIPRATE.default_egress_fip_rate_kbps is not None:
            self._validate_fip_rate_value(self.def_egress_rate_kbps,
                                          'default_egress_fip_rate_kbps',
                                          units='kbps')
        self.fip_rate_log = None
        if cfg.CONF.FIPRATE.fip_rate_change_log:
            formatter = ContextFormatter()
            formatter.conf.logging_context_format_string = (
                '%(asctime)s %(levelname)s [%(user_name)s] %(message)s')
            self.fip_rate_log = logging.getLogger('neutron.nuage.fip.rate')
            handler = handlers.WatchedFileHandler(
                cfg.CONF.FIPRATE.fip_rate_change_log)
            handler.setFormatter(formatter)
            self.fip_rate_log.logger.addHandler(handler)
        else:
            self.fip_rate_log = LOG

    def _validate_fip_rate_value(self, fip_value, attribute, units='mbps'):
        if fip_value < -1:
            raise cfg.ConfigFileValueError(_('%s can not be < -1') % attribute)

        if self.def_fip_rate > constants.MAX_VSD_INTEGER:
            raise cfg.ConfigFileValueError(_('%(attr)s cannot be > %(max)s') %
                                           {'attr': attribute,
                                            'max': constants.MAX_VSD_INTEGER})

        if units == 'kbps' and int(fip_value) != fip_value:
            raise cfg.ConfigFileValueError(_('%s cannot be'
                                             ' in fraction') % attribute)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        session = context.session
        rtr_if_info = super(NuageL3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            network = self.core_plugin.get_network(context,
                                                   rtr_if_info['network_id'])
            if network['router:external']:
                msg = _("Subnet in external network cannot be an interface of "
                        "a router.")
                raise nuage_exc.NuageBadRequest(msg=msg)
            return self._nuage_add_router_interface(context,
                                                    interface_info,
                                                    router_id,
                                                    rtr_if_info,
                                                    session)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).remove_router_interface(
                    context, router_id, interface_info)

    def _nuage_add_router_interface(self, context, interface_info,
                                    router_id, rtr_if_info, session):
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port = self.core_plugin._get_port(context, port_id)
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
            vport = self.vsdclient.get_nuage_vport_by_neutron_id(
                {'neutron_port_id': port['id'],
                 'l2dom_id': subnet_l2dom['nuage_subnet_id'],
                 'l3dom_id': subnet_l2dom['nuage_subnet_id']},
                required=False)
            if vport:
                self.vsdclient.delete_nuage_vport(vport['ID'])
        else:
            subnet_id = rtr_if_info['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
        l2domain_id = subnet_l2dom['nuage_subnet_id']
        subnet = self.core_plugin.get_subnet(context, subnet_id)
        vsd_zone = self.vsdclient.get_zone_by_routerid(
            router_id, subnet['shared'])
        self._nuage_validate_add_rtr_itf(
            session, router_id, subnet, subnet_l2dom, vsd_zone)

        filters = {
            'fixed_ips': {'subnet_id': [subnet_id]},
            'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
        }
        gw_ports = self.core_plugin.get_ports(context, filters=filters)
        for port in gw_ports:
            self.core_plugin.delete_port(context, port['id'])

        pnet_binding = nuagedb.get_network_binding(context.session,
                                                   subnet['network_id'])

        with nuage_utils.rollback() as on_exc, \
                session.begin(subtransactions=True):
            vsd_subnet = self.vsdclient.create_domain_subnet(
                vsd_zone, subnet, pnet_binding)
            on_exc(self.vsdclient.delete_domain_subnet,
                   vsd_subnet['ID'], subnet['id'], pnet_binding)
            nuagedb.update_subnetl2dom_mapping(
                subnet_l2dom,
                {'nuage_subnet_id': vsd_subnet['ID'],
                 'nuage_l2dom_tmplt_id': None})

            self.vsdclient.move_l2domain_to_l3subnet(
                l2domain_id, vsd_subnet['ID'])
            rollbacks = []
            try:
                self.nuage_callbacks.notify(resources.ROUTER_INTERFACE,
                                            constants.AFTER_CREATE,
                                            self, context=context,
                                            router_id=router_id,
                                            subnet_id=subnet_id,
                                            rollbacks=rollbacks,
                                            subnet_mapping=subnet_l2dom)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for rollback in reversed(rollbacks):
                        rollback[0](*rollback[1], **rollback[2])
        self.core_plugin.update_port_status(context,
                                            rtr_if_info['port_id'],
                                            lib_constants.PORT_STATUS_ACTIVE)
        return rtr_if_info

    def _nuage_validate_add_rtr_itf(self, session, router_id, subnet,
                                    subnet_l2dom, nuage_zone):
        subnet_id = subnet['id']
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                               router_id)
        if not nuage_zone or not ent_rtr_mapping:
            raise nuage_router.RtrItfAddIncompleteRouterOnVsd(id=router_id)
        if not subnet_l2dom:
            raise nuage_router.RtrItfAddVsdSubnetNotFound(subnet=subnet_id)
        if subnet_l2dom['nuage_managed_subnet']:
            raise nuage_router.RtrItfAddSubnetIsVsdManaged(subnet=subnet_id)
        if (subnet_l2dom['net_partition_id'] !=
                ent_rtr_mapping['net_partition_id']):
            raise nuage_router.RtrItfAddDifferentNetpartitions(
                subnet=subnet_id, router=router_id)
        nuage_subnet_id = subnet_l2dom['nuage_subnet_id']
        nuage_rtr_id = ent_rtr_mapping['nuage_router_id']
        self.vsdclient.validate_create_domain_subnet(
            subnet, nuage_subnet_id, nuage_rtr_id)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def remove_router_interface(self, context, router_id, interface_info):
        if 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self.core_plugin.get_subnet(context, subnet_id)
            found = False
            try:
                filters = {'device_id': [router_id],
                           'device_owner':
                           [lib_constants.DEVICE_OWNER_ROUTER_INTF],
                           'network_id': [subnet['network_id']]}
                ports = self.core_plugin.get_ports(context, filters)

                for p in ports:
                    if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                        found = True
                        break
            except exc.NoResultFound:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            if not found:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
        elif 'port_id' in interface_info:
            port_db = self.core_plugin._get_port(context,
                                                 interface_info['port_id'])
            if not port_db:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
            subnet_id = port_db['fixed_ips'][0]['subnet_id']
            subnet = self.core_plugin.get_subnet(context, subnet_id)
        else:
            return super(NuageL3Plugin,
                         self).remove_router_interface(context,
                                                       router_id,
                                                       interface_info)
        session = context.session
        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                      subnet_id)
        if not subnet_l2dom:
            return super(NuageL3Plugin,
                         self).remove_router_interface(context,
                                                       router_id,
                                                       interface_info)
        nuage_subn_id = subnet_l2dom['nuage_subnet_id']

        neutron_subnet = self.core_plugin.get_subnet(context, subnet_id)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session,
            router_id)
        if not ent_rtr_mapping:
            msg = (_("Router %s does not hold net_partition "
                     "assoc on Nuage VSD. Router-IF delete failed")
                   % router_id)
            raise n_exc.BadRequest(resource='router', msg=msg)

        with nuage_utils.rollback() as on_exc:
            last_address = neutron_subnet['allocation_pools'][-1]['end']
            port = self._reserve_ip(self.core_plugin,
                                    context, neutron_subnet, last_address)
            pnet_binding = nuagedb.get_network_binding(
                context.session, neutron_subnet['network_id'])
            on_exc(self.core_plugin.delete_port, context, port['id'])

            self.vsdclient.confirm_router_interface_not_in_use(
                router_id, subnet)
            vsd_l2domain = self.vsdclient.create_l2domain_for_router_detach(
                subnet, subnet_l2dom)
            on_exc(self.vsdclient.delete_subnet, subnet['id'])
            result = super(NuageL3Plugin,
                           self).remove_router_interface(context, router_id,
                                                         interface_info)
            nuagedb.update_subnetl2dom_mapping(
                subnet_l2dom,
                {'nuage_subnet_id': vsd_l2domain['nuage_l2domain_id'],
                 'nuage_l2dom_tmplt_id': vsd_l2domain['nuage_l2template_id']})
            self.vsdclient.move_l3subnet_to_l2domain(
                nuage_subn_id,
                vsd_l2domain['nuage_l2domain_id'],
                subnet_l2dom,
                pnet_binding)

            rollbacks = []
            try:
                self.nuage_callbacks.notify(resources.ROUTER_INTERFACE,
                                            constants.AFTER_DELETE,
                                            self, context=context,
                                            router_id=router_id,
                                            subnet_id=subnet_id,
                                            rollbacks=rollbacks,
                                            subnet_mapping=subnet_l2dom)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for rollback in reversed(rollbacks):
                        rollback[0](*rollback[1], **rollback[2])
            LOG.debug("Deleted nuage domain subnet %s", nuage_subn_id)
            return result

    @log_helpers.log_method_call
    def _get_net_partition_for_router(self, context, rtr):
        ent = rtr.get('net_partition', None)
        if not ent:
            net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                            self.default_np_id)
        else:
            net_partition = (
                nuagedb.get_net_partition_by_id(context.session,
                                                rtr['net_partition'])
                or
                nuagedb.get_net_partition_by_name(context.session,
                                                  rtr['net_partition'])
            )
        if not net_partition:
            msg = _("Either net_partition is not provided with router OR "
                    "default net_partition is not created at the start")
            raise n_exc.BadRequest(resource='router', msg=msg)
        return net_partition

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_router(self, context, id, fields=None):
        router = super(NuageL3Plugin, self).get_router(context, id, fields)
        nuage_router = self.vsdclient.get_router_by_external(id)
        self._add_nuage_router_attributes(router, nuage_router)
        return self._fields(router, fields)

    def _add_nuage_router_attributes(self, router, nuage_router):
        if not nuage_router:
            return
        router['tunnel_type'] = nuage_router.get('tunnelType')
        router['rd'] = nuage_router.get('routeDistinguisher')
        router['rt'] = nuage_router.get('routeTarget')
        router['ecmp_count'] = nuage_router.get('ECMPCount')
        router['nuage_backhaul_vnid'] = nuage_router.get('backHaulVNID')
        router['nuage_backhaul_rd'] = (nuage_router.get(
            'backHaulRouteDistinguisher'))
        router['nuage_backhaul_rt'] = nuage_router.get('backHaulRouteTarget')

        for route in router.get('routes', []):
            params = {
                'address': route['destination'].split("/")[0],
                'nexthop': route['nexthop'],
                'nuage_domain_id': nuage_router['ID']
            }
            nuage_route = self.vsdclient.get_nuage_static_route(params)
            if nuage_route:
                route['rd'] = nuage_route['rd']

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def create_router(self, context, router):
        req_router = copy.deepcopy(router['router'])
        net_partition = self._get_net_partition_for_router(
            context,
            router['router'])
        if 'ecmp_count' in router and not context.is_admin:
            msg = _("ecmp_count can only be set by an admin user.")
            raise nuage_exc.NuageNotAuthorized(resource='router', msg=msg)
        if (cfg.CONF.RESTPROXY.nuage_pat == constants.NUAGE_PAT_NOT_AVAILABLE
                and req_router.get('external_gateway_info')):
            msg = _("nuage_pat config is set to 'not_available'. "
                    "Can't set external_gateway_info")
            raise nuage_exc.NuageBadRequest(resource='router', msg=msg)

        neutron_router = super(NuageL3Plugin, self).create_router(context,
                                                                  router)
        params = {
            'net_partition': net_partition,
            'tenant_id': neutron_router['tenant_id'],
            'nuage_pat': cfg.CONF.RESTPROXY.nuage_pat
        }
        try:
            nuage_router = self.vsdclient.create_router(
                neutron_router, req_router, params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).delete_router(
                    context, neutron_router['id'])

        if nuage_router:
            LOG.debug("Created nuage domain %s", nuage_router[
                'nuage_domain_id'])
            with context.session.begin(subtransactions=True):
                nuagedb.add_entrouter_mapping(context.session,
                                              net_partition['id'],
                                              neutron_router['id'],
                                              nuage_router['nuage_domain_id'],
                                              nuage_router['rt'],
                                              nuage_router['rd'])
            neutron_router['tunnel_type'] = nuage_router['tunnel_type']
            neutron_router['rd'] = nuage_router['rd']
            neutron_router['rt'] = nuage_router['rt']
            neutron_router['ecmp_count'] = nuage_router['ecmp_count']
            neutron_router['nuage_backhaul_vnid'] = \
                nuage_router['nuage_backhaul_vnid']
            neutron_router['nuage_backhaul_rd'] = \
                nuage_router['nuage_backhaul_rd']
            neutron_router['nuage_backhaul_rt'] = \
                nuage_router['nuage_backhaul_rt']

        return neutron_router

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def update_router(self, context, id, router):
        updates = router['router']
        original_router = self.get_router(context, id)
        self._validate_update_router(context, id, updates)
        ent_rtr_mapping = context.ent_rtr_mapping
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']

        curr_router = self.get_router(context, id)
        old_routes = self._get_extra_routes_by_router_id(context, id)

        router_updated = super(NuageL3Plugin, self).update_router(
            context,
            id,
            copy.deepcopy(router))
        if (len(updates) == 1 and 'external_gateway_info' in updates and
                'enable_snat' not in updates['external_gateway_info']):
            return router_updated
        if 'routes' in updates:
            self._update_nuage_router_static_routes(
                id, nuage_domain_id,
                old_routes,
                updates['routes'])
        try:
            if 'routes' in updates and len(updates) == 1:
                pass
            else:
                self._update_nuage_router(nuage_domain_id, curr_router,
                                          updates,
                                          ent_rtr_mapping)
        except Exception:
            with excutils.save_and_reraise_exception():
                if 'routes' in updates:
                    self._update_nuage_router_static_routes(
                        id,
                        nuage_domain_id,
                        updates['routes'],
                        old_routes)
        nuage_router = self.vsdclient.get_router_by_external(id)
        self._add_nuage_router_attributes(router_updated, nuage_router)

        rollbacks = []
        try:
            self.nuage_callbacks.notify(
                resources.ROUTER, constants.AFTER_UPDATE, self,
                context=context, updated_router=router_updated,
                original_router=original_router,
                request_router=updates, domain=nuage_router,
                rollbacks=rollbacks)
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])
        return router_updated

    def _validate_update_router(self, context, id, router):
        if 'ecmp_count' in router and not context.is_admin:
            msg = _("ecmp_count can only be set by an admin user.")
            raise nuage_exc.NuageNotAuthorized(resource='router', msg=msg)
        if (cfg.CONF.RESTPROXY.nuage_pat == constants.NUAGE_PAT_NOT_AVAILABLE
                and router.get('external_gateway_info')):
            msg = _("nuage_pat config is set to 'notavailable'. "
                    "Can't update ext-gw-info")
            raise nuage_exc.OperationNotSupported(resource='router', msg=msg)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(context.session,
                                                               id)
        if not ent_rtr_mapping:
            msg = (_("Router %s does not hold net-partition "
                     "assoc on VSD. extra-route failed") % id)
            raise n_exc.BadRequest(resource='router', msg=msg)
        context.ent_rtr_mapping = ent_rtr_mapping

    def _update_nuage_router_static_routes(self, id, nuage_domain_id,
                                           old_routes, new_routes):
        added, removed = helpers.diff_list_of_dict(old_routes, new_routes)
        routes_removed = []
        routes_added = []
        try:
            for route in removed:
                self._delete_nuage_static_route(nuage_domain_id, route)
                routes_removed.append(route)
            for route in added:
                self._add_nuage_static_route(id, nuage_domain_id, route)
                routes_added.append(route)
        except Exception as e:
            for route in routes_added:
                self._delete_nuage_static_route(nuage_domain_id, route)
            for route in routes_removed:
                self._add_nuage_static_route(id, nuage_domain_id, route)
            raise e

    def _add_nuage_static_route(self, router_id, nuage_domain_id, route):
        params = {
            'nuage_domain_id': nuage_domain_id,
            'neutron_rtr_id': router_id,
            'net': netaddr.IPNetwork(route['destination']),
            'nexthop': route['nexthop']
        }
        self.vsdclient.create_nuage_staticroute(params)

    def _delete_nuage_static_route(self, nuage_domain_id, route):
        destaddr = route['destination']
        cidr = destaddr.split('/')
        params = {
            "address": cidr[0],
            "nexthop": route['nexthop'],
            "nuage_domain_id": nuage_domain_id
        }
        self.vsdclient.delete_nuage_staticroute(params)

    def _update_nuage_router(self, nuage_id, curr_router, router_updates,
                             ent_rtr_mapping):
        params = {
            'net_partition_id': ent_rtr_mapping['net_partition_id'],
            'nuage_pat': cfg.CONF.RESTPROXY.nuage_pat
        }
        curr_router.update(router_updates)
        self.vsdclient.update_router(nuage_id, curr_router, params)
        ns_dict = {
            'nuage_rtr_rt':
                router_updates.get('rt', ent_rtr_mapping.get('nuage_rtr_rt')),
            'nuage_rtr_rd':
                router_updates.get('rd', ent_rtr_mapping.get('nuage_rtr_rd'))
        }
        nuagedb.update_entrouter_mapping(ent_rtr_mapping, ns_dict)

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_router(self, context, id):
        neutron_router = self.get_router(context, id)
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                               id)
        if ent_rtr_mapping:
            LOG.debug("Enterprise to router mapping found for router %s", id)
            filters = {
                'device_id': [id],
                'device_owner': [lib_constants.DEVICE_OWNER_ROUTER_INTF]
            }
            ports = self.core_plugin.get_ports(context, filters)
            if ports:
                raise l3.RouterInUse(router_id=id)
            nuage_domain_id = ent_rtr_mapping['nuage_router_id']
            self.vsdclient.delete_router(nuage_domain_id)

        super(NuageL3Plugin, self).delete_router(context, id)

        if ent_rtr_mapping and not self._check_router_subnet_for_tenant(
                context, neutron_router['tenant_id']):
            LOG.debug("No router/subnet found for tenant %s",
                      neutron_router['tenant_id'])
            user_id, group_id = self.vsdclient.get_usergroup(
                neutron_router['tenant_id'],
                ent_rtr_mapping['net_partition_id'])
            self.vsdclient.delete_user(user_id)
            self.vsdclient.delete_group(group_id)

    @log_helpers.log_method_call
    def _check_router_subnet_for_tenant(self, context, tenant_id):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [tenant_id]}
        routers = self.get_routers(context, filters=filters)
        subnets = self.core_plugin.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    @log_helpers.log_method_call
    def _check_floatingip_update(self, context, port,
                                 vport_type=constants.VM_VPORT,
                                 vport_id=None):
        filter = {'fixed_port_id': [port['id']]}
        local_fip = self.get_floatingips(context,
                                         filters=filter)
        if local_fip:
            fip = local_fip[0]
            self._create_update_floatingip(context,
                                           fip, port['id'],
                                           vport_type=vport_type,
                                           vport_id=vport_id,
                                           rate_update=False)

    @log_helpers.log_method_call
    def _create_update_floatingip(self, context,
                                  neutron_fip, port_id,
                                  last_known_router_id=None,
                                  vport_type=constants.VM_VPORT,
                                  vport_id=None,
                                  rate_update=True):
        if last_known_router_id:
            rtr_id = last_known_router_id
        else:
            rtr_id = neutron_fip['router_id']
        net_id = neutron_fip['floating_network_id']
        subn = nuagedb.get_ipalloc_for_fip(context.session,
                                           net_id,
                                           neutron_fip['floating_ip_address'])

        fip_pool = self.vsdclient.get_nuage_fip_pool_by_id(subn['subnet_id'])
        if not fip_pool:
            msg = _('sharedresource %s not found on VSD') % subn['subnet_id']
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)

        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(context.session,
                                                               rtr_id)
        if not ent_rtr_mapping:
            msg = _('router %s is not associated with '
                    'any net-partition') % rtr_id
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)

        params = {
            'router_id': ent_rtr_mapping['nuage_router_id'],
            'fip_id': neutron_fip['id'],
            'neutron_fip': neutron_fip
        }
        fip = self.vsdclient.get_nuage_fip_by_id(params)

        if not fip:
            LOG.debug("Floating ip not found in VSD for fip %s",
                      neutron_fip['id'])
            params = {
                'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
                'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
                'neutron_fip_ip': neutron_fip['floating_ip_address'],
                'neutron_fip_id': neutron_fip['id']
            }
            nuage_fip_id = self.vsdclient.create_nuage_floatingip(params)
        else:
            nuage_fip_id = fip['nuage_fip_id']

        # Update VM if required
        nuage_vport = self._get_vport_for_fip(context, port_id,
                                              vport_type=vport_type,
                                              vport_id=vport_id,
                                              required=False)

        if nuage_vport:
            nuage_fip = self.vsdclient.get_nuage_fip(nuage_fip_id)

            if nuage_fip['assigned']:
                n_vport = self.vsdclient.get_vport_assoc_with_fip(
                    nuage_fip_id)
                if n_vport:
                    disassoc_params = {
                        'nuage_vport_id': n_vport['ID'],
                        'nuage_fip_id': None
                    }
                    self.vsdclient.update_nuage_vm_vport(disassoc_params)

                if (nuage_vport['domainID']) != (
                        ent_rtr_mapping['nuage_router_id']):
                    fip_dict = {
                        'fip_id': neutron_fip['id'],
                        'fip_last_known_rtr_id': ent_rtr_mapping['router_id']
                    }
                    fip = self.vsdclient.get_nuage_fip_by_id(fip_dict)

                    if fip:
                        self._delete_nuage_fip(context, fip_dict)

                    # Now change the rtd_id to vport's router id
                    rtr_id = neutron_fip['router_id']

                    ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                        context.session,
                        rtr_id
                    )

                    if not ent_rtr_mapping:
                        msg = _('router %s is not associated with '
                                'any net-partition') % rtr_id
                        raise n_exc.BadRequest(resource='floatingip',
                                               msg=msg)

                    params = {
                        'router_id': ent_rtr_mapping['nuage_router_id'],
                        'fip_id': neutron_fip['id'],
                        'neutron_fip': neutron_fip
                    }
                    fip = self.vsdclient.get_nuage_fip_by_id(params)

                    if not fip:
                        LOG.debug("Floating ip not found in VSD for fip %s",
                                  neutron_fip['id'])
                        params = {
                            'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
                            'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
                            'neutron_fip_ip':
                                neutron_fip['floating_ip_address'],
                            'neutron_fip_id': neutron_fip['id']
                        }
                        nuage_fip_id = \
                            self.vsdclient.create_nuage_floatingip(params)
                    else:
                        nuage_fip_id = fip['nuage_fip_id']

            params = {
                'nuage_vport_id': nuage_vport['ID'],
                'nuage_fip_id': nuage_fip_id
            }
            self.vsdclient.update_nuage_vm_vport(params)
            self.fip_rate_log.info(
                'FIP %s (owned by tenant %s) associated to port %s'
                % (neutron_fip['id'], neutron_fip['tenant_id'], port_id))

        # Check if we have to associate a FIP to a VIP
        self._process_fip_to_vip(context, port_id, nuage_fip_id)

        if not rate_update:
            return
        # Add QOS to port for rate limiting
        nuage_fip_rate = neutron_fip.get('nuage_fip_rate_values')
        nuage_fip_rate_configured = nuage_fip_rate.pop('cli_configured', None)
        if nuage_fip_rate_configured and not nuage_vport:
            msg = _('Rate limiting requires the floating ip to be '
                    'associated to a port.')
            raise nuage_exc.NuageBadRequest(msg=msg)
        if nuage_fip_rate_configured and not nuage_vport:
            del neutron_fip['nuage_fip_rate_values']
        if nuage_vport:
            self.vsdclient.create_update_rate_limiting(
                nuage_fip_rate, nuage_vport['ID'],
                neutron_fip['id'])
            for direction, value in nuage_fip_rate.iteritems():
                if 'kbps' in direction:
                    rate_unit = 'K'
                    if 'ingress' in direction:
                        neutron_fip['nuage_ingress_fip_rate_kbps'] = value
                    else:
                        neutron_fip['nuage_egress_fip_rate_kbps'] = value
                else:
                    rate_unit = 'M'
                    neutron_fip['nuage_egress_fip_rate_kbps'] = float(
                        value) * 1000 if float(value) != -1 else -1
                self.fip_rate_log.info(
                    'FIP %s (owned by tenant %s) %s updated to %s %sb/s'
                    % (neutron_fip['id'], neutron_fip['tenant_id'],
                       direction, value, rate_unit))

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_floatingip(self, context, id, fields=None):
        fip = super(NuageL3Plugin, self).get_floatingip(context, id)

        if (not fields or 'nuage_egress_fip_rate_kbps' in fields
            or 'nuage_ingress_fip_rate_kbps' in fields) and fip.get(
           'port_id'):
            try:
                nuage_vport = self._get_vport_for_fip(context, fip['port_id'])
                nuage_rate_limit = self.vsdclient.get_rate_limit(
                    nuage_vport['ID'], fip['id'])
                for direction, value in nuage_rate_limit.iteritems():
                    if 'ingress' in direction:
                        fip['nuage_ingress_fip_rate_kbps'] = value
                    elif 'egress' in direction:
                        fip['nuage_egress_fip_rate_kbps'] = value
            except Exception as e:
                msg = (_('Got exception while retrieving fip rate from vsd: '
                         '%s') % e.message)
                LOG.error(msg)

        return self._fields(fip, fields)

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        neutron_fip = super(NuageL3Plugin, self).create_floatingip(
            context, floatingip,
            initial_status=lib_constants.FLOATINGIP_STATUS_DOWN)
        nuage_fip_rate = self._get_values_for_fip_rate(
            fip, for_update='port_id' not in fip)
        fip_rate_configured = nuage_fip_rate.get('cli_configured')
        if fip_rate_configured:
            if not fip.get('port_id'):
                msg = _('Rate limiting requires the floating ip to be '
                        'associated to a port.')
                raise nuage_exc.NuageBadRequest(msg=msg)
        if not neutron_fip['router_id']:
            neutron_fip['nuage_egress_fip_rate_kbps'] = None
            neutron_fip['nuage_ingress_fip_rate_kbps'] = None
            return neutron_fip
        neutron_fip['nuage_fip_rate_values'] = nuage_fip_rate

        try:
            self._create_update_floatingip(context, neutron_fip,
                                           fip['port_id'])
            self.update_floatingip_status(
                context, neutron_fip['id'],
                lib_constants.FLOATINGIP_STATUS_ACTIVE)
            neutron_fip['status'] = lib_constants.FLOATINGIP_STATUS_ACTIVE
        except (nuage_exc.OperationNotSupported, n_exc.BadRequest):
            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).delete_floatingip(
                    context, neutron_fip['id'])
        return neutron_fip

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context, filters={'port_id': [port_id]})
        router_ids = super(NuageL3Plugin, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)

        if not fips:
            return router_ids

        # we can hav only 1 fip associated with a vPort at a time.fips[0]
        self.update_floatingip_status(
            context, fips[0]['id'], lib_constants.FLOATINGIP_STATUS_DOWN)

        # Disassociate only if nuage_port has a FIP associated with it.
        # Calling disassociate on a port with no FIP causes no issue in Neutron
        # but VSD throws an exception
        nuage_vport = self._get_vport_for_fip(context, port_id, required=False)
        if nuage_vport and nuage_vport.get('associatedFloatingIPID'):
            for fip in fips:
                self.vsdclient.delete_rate_limiting(
                    nuage_vport['ID'], fip['id'])
                self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                       'disassociated from port %s'
                                       % (fip['id'], fip['tenant_id'],
                                          port_id))
            params = {
                'nuage_vport_id': nuage_vport['ID'],
                'nuage_fip_id': None
            }
            self.vsdclient.update_nuage_vm_vport(params)
            LOG.debug("Disassociated floating ip from VM attached at port %s",
                      port_id)

        return router_ids

    def _get_values_for_fip_rate(self, fip, for_update=False):
        fip_rate_values = {}
        egress_fip_rate_mbps = fip.get('nuage_fip_rate',
                                       lib_constants.ATTR_NOT_SPECIFIED)
        ingress_fip_rate_kbps = fip.get('nuage_ingress_fip_rate_kbps',
                                        lib_constants.ATTR_NOT_SPECIFIED)
        egress_fip_rate_kbps = fip.get('nuage_egress_fip_rate_kbps',
                                       lib_constants.ATTR_NOT_SPECIFIED)
        egress_fip_rate_mbps_configured = (egress_fip_rate_mbps is not
                                           lib_constants.ATTR_NOT_SPECIFIED)
        egress_fip_rate_kbps_configured = (egress_fip_rate_kbps is not
                                           lib_constants.ATTR_NOT_SPECIFIED)
        ingress_fip_rate_kbps_configured = (ingress_fip_rate_kbps is not
                                            lib_constants.ATTR_NOT_SPECIFIED)
        if egress_fip_rate_kbps_configured:
            fip_rate_values['egress_nuage_fip_rate_kbps'] = (
                egress_fip_rate_kbps)
            fip_rate_values['cli_configured'] = True
        elif egress_fip_rate_mbps_configured:
            fip_rate_values['egress_nuage_fip_rate_mbps'] = (
                egress_fip_rate_mbps)
            fip_rate_values['cli_configured'] = True
        if ingress_fip_rate_kbps_configured:
            fip_rate_values['ingress_nuage_fip_rate_kbps'] = (
                ingress_fip_rate_kbps)
            fip_rate_values['cli_configured'] = True
        if for_update:
            return fip_rate_values
        return self._get_missing_rate_values(fip_rate_values)

    def _get_missing_rate_values(self, fip_rate_values):
        if not (fip_rate_values.get('egress_nuage_fip_rate_kbps') is not None
                or fip_rate_values.get(
                'egress_nuage_fip_rate_mbps') is not None):
            if self.def_egress_rate_kbps is not None:
                fip_rate_values['egress_nuage_fip_rate_kbps'] = (
                    self.def_egress_rate_kbps)
            elif self.def_fip_rate is not None:
                fip_rate_values['egress_nuage_fip_rate_mbps'] = (
                    self.def_fip_rate)
        if not (fip_rate_values.get('ingress_nuage_fip_rate_kbps'
                                    ) is not None):
            fip_rate_values['ingress_nuage_fip_rate_kbps'] = (
                self.def_ingress_rate_kbps)
        return fip_rate_values

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        orig_fip = self._get_floatingip(context, id)
        port_id = orig_fip['fixed_port_id']
        router_ids = []
        neutron_fip = self._make_floatingip_dict(orig_fip)
        nuage_fip_rate = self._get_values_for_fip_rate(
            fip,
            for_update='port_id' not in fip)
        fip_rate_configured = nuage_fip_rate.get('cli_configured', None)

        with context.session.begin(subtransactions=True):
            if 'port_id' in fip or fip.get('description'):
                neutron_fip = super(NuageL3Plugin, self).update_floatingip(
                    context, id, floatingip)
            last_known_router_id = orig_fip['last_known_router_id']
            if fip.get('port_id'):
                if not neutron_fip['router_id']:
                    ret_msg = 'floating-ip is not associated yet'
                    raise n_exc.BadRequest(resource='floatingip',
                                           msg=ret_msg)
                neutron_fip['nuage_fip_rate_values'] = nuage_fip_rate
                try:
                    self._create_update_floatingip(context,
                                                   neutron_fip,
                                                   fip['port_id'],
                                                   last_known_router_id)
                    self.update_floatingip_status(
                        context, neutron_fip['id'],
                        lib_constants.FLOATINGIP_STATUS_ACTIVE)
                    neutron_fip['status'] = (
                        lib_constants.FLOATINGIP_STATUS_ACTIVE)
                except nuage_exc.OperationNotSupported:
                    with excutils.save_and_reraise_exception():
                        router_ids = super(
                            NuageL3Plugin, self).disassociate_floatingips(
                            context, fip['port_id'], do_notify=False)
                except n_exc.BadRequest:
                    with excutils.save_and_reraise_exception():
                        super(NuageL3Plugin, self).delete_floatingip(
                            context, id)
            elif 'port_id' in fip:
                # This happens when {'port_id': null} is in request.
                # Disassociate
                if fip_rate_configured:
                    ret_msg = _('Rate limiting requires the floating ip to be '
                                'associated to a port.')
                    raise n_exc.BadRequest(resource='floatingip', msg=ret_msg)

                # Check for disassociation of fip from vip, only if port_id
                # is not None
                if port_id:
                    self._process_fip_to_vip(context, port_id)

                nuage_vport = self._get_vport_for_fip(context, port_id)
                if nuage_vport:
                    params = {
                        'nuage_vport_id': nuage_vport['ID'],
                        'nuage_fip_id': None
                    }
                    self.vsdclient.update_nuage_vm_vport(params)
                    fip_id = id
                    ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                        context.session,
                        last_known_router_id)
                    if not ent_rtr_mapping:
                        msg = _('router %s is not associated with '
                                'any net-partition') % last_known_router_id
                        raise n_exc.BadRequest(resource='floatingip', msg=msg)

                    params = {
                        'router_id': ent_rtr_mapping['nuage_router_id'],
                        'fip_id': fip_id
                    }
                    nuage_fip = self.vsdclient.get_nuage_fip_by_id(params)
                    if nuage_fip:
                        self.vsdclient.delete_nuage_floatingip(
                            nuage_fip['nuage_fip_id'])
                        LOG.debug('Floating-ip %s deleted from VSD', fip_id)

                    self.vsdclient.delete_rate_limiting(
                        nuage_vport['ID'], id)
                    self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                           'disassociated from port %s'
                                           % (id, neutron_fip['tenant_id'],
                                              port_id))

                self.update_floatingip_status(
                    context, neutron_fip['id'],
                    lib_constants.FLOATINGIP_STATUS_DOWN)
                neutron_fip['status'] = lib_constants.FLOATINGIP_STATUS_DOWN

        # purely rate limit update. Use existing port data.
        if 'port_id' not in fip and fip_rate_configured:
            if not port_id:
                msg = _('Rate limiting requires the floating ip to be '
                        'associated to a port.')
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
            # Add QOS to port for rate limiting
            nuage_vport = self._get_vport_for_fip(context, port_id)
            nuage_fip_rate.pop('cli_configured', None)
            orig_fip['nuage_fip_rate_values'] = nuage_fip_rate

            self.vsdclient.create_update_rate_limiting(
                nuage_fip_rate, nuage_vport['ID'],
                orig_fip['id'])
            for direction, value in nuage_fip_rate.iteritems():
                if 'kbps' in direction:
                    rate_unit = 'K'
                    if 'ingress' in direction:
                        neutron_fip['nuage_ingress_fip_rate_kbps'] = value
                    else:
                        neutron_fip['nuage_egress_fip_rate_kbps'] = value
                else:
                    rate_unit = 'M'
                    neutron_fip['nuage_egress_fip_rate_kbps'] = float(
                        value) * 1000 if float(value) != -1 else -1
                self.fip_rate_log.info(
                    'FIP %s (owned by tenant %s) %s updated to %s %sb/s'
                    % (orig_fip['id'], orig_fip['tenant_id'], direction, value,
                       rate_unit))
            neutron_fip['nuage_fip_rate'] = orig_fip['nuage_fip_rate_values']
        elif not fip_rate_configured:
            neutron_fip = self.get_floatingip(context, id)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)

        return neutron_fip

    @nuage_utils.handle_nuage_api_error
    @db.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_floatingip(self, context, fip_id):
        fip = self._get_floatingip(context, fip_id)
        port_id = fip['fixed_port_id']
        if port_id:
            nuage_vport = self._get_vport_for_fip(context, port_id,
                                                  required=False)
            if nuage_vport and nuage_vport['ID'] is not None:
                params = {
                    'nuage_vport_id': nuage_vport['ID'],
                    'nuage_fip_id': None
                }
                self.vsdclient.update_nuage_vm_vport(params)
                LOG.debug("Floating-ip %(fip)s is disassociated from "
                          "vport %(vport)s",
                          {'fip': fip_id,
                           'vport': nuage_vport['ID']})
                self.vsdclient.delete_rate_limiting(
                    nuage_vport['ID'], fip_id)
                self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                       'disassociated from port %s'
                                       % (fip_id, fip['tenant_id'],
                                          port_id))
            else:
                # Could be vip-port (fip2vip feature)
                port = self.core_plugin.get_port(context, port_id)
                if (port.get('device_owner') ==
                        constants.DEVICE_OWNER_VIP_NUAGE):
                    neutron_subnet_id = port['fixed_ips'][0]['subnet_id']
                    vip = port['fixed_ips'][0]['ip_address']
                    self.vsdclient.disassociate_fip_from_vips(
                        neutron_subnet_id, vip)
            router_id = fip['router_id']
        else:
            router_id = fip['last_known_router_id']

        if router_id:
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                context.session,
                router_id)
            if ent_rtr_mapping:
                params = {
                    'router_id': ent_rtr_mapping['nuage_router_id'],
                    'fip_id': fip_id
                }
                nuage_fip = self.vsdclient.get_nuage_fip_by_id(params)
                if nuage_fip:
                    self.vsdclient.delete_nuage_floatingip(
                        nuage_fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

        super(NuageL3Plugin, self).delete_floatingip(context, fip_id)
        self.fip_rate_log.info('FIP %s (owned by tenant %s) deleted' %
                               (fip_id, fip['tenant_id']))

    def _get_vport_for_fip(self, context, port_id,
                           vport_type=constants.VM_VPORT,
                           vport_id=None, required=True):
        port = self.core_plugin.get_port(context, port_id)
        if not port['fixed_ips']:
            return

        vport = None
        params = {
            'neutron_port_id': port_id,
            'nuage_vport_type': vport_type,
            'nuage_vport_id': vport_id
        }
        try:
            vport = self.vsdclient.get_nuage_port_by_id(params)
        except Exception:
            pass
        if vport:
            return vport

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        params = {
            'neutron_port_id': port_id,
        }
        if subnet_mapping and subnet_mapping['nuage_l2dom_tmplt_id']:
            params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        elif subnet_mapping:
            params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        return self.vsdclient.get_nuage_vport_by_neutron_id(
            params, required=required)

    def _process_fip_to_vip(self, context, port_id, nuage_fip_id=None):
        port = self.core_plugin._get_port(context, port_id)
        neutron_subnet_id = port['fixed_ips'][0]['subnet_id']
        vip = port['fixed_ips'][0]['ip_address']
        self.vsdclient.associate_fip_to_vips(
            neutron_subnet_id, vip, nuage_fip_id)

    @log_helpers.log_method_call
    def _delete_nuage_fip(self, context, fip_dict):
        if fip_dict:
            fip_id = fip_dict['fip_id']
            port_id = fip_dict.get('fip_fixed_port_id')
            if port_id:
                router_id = fip_dict['fip_router_id']
            else:
                router_id = fip_dict['fip_last_known_rtr_id']
            if router_id:
                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                    context.session,
                    router_id)
                if not ent_rtr_mapping:
                    msg = _('router %s is not associated with '
                            'any net-partition') % router_id
                    raise n_exc.BadRequest(resource='floatingip', msg=msg)
                params = {
                    'router_id': ent_rtr_mapping['nuage_router_id'],
                    'fip_id': fip_id
                }

                nuage_fip = self.vsdclient.get_nuage_fip_by_id(params)
                if nuage_fip:
                    self.vsdclient.delete_nuage_floatingip(
                        nuage_fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

    def _nuage_vips_on_subnet(self, context, subnet):
        vip_found = False
        filters = {'device_owner':
                   [constants.DEVICE_OWNER_VIP_NUAGE],
                   'network_id': [subnet['network_id']]}
        ports = self.core_plugin.get_ports(context, filters)

        for p in ports:
            if p['fixed_ips'][0]['subnet_id'] == subnet['id']:
                vip_found = True
                break
        return vip_found
