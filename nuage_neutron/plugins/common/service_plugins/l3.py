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
from neutron._i18n import _
from neutron.db import dns_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib.db import api as lib_db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as lib_plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log.formatters import ContextFormatter
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils
import six

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common.extensions import nuage_router
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import routing_mechanisms
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id
from nuage_neutron.vsdclient.restproxy import ResourceNotFoundException

LOG = logging.getLogger(__name__)


class NuageL3Plugin(base_plugin.BaseNuagePlugin,
                    service_base.ServicePluginBase,
                    extraroute_db.ExtraRoute_db_mixin,
                    l3_gwmode_db.L3_NAT_db_mixin,
                    dns_db.DNSDbMixin):
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
        self.supported_network_types = [lib_constants.TYPE_VXLAN]

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    def get_plugin_type(self):
        return lib_plugin_constants.L3

    def get_plugin_description(self):
        return "Plugin providing support for routers and floatingips."

    def init_fip_rate_log(self):
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

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def add_router_interface(self, context, router_id, interface_info=None):
        # pre-commit begins here
        session = context.session
        vport = dss_mapping = None
        subnet_id, subnet_mapping, vport = (
            self._process_router_interface_add_info(context,
                                                    interface_info,
                                                    session,
                                                    vport))
        subnet = self.core_plugin.get_subnet(context, subnet_id)
        network = self.core_plugin.get_network(context, subnet['network_id'])

        if not self.is_network_type_supported(network):
            if self.is_nuage_hybrid_mpls_network(network):
                msg = (('It is not allowed to add a router interface '
                        'to a network type {}, or if it has a segment '
                        'of this type.')
                       .format(constants.NUAGE_HYBRID_MPLS_NET_TYPE))
                raise nuage_exc.NuageBadRequest(msg=msg)
            return super(NuageL3Plugin, self).add_router_interface(
                context, router_id, interface_info)

        if nuagedb.get_nuage_l2bridge_id_for_network(session,
                                                     network['id']):
            msg = _("It is not allowed to add a router interface to a"
                    "subnet that is attached to a nuage_l2bridge.")
            raise nuage_exc.NuageBadRequest(msg=msg)

        if network['router:external']:
            msg = _("Subnet in external network cannot be an interface of "
                    "a router.")
            raise nuage_exc.NuageBadRequest(msg=msg)

        vsd_zone = self.vsdclient.get_zone_by_routerid(router_id,
                                                       subnet['shared'])
        dual_stack_subnet = self.get_dual_stack_subnet(context, subnet)
        ipv4_subnet, ipv6_subnet = self.seperate_ipv4_ipv6_subnet(
            subnet, dual_stack_subnet)

        if dual_stack_subnet:
            dss_mapping = nuagedb.get_subnet_l2dom_by_id(
                session, dual_stack_subnet['id'])
            self._nuage_dualstack_valid_dss_rtr(
                dual_stack_subnet, dss_mapping, router_id)

        ipv4_subnet_mapping, ipv6_subnet_mapping = \
            self.seperate_ipv4_ipv6_mapping(subnet, ipv4_subnet,
                                            subnet_mapping, dss_mapping)

        nuage_subnet_id, nuage_rtr_id = self._nuage_validate_add_rtr_itf(
            session, router_id,
            subnet, subnet_mapping, vsd_zone,
            dual_stack_subnet)

        # pre-commit ends here

        rtr_if_info = super(NuageL3Plugin, self).add_router_interface(
            context, router_id, interface_info)

        # post-commit begins from here

        if vport:
            self.vsdclient.delete_nuage_vport(vport['ID'])
        try:
            if subnet_mapping and self._is_l3(subnet_mapping):
                # This subnet is already l3
                self._notify_add_del_router_interface(
                    constants.AFTER_CREATE,
                    context=context,
                    router_id=router_id,
                    subnet_id=subnet_id,
                    subnet_mapping=subnet_mapping)
                self._update_port_status(context, rtr_if_info['port_id'],
                                         lib_constants.PORT_STATUS_ACTIVE)
                return rtr_if_info
            self.vsdclient.validate_create_domain_subnet(
                subnet, nuage_subnet_id, nuage_rtr_id)
            return self._nuage_add_router_interface(
                context, session, router_id, rtr_if_info,
                subnet_mapping, subnet_id, ipv4_subnet, ipv6_subnet, subnet,
                vsd_zone, ipv4_subnet_mapping, ipv6_subnet_mapping,
                network['name'])
        except Exception as exc:
            msg = ["overlaps with another subnet",
                   "overlaps with existing network"]
            if msg[0] in str(exc) or msg[1] in str(exc):
                subnet_id = rtr_if_info['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                    session, subnet_id)
                nuage_id = subnet_mapping.get('nuage_subnet_id')
                if nuage_id:
                    vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                        subnet_mapping)
                    if vsd_subnet:
                        msg = "In add_router_interface exception, " \
                              "nuage domain %s exists already. " \
                              "Ignoring RestProxy error: %s" % (
                                  vsd_subnet['ID'], exc)
                        LOG.warn(msg)
                        # this subnet has already moved to l3
                        # concurrently, so we are good here.

                        self._notify_add_del_router_interface(
                            constants.AFTER_CREATE,
                            context=context,
                            router_id=router_id,
                            subnet_id=subnet_id,
                            subnet_mapping=subnet_mapping)

                        self._update_port_status(
                            context, rtr_if_info['port_id'],
                            lib_constants.PORT_STATUS_ACTIVE)
                        return rtr_if_info

            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).remove_router_interface(
                    context, router_id, interface_info)

    def _process_router_interface_add_info(self, context, interface_info,
                                           session, vport):
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        if add_by_port:
            port_id = interface_info['port_id']
            port = self.core_plugin._get_port(context, port_id)
            if not port['fixed_ips']:
                msg = _("Port must have fixed ip mapping of a subnet")
                raise n_exc.BadRequest(resource='port', msg=msg)
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
            if subnet_l2dom:
                port_params = {'neutron_port_id': port['id']}
                if self._is_l2(subnet_l2dom):
                    port_params['l2dom_id'] = subnet_l2dom['nuage_subnet_id']
                else:
                    port_params['l3dom_id'] = subnet_l2dom['nuage_subnet_id']
                vport = self.vsdclient.get_nuage_vport_by_neutron_id(
                    port_params,
                    required=False)
        else:
            subnet_id = interface_info['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
        return subnet_id, subnet_l2dom, vport

    def _check_existing_subnet_on_network(self, context, subnet):
        subnets = self.core_plugin.get_subnets(
            context,
            filters={'network_id': [subnet['network_id']]})
        other_subnets = (s for s in subnets if s['id'] != subnet['id'])
        return next(other_subnets, None)

    def seperate_ipv4_ipv6_subnet(self, subnet, dual_stack_subnet):
        if self._is_ipv4(subnet):
            ipv4_subnet, ipv6_subnet = subnet, dual_stack_subnet
        else:
            ipv4_subnet, ipv6_subnet = dual_stack_subnet, subnet
        return ipv4_subnet, ipv6_subnet

    def seperate_ipv4_ipv6_mapping(self, subnet, ipv4_subnet, sub_mapping,
                                   dss_mapping):
        if ipv4_subnet and self._is_ipv4(subnet):
            return sub_mapping, dss_mapping
        else:
            return dss_mapping, sub_mapping

    def check_if_subnet_is_attached_to_router(self, context, subnet):
        filters = {
            'network_id': [subnet['network_id']],
            'device_owner': [lib_constants.DEVICE_OWNER_ROUTER_INTF]
        }
        ports = self.core_plugin.get_ports(context, filters)
        for p in ports:
            for ip in p['fixed_ips']:
                if ip['subnet_id'] in subnet['id']:
                    router_id = nuagedb.get_routerport_by_port_id(
                        context.session, p['id'])['router_id']
                    return True, str(router_id)
        return False, None

    def _nuage_dualstack_valid_dss_rtr(self, dual_stack_subnet,
                                       dss_l2dom,
                                       router_id):
        vsd_dss = self.vsdclient.get_nuage_subnet_by_mapping(dss_l2dom)

        if vsd_dss and self._is_l3(dss_l2dom):
            nuage_dss_rtr_id = (
                self.vsdclient.get_l3domain_id_by_domain_subnet_id(
                    vsd_dss['ID']))
            nuage_rtr_id = self.vsdclient.get_l3domain_by_external_id(
                router_id)["ID"]
            if nuage_rtr_id != nuage_dss_rtr_id:
                raise nuage_router.RtrItfAddDualSSAlreadyAttachedToAnotherRtr(
                    router=nuage_dss_rtr_id, subnet=dual_stack_subnet['id'])

    def _nuage_add_router_interface(self, context, session, router_id,
                                    rtr_if_info, subnet_mapping, subnet_id,
                                    ipv4_subnet, ipv6_subnet, subnet,
                                    vsd_zone, ipv4_subnet_mapping,
                                    ipv6_subnet_mapping, network_name):
        if ipv4_subnet and ipv4_subnet['enable_dhcp']:
            self.delete_dhcp_nuage_port(context, ipv4_subnet)
        elif ipv6_subnet and ipv6_subnet['enable_dhcp']:
            self.delete_dhcp_nuage_port(context, ipv6_subnet)

        with nuage_utils.rollback() as on_exc:
            vsd_subnet = self.vsdclient.create_domain_subnet(
                vsd_zone, ipv4_subnet, ipv6_subnet, network_name,
                config.ingress_replication_enabled())

            on_exc(self.vsdclient.delete_domain_subnet,
                   vsd_subnet['ID'], subnet['id'])

            self.vsdclient.move_l2domain_to_l3subnet(
                subnet_mapping['nuage_subnet_id'],
                vsd_subnet['ID'])
            self.set_mapping_as_l3subnet(session, ipv4_subnet_mapping,
                                         ipv6_subnet_mapping, vsd_subnet)

            self._notify_add_del_router_interface(
                constants.AFTER_CREATE,
                context=context,
                router_id=router_id,
                subnet_id=subnet_id,
                subnet_mapping=subnet_mapping)

        self._update_port_status(context, rtr_if_info['port_id'],
                                 lib_constants.PORT_STATUS_ACTIVE)
        return rtr_if_info

    @staticmethod
    def set_mapping_as_l2domain(session, ipv4_subnet_mapping,
                                ipv6_subnet_mapping, vsd_l2domain):
        with session.begin(subtransactions=True):
            if ipv4_subnet_mapping:
                nuagedb.update_subnetl2dom_mapping(
                    ipv4_subnet_mapping,
                    {'nuage_subnet_id': vsd_l2domain['nuage_l2domain_id'],
                     'nuage_l2dom_tmplt_id': vsd_l2domain[
                         'nuage_l2template_id']})
            if ipv6_subnet_mapping:
                nuagedb.update_subnetl2dom_mapping(
                    ipv6_subnet_mapping,
                    {'nuage_subnet_id': vsd_l2domain['nuage_l2domain_id'],
                     'nuage_l2dom_tmplt_id':
                         vsd_l2domain['nuage_l2template_id']})

    def _notify_add_del_router_interface(
            self, event,
            context,
            router_id,
            subnet_id,
            subnet_mapping):

        rollbacks = []
        try:
            self.nuage_callbacks.notify(resources.ROUTER_INTERFACE,
                                        event,
                                        self,
                                        context=context,
                                        router_id=router_id,
                                        subnet_id=subnet_id,
                                        rollbacks=rollbacks,
                                        subnet_mapping=subnet_mapping)
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])

    def _update_port_status(self, context, port_id, status):
        self.core_plugin.update_port_status(context=context,
                                            port_id=port_id,
                                            status=status)

    @staticmethod
    def _nuage_validate_add_rtr_itf(session, router_id, subnet,
                                    subnet_l2dom, nuage_zone,
                                    dual_stack_subnet):
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
        if (not dual_stack_subnet and
                subnet_l2dom['nuage_l2dom_tmplt_id'] is None):
            raise nuage_router.RtrItfAddSubnetForMultipleRouters(
                subnet=subnet_id)
        nuage_subnet_id = subnet_l2dom['nuage_subnet_id']
        nuage_rtr_id = ent_rtr_mapping['nuage_router_id']
        return nuage_subnet_id, nuage_rtr_id

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def remove_router_interface(self, context, router_id, interface_info):
        port_id_specified = interface_info and 'port_id' in interface_info
        subnet_id_specified = interface_info and 'subnet_id' in interface_info
        if subnet_id_specified:
            subnet_id = interface_info['subnet_id']
            subnet = self.core_plugin.get_subnet(context, subnet_id)
            if not self._is_vxlan_network_by_id(context,
                                                subnet['network_id']):
                return super(NuageL3Plugin,
                             self).remove_router_interface(context,
                                                           router_id,
                                                           interface_info)
            filters = {'device_id': [router_id],
                       'device_owner':
                           [lib_constants.DEVICE_OWNER_ROUTER_INTF],
                       'network_id': [subnet['network_id']]}
            router_interfaces = any(p['fixed_ips'][0]['subnet_id'] == subnet_id
                                    for p in self.core_plugin.get_ports(
                context, filters))
            if not router_interfaces:
                raise l3_exc.RouterInterfaceNotFoundForSubnet(
                    router_id=router_id, subnet_id=subnet_id)
        elif port_id_specified:
            try:
                port_db = self.core_plugin._get_port(context,
                                                     interface_info['port_id'])
            except n_exc.PortNotFound:
                raise l3_exc.RouterInterfaceNotFound(
                    router_id=router_id, port_id=interface_info['port_id'])
            if not self._is_vxlan_network_by_id(context,
                                                port_db['network_id']):
                return super(NuageL3Plugin,
                             self).remove_router_interface(context,
                                                           router_id,
                                                           interface_info)
            if not port_db or port_db['device_id'] != router_id:
                raise l3_exc.RouterInterfaceNotFound(
                    router_id=router_id, port_id=interface_info['port_id'])
            subnet_id = port_db['fixed_ips'][0]['subnet_id']
            subnet = self.core_plugin.get_subnet(context, subnet_id)
        else:
            # let upstream handle the error reporting
            return super(NuageL3Plugin,
                         self).remove_router_interface(context,
                                                       router_id,
                                                       interface_info)
        session = context.session
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                        subnet_id)
        if not subnet_mapping:
            return super(NuageL3Plugin,
                         self).remove_router_interface(context,
                                                       router_id,
                                                       interface_info)
        nuage_subn_id = subnet_mapping['nuage_subnet_id']
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session,
            router_id)
        if not ent_rtr_mapping:
            msg = (_("Router %s does not hold net_partition "
                     "assoc on Nuage VSD. Router-IF delete failed")
                   % router_id)
            raise n_exc.BadRequest(resource='router', msg=msg)

        dual_stack_subnet = self.get_dual_stack_subnet(context, subnet)

        dss_mapping = None
        if dual_stack_subnet:
            router_attached, r_id = self.check_if_subnet_is_attached_to_router(
                context, dual_stack_subnet)
            if router_attached and not ('port_id' in interface_info):
                return super(NuageL3Plugin, self).remove_router_interface(
                    context, router_id, interface_info)
            dss_mapping = nuagedb.get_subnet_l2dom_by_id(
                session, dual_stack_subnet['id'])

        ipv4_subnet, ipv6_subnet = self.seperate_ipv4_ipv6_subnet(
            subnet, dual_stack_subnet)

        ipv4_subnet_mapping, ipv6_subnet_mapping = \
            self.seperate_ipv4_ipv6_mapping(subnet, ipv4_subnet,
                                            subnet_mapping, dss_mapping)

        with nuage_utils.rollback() as on_exc:
            dhcp_port = self.create_update_dhcp_nuage_port(context, subnet)
            if dual_stack_subnet:
                dhcp_port = self.create_update_dhcp_nuage_port(
                    context, dual_stack_subnet, dualstack=subnet)
            ipv4_dhcp_ip = ipv6_dhcp_ip = None
            if dhcp_port:
                on_exc(self.delete_dhcp_nuage_port_by_id, context,
                       dhcp_port['id'])
                for fixed_ip in dhcp_port['fixed_ips']:
                    if (ipv4_subnet and
                            fixed_ip['subnet_id'] == ipv4_subnet['id']):
                        ipv4_dhcp_ip = fixed_ip['ip_address']
                    if (ipv6_subnet and
                            fixed_ip['subnet_id'] == ipv6_subnet['id']):
                        ipv6_dhcp_ip = fixed_ip['ip_address']

            self.vsdclient.confirm_router_interface_not_in_use(router_id,
                                                               subnet)
            network = self.core_plugin.get_network(context,
                                                   subnet['network_id'])
            subnet_mapping['network_name'] = network['name']
            with session.begin(subtransactions=True):
                vsd_l2domain = (
                    self.vsdclient.create_l2domain_for_router_detach(
                        ipv4_subnet, subnet_mapping, ipv6_subnet,
                        ipv4_dhcp_ip, ipv6_dhcp_ip,
                        config.default_allow_non_ip_enabled(),
                        config.ingress_replication_enabled()))
                on_exc(self.vsdclient.delete_subnet,
                       l2dom_id=vsd_l2domain['nuage_l2domain_id'])
            result = super(NuageL3Plugin,
                           self).remove_router_interface(context, router_id,
                                                         interface_info)
            self.set_mapping_as_l2domain(session,
                                         ipv4_subnet_mapping,
                                         ipv6_subnet_mapping,
                                         vsd_l2domain)

            self.vsdclient.move_l3subnet_to_l2domain(
                nuage_subn_id,
                vsd_l2domain['nuage_l2domain_id'],
                ipv4_subnet_mapping,
                subnet,
                ipv6_subnet_mapping
            )

            self._notify_add_del_router_interface(
                constants.AFTER_DELETE,
                context=context,
                router_id=router_id,
                subnet_id=subnet_id,
                subnet_mapping=subnet_mapping)
            routing_mechanisms.delete_nuage_subnet_parameters(context,
                                                              subnet_id)
            LOG.debug("Deleted nuage domain subnet %s", nuage_subn_id)
            return result

    @staticmethod
    def set_mapping_as_l3subnet(session, ipv4_subnet_mapping,
                                ipv6_subnet_mapping, vsd_subnet):
        with session.begin(subtransactions=True):
            if ipv4_subnet_mapping:
                nuagedb.update_subnetl2dom_mapping(
                    ipv4_subnet_mapping,
                    {'nuage_subnet_id': vsd_subnet['ID'],
                     'nuage_l2dom_tmplt_id': None})
            if ipv6_subnet_mapping:
                nuagedb.update_subnetl2dom_mapping(
                    ipv6_subnet_mapping,
                    {'nuage_subnet_id': vsd_subnet['ID'],
                     'nuage_l2dom_tmplt_id': None})

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_router(self, context, id, fields=None):
        router = super(NuageL3Plugin, self).get_router(context, id, fields)
        nuage_router = self.vsdclient.get_l3domain_by_external_id(id)
        self._add_nuage_router_attributes(context.session, router,
                                          nuage_router)
        return self._fields(router, fields)

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        routers = super(NuageL3Plugin, self).get_routers(context, filters,
                                                         fields, sorts, limit,
                                                         marker, page_reverse)
        for router in routers:
            self._add_nuage_router_attributes(context.session, router)
            self._fields(router, fields)
        return routers

    def _add_nuage_router_attributes(self, session, router, nuage_router=None):
        # Local db:
        aggregate_flows_param = nuagedb.get_router_parameter(
            session, router['id'], constants.AGGREGATE_FLOWS)
        router[constants.AGGREGATE_FLOWS] = (
            aggregate_flows_param['parameter_value'] if
            aggregate_flows_param else constants.AGGREGATE_FLOWS_OFF)

        routing_mechanisms.add_nuage_router_attributes(session, router)

        if not nuage_router:
            return
        # VSD params
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            session, router['id'])
        router['net_partition'] = ent_rtr_mapping['net_partition_id']

        router['tunnel_type'] = nuage_router.get('tunnelType')
        router['rd'] = nuage_router.get('routeDistinguisher')
        router['rt'] = nuage_router.get('routeTarget')
        router['ecmp_count'] = nuage_router.get('ECMPCount')
        router['nuage_backhaul_vnid'] = nuage_router.get('backHaulVNID')
        router['nuage_backhaul_rd'] = (nuage_router.get(
            'backHaulRouteDistinguisher'))
        router['nuage_backhaul_rt'] = nuage_router.get('backHaulRouteTarget')
        router['nuage_router_template'] = nuage_router.get('templateID')
        for route in router.get('routes', []):
            params = {
                'address': route['destination'],
                'nexthop': route['nexthop'],
                'nuage_domain_id': nuage_router['ID']
            }
            nuage_route = self.vsdclient.get_nuage_static_route(params)
            if nuage_route:
                route['rd'] = nuage_route['rd']

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def create_router(self, context, router):
        routing_mechanisms.update_routing_values(router['router'])

        req_router = copy.deepcopy(router['router'])
        net_partition = self._get_net_partition_for_entity(
            context, router['router'])
        self._validate_create_router(context, net_partition['name'], router)
        neutron_router = super(NuageL3Plugin, self).create_router(context,
                                                                  router)
        nuage_router = None
        try:
            nuage_router = self.vsdclient.create_l3domain(
                neutron_router, req_router, net_partition, context.tenant_name,
                config.default_allow_non_ip_enabled())
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).delete_router(
                    context, neutron_router['id'])

        if nuage_router:
            LOG.debug("Created nuage domain %s", nuage_router['ID'])
            with context.session.begin(subtransactions=True):
                nuagedb.add_entrouter_mapping(
                    context.session, net_partition['id'],
                    neutron_router['id'], nuage_router['ID'],
                    nuage_router['routeTarget'],
                    nuage_router['routeDistinguisher'])
                routing_mechanisms.update_nuage_router_parameters(
                    req_router, context, neutron_router['id']
                )
                self._update_nuage_router_aggregate_flows(context, req_router,
                                                          neutron_router['id'])
            self._add_nuage_router_attributes(context.session, neutron_router,
                                              nuage_router)
        return neutron_router

    def _validate_create_router(self, context, netpart_name, router):
        if netpart_name == constants.SHARED_INFRASTRUCTURE:
            msg = _("It is not allowed to create routers in "
                    "the net_partition {}").format(netpart_name)
            raise n_exc.BadRequest(resource='router', msg=msg)
        if 'ecmp_count' in router and not context.is_admin:
            msg = _("ecmp_count can only be set by an admin user.")
            raise nuage_exc.NuageNotAuthorized(resource='router', msg=msg)

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def update_router(self, context, id, router):
        updates = router['router']
        original_router = self.get_router(context, id)
        self._validate_update_router(context, id, updates)
        routing_mechanisms.update_routing_values(updates, original_router)
        ent_rtr_mapping = context.ent_rtr_mapping
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']

        curr_router = self.get_router(context, id)
        old_routes = self._get_extra_routes_by_router_id(context, id)
        # Replace routes in curr_router with old_routes as the curr_router
        # contains also rd which disrupts rollback
        original_router['routes'] = old_routes
        with nuage_utils.rollback() as on_exc:
            router_updated = super(NuageL3Plugin, self).update_router(
                context,
                id,
                copy.deepcopy(router))
            rollback_router_updates = {key: original_router[key] for key
                                       in updates.keys()}
            on_exc(super(NuageL3Plugin, self).update_router,
                   context,
                   id,
                   {'router': copy.deepcopy(rollback_router_updates)})

            if 'routes' in updates:
                self._update_nuage_router_static_routes(id,
                                                        nuage_domain_id,
                                                        old_routes,
                                                        updates['routes'])
                on_exc(self._update_nuage_router_static_routes, id,
                       nuage_domain_id, updates['routes'], old_routes)

            if 'routes' in updates and len(updates) == 1:
                pass
            else:
                self._update_nuage_router(nuage_domain_id, curr_router,
                                          updates,
                                          ent_rtr_mapping)
                on_exc(self._update_nuage_router, nuage_domain_id, updates,
                       curr_router, ent_rtr_mapping)
            routing_mechanisms.update_nuage_router_parameters(
                updates, context, curr_router['id'])
            on_exc(routing_mechanisms.update_nuage_router_parameters,
                   original_router, context, original_router['id'])
            self._update_nuage_router_aggregate_flows(context, updates,
                                                      original_router['id'])
            on_exc(self._update_nuage_router_aggregate_flows,
                   context, original_router, original_router['id'])
            nuage_router = self.vsdclient.get_l3domain_by_external_id(id)
            self._add_nuage_router_attributes(context.session,
                                              router_updated, nuage_router)

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

    def _update_nuage_router_aggregate_flows(self, context, updates,
                                             router_id):
        if updates.get(constants.AGGREGATE_FLOWS):
            if (updates[constants.AGGREGATE_FLOWS] !=
                    constants.AGGREGATE_FLOWS_OFF):
                nuagedb.add_router_parameter(
                    context.session, router_id, constants.AGGREGATE_FLOWS,
                    updates[constants.AGGREGATE_FLOWS])
            else:
                param = nuagedb.get_router_parameter(
                    context.session,
                    router_id,
                    constants.AGGREGATE_FLOWS)
                if param:
                    nuagedb.delete_router_parameter(context.session,
                                                    param)

    def _add_nuage_static_route(self, router_id, nuage_domain_id, route):
        params = {
            'nuage_domain_id': nuage_domain_id,
            'neutron_rtr_id': router_id,
            'net': netaddr.IPNetwork(route['destination']),
            'nexthop': route['nexthop']
        }
        self.vsdclient.create_nuage_staticroute(params)

    def _delete_nuage_static_route(self, nuage_domain_id, route):
        params = {
            "address": route['destination'],
            "nexthop": route['nexthop'],
            "nuage_domain_id": nuage_domain_id
        }
        self.vsdclient.delete_nuage_staticroute(params)

    def _update_nuage_router(self, nuage_id, curr_router, router_updates,
                             ent_rtr_mapping):
        curr_router.update(router_updates)
        self.vsdclient.update_router(nuage_id, curr_router, router_updates)
        ns_dict = {
            'nuage_rtr_rt':
                router_updates.get('rt', ent_rtr_mapping.get('nuage_rtr_rt')),
            'nuage_rtr_rd':
                router_updates.get('rd', ent_rtr_mapping.get('nuage_rtr_rd'))
        }
        nuagedb.update_entrouter_mapping(ent_rtr_mapping, ns_dict)

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_router(self, context, id):
        neutron_router = self.get_router(context, id)
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session, id)

        # Can probably be removed after blueprint enginefacade-switch reaches
        # router-delete code upstream.
        # https://blueprints.launchpad.net/neutron/+spec/enginefacade-switch
        try:
            session.expunge(ent_rtr_mapping)
        except Exception as e:
            LOG.warn('Got exception when expunging session: %s', e)

        if ent_rtr_mapping:
            LOG.debug("Enterprise to router mapping found for router %s", id)

            # First verify whether router is allowed to be deleted
            self._ensure_router_not_in_use(context, id)

            nuage_domain_id = ent_rtr_mapping['nuage_router_id']
            vsd_retry_error_codes = [(vsd_constants.CONFLICT_ERR_CODE,
                                      vsd_constants.VSD_VM_EXISTS_ON_VPORT),
                                     (vsd_constants.CONFLICT_ERR_CODE,
                                      vsd_constants.VSD_PG_IN_USE),
                                     (vsd_constants.CONFLICT_ERR_CODE,
                                      vsd_constants.VSD_VM_EXIST)]
            nuage_utils.retry_on_vsdclient_error(
                self.vsdclient.delete_l3domain,
                nr_attempts=cfg.CONF.RESTPROXY.
                server_max_retries_on_domain_delete,
                vsd_error_codes=vsd_retry_error_codes)(nuage_domain_id)

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
    def _check_fip_on_port_with_multiple_ips(self, context, port):
        # Block associating a fip to a port with multiple ip as of 5.3.1
        fixed_ips = port['fixed_ips']
        if not fixed_ips:
            return
        ipv4s, ipv6s = self.count_fixed_ips_per_version(fixed_ips)
        if ipv4s > 1 or ipv6s > 1:
            msg = _('floating ip cannot be associated to '
                    'port {} because it has multiple ipv4 or multiple ipv6'
                    'ips.').format(port['id'])
            raise nuage_exc.NuageBadRequest(msg=msg)

    @log_helpers.log_method_call
    def _create_update_floatingip(self, context,
                                  neutron_fip, neutron_port, new_vport,
                                  original_fip=None):

        ent_rtr_mapping, fip_pool = self._validate_processing_fip(
            context, neutron_fip, neutron_port)
        nuage_fip = self.vsdclient.get_nuage_fip_by_id(neutron_fip['id'])
        # 4 possible operations needed
        # - Create floating ip on domain: fip_creation_needed
        # - Disassociate floating ip from existing VM: fip_disassociate_needed
        # - Delete floating ip from domain: fip_deletion_needed
        # - Associate floating ip: always needed
        fip_creation_needed = True if not nuage_fip else False
        fip_disassociate_needed = False
        fip_delete_needed = False
        if nuage_fip:
            last_known_router_id = (
                original_fip['last_known_router_id'] or
                original_fip['router_id']) if original_fip else None
            # Disassociate fip from previous Port
            fip_disassociate_needed = True
            if last_known_router_id != neutron_fip['router_id']:
                # Move to another domain
                fip_delete_needed = True
                fip_creation_needed = True

        # Disassociate & delete:
        if fip_disassociate_needed:
            self._disassociate_floatingip(
                context, neutron_fip, nuage_fip,
                detached_port_id=original_fip['fixed_port_id'],
                do_delete=fip_delete_needed)

        # Create
        if fip_creation_needed:
            # Create floating ip on l3 domain
            LOG.debug("Floating ip not found in VSD for fip %s",
                      neutron_fip['id'])
            params = {
                'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
                'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
                'neutron_fip_ip': neutron_fip['floating_ip_address'],
                'neutron_fip_id': neutron_fip['id']
            }
            nuage_fip = self.vsdclient.create_nuage_floatingip(params)

        # Associate
        if new_vport:
            params = {
                'nuage_vport_id': new_vport['ID'],
                'nuage_fip_id': nuage_fip['ID']
            }
            self.vsdclient.update_nuage_vm_vport(params)
            self.fip_rate_log.info(
                'FIP %s (owned by tenant %s) associated to port %s'
                % (neutron_fip['id'], neutron_fip['tenant_id'],
                   neutron_port['id']))

        # Check if we have to associate a FIP to a VIP
        self._process_fip_to_vip(context, neutron_port,
                                 nuage_fip['ID'])
        return nuage_fip

    def _validate_processing_fip(self, context,
                                 neutron_fip, neutron_port):
        self._check_fip_on_port_with_multiple_ips(context,
                                                  neutron_port)
        net_id = neutron_fip['floating_network_id']
        subn = nuagedb.get_ipalloc_for_fip(context.session,
                                           net_id,
                                           neutron_fip['floating_ip_address'])
        fip_subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                            subn['subnet_id'])
        fip_pool = self.vsdclient.get_nuage_fip_pool_by_id(
            fip_subnet_mapping['nuage_subnet_id'])
        if not fip_pool:
            msg = _('sharedresource %s not found on VSD') % subn['subnet_id']
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, neutron_fip['router_id'])
        if not ent_rtr_mapping:
            msg = _('router %s is not associated with '
                    'any net-partition') % neutron_fip['router_id']
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)

        return ent_rtr_mapping, fip_pool

    def _update_proprietary_fip_qos(self, neutron_fip, nuage_vport, nuage_fip):
        # Add QOS to port for rate limiting
        if nuage_vport:
            self.vsdclient.create_update_fip_qos(
                neutron_fip, nuage_fip)
            self.fip_rate_log.info(
                "FIP {} updated with 'nuage_egress_fip_rate_kbps':{}, "
                "'nuage_ingress_fip_rate_kbps':{}.".format(
                    neutron_fip['id'],
                    neutron_fip['nuage_egress_fip_rate_kbps'],
                    neutron_fip['nuage_ingress_fip_rate_kbps']
                ))

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def get_floatingip(self, context, id, fields=None):
        fip = super(NuageL3Plugin, self).get_floatingip(context, id)

        if ((not fields or 'nuage_egress_fip_rate_kbps' in fields or
             'nuage_ingress_fip_rate_kbps' in fields) and
                fip.get('port_id')):
            nuage_fip = self.vsdclient.get_nuage_fip_by_id(id)
            if nuage_fip:
                nuage_rate_limit = self.vsdclient.get_fip_qos(nuage_fip)
                for direction, value in six.iteritems(nuage_rate_limit):
                    if 'ingress' in direction:
                        fip['nuage_ingress_fip_rate_kbps'] = value
                    elif 'egress' in direction:
                        fip['nuage_egress_fip_rate_kbps'] = value

        return self._fields(fip, fields)

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def create_floatingip(self, context, floatingip,
                          initial_status=lib_constants.
                          FLOATINGIP_STATUS_ACTIVE):
        fip = floatingip['floatingip']
        neutron_fip = super(NuageL3Plugin, self).create_floatingip(
            context, floatingip,
            initial_status=lib_constants.FLOATINGIP_STATUS_DOWN)
        if not self._is_vxlan_network_by_id(
                context, neutron_fip['floating_network_id']):
            return neutron_fip
        self._verify_process_proprietary_fip_qos(fip, neutron_fip)
        if not neutron_fip['router_id']:
            # no port attached, no action needed for now
            return neutron_fip

        try:
            port = self.core_plugin.get_port(context, fip['port_id'])
            nuage_vport = self._get_vport_for_neutron_port(
                context, port['id'],
                required=False)
            nuage_fip = self._create_update_floatingip(context, neutron_fip,
                                                       port, nuage_vport)
            self._update_proprietary_fip_qos(neutron_fip, nuage_vport,
                                             nuage_fip)
            self.update_floatingip_status(
                context, neutron_fip['id'],
                lib_constants.FLOATINGIP_STATUS_ACTIVE)
            neutron_fip['status'] = lib_constants.FLOATINGIP_STATUS_ACTIVE
        except (nuage_exc.OperationNotSupported, n_exc.BadRequest,
                ResourceNotFoundException):
            with excutils.save_and_reraise_exception():
                super(NuageL3Plugin, self).delete_floatingip(
                    context, neutron_fip['id'])
        return neutron_fip

    def _verify_process_proprietary_fip_qos(self, input, neutron_fip,
                                            for_update=False):
        ingress_fip_rate = input.get('nuage_ingress_fip_rate_kbps')
        egress_fip_rate = input.get('nuage_egress_fip_rate_kbps')
        if ((ingress_fip_rate is not None or
             egress_fip_rate is not None) and not neutron_fip.get('port_id')):
            # Legacy FIP QOS is not stored in OpenStack and can only be set
            # when there is a vPort.
            msg = _('Rate limiting requires the floating ip to be '
                    'associated to a port.')
            raise n_exc.BadRequest(resource='floatingip', msg=msg)
        if not for_update:
            # Only on first create of the nuage_fip we set the default values
            ingress_fip_rate = (ingress_fip_rate or
                                cfg.CONF.FIPRATE.default_ingress_fip_rate_kbps)
            egress_fip_rate = (egress_fip_rate or
                               cfg.CONF.FIPRATE.default_egress_fip_rate_kbps)
        # Update neutron_fip object
        neutron_fip['nuage_ingress_fip_rate_kbps'] = ingress_fip_rate
        neutron_fip['nuage_egress_fip_rate_kbps'] = egress_fip_rate

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def update_floatingip(self, context, id, floatingip):
        # Upstream Neutron disassociates port from fip if updated with None
        # so we simulate same behavior in our plugin as well
        if not floatingip['floatingip']:
            floatingip['floatingip'] = {'port_id': None}
        updates = floatingip['floatingip']
        orig_fip = self._get_floatingip(context, id)
        if not self._is_vxlan_network_by_id(context,
                                            orig_fip['floating_network_id']):
            return super(NuageL3Plugin, self).update_floatingip(context,
                                                                id,
                                                                floatingip)
        original_port_id = orig_fip['fixed_port_id']

        with context.session.begin(subtransactions=True):
            # Upstream update
            with nuage_utils.rollback() as on_exc:
                neutron_fip = super(NuageL3Plugin, self).update_floatingip(
                    context, id, floatingip)
                orig_fip_dict = self._make_floatingip_dict(orig_fip)
                reverse_updates = {key: orig_fip_dict.get(key) for key
                                   in updates}
                on_exc(super(NuageL3Plugin, self).update_floatingip,
                       context, id, {"floatingip": reverse_updates})
                self._verify_process_proprietary_fip_qos(
                    updates, neutron_fip, for_update=original_port_id)

                if (updates.get('port_id') and
                        updates.get('port_id') != orig_fip['fixed_port_id']):
                    # Attached port has changed
                    if not neutron_fip['router_id']:
                        ret_msg = 'floating-ip is not associated yet'
                        raise n_exc.BadRequest(resource='floatingip',
                                               msg=ret_msg)
                    port = self.core_plugin.get_port(context,
                                                     updates['port_id'])
                    nuage_vport = self._get_vport_for_neutron_port(
                        context, port['id'], required=False)
                    nuage_fip = self._create_update_floatingip(
                        context, neutron_fip, port, nuage_vport,
                        original_fip=orig_fip)

                    # Rollback
                    def rollback_create_update_floatingip():
                        if original_port_id:
                            # Restore previous state
                            original_port = self.core_plugin.get_port(
                                context, original_port_id)
                            original_vport = self._get_vport_for_neutron_port(
                                context, original_port['id'], required=False)
                            self._create_update_floatingip(
                                context, orig_fip, original_port,
                                original_vport, original_fip=neutron_fip)
                        else:
                            # Delete created fip
                            self._disassociate_floatingip(
                                context, neutron_fip,
                                detached_port_id=port['id'])
                    on_exc(rollback_create_update_floatingip)

                    self._update_proprietary_fip_qos(neutron_fip, nuage_vport,
                                                     nuage_fip)
                    self.update_floatingip_status(
                        context, neutron_fip['id'],
                        lib_constants.FLOATINGIP_STATUS_ACTIVE)
                    neutron_fip['status'] = (
                        lib_constants.FLOATINGIP_STATUS_ACTIVE)
                elif not updates.get('port_id') and 'port_id' in updates:
                    # This happens when {'port_id': null} is in request.
                    # Disassociate
                    self._disassociate_floatingip(
                        context, neutron_fip,
                        detached_port_id=original_port_id)
                elif (neutron_fip['nuage_ingress_fip_rate_kbps'] is not None or
                      neutron_fip['nuage_egress_fip_rate_kbps'] is not None):
                    nuage_vport = self._get_vport_for_neutron_port(
                        context, original_port_id, required=False)
                    nuage_fip = self.vsdclient.get_nuage_fip_by_id(
                        neutron_fip['id'])
                    self._update_proprietary_fip_qos(neutron_fip, nuage_vport,
                                                     nuage_fip)

        return neutron_fip

    def _disassociate_floatingip(self, context, neutron_fip, nuage_fip=None,
                                 detached_port_id=None, do_delete=True):
        # Check for disassociation of fip from vip, only if previously
        # attached to port
        if detached_port_id:
            neutron_port = self.core_plugin.get_port(context, detached_port_id)
            self._process_fip_to_vip(context, neutron_port,
                                     nuage_fip_id=None)

        nuage_vport = self._get_vport_for_neutron_port(context,
                                                       detached_port_id,
                                                       required=False)
        nuage_fip = nuage_fip or self.vsdclient.get_nuage_fip_by_id(
            neutron_fip['id'])
        if nuage_vport and nuage_vport.get('associatedFloatingIPID'):
            # First delete legacy fip qos, as it is not allowed to have fip
            # qos attached to a fip that is not attached to vPort.
            self.vsdclient.delete_fip_qos(nuage_fip)
            self.fip_rate_log.info(
                'FIP {} (owned by tenant {}) disassociated '
                'from port {}'.format(
                    neutron_fip['id'], neutron_fip['tenant_id'],
                    detached_port_id))

            params = {
                'nuage_vport_id': nuage_vport['ID'],
                'nuage_fip_id': None
            }
            self.vsdclient.update_nuage_vm_vport(params)
            LOG.debug("Floating-ip %(fip)s is disassociated from "
                      "vport %(vport)s",
                      {'fip': neutron_fip['id'],
                       'vport': nuage_vport['ID']})

        # Delete fip from VSD
        if do_delete and nuage_fip:
            self.vsdclient.delete_nuage_floatingip(
                nuage_fip['ID'])
            LOG.debug('Floating-ip %s deleted '
                      'from VSD', neutron_fip['id'])

        self.update_floatingip_status(
            context, neutron_fip['id'],
            lib_constants.FLOATINGIP_STATUS_DOWN)
        neutron_fip['status'] = lib_constants.FLOATINGIP_STATUS_DOWN

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context, filters={'port_id': [port_id]})
        router_ids = super(NuageL3Plugin, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)

        if not fips:
            return router_ids
        for fip in fips:
            self._disassociate_floatingip(context,
                                          fip,
                                          detached_port_id=port_id)

        return router_ids

    @nuage_utils.handle_nuage_api_errorcode
    @lib_db_api.retry_if_session_inactive()
    @log_helpers.log_method_call
    def delete_floatingip(self, context, fip_id):
        fip = self._get_floatingip(context, fip_id)

        if not self._is_vxlan_network_by_id(context,
                                            fip['floating_network_id']):
            return super(NuageL3Plugin, self).delete_floatingip(context,
                                                                fip_id)
        port_id = fip['fixed_port_id']
        self._disassociate_floatingip(context, fip, detached_port_id=port_id)
        super(NuageL3Plugin, self).delete_floatingip(context, fip_id)
        self.fip_rate_log.info('FIP %s (owned by tenant %s) deleted' %
                               (fip_id, fip['tenant_id']))

    def _get_vport_for_neutron_port(self, context, port_id, required=True):
        if not port_id:
            return
        subnet_mapping = nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                             port_id)
        l2_id, l3_id = get_l2_and_l3_sub_id(subnet_mapping)
        params = {
            'neutron_port_id': port_id,
            'l2dom_id': l2_id,
            'l3dom_id': l3_id
        }
        return self.vsdclient.get_nuage_vport_by_neutron_id(
            params, required=required)

    def _process_fip_to_vip(self, context, neutron_port, nuage_fip_id):
        if neutron_port.get('device_owner') in self.get_device_owners_vip():
            # TODO(Team) Take fixed ip on floating ip attach into account
            for fixed_ip in neutron_port['fixed_ips']:
                neutron_subnet_id = fixed_ip['subnet_id']
                neutron_subnet = self.core_plugin.get_subnet(context,
                                                             neutron_subnet_id)
                if self._is_ipv4(neutron_subnet):
                    vip = fixed_ip['ip_address']
                    self.vsdclient.update_fip_to_vips(neutron_subnet,
                                                      vip,
                                                      nuage_fip_id)
                    return  # exit loop

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

                nuage_fip = self.vsdclient.get_nuage_fip_by_id(fip_id)
                if nuage_fip:
                    self.vsdclient.delete_nuage_floatingip(
                        nuage_fip['ID'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

    def _is_vxlan_network_by_id(self, context, network_id):
        network = self.core_plugin.get_network(context,
                                               network_id)
        return self.is_of_network_type(network, lib_constants.TYPE_VXLAN)
