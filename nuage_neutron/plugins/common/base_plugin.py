# Copyright 2017 NOKIA
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
import socket
import struct
import time

import netaddr
from neutron._i18n import _
from neutron.db import db_base_plugin_v2
from neutron.plugins.common import utils as plugin_utils
from neutron.services.trunk import constants as t_consts
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api import validators as lib_validators
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import PortNotFound
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log
import six

from nuage_neutron.plugins.common import callback_manager
from nuage_neutron.plugins.common.capabilities import Capabilities
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common.exceptions import \
    NuageDualstackSubnetNotFound
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import routing_mechanisms
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import rollback as utils_rollback
from nuage_neutron.plugins.common.utils import SubnetUtilsBase
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import IsSet
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.plugins.common.validation import validate
from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.vsdclient_fac import VsdClientFactory

LOG = log.getLogger(__name__)


class RootNuagePlugin(SubnetUtilsBase):
    supported_network_types = []

    def __init__(self):
        super(RootNuagePlugin, self).__init__()
        config.nuage_register_cfg_opts()
        self.nuage_callbacks = callback_manager.get_callback_manager()
        self.vsdclient = None  # deferred initialization
        self._default_np_id = None
        self._l2_plugin = None
        self._l3_plugin = None

    @staticmethod
    def _is_trunk_subport(port):
        return t_consts.TRUNK_SUBPORT_OWNER == port.get('device_owner')

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    @property
    def l3_plugin(self):
        if self._l3_plugin is None:
            self._l3_plugin = directory.get_plugin(
                lib_constants.L3)
        return self._l3_plugin

    @property
    def default_np_id(self):
        if self._default_np_id is None:
            self._default_np_id = directory.get_plugin(
                constants.NUAGE_APIS).get_default_np_id()
        return self._default_np_id

    def init_vsd_client(self):
        cms_id = cfg.CONF.RESTPROXY.cms_id

        if not cms_id:
            raise cfg.ConfigFileValueError(
                _('Missing cms_id in configuration.'))

        self.vsdclient = VsdClientFactory.new_vsd_client(
            cms_id,
            server=cfg.CONF.RESTPROXY.server,
            base_uri=cfg.CONF.RESTPROXY.base_uri,
            serverssl=cfg.CONF.RESTPROXY.serverssl,
            verify_cert=cfg.CONF.RESTPROXY.verify_cert,
            serverauth=cfg.CONF.RESTPROXY.serverauth,
            auth_resource=cfg.CONF.RESTPROXY.auth_resource,
            organization=cfg.CONF.RESTPROXY.organization,
            servertimeout=cfg.CONF.RESTPROXY.server_timeout,
            max_retries=cfg.CONF.RESTPROXY.server_max_retries)

    def _create_nuage_vport(self, port, vsd_subnet, description=None):
        params = {
            'port_id': port['id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id'],
            'description': description,
            'vsd_subnet': vsd_subnet,
            'address_spoof': (constants.DISABLED
                              if port.get(psec.PORTSECURITY, True)
                              else constants.ENABLED)
        }

        return self.vsdclient.create_vport(params)

    @log_helpers.log_method_call
    def _check_router_subnet_for_tenant(self, context, tenant_id):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [tenant_id]}
        routers = self.l3_plugin.get_routers(context, filters=filters)
        subnets = self.core_plugin.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    def _validate_vmports_same_netpartition(self, db_context, current_port,
                                            np_id):
        filters = {'device_id': [current_port['device_id']]}
        ports = self.core_plugin.get_ports(db_context, filters)
        for port in ports:
            if port['id'] == current_port['id']:
                continue
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                            subnet_id)
            if subnet_mapping and subnet_mapping['net_partition_id'] != np_id:
                msg = ("VM with ports belonging to subnets across "
                       "enterprises is not allowed in VSP")
                raise NuageBadRequest(msg=msg)

    def _validate_cidr(self, subnet, nuage_subnet, shared_subnet):
        nuage_subnet = shared_subnet or nuage_subnet
        if nuage_subnet.get('DHCPManaged', True):
            if subnet['ip_version'] == 4:
                subnet_validate = {'enable_dhcp': Is(nuage_subnet.get(
                    'enableDHCPv4', True))}
                if nuage_subnet['IPType'] == constants.IP_TYPE_IPV6:
                    msg = (_("Subnet with ip_version %(ip_version)s can't be "
                             "linked to vsd subnet with IPType %(ip_type)s.")
                           % {'ip_version': subnet['ip_version'],
                              'ip_type': nuage_subnet['IPType']})
                    raise NuageBadRequest(msg=msg)
                nuage_cidr = (netaddr.IPNetwork(nuage_subnet['address'] + '/' +
                                                nuage_subnet['netmask'])
                              if nuage_subnet.get('address') else None)
            else:
                subnet_validate = {'enable_dhcp': Is(nuage_subnet.get(
                    'enableDHCPv6', False))}
                if nuage_subnet['IPType'] == constants.IP_TYPE_IPV4:
                    msg = (_("Subnet with ip_version %(ip_version)s can't be "
                             "linked to vsd subnet with IPType %(ip_type)s.")
                           % {'ip_version': subnet['ip_version'],
                              'ip_type': nuage_subnet['IPType']})
                    raise NuageBadRequest(msg=msg)
                nuage_cidr = (netaddr.IPNetwork(nuage_subnet['IPv6Address'])
                              if nuage_subnet.get('IPv6Address') else None)

            if not self.compare_cidr(subnet['cidr'], nuage_cidr):
                msg = 'OSP cidr %s and NuageVsd cidr %s do not match' % \
                      (subnet['cidr'], nuage_cidr)
                raise NuageBadRequest(msg=msg)
        else:
            subnet_validate = {'enable_dhcp': Is(False)}

        validate("subnet", subnet, subnet_validate)
        if nuage_subnet["type"] == constants.L2DOMAIN:
            if subnet['enable_dhcp']:
                if ((subnet['ip_version'] == 4 and
                     not nuage_subnet['gateway']) or
                        (subnet['ip_version'] == 6 and
                         not nuage_subnet['IPv6Gateway'])):
                    msg = (_("DHCP enabled subnet can't be linked to vsd "
                             "L2Domain without DHCP server IP"))
                    raise NuageBadRequest(msg=msg)
            elif nuage_subnet['DHCPManaged']:
                if ((subnet['ip_version'] == 4 and nuage_subnet['gateway']) or
                        (subnet['ip_version'] == 6 and
                         nuage_subnet['IPv6Gateway'])):
                    msg = (_("DHCP disabled subnet can't be linked to vsd "
                             "L2Domain with DHCP server IP"))
                    raise NuageBadRequest(msg=msg)

    def _validate_allocation_pools(self, context, subnet, subnet_info):
        if not subnet_info:
            return  # no other linked subnet, all good

        # this is not the only subnet linked to same nuage subnet
        # need to validate allocation pools being disjunct

        LOG.debug('_validate_allocation_pools: subnet %s has allocation pools '
                  '%s', subnet['id'], subnet['allocation_pools'])

        def pools_to_ip_sets(_ip_pools, _ip_sets, _ip_ranges):

            def pools_to_ip_range(ip_pools):
                __ip_ranges = []
                for ip_pool in ip_pools:
                    __ip_ranges.append(netaddr.IPRange(ip_pool['start'],
                                                       ip_pool['end']))
                return __ip_ranges

            for ip_range in pools_to_ip_range(_ip_pools):
                _ip_sets.append(netaddr.IPSet(ip_range.cidrs()))
                _ip_ranges.append(ip_range)

            return _ip_sets

        # Create an IPSet for it for easily verifying overlaps
        # Initiate it with the new subnet itself
        ip_ranges = []
        ip_sets = pools_to_ip_sets(subnet['allocation_pools'], [], ip_ranges)

        # add other ip pools
        for mapping in subnet_info['mappings']:
            # skip comparing a subnet with itself (occurs on subnet-update)
            if mapping['subnet_id'] == subnet['id']:
                continue
            sub = self.core_plugin.get_subnet(context, mapping['subnet_id'])
            pools_to_ip_sets(sub['allocation_pools'], ip_sets, ip_ranges)

            LOG.debug('_validate_allocation_pools: validating with subnet %s '
                      'with allocation pools %s', sub, sub['allocation_pools'])

        # inspired by IpamBackendMixin.validate_allocation_pools:
        #                    ~    ~    ~
        # Use integer cursors as an efficient way for implementing
        # comparison and avoiding comparing the same pair twice
        for l_cursor in range(len(ip_sets)):
            for r_cursor in range(l_cursor + 1, len(ip_sets)):
                if ip_sets[l_cursor] & ip_sets[r_cursor]:
                    msg = "Found overlapping allocation pools {} with {}".\
                        format(ip_ranges[l_cursor], ip_ranges[r_cursor])
                    LOG.debug('_validate_allocation_pools: ' + msg)
                    raise NuageBadRequest(msg=msg)

    @log_helpers.log_method_call
    def _resource_finder(self, context, for_resource, resource_type,
                         resource):
        match = re.match(lib_constants.UUID_PATTERN, resource)
        if match:
            obj_lister = getattr(self, "get_%s" % resource_type)
            found_resource = obj_lister(context, resource)
            if not found_resource:
                msg = (_("%(resource)s with id %(resource_id)s does not "
                         "exist") % {'resource': resource_type,
                                     'resource_id': resource})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
        else:
            filter = {'name': [resource]}
            obj_lister = getattr(self, "get_%ss" % resource_type)
            found_resource = obj_lister(context, filters=filter)
            if not found_resource:
                msg = (_("Either %(resource)s %(req_resource)s not found "
                         "or you dont have credential to access it")
                       % {'resource': resource_type,
                          'req_resource': resource})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            if len(found_resource) > 1:
                msg = (_("More than one entry found for %(resource)s "
                         "%(req_resource)s. Use id instead")
                       % {'resource': resource_type,
                          'req_resource': resource})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            found_resource = found_resource[0]
        return found_resource

    @log_helpers.log_method_call
    def create_update_dhcp_nuage_port(self, context, neutron_subnet,
                                      nuage_subnet=None, dualstack=None):
        fixed_ips = []
        dhcp_ports = None
        if dualstack and dualstack['enable_dhcp']:
            filters = {
                'fixed_ips': {'subnet_id': [dualstack['id']]},
                'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
            }
            dhcp_ports = self.core_plugin.get_ports(context, filters=filters)
            fixed_ips = dhcp_ports[0]['fixed_ips']

        if nuage_subnet and nuage_subnet.get('DHCPManaged', True):
            if self._is_ipv4(neutron_subnet) and nuage_subnet['enableDHCPv4']:
                fixed_ips.append({'ip_address': nuage_subnet['gateway'],
                                  'subnet_id': neutron_subnet['id']})
            if self._is_ipv6(neutron_subnet) and nuage_subnet['enableDHCPv6']:
                fixed_ips.append({'ip_address': nuage_subnet['IPv6Gateway'],
                                  'subnet_id': neutron_subnet['id']})
        else:
            if neutron_subnet['enable_dhcp']:
                fixed_ips.append({'subnet_id': neutron_subnet['id']})
        if fixed_ips:
            if dhcp_ports:
                return db_base_plugin_v2.NeutronDbPluginV2.update_port(
                    self.core_plugin, context, dhcp_ports[0]['id'],
                    {'port': {'fixed_ips': fixed_ips}})
            else:
                p_data = {
                    'network_id': neutron_subnet['network_id'],
                    'tenant_id': neutron_subnet['tenant_id'],
                    'fixed_ips': fixed_ips,
                    'device_owner': constants.DEVICE_OWNER_DHCP_NUAGE
                }
                port = plugin_utils._fixup_res_dict(context,
                                                    port_def.COLLECTION_NAME,
                                                    p_data)
                port['status'] = lib_constants.PORT_STATUS_ACTIVE
                return self.core_plugin._create_port_db(context,
                                                        {'port': port})[0]
        else:
            return None

    @log_helpers.log_method_call
    def delete_dhcp_nuage_port(self, context, neutron_subnet, dualstack=None):
        if dualstack and dualstack['enable_dhcp']:
            filters = {
                'fixed_ips': {'subnet_id': [dualstack['id']]},
                'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
            }
            dhcp_ports = self.core_plugin.get_ports(context,
                                                    filters=filters)
            original_fixed_ips = dhcp_ports[0]['fixed_ips']
            # Remove DHCP ip for neutron subnet
            fixed_ips = [fixed_ip for fixed_ip in original_fixed_ips
                         if fixed_ip['subnet_id'] != neutron_subnet['id']]
            db_base_plugin_v2.NeutronDbPluginV2.update_port(
                self.core_plugin, context, dhcp_ports[0]['id'],
                {'port': {'fixed_ips': fixed_ips}})
        else:
            filters = {
                'fixed_ips': {'subnet_id': [neutron_subnet['id']]},
                'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
            }
            dhcp_ports = self.core_plugin.get_ports(context,
                                                    filters=filters)
            if dhcp_ports:
                try:
                    db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                        self.core_plugin, context, dhcp_ports[0]['id'])
                except PortNotFound:
                    LOG.info("Port %s has been deleted concurrently",
                             dhcp_ports[0]['id'])

    @log_helpers.log_method_call
    def delete_dhcp_nuage_port_by_id(self, context, port_id):
        try:
            db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                self.core_plugin, context, port_id)
        except PortNotFound:
            LOG.info("Port %s has been deleted concurrently", port_id)

    @staticmethod
    def _check_security_groups_per_port_limit(sgs_per_port):
        if len(sgs_per_port) > constants.MAX_SG_PER_PORT:
            msg = (("Number of %s specified security groups exceeds the "
                    "maximum of %s security groups on a port "
                    "supported on nuage VSP") % (len(sgs_per_port),
                                                 constants.MAX_SG_PER_PORT))
            raise NuageBadRequest(msg=msg)

    @staticmethod
    def is_of_network_type(network, type):
        net_type = 'provider:network_type'
        if network.get(net_type) == type:
            return True
        return any(segment.get(net_type) == type for segment in
                   network.get('segments', []))

    def is_network_type_supported(self, network):
        return any(self.is_of_network_type(network, network_type) for
                   network_type in self.supported_network_types)

    def is_nuage_hybrid_mpls_network(self, network):
        return self.is_of_network_type(network,
                                       constants.NUAGE_HYBRID_MPLS_NET_TYPE)

    def _validate_config_for_nuage_driver(self, nuage_driver,
                                          min_required_service_plugins,
                                          min_required_extensions):
        mentioned_service_plugins = cfg.CONF.service_plugins
        mentioned_extensions = cfg.CONF.ml2.extension_drivers

        self._check_config(mentioned_service_plugins,
                           min_required_service_plugins,
                           'service_plugin(s)',
                           nuage_driver)
        self._check_config(mentioned_extensions,
                           min_required_extensions,
                           'extension(s)',
                           nuage_driver)
        # Additional check: extension driver nuage_network is required
        # only when NuageL2Bridge service plugin is enabled.
        nuagel2bridge = ('NuageL2Bridge',
                         'nuage_neutron.plugins.common.service_plugins.'
                         'nuage_l2bridge.NuageL2BridgePlugin')
        nuage_network = ('nuage_network',
                         'nuage_neutron.plugins.nuage_ml2.'
                         'nuage_network_ext_driver.'
                         'NuageNetworkExtensionDriver')
        if (nuagel2bridge[0] in mentioned_service_plugins or
                nuagel2bridge[1] in mentioned_service_plugins):
            if (nuage_network[0] not in mentioned_extensions and
                    nuage_network[1] not in mentioned_extensions):
                msg = ("Missing required extension "
                       "'nuage_network' for service plugin "
                       "NuageL2Bridge")
                raise cfg.ConfigFileValueError(msg)

    @staticmethod
    def _check_config(mentioned, min_required, resource, driver_name):
        missing = []
        for key, value in six.iteritems(min_required):
            for conf_val in mentioned:
                if (conf_val == key or
                        conf_val == value and resource == 'service_plugin(s)'):
                    break
            else:
                missing.append(key)
        if missing:
            msg = ("Missing required " + resource + ' ' + str(missing) +
                   " for mechanism driver " + driver_name)
            raise cfg.ConfigFileValueError(msg)

    @log_helpers.log_method_call
    def _get_subnet_from_neutron(self, db_context, subnet_id):
        """_check_subnet_exists_in_neutron

        :rtype: dict
        """
        try:
            subnet_db = self.core_plugin.get_subnet(db_context, subnet_id)
            return subnet_db
        except n_exc.SubnetNotFound:
            return None

    @log_helpers.log_method_call
    def _get_port_from_neutron(self, db_context, port):
        """_check_port_exists_in_neutron

        :rtype: dict
        """
        try:
            port_db = self.core_plugin.get_port(db_context, port['id'])
            return port_db
        except n_exc.PortNotFound:
            return None

    @log_helpers.log_method_call
    def get_dual_stack_subnet(self, context, neutron_subnet,
                              vsd_managed=False):
        subnets = self.core_plugin.get_subnets(
            context, filters={'network_id': [neutron_subnet['network_id']]})
        dual_subnets = []
        for subnet in subnets:
            if (subnet['id'] != neutron_subnet['id'] and
                    subnet['ip_version'] != neutron_subnet['ip_version']):
                if vsd_managed:
                    dual_subnets.append(subnet)
                else:
                    return subnet
        return dual_subnets

    def get_vsd_managed_dual_subnet(self, context, subnet, nuage_subnet_id):
        dual_stack_subnets = self.get_dual_stack_subnet(context, subnet,
                                                        vsd_managed=True)
        for dual_stack_subnet in dual_stack_subnets:
            dual_subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, dual_stack_subnet['id'])
            if dual_subnet_mapping['nuage_subnet_id'] == nuage_subnet_id:
                return dual_stack_subnet
        return None

    @log_helpers.log_method_call
    def _find_vsd_subnet(self, context, subnet_mapping):
        try:
            vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                subnet_mapping,
                required=True)
            return vsd_subnet
        except restproxy.ResourceNotFoundException:
            neutron_subnet = self._get_subnet_from_neutron(
                context, subnet_mapping['subnet_id'])
            if not neutron_subnet:
                LOG.info("Subnet %s has been deleted concurrently",
                         subnet_mapping['subnet_id'])
                return
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session,
                neutron_subnet['id'])
            if self._is_os_mgd(subnet_mapping):
                LOG.debug("Retrying to get the subnet from vsd.")
                # Here is for the case that router attach/detach has happened
                # but neutron DB is not updated. Then we use externalID and
                # cidr to get that subnet in vsd.
                if self._is_l2(subnet_mapping):
                    return self.vsdclient.get_domain_subnet_by_ext_id_and_cidr(
                        neutron_subnet)
                else:
                    return self.vsdclient.get_l2domain_by_ext_id_and_cidr(
                        neutron_subnet)
            else:
                raise

    def _get_default_net_partition_for_current_project(self, context):
        session = context.session
        net_partition = nuagedb.get_net_partition_for_project(
            session, context.project_id)
        if not net_partition:
            net_partition = nuagedb.get_net_partition_by_id(session,
                                                            self.default_np_id)
            if not net_partition:
                msg = _('Default net_partition was not created at '
                        'system startup.')
                raise NuageBadRequest(resource='subnet', msg=msg)
        return net_partition

    @staticmethod
    def _get_netpartition_from_db(session, np_id_or_name):
        return (
            nuagedb.get_net_partition_by_id(session, np_id_or_name) or
            nuagedb.get_net_partition_by_name(session, np_id_or_name))

    @staticmethod
    def _add_net_partition(session, netpartition):
        return nuagedb.add_net_partition(
            session, netpartition['id'], None, None,
            netpartition['name'], None, None)

    def _validate_net_partition(self, np_id_or_name, context):
        # check db first
        netpartition_db = self._get_netpartition_from_db(context.session,
                                                         np_id_or_name)

        # check vsd by the net-partition in db if found, else try np_id_or_name
        # - note that np_id_or_name only makes sense when a name is given -
        netpartition = self.vsdclient.get_netpartition_by_name(
            netpartition_db['name'] if netpartition_db else np_id_or_name)
        require(netpartition, "netpartition", np_id_or_name)
        if netpartition_db:
            if netpartition_db['id'] == netpartition['id']:
                return netpartition_db
            else:
                # fix neutron with enterprise id (it seems changed?)
                # ... not sure how this would ever happen (legacy code) ...
                net_part_db = nuagedb.get_net_partition_with_lock(
                    context.session, netpartition_db['id'])
                nuagedb.delete_net_partition(context.session, net_part_db)
                return self._add_net_partition(context.session,
                                               netpartition)
        else:
            # enterprise exists on VSD but not yet in neutron; add it
            return self._add_net_partition(context.session, netpartition)

    def _get_net_partition_for_entity(self, context, entity):
        np_id_or_name = entity.get('net_partition')
        if np_id_or_name:
            np = self._get_netpartition_from_db(context.session, np_id_or_name)
            if not np:
                msg = _('Net-partition {} does not exist.').format(
                    np_id_or_name)
                raise NuageBadRequest(resource='subnet', msg=msg)
            return np
        else:
            return self._get_default_net_partition_for_current_project(context)

    @log_helpers.log_method_call
    def calculate_vips_for_port_ips(self, context, port):
        fixed_ips = port['fixed_ips']
        ips = {4: [], 6: []}
        for fixed_ip in fixed_ips:
            try:
                subnet = self.core_plugin.get_subnet(context,
                                                     fixed_ip['subnet_id'])
            except n_exc.SubnetNotFound:
                LOG.info("Subnet %s has been deleted concurrently",
                         fixed_ip['subnet_id'])
                continue
            ips[subnet['ip_version']].append(fixed_ip['ip_address'])
        for key in ips.keys():
            ips[key] = self.sort_ips(ips[key])
        port[constants.VIPS_FOR_PORT_IPS] = (ips[4][:-1] +
                                             ips[6][:-1])
        return ips

    @staticmethod
    def vnic_is_l2bridge_compatible(port_vnic_type):
        return Capabilities.by_port_vnic_type[port_vnic_type][
            Capabilities.BRIDGED_NETWORKS]

    def _validate_nuage_l2bridges(self, db_context, port):
        nuage_l2bridge = nuagedb.get_nuage_l2bridge_id_for_network(
            db_context.session, port['network_id'])
        if nuage_l2bridge:
            if not self.vnic_is_l2bridge_compatible(
                    port.get(portbindings.VNIC_TYPE)):
                msg = _("This port is being created on a network connected "
                        "to nuage_l2bridge {}. It is not allowed to create "
                        "ports with vnic type {} on such a network.").format(
                    nuage_l2bridge, port.get(portbindings.VNIC_TYPE))
                raise NuageBadRequest(resource='port', msg=msg)

    @staticmethod
    def get_auto_create_port_owners():
        return [lib_constants.DEVICE_OWNER_ROUTER_INTF,
                lib_constants.DEVICE_OWNER_ROUTER_GW,
                lib_constants.DEVICE_OWNER_FLOATINGIP,
                constants.DEVICE_OWNER_VIP_NUAGE,
                constants.DEVICE_OWNER_IRONIC,
                constants.DEVICE_OWNER_OCTAVIA
                ]

    @staticmethod
    def needs_vport_for_fip_association(device_owner):
        return (device_owner not in
                RootNuagePlugin.get_device_owners_vip() +
                [constants.DEVICE_OWNER_IRONIC])

    @staticmethod
    def needs_vport_creation(device_owner):
        if (device_owner in RootNuagePlugin.get_auto_create_port_owners() or
                device_owner.startswith(tuple(
                    cfg.CONF.PLUGIN.device_owner_prefix))):
            return False
        return True

    @staticmethod
    def get_device_owners_vip():
        return ([constants.DEVICE_OWNER_VIP_NUAGE,
                 constants.DEVICE_OWNER_OCTAVIA] +
                cfg.CONF.PLUGIN.device_owner_prefix)

    @staticmethod
    def count_fixed_ips_per_version(fixed_ips):
        ipv4s = 0
        ipv6s = 0
        for fixed_ip in fixed_ips:
            if netaddr.valid_ipv4(fixed_ip['ip_address']):
                ipv4s += 1
            if netaddr.valid_ipv6(fixed_ip['ip_address']):
                ipv6s += 1
        return ipv4s, ipv6s

    @staticmethod
    def _convert_ipv6(ip):
        hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, ip))
        return (hi << 64) | lo

    @staticmethod
    def sort_ips(ips):
        # (gridinv): attempt first ipv4 conversion
        # on socket.error assume ipv6
        try:
            return sorted(ips,
                          key=lambda ip: struct.unpack(
                              '!I', socket.inet_pton(socket.AF_INET, ip))[0])
        except socket.error:
            return sorted(ips,
                          key=lambda ip: RootNuagePlugin._convert_ipv6(ip))

    @log_helpers.log_method_call
    def _create_nuage_subnet(self, context, neutron_subnet, netpart_id,
                             l2bridge):

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, neutron_subnet['id'])
        if subnet_mapping:
            # no-op, already connected
            return

        is_nuage_l3 = False
        r_param = {}
        network = self.core_plugin.get_network(context,
                                               neutron_subnet['network_id'])
        is_ipv4 = self._is_ipv4(neutron_subnet)
        dual_stack_subnet = self.get_dual_stack_subnet(context, neutron_subnet)
        if dual_stack_subnet:
            # Subnet with different ip_version is already present and now check
            # if router interface is attached or not
            is_nuage_l3, router_id = \
                self.check_subnet_is_nuage_l3(
                    context, dual_stack_subnet)
            if is_nuage_l3:
                r_param['router_id'] = router_id

        if l2bridge and l2bridge['nuage_subnet_id']:
            # There exists already a nuage subnet for this l2bridge
            bridged_subnets = nuagedb.get_subnets_for_nuage_l2bridge(
                context.session, l2bridge['id'])
            # Exclude the current subnet
            ipv4s = [s['id'] for s in bridged_subnets
                     if self._is_ipv4(s) and
                     s['id'] != neutron_subnet['id']]
            ipv6s = [s['id'] for s in bridged_subnets
                     if self._is_ipv6(s) and
                     s['id'] != neutron_subnet['id']]
            if ((not ipv4s and self._is_ipv4(neutron_subnet)) or
                    (not ipv6s and self._is_ipv6(neutron_subnet))):
                # Change dual_stack_subnet which gets from l2bridge
                if not dual_stack_subnet:
                    dual_stack_subnet = self.core_plugin.get_subnet(
                        context, ipv4s[0] if ipv4s else ipv6s[0])
            else:
                # No action, VSD subnet already exists
                mapping = nuagedb.get_subnet_l2dom_by_subnet_ids_locking(
                    context.session, ipv4s if ipv4s else ipv6s)
                if mapping:
                    # Connecting this subnet to the already created vsd
                    # subnet
                    nuage_subnet = {
                        'nuage_l2template_id':
                            mapping['nuage_l2dom_tmplt_id'],
                        'nuage_userid': mapping['nuage_user_id'],
                        'nuage_groupid': mapping['nuage_group_id'],
                        'nuage_l2domain_id': mapping['nuage_subnet_id']
                    }
                    self.create_update_dhcp_nuage_port(
                        context, neutron_subnet, dualstack=dual_stack_subnet)
                    self._create_subnet_mapping(context,
                                                netpart_id,
                                                neutron_subnet,
                                                nuage_subnet)
                    return

        # If the request is for IPv4, then the dualstack subnet will be IPv6
        # and vice versa
        if is_ipv4:
            ipv4_subnet, ipv6_subnet = neutron_subnet, dual_stack_subnet
        else:
            ipv4_subnet, ipv6_subnet = dual_stack_subnet, neutron_subnet
        params = {
            'netpart_id': netpart_id,
            'tenant_id': neutron_subnet['tenant_id'],
            'shared': network['shared'],
            'dhcp_ip': None,
            'dhcpv6_ip': None,
            'tenant_name': context.tenant_name,
            'network_id': network['id'],
            'network_name': network['name'],
            'allow_non_ip': config.default_allow_non_ip_enabled(),
            'ingressReplicationEnabled': config.ingress_replication_enabled()
        }

        if self.is_nuage_hybrid_mpls_network(network):
            params['tunnelType'] = vsd_constants.VSD_TUNNEL_TYPES['MPLS']

        if not is_nuage_l3:
            if neutron_subnet['enable_dhcp']:
                if (dual_stack_subnet and neutron_subnet['network_id'] ==
                        dual_stack_subnet['network_id']):
                    dhcp_port = self.create_update_dhcp_nuage_port(
                        context, neutron_subnet, dualstack=dual_stack_subnet)
                else:
                    dhcp_port = self.create_update_dhcp_nuage_port(
                        context, neutron_subnet)
                if dhcp_port:
                    for dhcp_ip in dhcp_port['fixed_ips']:
                        if (ipv4_subnet and
                                dhcp_ip['subnet_id'] == ipv4_subnet['id']):
                            params['dhcp_ip'] = dhcp_ip['ip_address']
                        if (ipv6_subnet and
                                dhcp_ip['subnet_id'] == ipv6_subnet['id']):
                            params['dhcpv6_ip'] = dhcp_ip['ip_address']

        if dual_stack_subnet:
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                context.session, dual_stack_subnet['id'])
            if subnet_mapping is None:
                raise NuageDualstackSubnetNotFound(resource="Subnet")
            params['mapping'] = subnet_mapping

        params.update(r_param)

        with utils_rollback() as on_exc:
            nuage_subnet = self.vsdclient.create_subnet(
                ipv4_subnet=ipv4_subnet,
                ipv6_subnet=ipv6_subnet,
                params=params)

            mapping_for_rollback = l2dom_id = None

            if dual_stack_subnet:
                # ipv6/ipv4 subnet with ipv4/ipv6 subnet present
                # -> on rollback, dualstack (L3 and L2) to rollback to
                # single stack

                # nuage_subnet is None: copy ipv4/ipv6 mapping for creating
                # ipv6/ipv4 mapping
                nuage_subnet = {
                    'nuage_l2template_id':
                        subnet_mapping['nuage_l2dom_tmplt_id'],
                    'nuage_userid': subnet_mapping['nuage_user_id'],
                    'nuage_groupid': subnet_mapping['nuage_group_id'],
                    'nuage_l2domain_id': subnet_mapping['nuage_subnet_id']
                }
                # If dualstack is in l3, nuage_subnet_id is needed in
                # mapping_for_rollback.
                mapping_for_rollback = {
                    'nuage_l2dom_tmplt_id':
                        nuage_subnet['nuage_l2template_id'],
                    'nuage_subnet_id': nuage_subnet['nuage_l2domain_id']
                }
                if is_ipv4:
                    ipv4_subnet = None
                else:
                    ipv6_subnet = None
            else:
                # 1. ipv4/ipv6 subnet in l2
                # -> on rollback, delete ipv4/ipv6 l2domain
                l2dom_id = nuage_subnet['nuage_l2domain_id']

            on_exc(self.vsdclient.delete_subnet,
                   mapping=mapping_for_rollback, l2dom_id=l2dom_id,
                   ipv4_subnet=ipv4_subnet, ipv6_subnet=ipv6_subnet)

            if nuage_subnet or dual_stack_subnet:
                self._create_subnet_mapping(context, netpart_id,
                                            neutron_subnet,
                                            nuage_subnet)

                if l2bridge and not l2bridge['nuage_subnet_id']:
                    l2bridge['nuage_subnet_id'] = nuage_subnet[
                        'nuage_l2domain_id']

    @staticmethod
    def _create_subnet_mapping(context, netpart_id, neutron_subnet,
                               nuage_subnet):
        l2dom_id = nuage_subnet['nuage_l2template_id']
        user_id = nuage_subnet['nuage_userid']
        group_id = nuage_subnet['nuage_groupid']
        nuage_id = nuage_subnet['nuage_l2domain_id']
        with context.session.begin(subtransactions=True):
            nuagedb.add_subnetl2dom_mapping(context.session,
                                            neutron_subnet['id'],
                                            nuage_id,
                                            netpart_id,
                                            neutron_subnet['ip_version'],
                                            l2dom_id=l2dom_id,
                                            nuage_user_id=user_id,
                                            nuage_group_id=group_id)

        neutron_subnet['net_partition'] = netpart_id
        if neutron_subnet.get('vsd_managed'):
            neutron_subnet['nuagenet'] = nuage_id

    @staticmethod
    def _validate_l2bridge_added_subnet_parameter(
            bridged_subnet, added_subnet, parameter, l2bridge):
        to_check = bridged_subnet.get(parameter)
        new = added_subnet.get(parameter)
        if to_check != new:
            msg = _("The {} associated with nuage_l2bridge {} "
                    "is {}. {} is not compatible. ").format(
                parameter, l2bridge['id'], to_check, new)
            raise NuageBadRequest(msg=msg)

    def _create_vsd_managed_subnet(self, context, subnet):
        nuage_subnet_id = subnet['nuagenet']
        if not subnet.get('net_partition'):
            subnet['net_partition'] = self._get_net_partition_for_entity(
                context, subnet)['id']
        nuage_np_id = self._validate_net_partition(
            subnet['net_partition'], context)['id']
        if not self.vsdclient.check_if_l2_dom_in_correct_ent(
                nuage_subnet_id, {'id': nuage_np_id}):
            msg = ("Provided Nuage subnet not in the provided"
                   " Nuage net-partition")
            raise NuageBadRequest(msg=msg)
        subnet_info = nuagedb.get_subnet_info_by_nuage_id(
            context.session, nuage_subnet_id, ip_type=subnet['ip_version'])
        # retrieve subnet type - it could yield None is not yet known
        subnet_type = subnet_info['subnet_type'] if subnet_info else None
        nuage_subnet, shared_subnet = self._get_nuage_subnet(
            nuage_subnet_id, subnet_type=subnet_type)

        network = self.core_plugin.get_network(context,
                                               subnet['network_id'])

        expected_tunnel_type = (vsd_constants.VSD_TUNNEL_TYPES['MPLS'] if
                                self.is_nuage_hybrid_mpls_network(network)
                                else vsd_constants.VSD_TUNNEL_TYPES['VXLAN'])
        if not nuage_subnet['l2EncapType'] == expected_tunnel_type:
            network_type = (lib_constants.TYPE_VXLAN if
                            expected_tunnel_type ==
                            vsd_constants.VSD_TUNNEL_TYPES['VXLAN']
                            else constants.NUAGE_HYBRID_MPLS_NET_TYPE)
            msg = (('Provided Nuage subnet has tunnel type '
                    '{} which is not supported by {} networks')
                   .format(nuage_subnet['l2EncapType'],
                           network_type.upper()))
            raise NuageBadRequest(msg=msg)

        # Check the nuage subnet type is standard if linking to domain subnet
        if (nuage_subnet.get('resourceType') and
                nuage_subnet['resourceType'] != 'STANDARD'):
            msg = (_("The nuage subnet type is {}. Only STANDARD type subnet "
                     "is allowed to be linked.")
                   .format(nuage_subnet['resourceType']))
            raise NuageBadRequest(msg=msg)
        self._validate_cidr(subnet, nuage_subnet, shared_subnet)
        self._validate_allocation_pools(context, subnet, subnet_info)
        match, os_gw_ip, vsd_gw_ip = self._check_gateway_from_vsd(
            nuage_subnet, shared_subnet, subnet)
        if not match:
            if not vsd_gw_ip:
                vsd_gw_ip = 'not being present'
            msg = ("The specified gateway {} does not match with "
                   "gateway on VSD {}".format(os_gw_ip, vsd_gw_ip))
            raise NuageBadRequest(msg=msg)
        nuage_uid, nuage_gid = self.vsdclient.attach_nuage_group_to_nuagenet(
            context.tenant, nuage_np_id, nuage_subnet_id, subnet.get('shared'),
            context.tenant_name)
        try:
            with context.session.begin(subtransactions=True):
                dual_stack_subnet = self.get_vsd_managed_dual_subnet(
                    context, subnet, nuage_subnet_id)
                self.create_update_dhcp_nuage_port(
                    context, subnet,
                    nuage_subnet=shared_subnet or nuage_subnet,
                    dualstack=dual_stack_subnet)
                l2dom_id = None
                if nuage_subnet["type"] == constants.L2DOMAIN:
                    l2dom_id = nuage_subnet_id
                nuagedb.add_subnetl2dom_mapping(
                    context.session, subnet['id'], nuage_subnet_id,
                    nuage_np_id, subnet['ip_version'],
                    nuage_user_id=nuage_uid, l2dom_id=l2dom_id,
                    nuage_group_id=nuage_gid, managed=True)
                subnet['vsd_managed'] = True
        except Exception:
            self._cleanup_group(context, nuage_np_id, nuage_subnet_id, subnet)
            raise

    def _check_gateway_from_vsd(self, nuage_subnet, shared_subnet, subnet):
        """_check_gateway_from_vsd

        This methods checks the openstack gateway with the VSD gateway and
        returns whether they match, as well as their values which are used in
        the error report when they don't match.

        One side effect of this function is that in case of L2, v4 and
        in OpenStack a GW is specified as the .1 IP, and in VSD no option 3
        is set, we tolerate (so match will be True), but we _clear_ the
        gateway IP in OpenStack also.

        :rtype: (bool, string, string)
        :returns matching_gws: boolean report whether the gateways match
        :returns os_gw_ip: the OpenStack gateway, used for error reporting
        :returns vsd_gw_ip: the VSD gateway, used for error reporting

        """
        gateway_subnet = shared_subnet or nuage_subnet
        is_l2 = nuage_subnet['type'] == constants.L2DOMAIN
        is_v6 = self._is_ipv6(subnet)
        os_gw_ip = subnet['gateway_ip']

        if is_l2:
            if is_v6:
                # There is no concept of IPV6 gateway for L2domain on VSD as
                # it's done through RA.
                vsd_gw_ip = os_gw_ip

            else:  # v4

                # fetch option 3 from vsd
                vsd_gw_ip = self.vsdclient.get_gw_from_dhcp_l2domain(
                    gateway_subnet['ID'])

        # l3
        elif is_v6:
            vsd_gw_ip = gateway_subnet['IPv6Gateway']
        else:
            vsd_gw_ip = gateway_subnet['gateway']

        matching_gws = self._is_equal_ip(os_gw_ip, vsd_gw_ip)

        return matching_gws, os_gw_ip, vsd_gw_ip

    def _cleanup_group(self, db_context, nuage_npid, nuage_subnet_id, subnet):
        try:
            if db_context.tenant == subnet['tenant_id']:
                tenants = [db_context.tenant]
            else:
                tenants = [db_context.tenant, subnet['tenant_id']]
            self.vsdclient.detach_nuage_group_to_nuagenet(
                tenants, nuage_subnet_id,
                subnet.get('shared'))
        except Exception as e:
            LOG.error("Failed to detach group from vsd subnet {tenant: %s,"
                      " netpartition: %s, vsd subnet: %s}",
                      db_context.tenant, nuage_npid, nuage_subnet_id)
            raise e

    def _get_nuage_subnet(self, nuage_subnet_id, subnet_db=None,
                          subnet_type=None):
        if subnet_db is None:
            nuage_subnet = self.vsdclient.get_nuage_subnet_by_id(
                nuage_subnet_id, subnet_type=subnet_type)
        else:
            nuage_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                subnet_db)
        require(nuage_subnet, 'subnet or domain', nuage_subnet_id)
        shared = nuage_subnet['associatedSharedNetworkResourceID']
        shared_subnet = None
        if shared:
            shared_subnet = self.vsdclient.get_nuage_subnet_by_id(
                shared,
                subnet_type=subnet_type)
            require(shared_subnet, 'sharednetworkresource', shared)
            shared_subnet['subnet_id'] = shared
        return nuage_subnet, shared_subnet

    def create_nuage_subnet_precommit(self, db_context, network, prefixlen,
                                      subnet, vsd_managed):
        l2bridge = None
        l2bridge_id = subnet.get('nuage_l2bridge')
        if l2bridge_id:
            l2bridge = nuagedb.get_nuage_l2bridge_blocking(db_context.session,
                                                           l2bridge_id)

        self._validate_create_subnet(db_context,
                                     network, prefixlen, subnet, vsd_managed,
                                     l2bridge)
        if vsd_managed:
            self._create_vsd_managed_subnet(db_context, subnet)
        else:
            self._create_openstack_managed_subnet(db_context, subnet, l2bridge)

        # take out underlay extension from the json response
        if subnet.get('underlay') == lib_constants.ATTR_NOT_SPECIFIED:
            subnet['underlay'] = None
        if 'underlay' not in subnet:
            subnet['underlay'] = None

    def _validate_create_subnet(self, db_context,
                                network, prefixlen, subnet, vsd_managed,
                                l2bridge):
        pass

    def _validate_create_openstack_managed_subnet(self, context, subnet,
                                                  network_subnets):
        if (lib_validators.is_attr_set(subnet.get('gateway_ip')) and
                netaddr.IPAddress(subnet['gateway_ip']) not in
                netaddr.IPNetwork(subnet['cidr'])):
            msg = "Gateway IP outside of the subnet CIDR "
            raise NuageBadRequest(resource='subnet', msg=msg)

        if self.is_external(context, subnet['network_id']):
            self._validate_nuage_sharedresource(
                subnet['network_id'], network_subnets, subnet)
        else:
            if lib_validators.is_attr_set(subnet.get('net_partition')):
                netpart = self._get_net_partition_for_entity(context, subnet)
                if netpart['name'] == constants.SHARED_INFRASTRUCTURE:
                    msg = (_("It is not allowed to create OpenStack managed "
                             "subnets in the net_partition {}")
                           .format(netpart['name']))
                    raise NuageBadRequest(resource='subnet', msg=msg)
            if lib_validators.is_attr_set(subnet.get('underlay')):
                msg = _("underlay attribute can not be set for "
                        "internal subnets")
                raise NuageBadRequest(resource='subnet', msg=msg)
            if lib_validators.is_attr_set(subnet.get('nuage_uplink')):
                msg = _("nuage_uplink attribute can not be set for "
                        "internal subnets")
                raise NuageBadRequest(resource='subnet', msg=msg)

        ipv4s = len([s for s in network_subnets if self._is_ipv4(s)])
        ipv6s = len([s for s in network_subnets if self._is_ipv6(s)])

        if (ipv4s > 0 and ipv6s > 1) or (ipv6s > 0 and ipv4s > 1):
            msg = _("A network can only have maximum 1 ipv4 and 1 ipv6 subnet "
                    "existing together")
            raise NuageBadRequest(msg=msg)

    def _validate_nuage_sharedresource(self, net_id, network_subnets,
                                       subnet=None):
        if any(map(self._is_ipv6, network_subnets)):
            msg = _("Subnet with ip_version 6 is currently not supported "
                    "for router:external networks.")
            raise NuageBadRequest(msg=msg)

        if subnet:
            fip_underlays = [s['underlay'] for s in network_subnets
                             if s['id'] != subnet['id']]
            subn_underlay = (subnet['underlay'] if subnet.get('underlay')
                             is not None else
                             cfg.CONF.RESTPROXY.nuage_fip_underlay)
            if len(set(fip_underlays + [subn_underlay])) > 1:
                msg = (_('It is not allowed to mix external '
                         'subnets with underlay '
                         'enabled and disabled in the same external '
                         'network {}.').format(net_id))
                raise NuageBadRequest(msg=msg)

    @staticmethod
    def _validate_create_vsd_managed_subnet(network, subnet):
        subnet_validate = {'nuagenet': IsSet()}
        validate("subnet", subnet, subnet_validate)
        net_validate = {'router:external': Is(False)}
        validate("network", network, net_validate)

        # Check that network is not attached to a nuage_l2bridge
        if network.get('nuage_l2bridge'):
            msg = _("The network is attached to nuage_l2bridge {}."
                    "Please consult documentation on how to achieve SRIOV"
                    "duplex for VSD managed subnets.").format(
                network['nuage_l2bridge'])
            raise NuageBadRequest(msg=msg)

    def is_external(self, context, net_id):
        return self.core_plugin._network_is_external(context, net_id)

    @handle_nuage_api_errorcode
    def _create_openstack_managed_subnet(self, context, subnet, l2bridge):
        if self.is_external(context, subnet['network_id']):
            network_subnets = self.core_plugin.get_subnets_by_network(
                context, subnet['network_id'])
            return self._add_nuage_sharedresource(
                context, subnet, constants.SR_TYPE_FLOATING, network_subnets)
        nuage_np_id = self._get_net_partition_for_entity(context, subnet)['id']
        attempt = 0
        while True:
            try:
                with context.session.begin(subtransactions=True):
                    self._create_nuage_subnet(
                        context, subnet, nuage_np_id, l2bridge)
                return
            except NuageDualstackSubnetNotFound:
                if attempt < 25:
                    LOG.debug("Retrying due to concurrency.")
                    attempt += 1
                    time.sleep(0.2)
                    continue
                msg = "Failed to create subnet on vsd"
                raise Exception(msg)

    @handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def _add_nuage_sharedresource(self, context, subnet, fip_type,
                                  network_subnets):
        subnet['net_partition'] = constants.SHARED_INFRASTRUCTURE
        shared_netpart = self._get_net_partition_for_entity(context, subnet)
        netpart_id = shared_netpart['id']

        l3dom_params = {
            'netpart_id': netpart_id,
            'templateID': shared_netpart['l3dom_tmplt_id']
        }
        subnet_params = {
            'resourceType': fip_type,
            'nuage_uplink': self.get_nuage_uplink(subnet, network_subnets),
            'ingressReplicationEnabled': config.ingress_replication_enabled()
        }
        if subnet.get('underlay') in [True, False]:
            subnet_params['underlay'] = subnet.get('underlay')
            l3dom_params['FIPUnderlay'] = subnet.get('underlay')
        else:
            subnet['underlay'] = cfg.CONF.RESTPROXY.nuage_fip_underlay
            subnet_params['underlay'] = subnet['underlay']
            l3dom_params['FIPUnderlay'] = subnet['underlay']

        zone_id = l3dom_id = None
        if subnet_params.get('nuage_uplink'):
            zone_id = subnet_params['nuage_uplink']
        elif l3dom_params['FIPUnderlay'] is False:
            l3dom_id = self.vsdclient.create_shared_l3domain(l3dom_params)
        else:
            l3dom_id = (self.vsdclient
                        .get_fip_underlay_enabled_domain_by_netpart(
                            netpart_id))
            if not l3dom_id:
                try:
                    l3dom_id = self.vsdclient.create_shared_l3domain(
                        l3dom_params)
                except restproxy.RESTProxyError as e:
                    msg = ("Shared infrastructure enterprise can have max "
                           "1 Floating IP domains.")
                    if str(e) == msg:
                        LOG.debug("Hit concurrent creation of Floating IP "
                                  "domain in Shared Infrastructure. "
                                  "Obtaining the one created")
                        l3dom_id = (
                            self.vsdclient
                                .get_fip_underlay_enabled_domain_by_netpart
                            (netpart_id))
                    else:
                        raise

        if zone_id is None and l3dom_id is not None:
            zone_id = self.vsdclient.get_zone_by_domainid(
                l3dom_id)[0]['zone_id']

        if subnet['underlay']:
            with context.session.begin(subtransactions=True):
                nuagedb.add_subnet_parameter(
                    context.session, subnet['id'],
                    constants.NUAGE_UNDERLAY,
                    constants.NUAGE_UNDERLAY_FIP)

        with utils_rollback() as on_exc:
            nuage_subnet = self.vsdclient.create_shared_subnet(
                zone_id, subnet, subnet_params)
            on_exc(self.vsdclient.delete_subnet,
                   l3_vsd_subnet_id=nuage_subnet['ID'])

            subnet['nuage_uplink'] = nuage_subnet['parentID']
            nuage_subnet['nuage_l2template_id'] = None  # L3
            nuage_subnet['nuage_l2domain_id'] = nuage_subnet['ID']

            self._create_subnet_mapping(context, shared_netpart['id'],
                                        subnet, nuage_subnet)

    @staticmethod
    def get_nuage_uplink(subnet, network_subnets):
        nuage_uplink = None
        nuage_uplinks = {s['nuage_uplink'] for s in network_subnets
                         if s['id'] != subnet['id'] and s.get('nuage_uplink')}
        if subnet.get('nuage_uplink'):
            nuage_uplink = subnet.get('nuage_uplink')
        elif cfg.CONF.RESTPROXY.nuage_uplink:
            nuage_uplink = cfg.CONF.RESTPROXY.nuage_uplink
        elif nuage_uplinks:
            # Use the same parent of the existing subnets in the network
            nuage_uplink = list(nuage_uplinks)[0]
        if nuage_uplink:
            nuage_uplinks.add(nuage_uplink)
            if len(nuage_uplinks) > 1:
                msg = _("It is not possible for subnets in an "
                        "external network to have different nuage_uplink "
                        "specified: {}.").format(nuage_uplinks)
                raise NuageBadRequest(msg=msg)
        return nuage_uplink

    def update_subnet(self, context):
        updated_subnet = context.current
        original_subnet = context.original
        db_context = context._plugin_context
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        updated_subnet['id'])
        net_id = original_subnet['network_id']
        network_external = self.is_external(db_context, net_id)
        if not subnet_mapping:
            return

        l2bridge_id = nuagedb.get_nuage_l2bridge_id_for_subnet(
            db_context.session, updated_subnet['id'])
        self._validate_update_subnet(db_context, network_external,
                                     subnet_mapping, updated_subnet,
                                     original_subnet, l2bridge_id)
        if subnet_mapping and self._is_vsd_mgd(subnet_mapping):
            # in case of VSD managed subnet, no action on VSD needed
            return

        nuage_subnet_id = subnet_mapping['nuage_subnet_id']
        dual_stack_subnet = self.get_dual_stack_subnet(db_context,
                                                       updated_subnet)
        if network_external:
            return self._update_ext_network_subnet(nuage_subnet_id,
                                                   updated_subnet)

        dhcp_opts_changed = self._validate_dhcp_opts_changed(
            original_subnet,
            updated_subnet)

        curr_enable_dhcp = original_subnet.get('enable_dhcp')
        updated_enable_dhcp = updated_subnet.get('enable_dhcp')

        params = {
            "dhcp_enable_changed": curr_enable_dhcp != updated_enable_dhcp,
            "subnet_enable_dhcp": updated_subnet.get('enable_dhcp'),
            "dualstack": True if dual_stack_subnet else False,
            "ip_type": constants.IP_TYPE_IPV4 if self._is_ipv4(
                updated_subnet) else constants.IP_TYPE_IPV6,
            "subnet_name": updated_subnet['name'] if original_subnet.get(
                'name') != updated_subnet.get('name') else None
        }

        if self._is_l2(subnet_mapping):
            if not curr_enable_dhcp and updated_enable_dhcp:
                dhcp_port = self.create_update_dhcp_nuage_port(
                    db_context, updated_subnet, dualstack=dual_stack_subnet)
                for dhcp_ip in dhcp_port['fixed_ips']:
                    if dhcp_ip['subnet_id'] == updated_subnet['id']:
                        params['dhcp_ip'] = dhcp_ip['ip_address']
            elif curr_enable_dhcp and not updated_enable_dhcp:
                self.delete_dhcp_nuage_port(
                    context=db_context, neutron_subnet=updated_subnet,
                    dualstack=dual_stack_subnet)
                params['dhcp_ip'] = None
            if dhcp_opts_changed:
                self.vsdclient.update_l2domain_dhcp_options(
                    nuage_subnet_id, updated_subnet)
            # Update l2domain Template
            self.vsdclient.update_l2domain_template(
                nuage_l2dom_tmplt_id=(
                    subnet_mapping["nuage_l2dom_tmplt_id"]), **params)
            # Update l2domain
            self.vsdclient.update_l2domain(
                nuage_l2dom_id=nuage_subnet_id, **params)
        else:
            params.update({
                "subnet_nuage_underlay":
                    updated_subnet.get(constants.NUAGE_UNDERLAY),
                "subnet_enable_dhcp": updated_subnet.get('enable_dhcp')
            })
            if dhcp_opts_changed:
                self.vsdclient.update_domain_subnet_dhcp_options(
                    nuage_subnet_id, updated_subnet)
            # Update l3domain subnet
            self.vsdclient.update_domain_subnet(nuage_subnet_id,
                                                params)
            routing_mechanisms.update_nuage_subnet_parameters(db_context,
                                                              updated_subnet)

    def _validate_update_subnet(self, context, network_external,
                                subnet_mapping, updated_subnet, original,
                                l2bridge_id):
        updated_attributes = set(key for key in updated_subnet if
                                 updated_subnet.get(key) != original.get(key))

        if subnet_mapping and self._is_vsd_mgd(subnet_mapping):
            updatable_attrs = constants.VSD_MANAGED_SUBNET_UPDATABLE_ATTRIBUTES
            if not updated_attributes.issubset(updatable_attrs):
                msg = _("Subnet {} is a VSD-managed subnet. Update is not "
                        "supported for attributes other than {}.")\
                    .format(updated_subnet['id'], ', '.join(updatable_attrs))
                raise NuageBadRequest(resource='subnet', msg=msg)
            if "allocation_pools" in updated_attributes:
                # do a cross-network check that the new pool does not create
                # an overlap with other subnets pointing to the same VSD subnet
                subnet_info = nuagedb.get_subnet_info_by_nuage_id(
                    context.session,
                    updated_subnet['nuagenet'],
                    ip_type=updated_subnet['ip_version'])
                self._validate_allocation_pools(context, updated_subnet,
                                                subnet_info)
            return

        if (self._is_l3(subnet_mapping) and 'gateway_ip' in updated_subnet and
                not updated_subnet.get('gateway_ip')):
            msg = ("Subnet attached to a router interface "
                   "must have a gateway IP")
            raise NuageBadRequest(resource='subnet', msg=msg)

        if not network_external and updated_subnet.get('underlay') is not None:
            msg = _("underlay attribute can not be set for internal subnets")
            raise NuageBadRequest(resource='subnet', msg=msg)

        bridged_subnets = nuagedb.get_subnets_for_nuage_l2bridge(
            context.session, l2bridge_id)
        bridged_subnets = [
            x for x in bridged_subnets if
            x['network_id'] != updated_subnet['network_id']
        ]
        # update only allowed when no other subnets on l2bridge exist.
        if len(bridged_subnets) > 0 and not updated_attributes.isdisjoint(
                set(constants.L2BRIDGE_SUBNET_EQUAL_ATTRIBUTES)):
            msg = _("It is not allowed to update a subnet when it is attached "
                    "to a nuage_l2bridge connected to multiple subnets.")
            raise NuageBadRequest(resource='subnet', msg=msg)

        routing_mechanisms.validate_update_subnet(network_external,
                                                  subnet_mapping,
                                                  updated_subnet)

    def _update_ext_network_subnet(self, nuage_subnet_id, subnet):
        nuage_params = {
            'subnet_name': subnet.get('name'),
            'gateway_ip': subnet.get('gateway_ip')
        }
        self.vsdclient.update_nuage_subnet(nuage_subnet_id, nuage_params)

    @log_helpers.log_method_call
    def check_subnet_is_nuage_l3(self, context, subnet):
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

    def _validate_dhcp_opts_changed(self, original_subnet, updated_subnet):
        for k in ['dns_nameservers', 'host_routes', 'gateway_ip']:
            if original_subnet.get(k) != updated_subnet.get(k):
                return True
        return False


class BaseNuagePlugin(RootNuagePlugin):

    def __init__(self):
        super(BaseNuagePlugin, self).__init__()
        self.init_vsd_client()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in six.iteritems(resource)
                         if key in fields))
        return resource
