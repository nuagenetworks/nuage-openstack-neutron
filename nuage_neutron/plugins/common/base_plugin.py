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

import netaddr
import re
import socket
import struct

from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log

from neutron._i18n import _
from neutron.db import db_base_plugin_v2
from neutron.services.trunk import constants as t_consts

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import PortNotFound
from neutron_lib.plugins import constants as lib_plugins_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils

from nuage_neutron.plugins.common import callback_manager
from nuage_neutron.plugins.common.capabilities import Capabilities
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.utils import SubnetUtilsBase
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.plugins.common.validation import validate
from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.vsdclient_fac import VsdClientFactory


LOG = log.getLogger(__name__)


class RootNuagePlugin(SubnetUtilsBase):

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
                lib_plugins_constants.L3)
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
            'address_spoof': (constants.INHERITED
                              if port.get(psec.PORTSECURITY, True)
                              else constants.ENABLED)
        }

        return self.vsdclient.create_vport(params)

    def get_vsd_shared_subnet_attributes(self, neutron_id):
        try:
            return self.vsdclient.get_sharedresource(neutron_id)
        except restproxy.ResourceNotFoundException:
            pass

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
        if nuage_subnet.get('DHCPManaged', True) is False:
            subnet_validate = {'enable_dhcp': Is(False)}
        else:
            if subnet['ip_version'] == 4:
                nuage_cidr = netaddr.IPNetwork(nuage_subnet['address'] + '/' +
                                               nuage_subnet['netmask'])
                subnet_validate = {'enable_dhcp': Is(nuage_cidr is not None)}
            else:
                if nuage_subnet['IPType'] == constants.IP_TYPE_IPV4:
                    msg = (_("Subnet with ip_version %(ip_version)s can't be "
                             "linked to vsd subnet with IPType %(ip_type)s.")
                           % {'ip_version': subnet['ip_version'],
                              'ip_type': nuage_subnet['IPType']})
                    raise NuageBadRequest(msg=msg)
                nuage_cidr = netaddr.IPNetwork(nuage_subnet['IPv6Address'])
                subnet_validate = {}

            if not self.compare_cidr(subnet['cidr'], nuage_cidr):
                msg = 'OSP cidr %s and NuageVsd cidr %s do not match' % \
                      (subnet['cidr'], nuage_cidr)
                raise NuageBadRequest(msg=msg)

        validate("subnet", subnet, subnet_validate)

    def _validate_allocation_pools(self, context, subnet, subnet_info):
        if not subnet_info:
            return  # no other linked subnet, all good

        # this is not the only subnet linked to same nuage subnet
        # need to validate allocation pools being disjunct

        LOG.debug('_validate_allocation_pools: subnet {} has allocation pools '
                  '{}'.format(subnet['id'], subnet['allocation_pools']))

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
            sub = self.core_plugin.get_subnet(context, mapping['subnet_id'])
            pools_to_ip_sets(sub['allocation_pools'], ip_sets, ip_ranges)

            LOG.debug('_validate_allocation_pools: validating with subnet {} '
                      'with allocation pools {}'.format(
                          sub, sub['allocation_pools']))

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
    def create_dhcp_nuage_port(self, context, neutron_subnet,
                               nuage_subnet=None):
        dhcp_ip = None
        if (nuage_subnet and nuage_subnet.get('DHCPManaged', True) and
                self._is_ipv4(neutron_subnet)):
            dhcp_ip = nuage_subnet['gateway']
        elif neutron_subnet.get('enable_dhcp'):
            dhcp_ip = neutron_subnet['allocation_pools'][-1]['end']

        if dhcp_ip:
            fixed_ip = [{'ip_address': dhcp_ip,
                         'subnet_id': neutron_subnet['id']}]
            p_data = {
                'network_id': neutron_subnet['network_id'],
                'tenant_id': neutron_subnet['tenant_id'],
                'fixed_ips': fixed_ip,
                'device_owner': constants.DEVICE_OWNER_DHCP_NUAGE
            }
            port = plugin_utils._fixup_res_dict(context,
                                                port_def.COLLECTION_NAME,
                                                p_data)
            port['status'] = lib_constants.PORT_STATUS_ACTIVE
            return self.core_plugin._create_port_db(context, {'port': port})[0]
        else:
            LOG.warning(_('CIDR parameter ignored for unmanaged subnet.'))
            LOG.warning(_('Allocation Pool parameter ignored '
                          'for unmanaged subnet.'))
            return None

    @staticmethod
    def _check_security_groups_per_port_limit(sgs_per_port):
        if len(sgs_per_port) > constants.MAX_SG_PER_PORT:
            msg = (("Number of %s specified security groups exceeds the "
                    "maximum of %s security groups on a port "
                    "supported on nuage VSP") % (len(sgs_per_port),
                                                 constants.MAX_SG_PER_PORT))
            raise NuageBadRequest(msg=msg)

    def is_vxlan_network(self, network):
        net_type = 'provider:network_type'
        if str(network.get(net_type)).lower() == 'vxlan':
            return True
        vxlan_segment = [segment for segment in network.get('segments', [])
                         if str(segment.get(net_type)).lower() == 'vxlan']
        return len(vxlan_segment) != 0

    def is_vxlan_network_by_id(self, context, network_id):
        network = self.core_plugin.get_network(context,
                                               network_id)
        return self.is_vxlan_network(network)

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
        for key, value in min_required.iteritems():
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

    # CAUTION : this method is dangerous as we are about to support multiple
    #           vsd mgd dualstack combo's soon.
    #           - TODO(team) this needs refactoring
    def _get_any_other_subnet_in_network(self, context, subnet):
        subnets = self.core_plugin.get_subnets(
            context,
            filters={'network_id': [subnet['network_id']]})
        other_subnets = (s for s in subnets if s['id'] != subnet['id'])
        return next(other_subnets, None)

    @log_helpers.log_method_call
    def get_dual_stack_subnet(self, context, neutron_subnet):
        # TODO(team) CAUTION : this is dangerous code
        any_other_subnet = self._get_any_other_subnet_in_network(
            context, neutron_subnet)
        if (any_other_subnet and any_other_subnet['ip_version'] !=
                neutron_subnet['ip_version']):
            return any_other_subnet
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
            if self._is_ipv6(neutron_subnet):
                neutron_subnet = self.get_dual_stack_subnet(
                    context, neutron_subnet)
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                    context.session,
                    neutron_subnet['id'])
            if self._is_os_mgd(subnet_mapping):
                LOG.debug("Retrying to get the subnet from vsd.")
                l2bridge_id = nuagedb.get_nuage_l2bridge_id_for_subnet(
                    context.session, subnet_mapping['subnet_id'])
                subnet = {'id': subnet_mapping['subnet_id'],
                          'nuage_l2bridge': l2bridge_id}
                if self._is_l2(subnet_mapping):
                    return self.vsdclient.get_domain_subnet_by_external_id(
                        subnet)
                else:
                    return self.vsdclient.get_l2domain_by_external_id(
                        subnet)
            else:
                raise

    def _get_default_partition(self, session):
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
                msg = _('Net-partition {} does not exist.').format(np)
                raise NuageBadRequest(resource='subnet', msg=msg)
            return np
        else:
            return self._get_default_partition(context.session)

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

    @log_helpers.log_method_call
    def _delete_gateway_port(self, context, ports):
        for port in ports:
            try:
                db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                    self.core_plugin, context, port['id'])
            except PortNotFound:
                LOG.info("Port %s has been deleted concurrently",
                         port['id'])

    @staticmethod
    def get_auto_create_port_owners():
        return [lib_constants.DEVICE_OWNER_ROUTER_INTF,
                lib_constants.DEVICE_OWNER_ROUTER_GW,
                lib_constants.DEVICE_OWNER_FLOATINGIP,
                constants.DEVICE_OWNER_VIP_NUAGE,
                constants.DEVICE_OWNER_IRONIC
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
        return ([constants.DEVICE_OWNER_VIP_NUAGE] +
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


class BaseNuagePlugin(RootNuagePlugin):

    def __init__(self):
        super(BaseNuagePlugin, self).__init__()
        self.init_vsd_client()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource
