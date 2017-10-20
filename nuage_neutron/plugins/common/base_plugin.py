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

from oslo_config import cfg
from oslo_log import helpers as log_helpers

from neutron._i18n import _
from neutron.api.v2 import attributes
from neutron.extensions import portsecurity as psec
from neutron.manager import NeutronManager
from neutron.plugins.common import constants as plugin_constants
from neutron.plugins.common import utils as plugin_utils
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions as n_exc

from nuage_neutron.plugins.common import callback_manager
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.utils import compare_cidr
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import validate
from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.vsdclient_fac import VsdClientFactory


class RootNuagePlugin(object):

    def __init__(self):
        super(RootNuagePlugin, self).__init__()
        config.nuage_register_cfg_opts()
        self.nuage_callbacks = callback_manager.get_callback_manager()
        self.vsdclient = None  # deferred initialization
        self._l2_plugin = None
        self._l3_plugin = None

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = NeutronManager.get_plugin()
        return self._l2_plugin

    @property
    def l3_plugin(self):
        if self._l3_plugin is None:
            self._l3_plugin = NeutronManager.get_service_plugins()[
                plugin_constants.L3_ROUTER_NAT]
        return self._l3_plugin

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

            if not compare_cidr(subnet['cidr'], nuage_cidr):
                msg = 'OSP cidr %s and NuageVsd cidr %s do not match' % \
                      (subnet['cidr'], nuage_cidr)
                raise NuageBadRequest(msg=msg)

        validate("subnet", subnet, subnet_validate)

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
    def _reserve_ip(self, context, subnet, ip):
        fixed_ip = [{'ip_address': ip, 'subnet_id': subnet['id']}]
        p_data = {
            'network_id': subnet['network_id'],
            'tenant_id': subnet['tenant_id'],
            'fixed_ips': fixed_ip,
            'device_owner': constants.DEVICE_OWNER_DHCP_NUAGE
        }
        port = plugin_utils._fixup_res_dict(context,
                                            attributes.PORTS,
                                            p_data)
        return self.core_plugin._create_port_db(context, {'port': port})[0]

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
    def _check_port_exists_in_neutron(self, db_context, port):
        try:
            port_db = self.core_plugin.get_port(db_context, port['id'])
            return port_db
        except n_exc.PortNotFound:
            return False


class BaseNuagePlugin(RootNuagePlugin):

    def __init__(self):
        super(BaseNuagePlugin, self).__init__()
        self.init_vsd_client()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource
