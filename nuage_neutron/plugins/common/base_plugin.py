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

import netaddr
from oslo_config import cfg
from oslo_utils import importutils

from neutron.extensions import portsecurity as psec
from nuage_neutron.plugins.common import callback_manager
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.validation import Is
from nuage_neutron.plugins.common.validation import validate


class BaseNuagePlugin(object):

    def __init__(self):
        super(BaseNuagePlugin, self).__init__()
        config.nuage_register_cfg_opts()
        self._nuageclient_init()
        self.nuage_callbacks = callback_manager.get_callback_manager()

    def _nuageclient_init(self):
        server = cfg.CONF.RESTPROXY.server
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        base_uri = cfg.CONF.RESTPROXY.base_uri
        auth_resource = cfg.CONF.RESTPROXY.auth_resource
        organization = cfg.CONF.RESTPROXY.organization
        cms_id = cfg.CONF.RESTPROXY.cms_id
        if not cms_id:
            raise cfg.ConfigFileValueError(
                _('Missing cms_id in configuration.'))
        nuageclient = importutils.import_module('nuagenetlib.nuageclient')
        self.nuageclient = nuageclient.NuageClient(cms_id=cms_id,
                                                   server=server,
                                                   base_uri=base_uri,
                                                   serverssl=serverssl,
                                                   serverauth=serverauth,
                                                   auth_resource=auth_resource,
                                                   organization=organization)

    def _create_nuage_vport(self, port, subnet_mapping, description=None):
        params = {
            'port_id': port['id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id'],
            'description': description,
            'parent_id': subnet_mapping['nuage_subnet_id'],
            'address_spoof': (constants.INHERITED
                              if port.get(psec.PORTSECURITY)
                              else constants.ENABLED)
        }
        if port['device_owner'] == constants.APPD_PORT:
            params['name'] = port['name']

        return self.nuageclient.create_vport(params)

    def _validate_vmports_same_netpartition(self, core_plugin, db_context,
                                            current_port, np_id):
        filters = {'device_id': [current_port['device_id']]}
        ports = core_plugin.get_ports(db_context, filters)
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
        shared_subnet = shared_subnet or {}
        if (not nuage_subnet['subnet_address']) and (
                not shared_subnet.get('subnet_address')):
            nuage_ip = None
        else:
            if shared_subnet.get('subnet_address'):
                nuage_subnet = shared_subnet
            nuage_ip = netaddr.IPNetwork(nuage_subnet['subnet_address'] + '/' +
                                         nuage_subnet['subnet_netmask'])

        subnet_validate = {'enable_dhcp': Is(nuage_ip is not None)}
        if nuage_ip:
            subnet_validate['cidr'] = Is(str(nuage_ip))
        validate("subnet", subnet, subnet_validate)
