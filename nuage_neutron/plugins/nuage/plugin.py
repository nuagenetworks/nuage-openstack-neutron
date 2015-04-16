# Copyright 2014 Alcatel-Lucent USA Inc.
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
import re
import sys
import json

import contextlib
import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import importutils
from oslo.db import exception as db_exc
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes
from neutron.common import constants as os_constants
from neutron.common import exceptions as n_exc
from neutron.common import log
from neutron.common import utils
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from oslo_log import log  as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.policy import Rules
from nuage_neutron.plugins.nuage.common import config
from nuage_neutron.plugins.nuage.common import constants
from nuage_neutron.plugins.nuage.common import exceptions as nuage_exc
from nuage_neutron.plugins.nuage import extensions
from nuage_neutron.plugins.nuage.extensions import netpartition
from nuage_neutron.plugins.nuage import nuagedb
from neutron import policy

LOG = logging.getLogger(__name__)


def handle_nuage_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as ex:
            if isinstance(ex, n_exc.NeutronException):
                raise
            et, ei, tb = sys.exc_info()
            raise nuage_exc.NuageAPIException, \
                nuage_exc.NuageAPIException(msg=ex), tb
    return wrapped


class NuagePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  netpartition.NetPartitionPluginBase,
                  sg_db.SecurityGroupDbMixin):
    """Class that implements Nuage Networks' hybrid plugin functionality."""
    vendor_extensions = ["net-partition", "nuage-router", "nuage-subnet",
                         "ext-gw-mode"]

    binding_view = "extension:port_binding:view"

    def __init__(self):
        super(NuagePlugin, self).__init__()
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        config.nuage_register_cfg_opts()
        self.nuageclient_init()
        self._prepare_default_netpartition()
        LOG.debug("NuagePlugin initialization done")

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_provider_nuage'])

    def nuageclient_init(self):
        server = cfg.CONF.RESTPROXY.server
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        base_uri = cfg.CONF.RESTPROXY.base_uri
        auth_resource = cfg.CONF.RESTPROXY.auth_resource
        organization = cfg.CONF.RESTPROXY.organization
        nuageclient = importutils.import_module('nuagenetlib.nuageclient')
        self.nuageclient = nuageclient.NuageClient(server, base_uri,
                                                   serverssl, serverauth,
                                                   auth_resource,
                                                   organization)

    @log.log
    def _synchronization_thread(self):
        sync_interval = cfg.CONF.SYNCMANAGER.sync_interval
        fip_quota = str(cfg.CONF.RESTPROXY.default_floatingip_quota)
        if sync_interval > 0:
            args = (fip_quota, cfg.CONF.SYNCMANAGER.enable_sync)
            sync_loop = loopingcall.FixedIntervalLoopingCall(
                self.syncmanager.synchronize, *args)
            sync_loop.start(interval=sync_interval)
        else:
            self.syncmanager.synchronize(fip_quota,
                                         cfg.CONF.SYNCMANAGER.enable_sync)

    @log.log
    def _resource_finder(self, context, for_resource, resource, user_req):
        match = re.match(attributes.UUID_PATTERN, user_req[resource])
        if match:
            obj_lister = getattr(self, "get_%s" % resource)
            found_resource = obj_lister(context, user_req[resource])
            if not found_resource:
                msg = (_("%(resource)s with id %(resource_id)s does not "
                         "exist") % {'resource': resource,
                                     'resource_id': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
        else:
            filter = {'name': [user_req[resource]]}
            obj_lister = getattr(self, "get_%ss" % resource)
            found_resource = obj_lister(context, filters=filter)
            if not found_resource:
                msg = (_("Either %(resource)s %(req_resource)s not found "
                         "or you dont have credential to access it")
                       % {'resource': resource,
                          'req_resource': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            if len(found_resource) > 1:
                msg = (_("More than one entry found for %(resource)s "
                         "%(req_resource)s. Use id instead")
                       % {'resource': resource,
                          'req_resource': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            found_resource = found_resource[0]
        return found_resource

    @log.log
    def _create_update_port(self, context, port, np_name,
                            subnet_mapping):
        filters = {'device_id': [port['device_id']]}
        ports = self.get_ports(context, filters)
        subn = self.get_subnet(context, port['fixed_ips'][0]['subnet_id'])
        params = {
            'port_id': port['id'],
            'id': port['device_id'],
            'mac': port['mac_address'],
            'netpart_name': np_name,
            'ip': port['fixed_ips'][0]['ip_address'],
            'no_of_ports': len(ports),
            'tenant': subn['tenant_id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id']
        }

        if subnet_mapping['nuage_managed_subnet']:
            params['parent_id'] = subnet_mapping['nuage_l2dom_tmplt_id']

        self.nuageclient.create_vms(params)

    @log.log
    def _get_router_by_subnet(self, context, subnet_id):
        filters = {
            'fixed_ips': {'subnet_id': [subnet_id]},
            'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
        }
        router_port = self.get_ports(context, filters=filters)
        if not router_port:
            msg = (_("Router for subnet %s not found ") % subnet_id)
            raise n_exc.BadRequest(resource='port', msg=msg)
        return router_port[0]['device_id']

    @log.log
    def _process_port_create_security_group(self, context, port,
                                            sec_group):
        if not attributes.is_attr_set(sec_group):
            port[ext_sg.SECURITYGROUPS] = []
            return
        if len(sec_group) > 1:
            msg = (_("Multiple security group on a port not supported "
                     "on nuage VSP"))
            raise nuage_exc.NuageBadRequest(msg=msg)
        port_id = port['id']
        with context.session.begin(subtransactions=True):
            for sg_id in sec_group:
                super(NuagePlugin,
                      self)._create_port_security_group_binding(context,
                                                                port_id,
                                                                sg_id)
        try:
            vptag_vport_list = []
            for sg_id in sec_group:
                params = {
                    'neutron_port_id': port_id
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if nuage_port and nuage_port.get('nuage_vport_id'):
                    nuage_vport_id = nuage_port['nuage_vport_id']
                    sg = self._get_security_group(context, sg_id)
                    sg_rules = self.get_security_group_rules(
                                        context,
                                        {'security_group_id': [sg_id]})
                    sg_params = {
                        'nuage_port': nuage_port,
                        'sg': sg,
                        'sg_rules': sg_rules
                    }
                    nuage_vptag_id = (
                        self.nuageclient.process_port_create_security_group(
                                                                    sg_params))
                    vptag_vport = {
                        'nuage_vporttag_id': nuage_vptag_id
                    }
                    vptag_vport_list.append(vptag_vport)

            if vptag_vport_list:
                params = {
                    'vptag_vport_list': vptag_vport_list,
                    'nuage_vport_id': nuage_vport_id
                }
                self.nuageclient.update_nuage_vport(params)
        except Exception:
            with excutils.save_and_reraise_exception():
                for sg_id in sec_group:
                    super(NuagePlugin,
                          self)._delete_port_security_group_bindings(context,
                                                                 port_id)
        # Convert to list as a set might be passed here and
        # this has to be serialized
        port[ext_sg.SECURITYGROUPS] = (list(sec_group) if sec_group else [])

    @log.log
    def _delete_port_security_group_bindings(self, context, port_id):
        super(NuagePlugin,
              self)._delete_port_security_group_bindings(context, port_id)
        self.nuageclient.delete_port_security_group_bindings(port_id)

    @lockutils.synchronized('create_port', 'nuage-port', external=True)
    @handle_nuage_api_error
    @log.log
    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            p = port['port']
            self._ensure_default_security_group_on_port(context, port)
            port = super(NuagePlugin, self).create_port(context, port)
            device_owner = port.get('device_owner', None)
            if device_owner not in constants.AUTO_CREATE_PORT_OWNERS:
                if 'fixed_ips' not in port or len(port['fixed_ips']) == 0:
                    return self._extend_port_dict_binding(context, port)
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                port_prefix = constants.NOVA_PORT_OWNER_PREF
                if subnet_mapping:
                    LOG.debug("Found subnet mapping for neutron subnet %s",
                              subnet_id)

                    if port['device_owner'].startswith(port_prefix):
                        #This request is coming from nova
                        try:
                            net_partition = nuagedb.get_net_partition_by_id(
                                session,
                                subnet_mapping['net_partition_id'])
                            self._create_update_port(
                                context,
                                port,
                                net_partition['name'],
                                subnet_mapping)
                        except Exception:
                            with excutils.save_and_reraise_exception():
                                super(NuagePlugin, self).delete_port(
                                    context,
                                    port['id'])
                    if (subnet_mapping['nuage_managed_subnet'] is False
                        and ext_sg.SECURITYGROUPS in p):
                        self._process_port_create_security_group(
                            context,
                            port,
                            p[ext_sg.SECURITYGROUPS])
                        LOG.debug("Created security group for port %s",
                                  port['id'])

                    elif (subnet_mapping['nuage_managed_subnet'] and
                          ext_sg.SECURITYGROUPS in p):
                        LOG.warning(_("Security Groups is ignored for ports on"
                                      " VSD Managed Subnet"))
                else:
                    if port['device_owner'].startswith(port_prefix):
                        # VM is getting spawned on a subnet type which
                        # is not supported by VSD. LOG error.
                        LOG.error(_('VM with uuid %s will not be resolved '
                                  'in VSD because its created on unsupported'
                                  'subnet type'), port['device_id'])
        return self._extend_port_dict_binding(context, port)

    @handle_nuage_api_error
    @log.log
    def update_port(self, context, id, port):
        p = port['port']
        sg_groups = None
        session = context.session
        with session.begin(subtransactions=True):
            original_port = self.get_port(context, id)
            changed_owner = p.get('device_owner')
            current_owner =  original_port['device_owner']

            if p.get('device_owner', '').startswith(
                constants.NOVA_PORT_OWNER_PREF):
                LOG.debug("Port %s is owned by nova:compute", id)
                port = self._get_port(context, id)
                port.update(p)
                if not port.get('fixed_ips'):
                    return self._make_port_dict(port)
                subnet_id = port['fixed_ips'][0]['subnet_id']

                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                if subnet_mapping:
                    params = {
                        'neutron_port_id': id,
                    }
                    nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                    if not nuage_port or not nuage_port.get('nuage_vport_id'):
                        net_partition = nuagedb.get_net_partition_by_id(
                            session, subnet_mapping['net_partition_id'])
                        self._create_update_port(context, port,
                                                 net_partition['name'],
                                                 subnet_mapping)
                else:
                    LOG.error(_('VM with uuid %s will not be resolved '
                              'in VSD because its created on unsupported'
                              'subnet type'), port['device_id'])

                self._check_floatingip_update(context, port)
                updated_port = self._make_port_dict(port)
                if subnet_mapping['nuage_managed_subnet'] is False:
                    sg_port = self._extend_port_dict_security_group(
                        updated_port,
                        port)
                    sg_groups = sg_port[ext_sg.SECURITYGROUPS]
            else:
                LOG.debug("Port %s is not owned by nova:compute", id)
                updated_port = super(NuagePlugin,
                    self).update_port(context, id,
                                      port)
                if not updated_port.get('fixed_ips'):
                    return updated_port
                subnet_id = updated_port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                            context.session, subnet_id)
                # nova delete has removed the compute:none from device_owner
                if not changed_owner and current_owner.startswith(
                        constants.NOVA_PORT_OWNER_PREF):
                    LOG.debug("Removing nova:compute onwership for port %s ",
                               id)
                    if subnet_mapping:
                        net_partition = nuagedb.get_net_partition_by_id(
                                session, subnet_mapping['net_partition_id'])
                        # delete nuage_vm
                        self._delete_nuage_vport(context, original_port,
                                                 net_partition['name'])
        if (subnet_mapping and
            subnet_mapping['nuage_managed_subnet'] is False):
            if sg_groups:
                self._delete_port_security_group_bindings(
                    context, updated_port['id'])
                self._process_port_create_security_group(context,
                                                         updated_port,
                                                         sg_groups)
                LOG.debug("Updated security-groups on port %s", id)
            elif ext_sg.SECURITYGROUPS in p:
                self._delete_port_security_group_bindings(
                    context, updated_port['id'])
                self._process_port_create_security_group(
                    context,
                    updated_port,
                    p[ext_sg.SECURITYGROUPS]
                )
        elif (subnet_mapping and subnet_mapping['nuage_managed_subnet']):
            if sg_groups or (ext_sg.SECURITYGROUPS in p):
                LOG.warning(_("Security Groups is ignored for ports on "
                              "VSD Managed Subnet"))
        return updated_port

    @log.log
    def _delete_nuage_vport(self, context, port, np_name):
        nuage_vif_id = None
        params = {
            'neutron_port_id': port['id'],
        }
        subn = self.get_subnet(context, port['fixed_ips'][0]['subnet_id'])
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)

        if constants.NOVA_PORT_OWNER_PREF in port['device_owner']:
            LOG.debug("Deleting VM port %s", port['id'])
            # This was a VM Port
            if nuage_port:
                nuage_vif_id = nuage_port['nuage_vif_id']
            filters = {'device_id': [port['device_id']]}
            ports = self.get_ports(context, filters)
            params = {
                'no_of_ports': len(ports),
                'netpart_name': np_name,
                'tenant': subn['tenant_id'],
                'mac': port['mac_address'],
                'nuage_vif_id': nuage_vif_id,
                'id': port['device_id']
            }
            self.nuageclient.delete_vms(params)

    @lockutils.synchronized('delete-port', 'nuage-del', external=True)
    @handle_nuage_api_error
    @log.log
    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        port = self._get_port(context, id)
        # This is required for to pass ut test_floatingip_port_delete
        self.disassociate_floatingips(context, id)
        if not port['fixed_ips']:
            return super(NuagePlugin, self).delete_port(context, id)

        sub_id = port['fixed_ips'][0]['subnet_id']

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        sub_id)
        if not subnet_mapping:
            LOG.debug("No subnet to l2domain mapping found for subnet %s",
                      sub_id)
            return super(NuagePlugin, self).delete_port(context, id)

        # Need to call this explicitly to delete vport to vporttag binding
        if (ext_sg.SECURITYGROUPS in port and
            subnet_mapping['nuage_managed_subnet'] is False):
            self._delete_port_security_group_bindings(context, id)

        netpart_id = subnet_mapping['net_partition_id']
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        netpart_id)

        self._delete_nuage_vport(context, port, net_partition['name'])
        super(NuagePlugin, self).delete_port(context, id)

    @log.log
    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    @log.log
    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS
            port[portbindings.VIF_DETAILS] = {
                portbindings.CAP_PORT_FILTER: False
            }
        return port

    @log.log
    def get_port(self, context, id, fields=None):
        port = super(NuagePlugin, self).get_port(context, id, fields)
        return self._fields(self._extend_port_dict_binding(context, port),
                            fields)

    @log.log
    def get_ports(self, context, filters=None, fields=None):
        ports = super(NuagePlugin, self).get_ports(context,
                                                         filters, fields)
        return [self._fields(self._extend_port_dict_binding(context, port),
                             fields) for port in ports]

    @log.log
    def _check_router_subnet_for_tenant(self, context, tenant_id):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [tenant_id]}
        routers = self.get_routers(context, filters=filters)
        subnets = self.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    @log.log
    def _extend_network_dict_provider_nuage(self, network, net_db,
                                            net_binding=None):
        binding = net_db.pnetbinding if net_db else net_binding
        if binding:
            network[pnet.NETWORK_TYPE] = binding.network_type
            network[pnet.PHYSICAL_NETWORK] = binding.physical_network
            network[pnet.SEGMENTATION_ID] = binding.vlan_id

    @log.log
    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(pnet.NETWORK_TYPE)
        physical_network = attrs.get(pnet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(pnet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return None, None, None
        if attrs.get(external_net.EXTERNAL):
            msg = _("provider network with external=True is not "
                    "supported in VSP")
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not network_type_set:
            msg = _("provider:network_type required")
            raise n_exc.InvalidInput(error_message=msg)
        elif network_type != 'vlan':
            msg = (_("provider:network_type %s not supported in VSP")
                   % network_type)
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not physical_network_set:
            msg = _("provider:physical_network required")
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not segmentation_id_set:
            msg = _("provider:segmentation_id required")
            raise nuage_exc.NuageBadRequest(msg=msg)

        self.nuageclient.validate_provider_network(network_type,
                                                   physical_network,
                                                   segmentation_id)

        return network_type, physical_network, segmentation_id

    @handle_nuage_api_error
    @log.log
    def create_network(self, context, network):
        binding = None
        (network_type, physical_network,
         vlan_id) = self._process_provider_create(context,
                                                  network['network'])
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(
                context,
                network['network']['tenant_id']
            )
            net = super(NuagePlugin, self).create_network(context,
                                                          network)
            self._process_l3_create(context, net, network['network'])
            if network_type == 'vlan':
                binding = nuagedb.add_network_binding(context.session,
                                            net['id'],
                                            network_type,
                                            physical_network, vlan_id)
            self._extend_network_dict_provider_nuage(net, None, binding)
        return net

    @log.log
    def _validate_update_network(self, context, id, network):
        subnets = self._get_subnets_by_network(context, id)
        for subn in subnets:
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                    context.session, subn['id'])
            if subnet_l2dom and subnet_l2dom.get('nuage_managed_subnet'):
                msg = _('Network %s has a VSD-Managed subnet associated'
                        ' with it') % id
                raise nuage_exc.OperationNotSupported(msg=msg)

        req_data = network['network']
        is_external_set = req_data.get(external_net.EXTERNAL)
        if not attributes.is_attr_set(is_external_set):
            return (None, None)
        neutron_net = self.get_network(context, id)
        if neutron_net.get(external_net.EXTERNAL) == is_external_set:
            return (None, None)
        subnet = self._validate_nuage_sharedresource(context, 'network', id)
        if subnet and not is_external_set:
            msg = _('External network with subnets can not be '
                    'changed to non-external network')
            raise nuage_exc.OperationNotSupported(msg=msg)
        if is_external_set:
            # Check if there are vm ports attached to this network
            # If there are, then updating the network is not allowed
            ports = self.get_ports(context, filters={'network_id': [id]})
            for p in ports:
                if p['device_owner'].startswith(
                        constants.NOVA_PORT_OWNER_PREF):
                    raise n_exc.NetworkInUse(net_id=id)
        return (is_external_set, subnet)

    @handle_nuage_api_error
    @log.log
    def update_network(self, context, id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        with context.session.begin(subtransactions=True):
            is_external_set, subnet = self._validate_update_network(context,
                                                                    id,
                                                                    network)
            net = super(NuagePlugin, self).update_network(context, id,
                                                          network)
            self._process_l3_update(context, net, network['network'])
            if subnet and is_external_set:
                subn = subnet[0]
                subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                              subn['id'])
                if subnet_l2dom:
                    user_id = subnet_l2dom['nuage_user_id']
                    group_id = subnet_l2dom['nuage_group_id']
                    LOG.debug("Found subnet %(subn_id)s to l2 domain mapping"
                              " %(nuage_subn_id)s",
                              {'subn_id': subn['id'],
                               'nuage_subn_id': (subnet_l2dom[
                                                       'nuage_subnet_id'])})
                    self.nuageclient.delete_subnet(subn['id'])
                    nuagedb.delete_subnetl2dom_mapping(context.session,
                                                       subnet_l2dom)
                    if not self._check_router_subnet_for_tenant(
                            context, subn['tenant_id']):
                        LOG.debug("No router/subnet found for tenant %s",
                                  subn['tenant_id'])
                        self.nuageclient.delete_user(user_id)
                        self.nuageclient.delete_group(group_id)

                    self._add_nuage_sharedresource(subnet[0],
                                                   id,
                                                   constants.SR_TYPE_FLOATING)
        return net

    @handle_nuage_api_error
    @log.log
    def delete_network(self, context, id):
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            filter = {'network_id': [id]}
            subnets = self.get_subnets(context, filters=filter)
            for subnet in subnets:
                LOG.debug("Deleting subnet %s", subnet['id'])
                self.delete_subnet(context, subnet['id'])
            LOG.debug('Deleting network %s', id)
            super(NuagePlugin, self).delete_network(context, id)

    @log.log
    def _get_net_partition_for_subnet(self, context, subnet):
        ent = subnet.get('net_partition', None)
        if not ent:
            def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
            net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                              def_net_part)
        else:
            net_partition = self._resource_finder(context, 'subnet',
                                                  'net_partition', subnet)
        if not net_partition:
            msg = _('Either net_partition is not provided with subnet OR '
                    'default net_partition is not created at the start')
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        return net_partition

    @log.log
    def _validate_create_subnet(self, context, subnet, network_external):
        subnets = self._get_subnets_by_network(context, subnet['network_id'])
        subnet_nuagenet = subnet.get('nuagenet')
        # do not allow os_managed subnets if the network already has
        # vsd_managed subnets. and not allow vsd_managed subnets if the
        #network already has os_managed subnets
        for subn in subnets:
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                    context.session, subn['id'])
            if subnet_l2dom:
                # vsd managed subnet
                if subnet_l2dom.get('nuage_managed_subnet'):
                    if not subnet_nuagenet:
                        msg = _('Network has vsd managed subnets, cannot create '
                                'os managed subnets')
                        raise nuage_exc.NuageBadRequest(msg=msg)
                else:
                    if subnet_nuagenet:
                        msg = _('Network has os managed subnets, cannot create '
                                'vsd managed subnets')
                        raise nuage_exc.NuageBadRequest(msg=msg)

        if (attributes.is_attr_set(subnet['gateway_ip'])
            and netaddr.IPAddress(subnet['gateway_ip'])
            not in netaddr.IPNetwork(subnet['cidr'])):
            msg = "Gateway IP outside of the subnet CIDR "
            raise nuage_exc.NuageBadRequest(msg=msg)

        if (not network_external and
            subnet['underlay'] != attributes.ATTR_NOT_SPECIFIED):
            msg = _("underlay attribute can not be set for internal subnets")
            raise nuage_exc.NuageBadRequest(msg=msg)

    @log.log
    def _validate_create_provider_subnet(self, context, net_id):
        net_filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=net_filter)
        if len(existing_subn) > 0:
            msg = _('Only one subnet is allowed per '
                    'Provider network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)

    @log.log
    def _delete_nuage_sharedresource(self, net_id):
        self.nuageclient.delete_nuage_sharedresource(net_id)

    @log.log
    def _validate_nuage_sharedresource(self, context, resource, net_id):
        filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=filter)
        if len(existing_subn) > 1:
            msg = _('Only one subnet is allowed per '
                    'external network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)
        return existing_subn

    @log.log
    def _add_nuage_sharedresource(self, subnet, net_id, type,
                                  req_subnet=None):
        net = netaddr.IPNetwork(subnet['cidr'])
        params = {
            'neutron_subnet': subnet,
            'net': net,
            'type': type,
            'net_id': net_id
        }
        params['underlay_config'] = cfg.CONF.RESTPROXY.nuage_fip_underlay
        if (req_subnet and req_subnet.get('underlay') in [True, False]):
            params['underlay'] = req_subnet.get('underlay')
        self.nuageclient.create_nuage_sharedresource(params)

    @log.log
    def _create_nuage_sharedresource(self, context, subnet, type):
        req_subnet = copy.deepcopy(subnet['subnet'])
        net_id = req_subnet['network_id']
        self._validate_nuage_sharedresource(context, 'subnet', net_id)
        with context.session.begin(subtransactions=True):
            neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                                                                    subnet)
            self._add_nuage_sharedresource(neutron_subnet,
                                           net_id, type,req_subnet=req_subnet)
            return neutron_subnet

    @log.log
    def _create_port_gateway(self, context, subnet, gw_ip=None):
        if gw_ip is not None:
            fixed_ip = [{'ip_address': gw_ip, 'subnet_id': subnet['id']}]
        else:
            fixed_ip = [{'subnet_id': subnet['id']}]

        port_dict = dict(port=dict(
            name='',
            device_id='',
            admin_state_up=True,
            network_id=subnet['network_id'],
            tenant_id=subnet['tenant_id'],
            fixed_ips=fixed_ip,
            mac_address=attributes.ATTR_NOT_SPECIFIED,
            device_owner=constants.DEVICE_OWNER_DHCP_NUAGE))
        port = super(NuagePlugin, self).create_port(context, port_dict)
        return port

    @log.log
    def _delete_port_gateway(self, context, ports):
        for port in ports:
            super(NuagePlugin, self).delete_port(context, port['id'])

    @log.log
    def _create_nuage_subnet(self, context, neutron_subnet, netpart_id,
                             pnet_binding):
        gw_port = None
        neutron_net = self.get_network(context,
                                       neutron_subnet['network_id'])
        net = netaddr.IPNetwork(neutron_subnet['cidr'])
        # list(net)[-1] is the broadcast

        params = {
            'netpart_id': netpart_id,
            'tenant_id': neutron_subnet['tenant_id'],
            'net': net,
            'pnet_binding': pnet_binding,
            'shared': neutron_net['shared']
        }

        if neutron_subnet.get('enable_dhcp'):
            last_address = neutron_subnet['allocation_pools'][-1]['end']
            gw_port = self._create_port_gateway(context, neutron_subnet,
                                                last_address)
            params['dhcp_ip'] = gw_port['fixed_ips'][0]['ip_address']
        else:
            LOG.warning(_("CIDR parameter ignored for unmanaged subnet "))
            LOG.warning(_("Allocation Pool parameter ignored for unmanaged subnet "))
            params['dhcp_ip'] = None

        try:
            nuage_subnet = self.nuageclient.create_subnet(neutron_subnet,
                                                          params)
        except Exception:
            with excutils.save_and_reraise_exception():
                if gw_port:
                    LOG.debug(_("Deleting gw_port %s") % gw_port['id'])
                    self._delete_port_gateway(context, [gw_port])
                super(NuagePlugin, self).delete_subnet(context,
                                                       neutron_subnet['id'])

        if nuage_subnet:
            l2dom_id = str(nuage_subnet['nuage_l2template_id'])
            user_id = nuage_subnet['nuage_userid']
            group_id = nuage_subnet['nuage_groupid']
            id = nuage_subnet['nuage_l2domain_id']
            with context.session.begin(subtransactions=True):
                nuagedb.add_subnetl2dom_mapping(context.session,
                                                neutron_subnet['id'],
                                                id,
                                                netpart_id,
                                                l2dom_id=l2dom_id,
                                                nuage_user_id=user_id,
                                                nuage_group_id=group_id)

    @log.log
    def _validate_adv_subnet(self, context, subn, nuage_netpart):
        net_id = subn['network_id']
        nuage_subn_id = subn['nuagenet']
        pnet_binding = nuagedb.get_network_binding(context.session, net_id)
        network_external = self._network_is_external(context, net_id)

        if pnet_binding:
            msg = (_("VSD-Managed Subnet create not allowed on provider "
                         "network"))
            raise nuage_exc.NuageBadRequest(msg=msg)

        if network_external:
            msg = (_("VSD-Managed Subnet create not allowed on external "
                         "network"))
            raise nuage_exc.NuageBadRequest(msg=msg)

        if nuage_netpart is None:
            msg = ("Provided net-partition does not match VSD "
                   "configuration. ")
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        if not self.nuageclient.ckeck_if_l2Dom_in_correct_ent(nuage_subn_id,
                                                              nuage_netpart):
            msg = ("Provided Nuage subnet not in the provided"
                   " Nuage net-partition")
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        if nuagedb.get_subnet_l2dom_by_nuage_id(context.session, nuage_subn_id):
            msg = ("Multiple Openstack subnets cannot be linked to the "
                   "same VSD network")
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        try:
            nuage_ip, nuage_netmask = self.nuageclient.get_nuage_cidr(
                nuage_subn_id)
        except Exception:
            msg = ("Provided nuagenet ID does not match VSD "
                   "configuration. ")
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        else:
            if nuage_ip:
                if not subn['enable_dhcp']:
                    msg = "DHCP must be enabled for this subnet"
                    raise n_exc.BadRequest(resource='subnet', msg=msg)
                cidr = netaddr.IPNetwork(subn['cidr'])
                if (nuage_ip != str(cidr.ip) or
                    nuage_netmask != str(cidr.netmask)):
                    msg = ("Provided IP configuration does not match VSD "
                           "configuration")
                    raise n_exc.BadRequest(resource='subnet', msg=msg)
            else:
            # this is the case for VSD-Managed unmanaged subnet
                if subn['enable_dhcp']:
                    msg = "DHCP must be disabled for this subnet"
                    raise n_exc.BadRequest(resource='subnet', msg=msg)

    @log.log
    def _get_gwip_for_adv_managed_subn(self, subn):
        gw_ip_from_cli = subn['gateway_ip']
        nuage_subn_id = subn['nuagenet']

        # case for adv. managed subnet
        # return the gw_ip with which the dhcp port is created
        # in case of adv. managed subnets
        (gw_ip_via_dhcp_options,
        gw_ip, is_l3) = self.nuageclient.get_gateway_ip_for_advsub(
                        nuage_subn_id)

        if is_l3:
            subn['gateway_ip'] = gw_ip
        else:
            # case for l2 only domain VSD-Managed subnets
            if gw_ip_via_dhcp_options:
                subn['gateway_ip'] = gw_ip_via_dhcp_options
            else:
                subn['gateway_ip'] = None

        if attributes.is_attr_set(gw_ip_from_cli):
            if gw_ip_from_cli != subn['gateway_ip']:
                msg = ("Provided gateway-ip does not match VSD "
                       "configuration. ")
                raise n_exc.BadRequest(resource='subnet', msg=msg)
        if attributes.is_attr_set(subn['dns_nameservers']):
            LOG.warning(_("DNS Nameservers parameter ignored for "
                          "VSD-Managed managed subnet "))
        # creating a dhcp_port with this gatewayIP
        return gw_ip

    @log.log
    def _link_nuage_adv_subnet(self, context, subnet):
        subn = subnet['subnet']
        nuage_subn_id = subn['nuagenet']
        nuage_tmplt_id = nuage_subn_id
        gw_ip = None

        nuage_netpart_name = subn.get('net_partition', None)

        if not nuage_netpart_name:
            msg = 'In advance mode, net-partition name must be provided'
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        nuage_netpart = nuagedb.get_net_partition_by_name(context.session,
                                                          nuage_netpart_name)

        self._validate_adv_subnet(context, subn, nuage_netpart)

        if subn['enable_dhcp']:
            gw_ip = self._get_gwip_for_adv_managed_subn(subn)
        else:
            LOG.warning(_("CIDR parameter ignored for unmanaged subnet "))
            LOG.warning(_("Allocation Pool parameter ignored for"
                          " unmanaged subnet "))
            if attributes.is_attr_set(subn['gateway_ip']):
                subn['gateway_ip'] = None
                LOG.warning(_("Gateway IP parameter ignored for "
                              "VSD-Managed unmanaged subnet "))
            if attributes.is_attr_set(subn['dns_nameservers']):
                subn['dns_nameservers'] = None
                LOG.warning(_("DNS Nameservers parameter ignored "
                              "for VSD-Managed unmanaged subnet "))

        try:
            with contextlib.nested(lockutils.lock('db-access'),
                context.session.begin(subtransactions=True)):
                neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                subnet)
                if subn['enable_dhcp']:
                    # Create the dhcp port only for adv. managed subnets
                    # this the dhcp port which is being created for the
                    # adv subnet
                    # l2 case: this is the dhcp server IP seen in VSD GUI
                    # l3 case: we just create a dhcp server
                    # IP port since we need to block a VM creation with
                    # the gwIp in this domain/subnet
                    self._create_port_gateway(context, neutron_subnet, gw_ip)

                subnet_l2dom = nuagedb.add_subnetl2dom_mapping(
                    context.session, neutron_subnet['id'],
                    nuage_subn_id, nuage_netpart['id'],
                    l2dom_id=str(nuage_tmplt_id), managed=True)
        except db_exc.DBError as e:
            if isinstance(e.inner_exception, sql_exc.IntegrityError):
                msg = _("A concurrent binding to the same VSD managed"
                        " subnet detected. This operation is not allowed.")
                raise n_exc.BadRequest(resource='subnet', msg=msg)

        try:
            nuage_npid = nuage_netpart['id']
            (nuage_uid,
             nuage_gid) = self.nuageclient.attach_nuage_group_to_nuagenet(
                 context.tenant, nuage_npid, nuage_subn_id,
                 neutron_subnet.get('shared'))
        except Exception:
            filters = {
                'fixed_ips': {'subnet_id': [neutron_subnet['id']]},
                'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
            }
            gw_ports = self.get_ports(context, filters=filters)
            self._delete_port_gateway(context, gw_ports)
            super(NuagePlugin, self).delete_subnet(context,
                                                   neutron_subnet['id'])
            msg = "Communication with Nuage VSD failed"
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        ns_dict = {}
        ns_dict['nuage_user_id'] = nuage_uid
        ns_dict['nuage_group_id'] = nuage_gid
        with context.session.begin(subtransactions=True):
            nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                               ns_dict)
        return neutron_subnet

    @handle_nuage_api_error
    @log.log
    def create_subnet(self, context, subnet):
        subn = subnet['subnet']
        net_id = subn['network_id']

        pnet_binding = nuagedb.get_network_binding(context.session, net_id)
        network_external = self._network_is_external(context, net_id)
        self._validate_create_subnet(context, subn, network_external)

        if subn.get('nuagenet', None):
            return self._link_nuage_adv_subnet(context, subnet)

        if network_external:
            return self._create_nuage_sharedresource(
                context, subnet, constants.SR_TYPE_FLOATING)

        if pnet_binding:
            self._validate_create_provider_subnet(context, net_id)

        net_partition = self._get_net_partition_for_subnet(context, subn)
        neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                                                                subnet)
        self._create_nuage_subnet(context, neutron_subnet, net_partition['id'],
                                  pnet_binding)
        return neutron_subnet

    @handle_nuage_api_error
    @log.log
    def update_subnet(self, context, id, subnet):
        subn = copy.deepcopy(subnet['subnet'])
        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                      id)
        if subnet_l2dom['nuage_managed_subnet']:
            msg = ("Subnet %s is a VSD-Managed subnet."
                    " Update is not supported." % subnet_l2dom['subnet_id'])
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        params = {
            'parent_id': subnet_l2dom['nuage_subnet_id'],
            'type': subnet_l2dom['nuage_l2dom_tmplt_id']
        }
        with context.session.begin(subtransactions=True):
            original_subnet = self.get_subnet(context, id)
            updated_subnet = super(NuagePlugin, self).update_subnet(
                context, id, subnet)

            curr_enable_dhcp = original_subnet.get('enable_dhcp')
            updated_enable_dhcp = updated_subnet.get('enable_dhcp')

            if not curr_enable_dhcp and updated_enable_dhcp:
                last_address = updated_subnet['allocation_pools'][-1]['end']
                gw_port = self._create_port_gateway(context,
                                                    updated_subnet,
                                                    last_address)
                params['net'] = netaddr.IPNetwork(original_subnet['cidr'])
                params['dhcp_ip'] = gw_port['fixed_ips'][0]['ip_address']
            elif curr_enable_dhcp and not updated_enable_dhcp:
                params['dhcp_ip'] = None
                filters = {
                    'fixed_ips': {'subnet_id': [id]},
                    'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
                }
                gw_ports = self.get_ports(context, filters=filters)
                self._delete_port_gateway(context, gw_ports)

            self.nuageclient.update_subnet(subn, params)

            return updated_subnet

    @handle_nuage_api_error
    @log.log
    def delete_subnet(self, context, id):
        subnet = self.get_subnet(context, id)

        filters = {
            'fixed_ips': {'subnet_id': [id]},
            'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
        }
        ports = self.get_ports(context, filters)
        for port in ports:
            if port['device_owner'] != constants.DEVICE_OWNER_DHCP_NUAGE:
                raise n_exc.SubnetInUse(subnet_id=id)
        self._delete_port_gateway(context, ports)

        if self._network_is_external(context, subnet['network_id']):
            LOG.debug("Network %s is external, so deleting the sharedresource",
                      subnet['network_id'])
            super(NuagePlugin, self).delete_subnet(context, id)
            return self._delete_nuage_sharedresource(id)

        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session, id)
        if subnet_l2dom:
            LOG.debug("Found l2domain mapping for subnet %s", id)
            try:
                self.nuageclient.delete_subnet(id)
            except Exception:
                msg = (_('Unable to complete operation on subnet %s.'
                         'One or more ports have an IP allocation '
                         'from this subnet.') % id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)
        super(NuagePlugin, self).delete_subnet(context, id)

        if subnet_l2dom:
            if subnet_l2dom['nuage_managed_subnet']:
                self.nuageclient.detach_nuage_group_to_nuagenet(
                    context.tenant, subnet_l2dom['net_partition_id'],
                    subnet_l2dom['nuage_subnet_id'], subnet['shared'])

            if not self._check_router_subnet_for_tenant(
                context, subnet['tenant_id']):
                LOG.debug("No router/subnet found for tenant %s", subnet[
                    'tenant_id'])
                self.nuageclient.delete_user(subnet_l2dom['nuage_user_id'])
                self.nuageclient.delete_group(subnet_l2dom['nuage_group_id'])

    @handle_nuage_api_error
    @log.log
    def add_router_interface(self, context, router_id, interface_info):
        session = context.session
        with session.begin(subtransactions=True):
            rtr_if_info = super(NuagePlugin,
                                self).add_router_interface(context,
                                                           router_id,
                                                           interface_info)
            subnet_id = rtr_if_info['subnet_id']
            subn = self.get_subnet(context, subnet_id)
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                                   router_id)
            nuage_zone = self.nuageclient.get_zone_by_routerid(router_id,
                                                               subn['shared'])
            if not nuage_zone or not ent_rtr_mapping:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Router %s does not hold default zone OR "
                         "domain in VSD. Router-IF add failed")
                       % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                          subnet_id)
            if not subnet_l2dom:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %s does not hold Nuage VSD reference. "
                         "Router-IF add failed") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            if subnet_l2dom['nuage_managed_subnet']:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = ("Subnet %s is a VSD-Managed subnet."
                       "Router-IF add failed" % rtr_if_info['subnet_id'])
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            if (subnet_l2dom['net_partition_id'] !=
                ent_rtr_mapping['net_partition_id']):
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %(subnet)s and Router %(router)s belong to "
                         "different net_partition Router-IF add "
                         "not permitted") % {'subnet': subnet_id,
                                             'router': router_id})
                raise n_exc.BadRequest(resource='subnet', msg=msg)
            nuage_subnet_id = subnet_l2dom['nuage_subnet_id']
            if self.nuageclient.vms_on_l2domain(nuage_subnet_id):
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %s has one or more active VMs "
                       "Router-IF add not permitted") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            nuage_rtr_id = ent_rtr_mapping['nuage_router_id']
            if self.nuageclient.validate_create_domain_subnet(
                subn, nuage_subnet_id, nuage_rtr_id):
                self.nuageclient.delete_subnet(subnet_id)
                LOG.debug("Deleted l2 domain %s", nuage_subnet_id)

            filters = {
                'fixed_ips': {'subnet_id': [subnet_id]},
                'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
            }
            gw_ports = self.get_ports(context, filters=filters)
            self._delete_port_gateway(context, gw_ports)
            net = netaddr.IPNetwork(subn['cidr'])
            pnet_binding = nuagedb.get_network_binding(context.session,
                                                       subn['network_id'])
            params = {
                'net': net,
                'zone_id': nuage_zone['nuage_zone_id'],
                'neutron_subnet_id': subnet_id,
                'pnet_binding': pnet_binding
            }
            if not attributes.is_attr_set(subn['gateway_ip']):
                subn['gateway_ip'] = str(netaddr.IPAddress(net.first + 1))

            try:
                nuage_subnet = self.nuageclient.create_domain_subnet(subn,
                                                                   params)
            except Exception:
                with excutils.save_and_reraise_exception():
                    super(NuagePlugin,
                          self).remove_router_interface(context,
                                                        router_id,
                                                        interface_info)

            if nuage_subnet:
                LOG.debug("Created nuage domain %s",
                          nuage_subnet['nuage_subnetid'])
                ns_dict = {}
                ns_dict['nuage_subnet_id'] = nuage_subnet['nuage_subnetid']
                ns_dict['nuage_l2dom_tmplt_id'] = None
                nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                                   ns_dict)

        return rtr_if_info

    @handle_nuage_api_error
    @log.log
    def remove_router_interface(self, context, router_id, interface_info):
        if 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
            found = False
            try:
                filters = {'device_id': [router_id],
                           'device_owner':
                           [os_constants.DEVICE_OWNER_ROUTER_INTF],
                           'network_id': [subnet['network_id']]}
                ports = self.get_ports(context, filters)

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
            port_db = self._get_port(context, interface_info['port_id'])
            if not port_db:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
            subnet_id = port_db['fixed_ips'][0]['subnet_id']

        session = context.session
        with session.begin(subtransactions=True):
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                          subnet_id)
            if not subnet_l2dom:
                return super(NuagePlugin,
                             self).remove_router_interface(context,
                                                           router_id,
                                                           interface_info)
            nuage_subn_id = subnet_l2dom['nuage_subnet_id']
            if self.nuageclient.vms_on_subnet(nuage_subn_id):
                msg = (_("Subnet %s has one or more active VMs "
                         "Router-IF delete not permitted") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            neutron_subnet = self.get_subnet(context, subnet_id)
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                context.session,
                router_id)
            if not ent_rtr_mapping:
                msg = (_("Router %s does not hold net_partition "
                         "assoc on Nuage VSD. Router-IF delete failed")
                       % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            last_address = neutron_subnet['allocation_pools'][-1]['end']
            gw_port = self._create_port_gateway(context, neutron_subnet,
                                                last_address)
            net = netaddr.IPNetwork(neutron_subnet['cidr'])
            netpart_id = ent_rtr_mapping['net_partition_id']
            pnet_binding = nuagedb.get_network_binding(
                context.session, neutron_subnet['network_id'])

            neutron_net = self.get_network(context,
                                           neutron_subnet['network_id'])

            params = {
                'tenant_id': neutron_subnet['tenant_id'],
                'net': net,
                'netpart_id': netpart_id,
                'nuage_subn_id': nuage_subn_id,
                'neutron_subnet': neutron_subnet,
                'pnet_binding': pnet_binding,
                'dhcp_ip': gw_port['fixed_ips'][0]['ip_address'],
                'neutron_router_id': router_id,
                'shared': neutron_net['shared']
            }
            nuage_subnet = self.nuageclient.remove_router_interface(params)
            LOG.debug("Deleted nuage domain subnet %s", nuage_subn_id)
            info = super(NuagePlugin,
                         self).remove_router_interface(context, router_id,
                                                       interface_info)

            if nuage_subnet:
                tmplt_id = str(nuage_subnet['nuage_l2template_id'])
                ns_dict = {}
                ns_dict['nuage_subnet_id'] = nuage_subnet['nuage_l2domain_id']
                ns_dict['nuage_l2dom_tmplt_id'] = tmplt_id
                nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                                   ns_dict)
        return info

    @log.log
    def _get_net_partition_for_router(self, context, rtr):
        ent = rtr.get('net_partition', None)
        if not ent:
            def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
            net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                              def_net_part)
        else:
            net_partition = self._resource_finder(context, 'router',
                                                  'net_partition', rtr)
        if not net_partition:
            msg = _("Either net_partition is not provided with router OR "
                    "default net_partition is not created at the start")
            raise n_exc.BadRequest(resource='router', msg=msg)
        return net_partition

    @handle_nuage_api_error
    @log.log
    def get_router(self, context, id, fields=None):
        router = super(NuagePlugin, self).get_router(context, id, fields)
        nuage_router = self.nuageclient.get_router_by_external(id)
        if nuage_router:
            if not fields or 'tunnel_type' in fields:
                router['tunnel_type'] = nuage_router['tunnelType']
            if not fields or 'rd' in fields:
                router['rd'] = nuage_router['routeDistinguisher']
            if not fields or 'rt' in fields:
                router['rt'] = nuage_router['routeTarget']
        return router

    @handle_nuage_api_error
    @log.log
    def create_router(self, context, router):
        req_router = copy.deepcopy(router['router'])
        net_partition = self._get_net_partition_for_router(context,
                                                           router['router'])
        if (cfg.CONF.RESTPROXY.nuage_pat == 'notavailable' and
            req_router.get('external_gateway_info')):
            msg = _("nuage_pat config is set to 'notavailable'. "
                    "Can't set ext-gw-info")
            raise nuage_exc.OperationNotSupported(resource='router', msg=msg)

        neutron_router = super(NuagePlugin, self).create_router(context,
                                                                router)
        params = {
            'net_partition': net_partition,
            'tenant_id': neutron_router['tenant_id'],
            'nuage_pat': cfg.CONF.RESTPROXY.nuage_pat
        }
        try:
            nuage_router = self.nuageclient.create_router(neutron_router,
                                                          req_router,
                                                          params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin, self).delete_router(context,
                                                       neutron_router['id'])

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

        return neutron_router

    @log.log
    def _validate_nuage_staticroutes(self, old_routes, added, removed):
        cidrs = []
        for old in old_routes:
            if old not in removed:
                ip = netaddr.IPNetwork(old['destination'])
                cidrs.append(ip)
        for route in added:
            ip = netaddr.IPNetwork(route['destination'])
            matching = netaddr.all_matching_cidrs(ip.ip, cidrs)
            if matching:
                msg = _('for same subnet, multiple static routes not allowed')
                raise n_exc.BadRequest(resource='router', msg=msg)
            cidrs.append(ip)

    @handle_nuage_api_error
    @log.log
    def update_router(self, context, id, router):
        r = router['router']
        if (cfg.CONF.RESTPROXY.nuage_pat == 'notavailable' and
            r.get('external_gateway_info')):
            msg = _("nuage_pat config is set to 'notavailable'. "
                    "Can't update ext-gw-info")
            raise nuage_exc.OperationNotSupported(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            if 'routes' in r:
                old_routes = self._get_extra_routes_by_router_id(context,
                                                                 id)
                added, removed = utils.diff_list_of_dict(old_routes,
                                                         r['routes'])
                self._validate_nuage_staticroutes(old_routes, added, removed)

                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                    context.session, id)
                if not ent_rtr_mapping:
                    msg = (_("Router %s does not hold net-partition "
                             "assoc on VSD. extra-route failed") % id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                # Let it do internal checks first and verify it.
                router_updated = super(NuagePlugin,
                                       self).update_router(context,
                                                           id,
                                                           router)
                for route in removed:
                    destaddr = route['destination']
                    cidr = destaddr.split('/')
                    params = {
                        "address": cidr[0],
                        "nexthop": route['nexthop'],
                        "nuage_domain_id": ent_rtr_mapping['nuage_router_id']
                    }
                    self.nuageclient.delete_nuage_staticroute(params)

                for route in added:
                    params = {
                        'parent_id': ent_rtr_mapping['nuage_router_id'],
                        'net': netaddr.IPNetwork(route['destination']),
                        'nexthop': route['nexthop']
                    }
                    self.nuageclient.create_nuage_staticroute(
                        params)
                return router_updated
            elif 'external_gateway_info' in r:
                curr_router = self.get_router(context, id)
                router_updated = super(NuagePlugin, self).update_router(
                    context, id, router)
                curr_ext_gw_info = curr_router['external_gateway_info']
                new_ext_gw_info = router_updated['external_gateway_info']
                send_update = False
                if curr_ext_gw_info and not new_ext_gw_info:
                    if curr_ext_gw_info['enable_snat']:
                        send_update = True
                elif not curr_ext_gw_info and new_ext_gw_info:
                    if new_ext_gw_info['enable_snat']:
                        send_update = True
                elif (curr_ext_gw_info and
                      new_ext_gw_info and
                      curr_ext_gw_info['enable_snat'] !=
                      new_ext_gw_info['enable_snat']):
                    send_update = True
                if send_update:
                    self.nuageclient.update_router_gw(
                        router_updated, params={
                        'nuage_pat': cfg.CONF.RESTPROXY.nuage_pat})
            else:
                neutron_router = None
                if ('rd' in r.keys() and r['rd'] or
                        'rt' in r.keys() and r['rt']):
                    neutron_router = self.get_router(context, id)
                    net_partition = self._get_net_partition_for_router(
                        context, router)

                    params = {
                        'net_partition': net_partition,
                        'tenant_id': neutron_router['tenant_id']
                    }

                    ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                        context.session, id)
                    if (ent_rtr_mapping and
                            (neutron_router['rd'] != r['rd'] or
                             neutron_router['rt'] != r['rt'])):
                        nuage_domain_id = ent_rtr_mapping['nuage_router_id']
                        self.nuageclient.update_router_rt_rd(neutron_router,
                                                             router['router'],
                                                             nuage_domain_id,
                                                             params)
                        ns_dict = {}
                        ns_dict['nuage_rtr_rt'] = r['rt']
                        ns_dict['nuage_rtr_rd'] = r['rd']
                        nuagedb.update_entrouter_mapping(ent_rtr_mapping,
                                                         ns_dict)
                if r.get('tunnel_type'):
                    if not neutron_router:
                        neutron_router = self.get_router(context, id)
                    if neutron_router['tunnel_type'] != r['tunnel_type']:
                        net_partition = self._get_net_partition_for_router(
                            context, router)
                        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                            context.session, id)

                        nuage_domain_id = ent_rtr_mapping['nuage_router_id']
                        self.nuageclient.update_router_tunnel_type(
                            neutron_router, router['router'], net_partition,
                            nuage_domain_id)

                router_updated = super(NuagePlugin, self).update_router(
                    context, id, router)
        return router_updated

    @handle_nuage_api_error
    @log.log
    def delete_router(self, context, id):
        neutron_router = self.get_router(context, id)
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                               id)
        if ent_rtr_mapping:
            LOG.debug("Enterprise to router mapping found for router %s", id)
            filters = {
                'device_id': [id],
                'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
            }
            ports = self.get_ports(context, filters)
            if ports:
                raise l3.RouterInUse(router_id=id)
            nuage_domain_id = ent_rtr_mapping['nuage_router_id']
            self.nuageclient.delete_router(nuage_domain_id)

        super(NuagePlugin, self).delete_router(context, id)

        if not self._check_router_subnet_for_tenant(
                context, neutron_router['tenant_id']):
            LOG.debug("No router/subnet found for tenant %s",
                      neutron_router['tenant_id'])
            user_id, group_id = self.nuageclient.get_usergroup(
                neutron_router['tenant_id'],
                ent_rtr_mapping['net_partition_id'])
            self.nuageclient.delete_user(user_id)
            self.nuageclient.delete_group(group_id)

    @log.log
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

    @log.log
    def _create_net_partition(self, session, net_part_name):
        params = {
            "name": net_part_name,
            "fp_quota": str(cfg.CONF.RESTPROXY.default_floatingip_quota)
        }
        nuage_net_partition = self.nuageclient.create_net_partition(params)
        net_partitioninst = None
        if nuage_net_partition:
            with session.begin(subtransactions=True):
                net_partitioninst = NuagePlugin._add_net_partition(
                    session,
                    nuage_net_partition,
                    net_part_name)
        if not net_partitioninst:
            return {}
        return self._make_net_partition_dict(net_partitioninst)

    @log.log
    def _validate_create_net_partition(self,
                                       net_part_name,
                                       session=db.get_session()):
        nuage_netpart = self.nuageclient.get_netpartition_data(
            net_part_name)
        netpart_db = nuagedb.get_net_partition_by_name(session, net_part_name)

        if nuage_netpart:
            with session.begin(subtransactions=True):
                if netpart_db:
                    # Net-partition exists in neutron and vsd
                    def_netpart = (
                        cfg.CONF.RESTPROXY.default_net_partition_name)
                    if def_netpart == net_part_name:
                        if nuage_netpart['np_id'] != netpart_db['id']:
                            msg = ("Default net-partition %s exists in "
                                   "Neutron and VSD, but the id is different"
                                   % net_part_name)
                            raise n_exc.BadRequest(resource='net_partition',
                                                   msg=msg)
                        LOG.info("Default net-partition %s already exists,"
                                 " so will just use it" % net_part_name)
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
                netpart_db = NuagePlugin._add_net_partition(session,
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
    @log.log
    def _add_net_partition(session, netpart, netpart_name):
        l3dom_id = netpart['l3dom_tid']
        l3isolated = constants.DEF_NUAGE_ZONE_PREFIX + '-' + l3dom_id
        l3shared = constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' + l3dom_id
        return nuagedb.add_net_partition(session,
                                         netpart['np_id'],
                                         l3dom_id,
                                         netpart['l2dom_tid'],
                                         netpart_name,
                                         l3isolated,
                                         l3shared)

    @log.log
    def _link_default_netpartition(self, netpart_name,
                                   l2template, l3template,
                                   l3isolated, l3shared):
        params = {
            'name': netpart_name,
            'l3template': l3template,
            'l2template': l2template
        }
        (np_id, l3dom_tid,
         l2dom_tid) = self.nuageclient.link_default_netpartition(params)
        #verify that the provided zones have been created already
        shared_match, isolated_match = self.nuageclient.validate_zone_create(
            l3dom_tid, l3isolated, l3shared)
        if not shared_match or not isolated_match:
            msg = ('Default zone names must be provided for '
                   'default net-partiton')
            raise n_exc.BadRequest(resource='net_partition', msg=msg)

        # basic verifications passed. add default netpartition to the DB
        session = db.get_session()
        netpartition = nuagedb.get_net_partition_by_name(session,
                                                         netpart_name)

        with session.begin():
            if netpartition:
                nuagedb.delete_net_partition(session, netpartition)
            net_partitioninst = nuagedb.add_net_partition(session,
                                                          np_id,
                                                          l3dom_tid,
                                                          l2dom_tid,
                                                          netpart_name,
                                                          l3isolated,
                                                          l3shared)
        return net_partitioninst

    @log.log
    def _prepare_default_netpartition(self):
        netpart_name = cfg.CONF.RESTPROXY.default_net_partition_name
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
        else:
            return self._validate_create_net_partition(netpart_name)

        '''NetPartition and templates already created. Just sync the
        neutron DB. They must all be in VSD. If not, its an error
        '''
        return self._link_default_netpartition(netpart_name,
                                               l2template,
                                               l3template,
                                               l3isolated,
                                               l3shared)

    @handle_nuage_api_error
    @log.log
    def create_net_partition(self, context, net_partition):
        ent = net_partition['net_partition']
        return self._validate_create_net_partition(ent["name"], context.session)

    @handle_nuage_api_error
    @log.log
    def delete_net_partition(self, context, id):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_entid(
            context.session, id)
        if ent_rtr_mapping:
            msg = (_("One or more router still attached to "
                     "net_partition %s.") % id)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)
        net_partition = nuagedb.get_net_partition_by_id(context.session, id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        l3dom_tmplt_id = net_partition['l3dom_tmplt_id']
        l2dom_tmplt_id = net_partition['l2dom_tmplt_id']
        self.nuageclient.delete_net_partition(net_partition['id'],
                                              l3dom_id=l3dom_tmplt_id,
                                              l2dom_id=l2dom_tmplt_id)
        with context.session.begin(subtransactions=True):
            nuagedb.delete_net_partition(context.session,
                                         net_partition)

    @log.log
    def get_net_partition(self, context, id, fields=None):
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        return self._make_net_partition_dict(net_partition, context=context)

    @log.log
    def get_net_partitions(self, context, filters=None, fields=None):
        net_partitions = nuagedb.get_net_partitions(context.session,
                                                    filters=filters,
                                                    fields=fields)
        return [self._make_net_partition_dict(net_partition, context, fields)
                for net_partition in net_partitions]

    @log.log
    def _check_floatingip_update(self, context, port):
        filter = {'fixed_port_id': [port['id']]}
        local_fip = self.get_floatingips(context,
                                         filters=filter)
        if local_fip:
            fip = local_fip[0]
            self._create_update_floatingip(context,
                                           fip, port['id'])

    @log.log
    def _create_update_floatingip(self, context,
                                  neutron_fip, port_id,
                                  last_known_router_id=None):
        if last_known_router_id:
            rtr_id = last_known_router_id
        else:
            rtr_id = neutron_fip['router_id']
        net_id = neutron_fip['floating_network_id']
        subn = nuagedb.get_ipalloc_for_fip(context.session,
                                           net_id,
                                           neutron_fip['floating_ip_address'])

        fip_pool = self.nuageclient.get_nuage_fip_pool_by_id(subn['subnet_id'])
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

        fip = self.nuageclient.get_nuage_fip_by_id(params)
        if not fip:
            LOG.debug("Floating ip not found in VSD for fip %s",
                      neutron_fip['id'])
            params = {
                'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
                'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
                'neutron_fip_ip': neutron_fip['floating_ip_address'],
                'neutron_fip_id': neutron_fip['id']
            }
            nuage_fip_id = self.nuageclient.create_nuage_floatingip(params)
        else:
            nuage_fip_id = fip['nuage_fip_id']

        # Update VM if required
        params = {
            'neutron_port_id': port_id,
            'nuage_fip_id': nuage_fip_id,
            'nuage_rtr_id': ent_rtr_mapping['nuage_router_id']
        }
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)
        if nuage_port:
            if (nuage_port['nuage_domain_id']) != (
                    ent_rtr_mapping['nuage_router_id']):
                msg = _('Floating IP can not be associated to VM in '
                        'different router context')
                raise nuage_exc.OperationNotSupported(msg=msg)

            params = {
                'nuage_vport_id': nuage_port['nuage_vport_id'],
                'nuage_fip_id': nuage_fip_id
            }
            self.nuageclient.update_nuage_vm_vport(params)

    @handle_nuage_api_error
    @log.log
    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            neutron_fip = super(NuagePlugin, self).create_floatingip(
                context, floatingip)
            if not neutron_fip['router_id']:
                return neutron_fip
            try:
                self._create_update_floatingip(context, neutron_fip,
                                               fip['port_id'])
            except (nuage_exc.OperationNotSupported, n_exc.BadRequest):
                with excutils.save_and_reraise_exception():
                    super(NuagePlugin, self).delete_floatingip(
                        context, neutron_fip['id'])
            return neutron_fip

    @handle_nuage_api_error
    @log.log
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(NuagePlugin, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)

        params = {
            'neutron_port_id': port_id,
        }
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)
        if nuage_port:
            params = {
                'nuage_vport_id': nuage_port['nuage_vport_id'],
                'nuage_fip_id': None
            }
            self.nuageclient.update_nuage_vm_vport(params)
            LOG.debug("Disassociated floating ip from VM attached at port %s",
                      port_id)

        return router_ids

    @handle_nuage_api_error
    @log.log
    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        orig_fip = self._get_floatingip(context, id)
        port_id = orig_fip['fixed_port_id']
        last_known_router_id = orig_fip['last_known_router_id']
        router_ids = []
        with context.session.begin(subtransactions=True):
            neutron_fip = super(NuagePlugin, self).update_floatingip(
                context, id, floatingip)
            if fip['port_id'] is not None:
                if not neutron_fip['router_id']:
                    ret_msg = 'floating-ip is not associated yet'
                    raise n_exc.BadRequest(resource='floatingip',
                                           msg=ret_msg)

                try:
                    self._create_update_floatingip(context,
                                                   neutron_fip,
                                                   fip['port_id'],
                                                   last_known_router_id)
                except nuage_exc.OperationNotSupported:
                    with excutils.save_and_reraise_exception():
                        router_ids = super(
                            NuagePlugin, self).disassociate_floatingips(
                                context, fip['port_id'], do_notify=False)
                except n_exc.BadRequest:
                    with excutils.save_and_reraise_exception():
                        super(NuagePlugin, self).delete_floatingip(
                            context, id)
            else:
                params = {
                    'neutron_port_id': port_id,
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if nuage_port:
                    params = {
                        'nuage_vport_id': nuage_port['nuage_vport_id'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(params)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)

        return neutron_fip

    @handle_nuage_api_error
    @log.log
    def delete_floatingip(self, context, fip_id):
        fip = self._get_floatingip(context, fip_id)
        port_id = fip['fixed_port_id']
        with context.session.begin(subtransactions=True):
            if port_id:
                params = {
                    'neutron_port_id': port_id,
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if (nuage_port and
                    nuage_port['nuage_vport_id'] is not None):
                    params = {
                        'nuage_vport_id': nuage_port['nuage_vport_id'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(params)
                    LOG.debug("Floating-ip %(fip)s is disassociated from "
                              "vport %(vport)s",
                              {'fip': fip_id,
                               'vport': nuage_port['nuage_vport_id']})

                router_id = fip['router_id']
            else:
                router_id = fip['last_known_router_id']

            if router_id:
                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                    context.session,
                    router_id)
                if not ent_rtr_mapping:
                    msg = _('router %s is not associated with '
                            'any net-partition') % router_id
                    raise n_exc.BadRequest(resource='floatingip',
                                       msg=msg)
                params = {
                    'router_id': ent_rtr_mapping['nuage_router_id'],
                    'fip_id': fip_id
                }
                fip = self.nuageclient.get_nuage_fip_by_id(params)
                if fip:
                    self.nuageclient.delete_nuage_floatingip(
                        fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

            super(NuagePlugin, self).delete_floatingip(context, fip_id)

    @handle_nuage_api_error
    @log.log
    def delete_security_group(self, context, id):
        filters = {'security_group_id': [id]}
        ports = self._get_port_security_group_bindings(context,
                                                       filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        sg_rules = self.get_security_group_rules(context,
                                                 {'security_group_id': [id]})

        if sg_rules:
            self.nuageclient.delete_nuage_sgrule(sg_rules)
        self.nuageclient.delete_nuage_secgroup(id)
        LOG.debug("Deleted security group %s", id)

        super(NuagePlugin, self).delete_security_group(context, id)

    @handle_nuage_api_error
    @log.log
    def create_security_group_rule(self, context, security_group_rule):
        sg_rule = security_group_rule['security_group_rule']
        self.nuageclient.validate_nuage_sg_rule_definition(sg_rule)
        sg_id = sg_rule['security_group_id']

        local_sg_rule = super(NuagePlugin,
                              self).create_security_group_rule(
                                        context, security_group_rule)

        try:
            nuage_vptag = self.nuageclient.get_sg_vptag_mapping(sg_id)
            if nuage_vptag:
                sg_params = {
                    'sg_id': sg_id,
                    'neutron_sg_rule': local_sg_rule,
                    'vptag': nuage_vptag
                }
                self.nuageclient.create_nuage_sgrule(sg_params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin,
                      self).delete_security_group_rule(context,
                                                   local_sg_rule['id'])

        return local_sg_rule

    @handle_nuage_api_error
    @log.log
    def delete_security_group_rule(self, context, id):
        local_sg_rule = self.get_security_group_rule(context, id)
        super(NuagePlugin, self).delete_security_group_rule(context, id)
        self.nuageclient.delete_nuage_sgrule([local_sg_rule])
        LOG.debug("Deleted security group rule %s", id)

