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

import contextlib
import copy
import functools
from logging import handlers

import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_log.formatters import ContextFormatter
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import excutils
from sqlalchemy import exc as sql_exc
from sqlalchemy import func
from sqlalchemy.orm import exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions as cb_exc
from neutron.callbacks import registry
from neutron.common import constants as os_constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db_common as ps_db_common
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from nuage_neutron.plugins.common import addresspair
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import extensions as common_extensions
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import port_dhcp_options
from nuage_neutron.plugins.common.service_plugins import resources
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.plugins.nuage import extensions
from nuage_neutron.plugins.nuage.extensions import nuage_router
from nuage_neutron.plugins.nuage import externalsg
from nuage_neutron.plugins.nuage import gateway
from nuagenetlib.restproxy import ResourceNotFoundException
from nuagenetlib.restproxy import RESTProxyError

LOG = logging.getLogger(__name__)


class NuagePlugin(port_dhcp_options.PortDHCPOptionsNuage,
                  addresspair.NuageAddressPair,
                  db_base_plugin_v2.NeutronDbPluginV2,
                  addr_pair_db.AllowedAddressPairsMixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  gateway.NuagegatewayMixin,
                  externalsg.NuageexternalsgMixin,
                  sg_db.SecurityGroupDbMixin,
                  portbindings_db.PortBindingMixin,
                  ps_db_common.PortSecurityDbCommon,
                  extradhcpopt_db.ExtraDhcpOptMixin):
    """Class that implements Nuage Networks' hybrid plugin functionality."""
    vendor_extensions = ["net-partition", "nuage-router", "nuage-subnet",
                         "ext-gw-mode", "nuage-floatingip", "nuage-gateway",
                         "vsd-resource", "allowed-address-pairs",
                         "nuage-external-security-group", "extra_dhcp_opt",
                         "port-security"]

    supported_extension_aliases = ["router", "binding", "external-net",
                                   "quotas", "provider", "extraroute",
                                   "security-group"] + vendor_extensions

    binding_view = "extension:port_binding:view"

    def __init__(self):
        super(NuagePlugin, self).__init__()
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        neutron_extensions.append_api_extensions_path(
            common_extensions.__path__)
        self._prepare_default_netpartition()
        self.init_fip_rate_log()
        LOG.debug("NuagePlugin initialization done")
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL,
            portbindings.VIF_DETAILS: {
                portbindings.CAP_PORT_FILTER: False
            }
        }

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_provider_nuage'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_port_security_dict'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_extend_port_security_dict'])

    def _extend_port_security_dict(self, response_data, db_data):
        if ('port-security' in getattr(
                self, 'supported_extension_aliases', [])):
            if db_data and db_data['port_security']:
                psec_value = db_data['port_security'][psec.PORTSECURITY]
                if psec_value:
                    response_data[psec.PORTSECURITY] = psec_value
                else:
                    response_data[psec.PORTSECURITY] = False

    def init_fip_rate_log(self):
        self.def_fip_rate = cfg.CONF.FIPRATE.default_fip_rate
        if self.def_fip_rate < -1:
            raise cfg.ConfigFileValueError(_('default_fip_rate can not be < '
                                             '-1'))
        if self.def_fip_rate > constants.MAX_VSD_INTEGER:
            raise cfg.ConfigFileValueError(_('default_fip_rate can not be > '
                                             '%s') % constants.MAX_VSD_INTEGER)

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

    @log_helpers.log_method_call
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

    @staticmethod
    @log_helpers.log_method_call
    def _validate_create_nuage_vport(session, ports, np_name, cur_port_id):
        for port in ports:
            if port['id'] != cur_port_id:
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                    session, subnet_id)
                if subnet_mapping:
                    net_partition = nuagedb.get_net_partition_by_id(
                        session, subnet_mapping['net_partition_id'])
                    if net_partition['name'] != np_name:
                        msg = ("VM with ports belonging to subnets across "
                               "enterprises is not allowed in VSP")
                        raise nuage_exc.NuageBadRequest(msg=msg)

    def _resolve_tenant_for_shared_network(self, context, port,
                                           net_partition_id):
        network_details = self.get_network(context, port['network_id'])
        if network_details['shared']:
            self.nuageclient.create_usergroup(
                port['tenant_id'],
                net_partition_id)

    @log_helpers.log_method_call
    def _create_update_port(self, context, port, np_name, subnet_mapping,
                            vsd_subnet):
        # Set the description to owner:compute for ports created by nova,
        # so that, vports created for these ports can be deleted on nova vm
        # delete
        vport_desc = ("device_owner:" + constants.NOVA_PORT_OWNER_PREF +
                      "(please donot edit)")
        self._validate_vmports_same_netpartition(
            self, context, port, subnet_mapping['net_partition_id'])
        self._resolve_tenant_for_shared_network(
            context, port, subnet_mapping['net_partition_id'])
        nuage_vport = self._create_nuage_vport(port, vsd_subnet,
                                               description=vport_desc)
        self._update_nuage_port(context, port, np_name, subnet_mapping,
                                nuage_vport, vsd_subnet)
        return nuage_vport

    @log_helpers.log_method_call
    def _update_nuage_port(self, context, port, np_name,
                           subnet_mapping, nuage_port, vsd_subnet):
        filters = {'device_id': [port.get('device_id')]}
        ports = self.get_ports(context, filters)
        no_of_ports = len(ports)
        subn = self.get_subnet(context, port['fixed_ips'][0]['subnet_id'])
        vm_id = port['device_id']
        # upstream neutron_lbaas assigns a constant device_id to all the
        # lbaas_ports (which is a bug), hence we use port ID as vm_id
        # instead of device_id for lbaas dummy VM
        # as get_ports by device_id would return multiple vip_ports,
        # as workaround set no_of_ports = 1
        if (port.get('device_owner') == os_constants.DEVICE_OWNER_LOADBALANCER
                + 'V2'):
            vm_id = port['id']
            no_of_ports = 1

        if no_of_ports > 1:
            self._validate_create_nuage_vport(context.session, ports, np_name,
                                              port['id'])
        params = {
            'port_id': port['id'],
            'id': vm_id,
            'mac': port['mac_address'],
            'netpart_name': np_name,
            'ip': port['fixed_ips'][0]['ip_address'],
            'no_of_ports': no_of_ports,
            'tenant': port['tenant_id'],
            'netpart_id': subnet_mapping['net_partition_id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id'],
            'vport_id': nuage_port.get('ID'),
            'subn_tenant': subn['tenant_id'],
            'portOnSharedSubn': subn['shared'],
            'address_spoof': (constants.INHERITED
                              if port[psec.PORTSECURITY]
                              else constants.ENABLED),
            'vsd_subnet': vsd_subnet,
            'dhcp_enabled': subn['enable_dhcp']
        }
        self._resolve_tenant_for_shared_network(
            context, port, subnet_mapping['net_partition_id'])
        self.nuageclient.create_vms(params)

    @log_helpers.log_method_call
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

    def _process_port_create_secgrp_for_port_sec(self, context, port):
        l2dom_id = None
        l3dom_id = None
        rtr_id = None
        policygroup_ids = []
        port_id = port['id']

        if not port.get('fixed_ips'):
            return self._make_port_dict(port)

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, port['fixed_ips'][0]['subnet_id'])

        if subnet_mapping:
            if subnet_mapping['nuage_l2dom_tmplt_id']:
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3dom_id = subnet_mapping['nuage_subnet_id']
                rtr_id = (self.nuageclient.
                          get_nuage_domain_id_from_subnet(l3dom_id))

            params = {
                'neutron_port_id': port_id,
                'l2dom_id': l2dom_id,
                'l3dom_id': l3dom_id,
                'rtr_id': rtr_id,
                'type': constants.VM_VPORT,
                'sg_type': constants.SOFTWARE
            }
            nuage_port = self.nuageclient.get_nuage_vport_for_port_sec(params)
            if nuage_port:
                nuage_vport_id = nuage_port.get('ID')
                if port[psec.PORTSECURITY]:
                    self.nuageclient.update_vport_policygroups(
                        nuage_vport_id, policygroup_ids)
                else:
                    sg_id = (self.nuageclient.
                             create_nuage_sec_grp_for_port_sec(params))
                    if sg_id:
                        params['sg_id'] = sg_id
                        (self.nuageclient.
                         create_nuage_sec_grp_rule_for_port_sec(params))
                        policygroup_ids.append(sg_id)
                        self.nuageclient.update_vport_policygroups(
                            nuage_vport_id, policygroup_ids)

    @log_helpers.log_method_call
    def _process_port_create_security_group(self, context, port, vport, sg_ids,
                                            vsd_subnet):
        if len(sg_ids) > 6:
            msg = (_("Exceeds maximum num of security groups on a port "
                     "supported on nuage VSP"))
            raise nuage_exc.NuageBadRequest(msg=msg)
        super(NuagePlugin,
              self)._process_port_create_security_group(context, port, sg_ids)

        if not port.get('fixed_ips'):
            return
        policygroup_ids = []
        for sg_id in sg_ids:
            sg = self._get_security_group(context, sg_id)
            sg_rules = self.get_security_group_rules(
                context,
                {'security_group_id': [sg_id]})
            sg_params = {
                'vsd_subnet': vsd_subnet,
                'sg': sg,
                'sg_rules': sg_rules
            }
            vsd_policygroup_id = (
                self.nuageclient.process_port_create_security_group(
                    sg_params))
            policygroup_ids.append(vsd_policygroup_id)

        self.nuageclient.update_vport_policygroups(vport['ID'],
                                                   policygroup_ids)

    def get_port(self, context, id, fields=None):
        port = super(NuagePlugin, self).get_port(context, id, fields=None)
        self.extend_port_dict(context, port, fields=fields)
        return self._fields(port, fields)

    def extend_port_dict(self, context, port, vport=None, fields=None):
        if vport is None:
            vport = self._get_vport_for_port(context, port)
        if vport:
            self.nuage_callbacks.notify(resources.PORT, constants.AFTER_SHOW,
                                        self, context=context, port=port,
                                        fields=fields, vport=vport)

    def _portsec_ext_port_create_processing(self, context, port_data, port):
        port_security = ((port_data.get(psec.PORTSECURITY) is None) or
                         port_data[psec.PORTSECURITY])

        # allowed address pair checks
        if self._check_update_has_allowed_address_pairs(port):
            if not port_security:
                raise addr_pair.AddressPairAndPortSecurityRequired()

        if port_security:
            self._ensure_default_security_group_on_port(context, port)
        elif self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()

    def _determine_port_security(self, context, port):
        """Returns a boolean (port_security_enabled).

        Port_security is the value associated with the port if one is present
        otherwise the value associated with the network is returned.
        """
        if (port.get('device_owner') and
                port['device_owner'].startswith('network:')):
            return False

        if attributes.is_attr_set(port.get(psec.PORTSECURITY)):
            port_security_enabled = port[psec.PORTSECURITY]
        else:
            port_security_enabled = self._get_network_security_binding(
                context, port['network_id'])

        return port_security_enabled

    @nuage_utils.handle_nuage_api_error
    @oslo_db_api.wrap_db_retry(max_retries=db.MAX_RETRIES,
                               retry_on_request=True,
                               retry_on_deadlock=True)
    @log_helpers.log_method_call
    def create_port(self, context, port):
        session = context.session
        net_partition = None
        p_data = port['port']
        vport = None

        self.nuage_callbacks.notify(resources.PORT, constants.BEFORE_CREATE,
                                    self, context=context, request_port=p_data)

        with db.exc_to_retry(db_exc.DBDuplicateEntry),\
                session.begin(subtransactions=True):
            result = super(NuagePlugin, self).create_port(context, port)

            # Create the port extension attributes.
            p_data[psec.PORTSECURITY] = self._determine_port_security(
                context, p_data)
            self._process_port_port_security_create(context, p_data, result)
            self._portsec_ext_port_create_processing(context, result, port)
            self._process_portbindings_create_and_update(context, p_data,
                                                         result)
        device_owner = result.get('device_owner', None)
        if nuage_utils.check_vport_creation(
                device_owner, cfg.CONF.PLUGIN.device_owner_prefix):
            if 'fixed_ips' not in result or len(result['fixed_ips']) == 0:
                return self.get_port(context, result['id'])
            subnet_id = result['fixed_ips'][0]['subnet_id']
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                            subnet_id)
            port_prefix = constants.NOVA_PORT_OWNER_PREF
            if subnet_mapping:
                LOG.debug("Found subnet mapping for neutron subnet %s",
                          subnet_id)
                vsd_subnet = self.nuageclient \
                    .get_subnet_or_domain_subnet_by_id(
                        subnet_mapping['nuage_subnet_id'])

                if result['device_owner'].startswith(port_prefix):
                    # This request is coming from nova
                    try:
                        net_partition = nuagedb.get_net_partition_by_id(
                            session,
                            subnet_mapping['net_partition_id'])
                        vport = self._create_update_port(
                            context, result, net_partition['name'],
                            subnet_mapping, vsd_subnet)
                    except Exception:
                        with excutils.save_and_reraise_exception():
                            self._delete_nuage_vport(context, result,
                                                     net_partition['name'],
                                                     subnet_mapping,
                                                     port_delete=True)
                            super(NuagePlugin, self).delete_port(context,
                                                                 result['id'])
                else:
                    # This request is port-create no special ports
                    try:
                        net_partition = nuagedb.get_net_partition_by_id(
                            session,
                            subnet_mapping['net_partition_id'])
                        vport = self._create_nuage_vport(result, vsd_subnet)
                    except Exception:
                        with excutils.save_and_reraise_exception():
                            super(NuagePlugin, self).delete_port(context,
                                                                 result['id'])
                    try:
                        (super(NuagePlugin, self).
                            _process_port_create_extra_dhcp_opts(
                                context, result, p_data.get(
                                    'extra_dhcp_opts')))
                    except Exception:
                        with excutils.save_and_reraise_exception():
                            self._delete_nuage_vport(context, result,
                                                     net_partition['name'],
                                                     subnet_mapping,
                                                     port_delete=True)
                            super(NuagePlugin, self).delete_port(context,
                                                                 result['id'])
                try:
                    result[addr_pair.ADDRESS_PAIRS] = (
                        self._process_create_allowed_address_pairs(
                            context, result,
                            p_data.get(addr_pair.ADDRESS_PAIRS)))
                    if (subnet_mapping['nuage_managed_subnet'] is False and
                            ext_sg.SECURITYGROUPS in p_data):
                        self._process_port_create_security_group(
                            context,
                            result,
                            vport,
                            p_data[ext_sg.SECURITYGROUPS],
                            vsd_subnet)
                        LOG.debug("Created security group for port %s",
                                  result['id'])
                    if not p_data[psec.PORTSECURITY]:
                        self._process_port_create_secgrp_for_port_sec(
                            context, result)
                    if (subnet_mapping['nuage_managed_subnet'] and
                            ext_sg.SECURITYGROUPS in p_data):
                        LOG.warning(_("Security Groups is ignored for "
                                      "ports on VSD Managed Subnet"))
                except Exception:
                    with excutils.save_and_reraise_exception():
                        self._delete_nuage_vport(context, result,
                                                 net_partition['name'],
                                                 subnet_mapping,
                                                 port_delete=True)
                        super(NuagePlugin, self).delete_port(context,
                                                             result['id'])
            else:
                if result['device_owner'].startswith(port_prefix):
                    # VM is getting spawned on a subnet type which
                    # is not supported by VSD. LOG error.
                    LOG.error(_('VM with uuid %s will not be resolved '
                                'in VSD because its created on unsupported'
                                'subnet type'), result['device_id'])

        rollbacks = []
        try:
            self.nuage_callbacks.notify(
                resources.PORT, constants.AFTER_CREATE, self, context=context,
                port=result, request_port=p_data, vport=vport,
                rollbacks=rollbacks)
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])
                if vport:
                    self._delete_nuage_vport(context, result,
                                             net_partition['name'],
                                             subnet_mapping,
                                             port_delete=True)
                super(NuagePlugin, self).delete_port(context, result['id'])
        return result

    def _validate_update_port(self, port, original_port, has_security_groups):
        original_device_owner = original_port.get('device_owner')
        if has_security_groups and not nuage_utils.check_vport_creation(
                original_device_owner, cfg.CONF.PLUGIN.device_owner_prefix):
            msg = _("device_owner of port with device_owner set to %s "
                    "can not have security groups") % original_device_owner
            raise nuage_exc.OperationNotSupported(msg=msg)

        if (original_device_owner == constants.DEVICE_OWNER_VIP_NUAGE
                and 'device_owner' in port.keys()):
            msg = _("device_owner of port with device_owner set to %s "
                    "can not be modified") % original_device_owner
            raise nuage_exc.OperationNotSupported(msg=msg)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def _params_to_get_vport(self, port_id, subnet_mapping, current_owner):
        l2dom_id = None
        l3dom_id = None
        if subnet_mapping['nuage_managed_subnet']:
            # This is because we do not know if this advanced subn
            # is a domain-subn ot not. In both cases, the
            # nuage_subnet_id is the ID of the l2dom or domSubn.
            l2dom_id = subnet_mapping['nuage_subnet_id']
            l3dom_id = subnet_mapping['nuage_subnet_id']
        else:
            if subnet_mapping['nuage_l2dom_tmplt_id']:
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3dom_id = subnet_mapping['nuage_subnet_id']

        params = {
            'neutron_port_id': port_id,
            'l2dom_id': l2dom_id,
            'l3dom_id': l3dom_id
        }
        return params

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def _process_update_nuage_vport(self, context, port_id, updated_port,
                                    subnet_mapping, current_owner, vport,
                                    vsd_subnet):
        if vport:
            net_partition = nuagedb.get_net_partition_by_id(
                context.session, subnet_mapping['net_partition_id'])
            self._update_nuage_port(context, updated_port,
                                    net_partition['name'],
                                    subnet_mapping, vport, vsd_subnet)
            return vport
        else:
            # should not come here, log debug message
            LOG.debug("Nuage vport does not exist for port %s ", id)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def _process_update_port(self, context, p, original_port,
                             subnet_mapping, no_of_ports):
        current_owner = original_port['device_owner']

        if psec.PORTSECURITY in p:
            params = self._params_to_get_vport(
                original_port['id'], subnet_mapping, current_owner)
            nuage_port = self.nuageclient.get_nuage_vport_by_neutron_id(
                params)
            if nuage_port:
                # Only update the VSD flag if the vport exists
                current_spoof = (constants.DISABLED
                                 if p[psec.PORTSECURITY]
                                 else constants.ENABLED)
                self.nuageclient.update_mac_spoofing_on_vport(
                    nuage_port['ID'], current_spoof)
            else:
                # case where the user has deleted the vPort on VSD
                raise nuage_exc.NuageNotFound(
                    resource='port', resource_id=original_port['id'])

        device_id_removed = ('device_id' in p and
                             (not p.get('device_id')))
        nova_device_owner_removed = (
            'device_owner' in p and (not p.get('device_owner')) and
            current_owner.startswith(constants.NOVA_PORT_OWNER_PREF))
        lbaas_device_owner_removed = (
            'device_owner' in p and (not p.get('device_owner')) and
            current_owner == os_constants.DEVICE_OWNER_LOADBALANCER + 'V2')
        # upstream neutron lbaas assigns a constant device_id to the lbaas
        # VIP port even when the VIP belongs to different loadbalancer
        # as get_ports by device_id would return multiple vip_ports,
        # as workaround set no_of_ports = 1
        if lbaas_device_owner_removed:
            no_of_ports = 1

        if ((nova_device_owner_removed or lbaas_device_owner_removed) and
                device_id_removed):
            LOG.debug("nova:compute onwership removed for port %s ",
                      id)
            if subnet_mapping:
                net_partition = nuagedb.get_net_partition_by_id(
                    context.session,
                    subnet_mapping['net_partition_id'])
                # delete nuage_vm
                self._delete_nuage_vport(context, original_port,
                                         net_partition['name'],
                                         subnet_mapping, no_of_ports)

    def _portsec_ext_port_update_processing(self, updated_port,
                                            context, port, id):
        port_security = ((updated_port.get(psec.PORTSECURITY) is None) or
                         updated_port[psec.PORTSECURITY])

        if port_security:
            return

        # check the address-pairs
        if self._check_update_has_allowed_address_pairs(port):
            #  has address pairs in request
            raise addr_pair.AddressPairAndPortSecurityRequired()
        elif not self._check_update_deletes_allowed_address_pairs(port):
            # not a request for deleting the address-pairs
            updated_port[addr_pair.ADDRESS_PAIRS] = (
                self.get_allowed_address_pairs(context, id))

            # check if address pairs has been in db
            if updated_port[addr_pair.ADDRESS_PAIRS]:
                raise addr_pair.AddressPairAndPortSecurityRequired()

        # checks if security groups were updated adding/modifying
        # security groups, port security is set
        if self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()
        elif not self._check_update_deletes_security_groups(port):
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [id]}
            security_groups = self._get_port_security_group_bindings(
                context, filters)
            if security_groups:
                raise psec.PortSecurityPortHasSecurityGroup()

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def update_port(self, context, id, port):
        create_vm = False
        p_data = port['port']
        p_sec_update_reqd = False
        session = context.session
        original_port = super(NuagePlugin, self).get_port(context, id)
        vport = self._get_vport_for_port(context, original_port)
        self.extend_port_dict(context, original_port, vport=vport)
        self.nuage_callbacks.notify(resources.PORT, 'before_update_nuage',
                                    self, context=context, request_port=p_data,
                                    original_port=original_port)

        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)

        if 'fixed_ips' in p_data and nuage_utils.check_vport_creation(
                p_data.get('device_owner', original_port['device_owner']),
                cfg.CONF.PLUGIN.device_owner_prefix):
            changed = [ip for ip in p_data['fixed_ips']
                       if ip not in original_port['fixed_ips']]
            if changed:
                msg = _("Can't update a port's fixed_ips to a different value."
                        " Incompatible fixed_ips: %s") % changed
                raise n_exc.BadRequest(resource='port', msg=msg)

        old_port = copy.deepcopy(original_port)
        new_sg = (set(port['port'].get(ext_sg.SECURITYGROUPS)) if
                  port['port'].get(ext_sg.SECURITYGROUPS) else set())
        orig_sg = (set(original_port.get(ext_sg.SECURITYGROUPS)) if
                   original_port.get(ext_sg.SECURITYGROUPS) else set())
        sgids_diff = list(new_sg ^ orig_sg)
        with db.exc_to_retry(db_exc.DBDuplicateEntry),\
                session.begin(subtransactions=True):
            current_owner = original_port['device_owner']
            lbaas_device_owner_added = (
                p_data.get('device_owner') ==
                os_constants.DEVICE_OWNER_LOADBALANCER + 'V2')
            lbaas_device_owner_removed = (
                'device_owner' in p_data and (not p_data.get('device_owner'))
                and current_owner == os_constants.DEVICE_OWNER_LOADBALANCER +
                'V2')

            self._validate_update_port(
                p_data, original_port, has_security_groups)

            filters = {'device_id': [original_port['device_id']]}
            ports = self.get_ports(context, filters)
            no_of_ports = len(ports)
            updated_port = super(NuagePlugin,
                                 self).update_port(context, id, port)
            if psec.PORTSECURITY in p_data:
                self._process_port_port_security_update(
                    context, p_data, updated_port)
            self._portsec_ext_port_update_processing(
                updated_port, context, port, id)
            if (original_port.get(psec.PORTSECURITY)
                    != updated_port.get(psec.PORTSECURITY)):
                p_sec_update_reqd = True
            self._process_portbindings_create_and_update(
                context, p_data, updated_port)
            if not updated_port.get('fixed_ips'):
                return updated_port
            subnet_id = updated_port['fixed_ips'][0]['subnet_id']
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
            if vport and vport['parentType'] == constants.L3SUBNET:
                vsd_subnet = self.nuageclient.get_domain_subnet_by_id(
                    subnet_mapping['nuage_subnet_id'])
            elif vport and vport['parentType'] == constants.L2DOMAIN:
                vsd_subnet = self.nuageclient.get_l2domain_by_id(
                    subnet_mapping['nuage_subnet_id'])
            else:
                vsd_subnet = self.nuageclient \
                    .get_subnet_or_domain_subnet_by_id(
                        subnet_mapping['nuage_subnet_id'])
            if (p_data.get('device_owner', '').startswith(
                    constants.NOVA_PORT_OWNER_PREF) or create_vm or
                    lbaas_device_owner_added):
                LOG.debug("Port %s is owned by nova:compute", id)
                if subnet_mapping:
                    self._process_update_nuage_vport(
                        context, id, updated_port, subnet_mapping,
                        current_owner, vport, vsd_subnet)
                else:
                    LOG.error(_('VM with uuid %s will not be resolved '
                                'in VSD because its created on unsupported'
                                ' subnet type'), port['device_id'])

            else:
                # nova removes device_owner and device_id fields, in this
                # update_port, hence before update_port, get_ports for
                # device_id and pass the no_of_ports to delete_nuage_vport
                self._process_update_port(context, p_data, original_port,
                                          subnet_mapping, no_of_ports)
            if addr_pair.ADDRESS_PAIRS in p_data:
                self.update_address_pairs_on_port(context, id, port,
                                                  original_port, updated_port)

        rollbacks = []
        try:
            if (subnet_mapping and
                    subnet_mapping['nuage_managed_subnet'] is False):
                if p_sec_update_reqd:
                    self._process_port_create_secgrp_for_port_sec(
                        context, updated_port)

            super(NuagePlugin, self)._update_extra_dhcp_opts_on_port(
                context, old_port.get('id'), port, updated_port)

            if (subnet_mapping and subnet_mapping['nuage_managed_subnet'] is
                False and delete_security_groups or (has_security_groups and
                                                     sgids_diff)):
                    super(NuagePlugin,
                          self)._delete_port_security_group_bindings(context,
                                                                     id)
                    sgids = self._get_security_groups_on_port(context, port)
                    self._process_port_create_security_group(
                        context, updated_port, vport, sgids, vsd_subnet)
                    deleted_sg_ids = orig_sg - new_sg
                    self.nuageclient.check_unused_policygroups(deleted_sg_ids)
            if not lbaas_device_owner_added and not lbaas_device_owner_removed:
                self.nuage_callbacks.notify(
                    resources.PORT, constants.AFTER_UPDATE, self,
                    context=context, updated_port=updated_port,
                    original_port=original_port, request_port=port['port'],
                    vport=vport, rollbacks=rollbacks)
            if vport:
                vport = self.nuageclient.get_nuage_vport_by_id(vport['ID'],
                                                               required=False)
            self.extend_port_dict(context, updated_port, vport=vport)
            return updated_port
        except Exception:
            with excutils.save_and_reraise_exception():
                for rollback in reversed(rollbacks):
                    rollback[0](*rollback[1], **rollback[2])
                # Revert the address pairs and port back to original state
                updated_port_dict = {
                    'port': {
                        addr_pair.ADDRESS_PAIRS: old_port.get(
                            addr_pair.ADDRESS_PAIRS)
                    }
                }
                self.update_address_pairs_on_port(context, id,
                                                  updated_port_dict,
                                                  updated_port,
                                                  old_port)

                super(NuagePlugin, self).update_port(context, id,
                                                     {'port': old_port})

    def _get_vport_for_port(self, context, port):
        if len(port['fixed_ips']) == 0:
            return None

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if not subnet_mapping:
            LOG.debug(_("No subnet mapping found for subnet %s") % subnet_id)
            return None

        vport = self.nuageclient.get_nuage_vport_by_neutron_id(
            {'neutron_port_id': port['id'],
             'l2dom_id': subnet_mapping['nuage_subnet_id'],
             'l3dom_id': subnet_mapping['nuage_subnet_id']},
            required=False)
        if not vport:
            LOG.warning(_("No vport found for port %s") % id)
            return None
        return vport

    @log_helpers.log_method_call
    def _delete_nuage_vport(self, context, port, np_name, subnet_mapping,
                            no_of_ports=None, port_delete=False):
        nuage_vif_id = None
        l2dom_id = None
        l3dom_id = None

        if subnet_mapping['nuage_managed_subnet']:
            # This is because we do not know if this advanced subn
            # is a domain-subn ot not. In both cases, the
            # nuage_subnet_id is the ID of the l2dom or domSubn.
            l2dom_id = subnet_mapping['nuage_subnet_id']
            l3dom_id = subnet_mapping['nuage_subnet_id']
        else:
            if subnet_mapping['nuage_l2dom_tmplt_id']:
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3dom_id = subnet_mapping['nuage_subnet_id']

        port_params = {
            'neutron_port_id': port['id'],
            'l2dom_id': l2dom_id,
            'l3dom_id': l3dom_id
        }
        subn = self.get_subnet(context, port['fixed_ips'][0]['subnet_id'])
        nuage_port = self.nuageclient.get_nuage_port_by_id(port_params)
        vm_id = port['device_id']
        # upstream neutron_lbaas assigns a constant device_id to all the
        # lbaas_ports (which is a bug), hence we use port ID as vm_id
        # instead of device_id for lbaas dummy VM
        if os_constants.DEVICE_OWNER_LOADBALANCER + 'V2' in port.get(
                'device_owner'):
            vm_id = port['id']
        if (constants.NOVA_PORT_OWNER_PREF in port['device_owner']
                or os_constants.DEVICE_OWNER_LOADBALANCER + 'V2' in port.get(
                'device_owner')):
            LOG.debug("Deleting VM port %s", port['id'])
            # This was a VM Port
            if nuage_port:
                nuage_vif_id = nuage_port['nuage_vif_id']
            # no_of_ports not passed in case of nova vm create
            # without using preexisting ports
            if not no_of_ports:
                filters = {'device_id': [port['device_id']]}
                ports = self.get_ports(context, filters)
                no_of_ports = len(ports)
            params = {
                'no_of_ports': no_of_ports,
                'netpart_name': np_name,
                'tenant': port['tenant_id'],
                'mac': port['mac_address'],
                'nuage_vif_id': nuage_vif_id,
                'id': vm_id,
                'subn_tenant': subn['tenant_id'],
                'l2dom_id': l2dom_id,
                'l3dom_id': l3dom_id,
                'portOnSharedSubn': subn['shared']
            }
            self.nuageclient.delete_vms(params)

            # Delete the vports that nova created on nova boot or when the
            # port is being deleted in neutron
            nuage_vport = self.nuageclient.get_nuage_vport_by_neutron_id(
                port_params, required=False)
            if nuage_vport:
                vport_desc = nuage_vport.get('description')
                nova_created = (constants.NOVA_PORT_OWNER_PREF in vport_desc
                                if vport_desc else False)
                if port_delete or nova_created:
                    self.nuageclient.delete_nuage_vport(nuage_vport.get('ID'))

        # delete nuage vport created explicitly
        if not nuage_port and nuage_utils.check_vport_creation(
                port.get('device_owner'), cfg.CONF.PLUGIN.device_owner_prefix):
            nuage_vport = self.nuageclient.get_nuage_vport_by_neutron_id(
                port_params, required=False)
            if nuage_vport:
                self.nuageclient.delete_nuage_vport(nuage_vport.get('ID'))

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

                nuage_fip = self.nuageclient.get_nuage_fip_by_id(params)
                if nuage_fip:
                    self.nuageclient.delete_nuage_floatingip(
                        nuage_fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

    def _pre_delete_port(self, context, port_id, port_check):
        """Do some preliminary operations before deleting the port."""
        LOG.debug("Deleting port %s", port_id)
        try:
            # notify interested parties of imminent port deletion;
            # a failure here prevents the operation from happening
            kwargs = {
                'context': context,
                'port_id': port_id,
                'port_check': port_check
            }
            registry.notify(
                resources.PORT, events.BEFORE_DELETE, self, **kwargs)
        except cb_exc.CallbackFailure as e:
            # preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise n_exc.ServicePortInUse(port_id=port_id, reason=e)

    @nuage_utils.handle_nuage_api_error
    @oslo_db_api.wrap_db_retry(max_retries=db.MAX_RETRIES,
                               retry_on_request=True,
                               retry_on_deadlock=True)
    @log_helpers.log_method_call
    def delete_port(self, context, id, l3_port_check=True):
        self._pre_delete_port(context, id, l3_port_check)
        port = self._get_port(context, id)
        fip = nuagedb.get_fip_by_floating_port_id(context.session,
                                                  id)
        # disassociate_floatingips() will change the row of
        # floatingips neutron table. Store the reqd. values
        # in fip_dict that will be used to delete nuage fip
        # that is associated with the port getting deleted.
        fip_dict = dict()
        if fip:
            fip_dict = {
                'fip_id': fip['id'],
                'fip_fixed_port_id': fip['fixed_port_id'],
                'fip_router_id': fip['router_id'],
                'fip_last_known_rtr_id': fip['last_known_router_id']
            }
        # This is required for to pass ut test_floatingip_port_delete
        self.disassociate_floatingips(context, id)
        self._delete_nuage_fip(context, fip_dict)
        if not port['fixed_ips']:
            return super(NuagePlugin, self).delete_port(context, id)

        sub_id = port['fixed_ips'][0]['subnet_id']

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        sub_id)
        if not subnet_mapping:
            LOG.debug("No subnet to l2domain mapping found for subnet %s",
                      sub_id)
            return super(NuagePlugin, self).delete_port(context, id)

        if nuage_utils.check_vport_creation(
                port.get('device_owner'), cfg.CONF.PLUGIN.device_owner_prefix):
            # Need to call this explicitly to delete vport to policygroup
            # binding
            if (ext_sg.SECURITYGROUPS in port and
                    subnet_mapping['nuage_managed_subnet'] is False):
                super(NuagePlugin,
                      self)._delete_port_security_group_bindings(context, id)

            netpart_id = subnet_mapping['net_partition_id']
            net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                            netpart_id)

            self._delete_nuage_vport(context, port, net_partition['name'],
                                     subnet_mapping, port_delete=True)
            securitygroups = port.get(ext_sg.SECURITYGROUPS, [])
            securitygroup_ids = [sg.security_group_id for sg in securitygroups]
            self.nuageclient.check_unused_policygroups(securitygroup_ids)
        else:
            # Check and delete gateway host vport associated with the port
            self.delete_gw_host_vport(context, port, subnet_mapping)

        super(NuagePlugin, self).delete_port(context, id)

    @log_helpers.log_method_call
    def get_ports_count(self, context, filters=None):
        if filters.get('tenant_id', None):
            query = context.session.query(func.count(models_v2.Port.id))
            query = query.filter_by(tenant_id=str(filters['tenant_id']))
            return query.scalar()
        else:
            return super(NuagePlugin, self).get_ports_count(context, filters)

    @log_helpers.log_method_call
    def _check_router_subnet_for_tenant(self, context, tenant_id):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [tenant_id]}
        routers = self.get_routers(context, filters=filters)
        subnets = self.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    @log_helpers.log_method_call
    def _extend_network_dict_provider_nuage(self, network, net_db,
                                            net_binding=None):
        binding = net_db.pnetbinding if net_db else net_binding
        if binding:
            network[pnet.NETWORK_TYPE] = binding.network_type
            network[pnet.PHYSICAL_NETWORK] = binding.physical_network
            network[pnet.SEGMENTATION_ID] = binding.vlan_id

    @log_helpers.log_method_call
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

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_network(self, context, network):
        data = network['network']
        (network_type, physical_network,
         vlan_id) = self._process_provider_create(context, data)
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(
                context,
                network['network']['tenant_id'])

            net_db = self.create_network_db(context, network)
            net = self._make_network_dict(net_db,
                                          process_extensions=False,
                                          context=context)
            # Create the network extension attributes.
            if psec.PORTSECURITY in data:
                self._process_network_port_security_create(context, data, net)

            self._process_l3_create(context, net, data)

            if network_type == 'vlan':
                nuagedb.add_network_binding(context.session,
                                            net['id'],
                                            network_type,
                                            physical_network,
                                            vlan_id)
            self._apply_dict_extend_functions(attributes.NETWORKS, net, net_db)
        return net

    @log_helpers.log_method_call
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
        subnet = self.get_subnets(context, filters={'network_id': [id]})
        if subnet and not is_external_set:
            msg = _('External network with subnets can not be '
                    'changed to non-external network')
            raise nuage_exc.OperationNotSupported(msg=msg)
        if len(subnet) > 1 and is_external_set:
            msg = _('Non-external network with more than one subnet '
                    'can not be changed to external network')
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

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def update_network(self, context, id, network):
        data = network['network']
        pnet._raise_if_updates_provider_attributes(data)
        with context.session.begin(subtransactions=True):
            is_external_set, subnet = self._validate_update_network(context,
                                                                    id,
                                                                    network)
            net = super(NuagePlugin, self).update_network(context, id,
                                                          network)

            # Update the network extension attributes.
            if psec.PORTSECURITY in network['network']:
                self._process_network_port_security_update(context, data,
                                                           net)
            self._process_l3_update(context, net, data)
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
                               'nuage_subn_id':
                                   subnet_l2dom['nuage_subnet_id']})
                    self.nuageclient.delete_subnet(subn['id'])
                    nuagedb.delete_subnetl2dom_mapping(context.session,
                                                       subnet_l2dom)
                    if not self._check_router_subnet_for_tenant(
                            context, subn['tenant_id']):
                        LOG.debug("No router/subnet found for tenant %s",
                                  subn['tenant_id'])
                        self.nuageclient.delete_user(user_id)
                        self.nuageclient.delete_group(group_id)

                    # delete the neutron port that was reserved with IP of
                    # the dhcp server that is reserved.
                    # Now, this port is not reqd.
                    filters = {
                        'fixed_ips': {'subnet_id': [subn['id']]},
                        'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
                    }
                    gw_ports = self.get_ports(context, filters=filters)
                    self._delete_port_gateway(context, gw_ports)

                    self._add_nuage_sharedresource(subnet[0],
                                                   id,
                                                   constants.SR_TYPE_FLOATING)
            if network['network'].get('shared') in [True, False]:
                subnets = self._get_subnets_by_network(context, id)
                for subn in subnets:
                    subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(
                        context.session, subn['id'])
                    if subnet_l2dom['nuage_l2dom_tmplt_id']:
                        # change of perm only reqd in l2dom case
                        self.nuageclient.change_perm_of_subns(
                            subnet_l2dom['net_partition_id'],
                            subnet_l2dom['nuage_subnet_id'],
                            network['network']['shared'],
                            subn['tenant_id'])
        return net

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
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

    @log_helpers.log_method_call
    def _get_net_partition_for_subnet(self, context, subnet):
        ent = subnet.get('net_partition', None)
        if not ent:
            net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                            self.default_np_id)
        else:
            net_partition = self._resource_finder(
                context, 'subnet', 'net_partition', subnet['net_partition'])
        if not net_partition:
            msg = _('Either net_partition is not provided with subnet OR '
                    'default net_partition is not created at the start')
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        return net_partition

    @log_helpers.log_method_call
    def _validate_create_subnet(self, context, subnet, network_external):
        subnets = self._get_subnets_by_network(context, subnet['network_id'])
        subnet_nuagenet = subnet.get('nuagenet')
        # Do not allow os_managed subnets if the network already has
        # vsd_managed subnets. and not allow vsd_managed subnets if the
        # network already has os_managed subnets
        if subnets:
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                          subnets[0]['id'])
            if subnet_l2dom:
                # vsd managed subnet
                if subnet_l2dom.get('nuage_managed_subnet'):
                    if not subnet_nuagenet:
                        msg = _('Network has vsd managed subnets, cannot '
                                'create os managed subnets')
                        raise nuage_exc.NuageBadRequest(msg=msg)
                else:
                    if subnet_nuagenet:
                        msg = _('Network has os managed subnets, cannot '
                                'create vsd managed subnets')
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

        if (not network_external and
                subnet['nuage_uplink']):
            msg = _("nuage-uplink attribute can not be set for "
                    "internal subnets ")
            raise nuage_exc.NuageBadRequest(msg=msg)

    @log_helpers.log_method_call
    def _validate_create_provider_subnet(self, context, net_id):
        net_filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=net_filter)
        if len(existing_subn) > 0:
            msg = _('Only one subnet is allowed per '
                    'Provider network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)

    @log_helpers.log_method_call
    def _delete_nuage_sharedresource(self, net_id):
        self.nuageclient.delete_nuage_sharedresource(net_id)

    @log_helpers.log_method_call
    def _validate_nuage_sharedresource(self, context, net_id):
        filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=filter)
        if len(existing_subn) > 0:
            msg = _('Only one subnet is allowed per '
                    'external network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)

    @log_helpers.log_method_call
    def _add_nuage_sharedresource(self, subnet, net_id, type,
                                  req_subnet=None):
        net = netaddr.IPNetwork(subnet['cidr'])
        params = {
            'neutron_subnet': subnet,
            'net': net,
            'type': type,
            'net_id': net_id,
            'underlay_config': cfg.CONF.RESTPROXY.nuage_fip_underlay
        }
        if req_subnet and req_subnet.get('underlay') in [True, False]:
            params['underlay'] = req_subnet.get('underlay')
            subnet['underlay'] = req_subnet.get('underlay')
        else:
            subnet['underlay'] = params['underlay_config']

        if req_subnet and req_subnet.get('nuage_uplink'):
            params['nuage_uplink'] = req_subnet.get('nuage_uplink')
            subnet['nuage_uplink'] = req_subnet.get('nuage_uplink')
        elif cfg.CONF.RESTPROXY.nuage_uplink:
            subnet['nuage_uplink'] = cfg.CONF.RESTPROXY.nuage_uplink
            params['nuage_uplink'] = cfg.CONF.RESTPROXY.nuage_uplink

        self.nuageclient.create_nuage_sharedresource(params)

    @log_helpers.log_method_call
    def _create_nuage_sharedresource(self, context, subnet, type):
        req_subnet = copy.deepcopy(subnet['subnet'])
        net_id = req_subnet['network_id']
        self._validate_nuage_sharedresource(context, net_id)
        with context.session.begin(subtransactions=True):
            neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                                                                    subnet)
            self._add_nuage_sharedresource(neutron_subnet,
                                           net_id, type,
                                           req_subnet=req_subnet)
            return neutron_subnet

    @oslo_db_api.wrap_db_retry(max_retries=db.MAX_RETRIES,
                               retry_on_request=True,
                               retry_on_deadlock=True)
    @log_helpers.log_method_call
    def _reserve_ip(self, context, subnet, ip):
        fixed_ip = [{'ip_address': ip, 'subnet_id': subnet['id']}]

        port_dict = dict(port=dict(
            name='',
            device_id='',
            admin_state_up=True,
            network_id=subnet['network_id'],
            tenant_id=subnet['tenant_id'],
            fixed_ips=fixed_ip,
            mac_address=attributes.ATTR_NOT_SPECIFIED,
            device_owner=constants.DEVICE_OWNER_DHCP_NUAGE))
        return super(NuagePlugin, self).create_port(context, port_dict)

    @log_helpers.log_method_call
    def _delete_port_gateway(self, context, ports):
        for port in ports:
            super(NuagePlugin, self).delete_port(context, port['id'])

    @log_helpers.log_method_call
    def _delete_port_gateway_v2(self, context, ports):
        for port in ports:
            delete_query = (context.session.query(models_v2.Port).
                            enable_eagerloads(False).filter_by(id=port['id']))
            if not context.is_admin:
                delete_query = delete_query.filter_by(
                    tenant_id=context.tenant_id)
            delete_query.with_lockmode('update')
            delete_query.delete()

    @log_helpers.log_method_call
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
            gw_port = self._reserve_ip(context, neutron_subnet,
                                       last_address)
            params['dhcp_ip'] = gw_port['fixed_ips'][0]['ip_address']
        else:
            LOG.warning(_("CIDR parameter ignored for unmanaged subnet "))
            LOG.warning(_("Allocation Pool parameter ignored"
                          " for unmanaged subnet "))
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

    @log_helpers.log_method_call
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

        if not self.nuageclient.check_if_l2Dom_in_correct_ent(nuage_subn_id,
                                                              nuage_netpart):
            msg = ("Provided Nuage subnet not in the provided"
                   " Nuage net-partition")
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        if nuagedb.get_subnet_l2dom_by_nuage_id(
                context.session, nuage_subn_id):
            msg = ("Multiple Openstack subnets cannot be linked to the "
                   "same VSD network")
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        nuage_subnet = self.nuageclient.get_subnet_or_domain_subnet_by_id(
            nuage_subn_id, required=True)
        shared_nuage_subnet = None
        if nuage_subnet['associatedSharedNetworkResourceID']:
            try:
                shared_nuage_subnet = (
                    self.nuageclient.get_nuage_sharedresource(
                        nuage_subnet['associatedSharedNetworkResourceID']))
            except Exception as e:
                if e.code == constants.RES_NOT_FOUND:
                    resp = self.nuageclient.get_subnet_or_domain_subnet_by_id(
                        nuage_subnet['associatedSharedNetworkResourceID'],
                        required=True)
                    if resp.get('type') == constants.L2DOMAIN:
                        e.message = ("The provided nuagenet ID is linked to a"
                                     " L2 Domain instance")
                        e.msg = ("The provided nuagenet ID is linked to a"
                                 " L2 Domain instance")
                        raise nuage_exc.NuageBadRequest(msg=e.msg)
                raise e
        self._validate_cidr(subn, nuage_subnet, shared_nuage_subnet)
        return nuage_subnet

    @log_helpers.log_method_call
    def _get_gwip_for_adv_managed_subn(self, os_subnet, vsd_subnet,
                                       shared_subnet):
        gw_ip_from_cli = os_subnet['gateway_ip']
        os_subnet['gateway_ip'] = self.nuageclient.get_gateway_ip_for_advsub(
            shared_subnet or vsd_subnet)

        # The _is_attr_set() is incomplete to use here, since the method
        # ignores the case if the user sets the attribute value to None.
        if ((gw_ip_from_cli is not attributes.ATTR_NOT_SPECIFIED) and
                (gw_ip_from_cli != os_subnet['gateway_ip'])):
                msg = ("Provided gateway-ip does not match VSD "
                       "configuration. ")
                raise n_exc.BadRequest(resource='subnet', msg=msg)
        if attributes.is_attr_set(os_subnet['dns_nameservers']):
            LOG.warning(_("DNS Nameservers parameter ignored for "
                          "VSD-Managed managed subnet "))
        # creating a dhcp_port with this gatewayIP
        return os_subnet['gateway_ip']

    @log_helpers.log_method_call
    def _link_nuage_adv_subnet(self, context, subnet):
        subn = subnet['subnet']
        nuage_subn_id = subn['nuagenet']
        tenant_id = subn['tenant_id']
        nuage_tmplt_id = nuage_subn_id
        nuage_netpart_name = subn.get('net_partition', None)

        if not nuage_netpart_name:
            msg = 'In advance mode, net-partition name must be provided'
            raise n_exc.BadRequest(resource='subnet', msg=msg)

        nuage_netpart = nuagedb.get_net_partition_by_name(context.session,
                                                          nuage_netpart_name)

        vsd_subnet = self._validate_adv_subnet(context, subn, nuage_netpart)
        shared = vsd_subnet['associatedSharedNetworkResourceID']
        shared_subnet = None
        if shared:
            shared_subnet = self.nuageclient.get_subnet_or_domain_subnet_by_id(
                shared)
        if subn['enable_dhcp']:
            gw_ip = self._get_gwip_for_adv_managed_subn(subn, vsd_subnet,
                                                        shared_subnet)
            if vsd_subnet['type'] == constants.L3SUBNET:
                reserve_ip = gw_ip
            else:
                reserve_ip = (shared_subnet['gateway'] if shared_subnet
                              else vsd_subnet['gateway'])
        else:
            LOG.warning(_("CIDR parameter ignored for unmanaged subnet "))
            LOG.warning(_("Allocation Pool parameter ignored for"
                          " unmanaged subnet "))
            # Setting the gateway_ip value to None when
            # a VSD Managed subnet is created with DHCP disabled.
            # LOG when we ignored the gateway_ip value is set,either
            # implicitly (or) explicitly by the user.
            if subn['gateway_ip'] is not None:
                LOG.warning(_("Gateway IP parameter ignored for "
                              "VSD-Managed unmanaged subnet "))
                subn['gateway_ip'] = None
            if attributes.is_attr_set(subn['dns_nameservers']):
                subn['dns_nameservers'] = None
                LOG.warning(_("DNS Nameservers parameter ignored "
                              "for VSD-Managed unmanaged subnet "))

        try:
            with contextlib.nested(
                    lockutils.lock('db-access'),
                    context.session.begin(subtransactions=True)):
                neutron_subnet = super(NuagePlugin, self).create_subnet(
                    context, subnet)
                if subn['enable_dhcp']:
                    # Create the dhcp port only for adv. managed subnets
                    # this the dhcp port which is being created for the
                    # adv subnet
                    # l2 case: this is the dhcp server IP seen in VSD GUI
                    # l3 case: we just create a dhcp server
                    # IP port since we need to block a VM creation with
                    # the gwIp in this domain/subnet
                    self._reserve_ip(context, neutron_subnet, reserve_ip)

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
                 tenant_id, nuage_npid, nuage_subn_id,
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
        if vsd_subnet['type'] == 'Subnet':
            ns_dict['nuage_l2dom_tmplt_id'] = None
        with context.session.begin(subtransactions=True):
            nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                               ns_dict)
        return neutron_subnet

    @log_helpers.log_method_call
    def get_subnet(self, context, id, fields=None):
        subnet = super(NuagePlugin, self).get_subnet(context, id, None)
        subnet = nuagedb.get_nuage_subnet_info(context.session, subnet, fields)
        network = self._get_network(context, subnet['network_id'])
        if network.get('external'):
            try:
                nuage_subnet = self.nuageclient.get_sharedresource(id)
                subnet['underlay'] = nuage_subnet['underlay']
                subnet['nuage_uplink'] = nuage_subnet['sharedResourceParentID']
            except ResourceNotFoundException:
                pass
        return self._fields(subnet, fields)

    @log_helpers.log_method_call
    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        subnets = super(NuagePlugin, self).get_subnets(context, filters, None,
                                                       sorts, limit, marker,
                                                       page_reverse)
        subnets = nuagedb.get_nuage_subnets_info(context.session, subnets,
                                                 fields, filters)
        for idx, subnet in enumerate(subnets):
            subnets[idx] = self._fields(subnet, fields)
        return subnets

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
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

    def _update_ext_network_subnet(self, context, id, net_id, subn, subnet):
        with context.session.begin(subtransactions=True):
            updated_subnet = super(NuagePlugin, self).update_subnet(
                context, id, subnet)
            nuage_params = {
                'subnet_name': subn.get('name'),
                'net_id': net_id,
                'gateway_ip': subn.get('gateway_ip')
            }
            self.nuageclient.update_nuage_sharedresource(id, nuage_params)
            nuage_subnet = self.nuageclient.get_sharedresource(id)
            updated_subnet['underlay'] = nuage_subnet['underlay']
            return updated_subnet

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def update_subnet(self, context, id, subnet):
        subn = copy.deepcopy(subnet['subnet'])
        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session, id)
        original_subnet = self.get_subnet(context, id)
        net_id = original_subnet['network_id']
        network_external = self._network_is_external(context, net_id)

        if network_external:
            return self._update_ext_network_subnet(context, id, net_id, subn,
                                                   subnet)
        if subnet_l2dom['nuage_managed_subnet']:
            msg = ("Subnet %s is a VSD-Managed subnet."
                   " Update is not supported." % subnet_l2dom['subnet_id'])
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        if not network_external and subn.get('underlay') is not None:
            msg = _("underlay attribute can not be set for internal subnets")
            raise nuage_exc.NuageBadRequest(msg=msg)

        params = {
            'parent_id': subnet_l2dom['nuage_subnet_id'],
            'type': subnet_l2dom['nuage_l2dom_tmplt_id']
        }
        with context.session.begin(subtransactions=True):
            updated_subnet = super(NuagePlugin, self).update_subnet(
                context, id, subnet)

            curr_enable_dhcp = original_subnet.get('enable_dhcp')
            updated_enable_dhcp = updated_subnet.get('enable_dhcp')

            if not curr_enable_dhcp and updated_enable_dhcp:
                last_address = updated_subnet['allocation_pools'][-1]['end']
                gw_port = self._reserve_ip(context,
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
            subn['id'] = subnet['subnet']['id']
            self.nuageclient.update_subnet(subn, params)

            return updated_subnet

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_subnet(self, context, id):
        subnet = self.get_subnet(context, id)

        filters = {
            'fixed_ips': {'subnet_id': [id]},
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
            except Exception as ex:
                if ex.code == constants.RES_CONFLICT:
                    raise n_exc.SubnetInUse(subnet_id=id)
                raise
        super(NuagePlugin, self).delete_subnet(context, id)

        if subnet_l2dom:
            if subnet_l2dom['nuage_managed_subnet']:
                if context.tenant == subnet['tenant_id']:
                    tenants = [context.tenant]
                else:
                    tenants = [context.tenant, subnet['tenant_id']]
                self.nuageclient.detach_nuage_group_to_nuagenet(
                    tenants,
                    subnet_l2dom['nuage_subnet_id'],
                    subnet['shared'])

            if not self._check_router_subnet_for_tenant(
                    context, subnet['tenant_id']):
                LOG.debug("No router/subnet found for tenant %s", subnet[
                    'tenant_id'])
                self.nuageclient.delete_user(subnet_l2dom['nuage_user_id'])
                self.nuageclient.delete_group(subnet_l2dom['nuage_group_id'])

    def _nuage_vips_on_subnet(self, context, subnet):
        vip_found = False
        filters = {'device_owner':
                   [constants.DEVICE_OWNER_VIP_NUAGE],
                   'network_id': [subnet['network_id']]}
        ports = self.get_ports(context, filters)

        for p in ports:
            if p['fixed_ips'][0]['subnet_id'] == subnet['id']:
                vip_found = True
                break
        return vip_found

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        session = context.session
        rtr_if_info = super(NuagePlugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            return self._nuage_add_router_interface(context,
                                                    interface_info,
                                                    router_id,
                                                    rtr_if_info,
                                                    session)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin, self).remove_router_interface(
                    context, router_id, interface_info)

    def _nuage_add_router_interface(self, context, interface_info,
                                    router_id, rtr_if_info, session):
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port = super(NuagePlugin, self)._get_port(context, port_id)
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
            vport = self.nuageclient.get_nuage_vport_by_neutron_id(
                {'neutron_port_id': port['id'],
                 'l2dom_id': subnet_l2dom['nuage_subnet_id'],
                 'l3dom_id': subnet_l2dom['nuage_subnet_id']},
                required=False)
            if vport:
                self.nuageclient.delete_nuage_vport(vport['ID'])
        else:
            subnet_id = rtr_if_info['subnet_id']
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session, subnet_id)
        l2domain_id = subnet_l2dom['nuage_subnet_id']
        subnet = self.get_subnet(context, subnet_id)
        vsd_zone = self.nuageclient.get_zone_by_routerid(router_id,
                                                         subnet['shared'])
        self._nuage_validate_add_rtr_itf(session, router_id,
                                         subnet, subnet_l2dom, vsd_zone)

        filters = {
            'fixed_ips': {'subnet_id': [subnet_id]},
            'device_owner': [constants.DEVICE_OWNER_DHCP_NUAGE]
        }
        gw_ports = self.get_ports(context, filters=filters)
        self._delete_port_gateway_v2(context, gw_ports)

        pnet_binding = nuagedb.get_network_binding(context.session,
                                                   subnet['network_id'])

        with nuage_utils.rollback() as on_exc, \
                session.begin(subtransactions=True):
            vsd_subnet = self.nuageclient.create_domain_subnet(
                vsd_zone, subnet, pnet_binding)
            on_exc(self.nuageclient.delete_domain_subnet,
                   vsd_subnet['ID'], subnet['id'], pnet_binding)
            nuagedb.update_subnetl2dom_mapping(
                subnet_l2dom,
                {'nuage_subnet_id': vsd_subnet['ID'],
                 'nuage_l2dom_tmplt_id': None})

            self.nuageclient.move_l2domain_to_l3subnet(l2domain_id,
                                                       vsd_subnet['ID'])
            self.process_address_pairs_of_subnet(context, subnet_l2dom,
                                                 constants.L3SUBNET)

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
        self.nuageclient.validate_create_domain_subnet(subnet, nuage_subnet_id,
                                                       nuage_rtr_id)

    def abort_add_router_interface(self, context, interface_info, router_id):
        super(NuagePlugin, self).remove_router_interface(context,
                                                         router_id,
                                                         interface_info)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
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
            subnet = self.get_subnet(context, subnet_id)
        session = context.session
        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                      subnet_id)
        if not subnet_l2dom:
            return super(NuagePlugin,
                         self).remove_router_interface(context,
                                                       router_id,
                                                       interface_info)
        nuage_subn_id = subnet_l2dom['nuage_subnet_id']
        if self._nuage_vips_on_subnet(context, subnet):
            msg = (_("Subnet %s has one or more active nuage VIPs "
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

        with nuage_utils.rollback() as on_exc, \
                session.begin(subtransactions=True):
            result = super(NuagePlugin,
                           self).remove_router_interface(context, router_id,
                                                         interface_info)
            last_address = neutron_subnet['allocation_pools'][-1]['end']
            port = self._reserve_ip(context, neutron_subnet, last_address)
            pnet_binding = nuagedb.get_network_binding(
                context.session, neutron_subnet['network_id'])
            on_exc(self._delete_port_gateway, context, [port])

            self.nuageclient.confirm_router_interface_not_in_use(router_id,
                                                                 subnet)
            vsd_l2domain = self.nuageclient.create_l2domain_for_router_detach(
                subnet, subnet_l2dom)
            on_exc(self.nuageclient.delete_subnet, subnet['id'])

            nuagedb.update_subnetl2dom_mapping(
                subnet_l2dom,
                {'nuage_subnet_id': vsd_l2domain['nuage_l2domain_id'],
                 'nuage_l2dom_tmplt_id': vsd_l2domain['nuage_l2template_id']})
            self.nuageclient.move_l3subnet_to_l2domain(
                nuage_subn_id,
                vsd_l2domain['nuage_l2domain_id'],
                subnet_l2dom,
                pnet_binding)
            self.process_address_pairs_of_subnet(context, subnet_l2dom,
                                                 constants.L2DOMAIN)
            LOG.debug("Deleted nuage domain subnet %s", nuage_subn_id)
            return result

    @log_helpers.log_method_call
    def _get_net_partition_for_router(self, context, rtr):
        ent = rtr.get('net_partition', None)
        if not ent:
            net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                            self.default_np_id)
        else:
            net_partition = self._resource_finder(
                context, 'router', 'net_partition', rtr['net_partition'])
        if not net_partition:
            msg = _("Either net_partition is not provided with router OR "
                    "default net_partition is not created at the start")
            raise n_exc.BadRequest(resource='router', msg=msg)
        return net_partition

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_router(self, context, id, fields=None):
        router = super(NuagePlugin, self).get_router(context, id, fields)
        nuage_router = self.nuageclient.get_router_by_external(id)
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
            nuage_route = self.nuageclient.get_nuage_static_route(params)
            if nuage_route:
                route['rd'] = nuage_route['rd']

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_router(self, context, router):
        req_router = copy.deepcopy(router['router'])
        net_partition = self._get_net_partition_for_router(context,
                                                           router['router'])
        if 'ecmp_count' in router and not context.is_admin:
            msg = _("ecmp_count can only be set by an admin user.")
            raise nuage_exc.NuageNotAuthorized(resource='router', msg=msg)
        if (cfg.CONF.RESTPROXY.nuage_pat == constants.NUAGE_PAT_NOT_AVAILABLE
                and req_router.get('external_gateway_info')):
            msg = _("nuage_pat config is set to 'not_available'. "
                    "Can't set external_gateway_info")
            raise nuage_exc.NuageBadRequest(resource='router', msg=msg)

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
            neutron_router['ecmp_count'] = nuage_router['ecmp_count']
            neutron_router['nuage_backhaul_vnid'] = \
                nuage_router['nuage_backhaul_vnid']
            neutron_router['nuage_backhaul_rd'] = \
                nuage_router['nuage_backhaul_rd']
            neutron_router['nuage_backhaul_rt'] = \
                nuage_router['nuage_backhaul_rt']

        return neutron_router

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def update_router(self, context, id, router):
        updates = router['router']
        original_router = self.get_router(context, id)
        self._validate_update_router(context, id, updates)
        ent_rtr_mapping = context.ent_rtr_mapping
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']

        with context.session.begin(subtransactions=True):
            curr_router = self.get_router(context, id)
            old_routes = self._get_extra_routes_by_router_id(context, id)

            router_updated = super(NuagePlugin, self).update_router(
                context,
                id,
                copy.deepcopy(router))

            new_routes = updates.get('routes', curr_router.get('routes'))
            self._update_nuage_router_static_routes(id, nuage_domain_id,
                                                    old_routes, new_routes)
            try:
                if 'routes' in updates and len(updates) == 1:
                    pass
                else:
                    self._update_nuage_router(nuage_domain_id, curr_router,
                                              updates,
                                              ent_rtr_mapping)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._update_nuage_router_static_routes(id,
                                                            nuage_domain_id,
                                                            new_routes,
                                                            old_routes)
        nuage_router = self.nuageclient.get_router_by_external(id)
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
        added, removed = utils.diff_list_of_dict(old_routes, new_routes)
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
        self.nuageclient.create_nuage_staticroute(params)

    def _delete_nuage_static_route(self, nuage_domain_id, route):
        destaddr = route['destination']
        cidr = destaddr.split('/')
        params = {
            "address": cidr[0],
            "nexthop": route['nexthop'],
            "nuage_domain_id": nuage_domain_id
        }
        self.nuageclient.delete_nuage_staticroute(params)

    def _update_nuage_router(self, nuage_id, curr_router, router_updates,
                             ent_rtr_mapping):
        params = {
            'net_partition_id': ent_rtr_mapping['net_partition_id'],
            'nuage_pat': cfg.CONF.RESTPROXY.nuage_pat
        }
        curr_router.update(router_updates)
        self.nuageclient.update_router(nuage_id, curr_router, params)
        ns_dict = {
            'nuage_rtr_rt':
                router_updates.get('rt', ent_rtr_mapping.get('nuage_rtr_rt')),
            'nuage_rtr_rd':
                router_updates.get('rd', ent_rtr_mapping.get('nuage_rtr_rd'))
        }
        nuagedb.update_entrouter_mapping(ent_rtr_mapping, ns_dict)

    @nuage_utils.handle_nuage_api_error
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
                'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
            }
            ports = self.get_ports(context, filters)
            if ports:
                raise l3.RouterInUse(router_id=id)
            nuage_domain_id = ent_rtr_mapping['nuage_router_id']
            self.nuageclient.delete_router(nuage_domain_id)

        super(NuagePlugin, self).delete_router(context, id)

        if ent_rtr_mapping and not self._check_router_subnet_for_tenant(
                context, neutron_router['tenant_id']):
            LOG.debug("No router/subnet found for tenant %s",
                      neutron_router['tenant_id'])
            user_id, group_id = self.nuageclient.get_usergroup(
                neutron_router['tenant_id'],
                ent_rtr_mapping['net_partition_id'])
            self.nuageclient.delete_user(user_id)
            self.nuageclient.delete_group(group_id)

    @log_helpers.log_method_call
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

    @log_helpers.log_method_call
    def _create_net_partition(self, session, net_part_name):
        params = {
            "name": net_part_name,
            "fp_quota": str(cfg.CONF.RESTPROXY.default_floatingip_quota)
        }
        nuage_net_partition = self.nuageclient.create_net_partition(params)
        net_partitioninst = None
        if nuage_net_partition:
            with session.begin(subtransactions=True):
                self.nuageclient.set_external_id_for_netpart_rel_elems(
                    nuage_net_partition)
                net_partitioninst = NuagePlugin._add_net_partition(
                    session,
                    nuage_net_partition,
                    net_part_name)
        if not net_partitioninst:
            return {}
        return self._make_net_partition_dict(net_partitioninst)

    @log_helpers.log_method_call
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
    @log_helpers.log_method_call
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
         l2dom_tid) = self.nuageclient.link_default_netpartition(params)
        # verify that the provided zones have been created already
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
        self.default_np_id = np_id
        return net_partitioninst

    @log_helpers.log_method_call
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
            default_netpart = self._validate_create_net_partition(
                netpart_name)
            self.default_np_id = default_netpart['id']
            return default_netpart

        '''NetPartition and templates already created. Just sync the
        neutron DB. They must all be in VSD. If not, its an error
        '''
        return self._link_default_netpartition(netpart_name,
                                               l2template,
                                               l3template,
                                               l3isolated,
                                               l3shared)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_net_partition(self, context, net_partition):
        ent = net_partition['net_partition']
        return self._validate_create_net_partition(ent["name"],
                                                   context.session)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def _validate_delete_net_partition(self, context, id, net_partition_name):
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
    @log_helpers.log_method_call
    def delete_net_partition(self, context, id):
        net_partition = nuagedb.get_net_partition_by_id(context.session, id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        self._validate_delete_net_partition(context, id, net_partition['name'])
        self.nuageclient.delete_net_partition(net_partition['id'])
        with context.session.begin(subtransactions=True):
            nuagedb.delete_net_partition(context.session,
                                         net_partition)

    @log_helpers.log_method_call
    def get_net_partition(self, context, id, fields=None):
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        id)
        if not net_partition:
            raise nuage_exc.NuageNotFound(resource='net_partition',
                                          resource_id=id)
        return self._make_net_partition_dict(net_partition, context=context)

    @log_helpers.log_method_call
    def get_net_partitions(self, context, filters=None, fields=None):
        net_partitions = nuagedb.get_net_partitions(context.session,
                                                    filters=filters,
                                                    fields=fields)
        return [self._make_net_partition_dict(net_partition, context, fields)
                for net_partition in net_partitions]

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
        nuage_vport = self._get_vport_for_fip(context, port_id,
                                              vport_type=vport_type,
                                              vport_id=vport_id,
                                              required=False)

        if nuage_vport:
            nuage_fip = self.nuageclient.get_nuage_fip(nuage_fip_id)

            if nuage_fip['assigned']:
                # check if there are any interfaces attached to the
                # vport (n_vport) where the fip is as of now associated.
                # if no interfaces attached to this vport, we will
                # disassociate the fip assoc with the vport it is
                # currently associated and associate this fip
                # with the new vport. (nuage_vport)
                n_vport = self.nuageclient.get_vport_assoc_with_fip(
                    nuage_fip_id)
                if n_vport and not n_vport['hasAttachedInterfaces']:
                    disassoc_params = {
                        'nuage_vport_id': n_vport['ID'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(disassoc_params)

                if (nuage_vport['domainID']) != (
                        ent_rtr_mapping['nuage_router_id']):
                    fip_dict = {
                        'fip_id': neutron_fip['id'],
                        'fip_last_known_rtr_id': ent_rtr_mapping['router_id']
                    }
                    fip = self.nuageclient.get_nuage_fip_by_id(fip_dict)

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
                    fip = self.nuageclient.get_nuage_fip_by_id(params)

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
                            self.nuageclient.create_nuage_floatingip(params)
                    else:
                        nuage_fip_id = fip['nuage_fip_id']

            params = {
                'nuage_vport_id': nuage_vport['ID'],
                'nuage_fip_id': nuage_fip_id
            }
            self.nuageclient.update_nuage_vm_vport(params)
            self.fip_rate_log.info(
                'FIP %s (owned by tenant %s) associated to port %s'
                % (neutron_fip['id'], neutron_fip['tenant_id'], port_id))

        # Check if we have to associate a FIP to a VIP
        self._process_fip_to_vip(context, port_id, nuage_fip_id)

        if not rate_update:
            return
        # Add QOS to port for rate limiting
        fip_rate = neutron_fip.get('nuage_fip_rate',
                                   attributes.ATTR_NOT_SPECIFIED)
        fip_rate_configured = fip_rate is not attributes.ATTR_NOT_SPECIFIED
        if fip_rate_configured and not nuage_vport:
            msg = _('Rate limiting requires the floating ip to be '
                    'associated to a port.')
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not fip_rate_configured and not nuage_vport:
            del neutron_fip['nuage_fip_rate']

        if nuage_vport:
            if not fip_rate_configured:
                neutron_fip['nuage_fip_rate'] = self.def_fip_rate
            self.nuageclient.create_update_rate_limiting(
                neutron_fip['nuage_fip_rate'], nuage_vport['ID'],
                neutron_fip['id'])
            self.fip_rate_log.info(
                'FIP %s (owned by tenant %s) rate limit updated to %s Mb/s' %
                (neutron_fip['id'], neutron_fip['tenant_id'],
                 (neutron_fip['nuage_fip_rate']
                  if neutron_fip['nuage_fip_rate'] is not None
                  else "unlimited")))

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_floatingip(self, context, id, fields=None):
        fip = super(NuagePlugin, self).get_floatingip(context, id)

        if (not fields or 'nuage_fip_rate' in fields) and fip.get('port_id'):
            try:
                nuage_vport = self._get_vport_for_fip(context, fip['port_id'])
                rate_limit = self.nuageclient.get_rate_limit(
                    nuage_vport['ID'], fip['id'])
                fip['nuage_fip_rate'] = rate_limit
            except Exception as e:
                msg = (_('Got exception while retrieving fip rate from vsd: '
                         '%s') % e.message)
                LOG.error(msg)

        return self._fields(fip, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            neutron_fip = super(NuagePlugin, self).create_floatingip(
                context, floatingip,
                initial_status=os_constants.FLOATINGIP_STATUS_DOWN)
            fip_rate = fip.get('nuage_fip_rate')
            fip_rate_configured = fip_rate is not attributes.ATTR_NOT_SPECIFIED
            if fip_rate_configured:
                if not fip.get('port_id'):
                    msg = _('Rate limiting requires the floating ip to be '
                            'associated to a port.')
                    raise nuage_exc.NuageBadRequest(msg=msg)
            neutron_fip['nuage_fip_rate'] = fip_rate

            if not neutron_fip['router_id']:
                neutron_fip['nuage_fip_rate'] = None
                return neutron_fip

            try:
                self._create_update_floatingip(context, neutron_fip,
                                               fip['port_id'])
                self.update_floatingip_status(
                    context, neutron_fip['id'],
                    os_constants.FLOATINGIP_STATUS_ACTIVE)
                neutron_fip['status'] = os_constants.FLOATINGIP_STATUS_ACTIVE
            except (nuage_exc.OperationNotSupported, n_exc.BadRequest):
                with excutils.save_and_reraise_exception():
                    super(NuagePlugin, self).delete_floatingip(
                        context, neutron_fip['id'])
            return neutron_fip

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context, filters={'port_id': [port_id]})
        router_ids = super(NuagePlugin, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)

        if not fips:
            return

        # we can hav only 1 fip associated with a vPort at a time.fips[0]
        self.update_floatingip_status(
            context, fips[0]['id'], os_constants.FLOATINGIP_STATUS_DOWN)

        # Disassociate only if nuage_port has a FIP associated with it.
        # Calling disassociate on a port with no FIP causes no issue in Neutron
        # but VSD throws an exception
        nuage_vport = self._get_vport_for_fip(context, port_id, required=False)
        if nuage_vport and nuage_vport.get('associatedFloatingIPID'):
            for fip in fips:
                self.nuageclient.delete_rate_limiting(
                    nuage_vport['ID'], fip['id'])
                self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                       'disassociated from port %s'
                                       % (fip['id'], fip['tenant_id'],
                                          port_id))
            params = {
                'nuage_vport_id': nuage_vport['ID'],
                'nuage_fip_id': None
            }
            self.nuageclient.update_nuage_vm_vport(params)
            LOG.debug("Disassociated floating ip from VM attached at port %s",
                      port_id)

        return router_ids

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        orig_fip = self._get_floatingip(context, id)
        port_id = orig_fip['fixed_port_id']
        router_ids = []
        fip_rate = fip.get('nuage_fip_rate', attributes.ATTR_NOT_SPECIFIED)
        fip_rate_configured = fip_rate is not attributes.ATTR_NOT_SPECIFIED
        neutron_fip = self._make_floatingip_dict(orig_fip)

        with context.session.begin(subtransactions=True):
            if 'port_id' in fip or fip.get('description'):
                neutron_fip = super(NuagePlugin, self).update_floatingip(
                    context, id, floatingip)
            last_known_router_id = orig_fip['last_known_router_id']
            if fip.get('port_id'):
                if not neutron_fip['router_id']:
                    ret_msg = 'floating-ip is not associated yet'
                    raise n_exc.BadRequest(resource='floatingip',
                                           msg=ret_msg)
                if fip_rate_configured:
                    neutron_fip['nuage_fip_rate'] = fip_rate

                try:
                    self._create_update_floatingip(context,
                                                   neutron_fip,
                                                   fip['port_id'],
                                                   last_known_router_id)
                    self.update_floatingip_status(
                        context, neutron_fip['id'],
                        os_constants.FLOATINGIP_STATUS_ACTIVE)
                    neutron_fip['status'] = (
                        os_constants.FLOATINGIP_STATUS_ACTIVE)
                except nuage_exc.OperationNotSupported:
                    with excutils.save_and_reraise_exception():
                        router_ids = super(
                            NuagePlugin, self).disassociate_floatingips(
                                context, fip['port_id'], do_notify=False)
                except n_exc.BadRequest:
                    with excutils.save_and_reraise_exception():
                        super(NuagePlugin, self).delete_floatingip(
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
                    self.nuageclient.update_nuage_vm_vport(params)
                    self.nuageclient.delete_rate_limiting(
                        nuage_vport['ID'], fip['id'])
                    self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                           'disassociated from port %s'
                                           % (id, fip['tenant_id'], port_id))

                self.update_floatingip_status(
                    context, neutron_fip['id'],
                    os_constants.FLOATINGIP_STATUS_DOWN)
                neutron_fip['status'] = os_constants.FLOATINGIP_STATUS_DOWN

        # purely rate limit update. Use existing port data.
        if 'port_id' not in fip and fip_rate_configured:
            if not port_id:
                msg = _('Rate limiting requires the floating ip to be '
                        'associated to a port.')
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
            # Add QOS to port for rate limiting
            nuage_vport = self._get_vport_for_fip(context, port_id)

            orig_fip['nuage_fip_rate'] = fip_rate

            self.nuageclient.create_update_rate_limiting(
                orig_fip['nuage_fip_rate'], nuage_vport['ID'],
                orig_fip['id'])
            self.fip_rate_log.info(
                'FIP %s (owned by tenant %s) rate limit updated to %s Mb/s'
                % (orig_fip['id'], orig_fip['tenant_id'],
                   (orig_fip['nuage_fip_rate']
                    if (orig_fip['nuage_fip_rate'] is not None
                        and orig_fip['nuage_fip_rate'] != -1)
                    else "unlimited")))
            neutron_fip['nuage_fip_rate'] = orig_fip['nuage_fip_rate']
        elif not fip_rate_configured:
            neutron_fip = self.get_floatingip(context, id)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)

        return neutron_fip

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_floatingip(self, context, fip_id):
        fip = self._get_floatingip(context, fip_id)
        port_id = fip['fixed_port_id']
        with context.session.begin(subtransactions=True):
            if port_id:
                nuage_vport = self._get_vport_for_fip(context, port_id,
                                                      required=False)
                if nuage_vport and nuage_vport['ID'] is not None:
                    params = {
                        'nuage_vport_id': nuage_vport['ID'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(params)
                    LOG.debug("Floating-ip %(fip)s is disassociated from "
                              "vport %(vport)s",
                              {'fip': fip_id,
                               'vport': nuage_vport['ID']})
                    self.nuageclient.delete_rate_limiting(
                        nuage_vport['ID'], fip_id)
                    self.fip_rate_log.info('FIP %s (owned by tenant %s) '
                                           'disassociated from port %s'
                                           % (fip_id, fip['tenant_id'],
                                              port_id))

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
                nuage_fip = self.nuageclient.get_nuage_fip_by_id(params)
                if nuage_fip:
                    self.nuageclient.delete_nuage_floatingip(
                        nuage_fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

            super(NuagePlugin, self).delete_floatingip(context, fip_id)
            self.fip_rate_log.info('FIP %s (owned by tenant %s) deleted' %
                                   (fip_id, fip['tenant_id']))

    def _get_vport_for_fip(self, context, port_id,
                           vport_type=constants.VM_VPORT,
                           vport_id=None, required=True):
        port = self.get_port(context, port_id)
        if not port['fixed_ips']:
            return

        vport = None
        params = {
            'neutron_port_id': port_id,
            'nuage_vport_type': vport_type,
            'nuage_vport_id': vport_id
        }
        try:
            vport = self.nuageclient.get_nuage_port_by_id(params)
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
        if subnet_mapping['nuage_l2dom_tmplt_id']:
            params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        return self.nuageclient.get_nuage_vport_by_neutron_id(
            params, required=required)

    def _process_fip_to_vip(self, context, port_id, nuage_fip_id=None):
        port = self._get_port(context, port_id)
        params = {
            'nuage_fip_id': nuage_fip_id,
            'neutron_subnet_id': port['fixed_ips'][0]['subnet_id'],
            'vip': port['fixed_ips'][0]['ip_address']
        }
        self.nuageclient.associate_fip_to_vips(params)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_security_group(self, context, id):
        filters = {'security_group_id': [id]}
        ports = self._get_port_security_group_bindings(context,
                                                       filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        self.nuageclient.delete_nuage_secgroup(id)
        LOG.debug("Deleted security group %s", id)

        super(NuagePlugin, self).delete_security_group(context, id)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def create_security_group_rule(self, context, security_group_rule):
        remote_sg = None
        sg_rule = security_group_rule['security_group_rule']
        self.nuageclient.validate_nuage_sg_rule_definition(sg_rule)
        sg_id = sg_rule['security_group_id']

        local_sg_rule = super(
            NuagePlugin, self).create_security_group_rule(
                context, security_group_rule)
        if local_sg_rule.get('remote_group_id'):
            remote_sg = self.get_security_group(
                context, local_sg_rule.get('remote_group_id'))
        try:
            nuage_policygroup = self.nuageclient.get_sg_policygroup_mapping(
                sg_id)
            if nuage_policygroup:
                sg_params = {
                    'sg_id': sg_id,
                    'neutron_sg_rule': local_sg_rule,
                    'policygroup': nuage_policygroup
                }
                if remote_sg:
                    sg_params['remote_group_name'] = remote_sg['name']
                self.nuageclient.create_nuage_sgrule(sg_params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin, self).delete_security_group_rule(
                    context, local_sg_rule['id'])

        return local_sg_rule

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def delete_security_group_rule(self, context, id):
        local_sg_rule = self.get_security_group_rule(context, id)
        super(NuagePlugin, self).delete_security_group_rule(context, id)
        self.nuageclient.delete_nuage_sgrule([local_sg_rule])
        LOG.debug("Deleted security group rule %s", id)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_subnet(self, context, id, fields=None):
        subnet = self.nuageclient.get_subnet_or_domain_subnet_by_id(
            id, required=True)
        vsd_subnet = {'id': subnet['ID'],
                      'name': subnet['name'],
                      'cidr': self._calc_cidr(subnet),
                      'gateway': subnet['gateway'],
                      'ip_version': subnet['IPType'],
                      'linked': self._is_subnet_linked(context.session,
                                                       subnet)}
        if subnet['type'] == constants.L3SUBNET:
            domain_id = self.nuageclient.get_router_by_domain_subnet_id(
                vsd_subnet['id'])
            netpart_id = self.nuageclient.get_router_np_id(domain_id)
        else:
            netpart_id = subnet['parentID']

        net_partition = self.nuageclient.get_net_partition_name_by_id(
            netpart_id)
        vsd_subnet['net_partition'] = net_partition
        return self._fields(vsd_subnet, fields)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_subnets(self, context, filters=None, fields=None):
        if 'vsd_zone_id' not in filters:
            msg = _('vsd_zone_id is a required filter parameter for this API.')
            raise n_exc.BadRequest(resource='vsd-subnets', msg=msg)
        l3subs = self.nuageclient.get_domain_subnet_by_zone_id(
            filters['vsd_zone_id'][0])
        vsd_to_os = {
            'subnet_id': 'id',
            'subnet_name': 'name',
            self._calc_cidr: 'cidr',
            'subnet_gateway': 'gateway',
            'subnet_iptype': 'ip_version',
            functools.partial(
                self._is_subnet_linked, context.session): 'linked',
            functools.partial(
                self._return_val, filters['vsd_zone_id'][0]): 'vsd_zone_id'
        }
        return self._trans_vsd_to_os(l3subs, vsd_to_os, filters, fields)

    def _calc_cidr(self, subnet):
        if (not subnet['address']) and (
                not subnet['associatedSharedNetworkResourceID']):
            return None

        shared_id = subnet['associatedSharedNetworkResourceID']
        if shared_id:
            subnet = self.nuageclient.get_nuage_sharedresource(shared_id)
        if subnet.get('address'):
            ip = netaddr.IPNetwork(subnet['address'] + '/' +
                                   subnet['netmask'])
            return str(ip)

    def _is_subnet_linked(self, session, subnet):
        if subnet['externalID']:
            return True

        l2dom_mapping = nuagedb.get_subnet_l2dom_by_nuage_id(
            session, subnet['ID'])
        return l2dom_mapping is not None

    @log_helpers.log_method_call
    def _get_default_net_partition(self, context):
        def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
        net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                          def_net_part)
        if not net_partition:
            msg = _("Default net_partition is not created at the start")
            raise n_exc.BadRequest(resource='netpartition', msg=msg)
        return net_partition

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_zones(self, context, filters=None, fields=None):
        if 'vsd_domain_id' not in filters:
            msg = _('vsd_domain_id is a required filter parameter for this '
                    'API.')
            raise n_exc.BadRequest(resource='vsd-zones', msg=msg)
        try:
            vsd_zones = self.nuageclient.get_zone_by_domainid(
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

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_domains(self, context, filters=None, fields=None):
        if 'vsd_organisation_id' not in filters:
            msg = _('vsd_organisation_id is a required filter parameter for '
                    'this API.')
            raise n_exc.BadRequest(resource='vsd-domains', msg=msg)
        vsd_domains = self.nuageclient.get_routers_by_netpart(
            filters['vsd_organisation_id'][0])
        vsd_l2domains = self.nuageclient.get_subnet_by_netpart(
            filters['vsd_organisation_id'][0])
        if vsd_domains:
            vsd_domains = [self._update_dict(vsd_domain, 'type', 'L3')
                           for vsd_domain in vsd_domains]
        if vsd_l2domains:
            vsd_l2domains = [self._update_dict(l2domain, 'type', 'L2')
                             for l2domain in vsd_l2domains
                             if self.l2domain_not_linked(context.session,
                                                         l2domain)]
        vsd_domains = ((vsd_domains if vsd_domains else [])
                       + (vsd_l2domains if vsd_l2domains else []))
        vsd_domains = [self._update_dict(vsd_domain, 'net_partition_id',
                                         filters['vsd_organisation_id'][0])
                       for vsd_domain in vsd_domains]
        vsd_to_os = {
            'domain_id': 'id',
            'domain_name': 'name',
            'type': 'type',
            'net_partition_id': 'net_partition_id'
        }
        return self._trans_vsd_to_os(vsd_domains, vsd_to_os, filters, fields)

    def l2domain_not_linked(self, session, l2domain):
        if l2domain['subnet_os_id']:
            return False

        l2dom_mapping = nuagedb.get_subnet_l2dom_by_nuage_id(
            session, l2domain['domain_id'])
        return l2dom_mapping is None

    def _update_dict(self, dict, key, val):
        dict[key] = val
        return dict

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def get_vsd_organisations(self, context, filters=None, fields=None):
        netpartitions = self.nuageclient.get_net_partitions()
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
                else:
                    os_obj[mapping[vsd_key]] = vsd_obj[vsd_key]

            if self._passes_filters(os_obj, filters):
                self._fields(os_obj, fields)
                os_list.append(os_obj)

        return os_list

    def _passes_filters(self, obj, filters):
        for filter in filters:
            if (filter in obj
                    and str(obj[filter]).lower() not in filters[filter]):
                return False
        return True

    def _return_val(self, val, dummy):
        return val

    def _filter_fields(self, subnet, fields):
        for key in subnet:
            if key not in fields:
                del subnet[key]
        return subnet

    def claim_fip_for_domain_from_shared_resource(self, context, id,
                                                  rtr_id, vpn_id):
        fip_pool = self.nuageclient.get_nuage_fip_pool_by_id(id)
        if not fip_pool:
            msg = _('sharedresource %s not found on VSD') % id
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, rtr_id)
        if not ent_rtr_mapping:
            msg = _('router %s is not associated with '
                    'any net-partition') % rtr_id
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)
        params = {
            'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
            'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
            'vpn_id': vpn_id
        }
        nuage_fip = self.nuageclient.create_nuage_fip_for_vpnaas(params)
        return nuage_fip

    def associate_fip_to_dummy_port(self, context, nuage_fip, port_id, rtr_id):
        nuage_vport = self._get_vport_for_fip(context, port_id)
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, rtr_id)
        if nuage_vport:
            if (nuage_vport['nuage_domain_id']) != (
                    ent_rtr_mapping['nuage_router_id']):
                msg = _('Floating IP can not be associated to port in '
                        'different router context')
                raise nuage_exc.OperationNotSupported(msg=msg)
        nuage_fip_id = nuage_fip['ID']
        params = {
            'nuage_vport_id': nuage_vport['nuage_vport_id'],
            'nuage_fip_id': nuage_fip_id
        }
        if nuage_fip['assigned']:
            n_vport = self.nuageclient.get_vport_assoc_with_fip(
                nuage_fip_id)
            if n_vport and not n_vport['hasAttachedInterfaces']:
                disassoc_params = {
                    'nuage_vport_id': n_vport['ID'],
                    'nuage_fip_id': None
                }
                self.nuageclient.update_nuage_vm_vport(disassoc_params)
        self.nuageclient.update_nuage_vm_vport(params)

    def get_active_routers_for_host(self, context, host=None):
        return self.get_routers(context)

    def add_rules_vpn_ping(self, context, rtr_id, remote_subn, port):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, rtr_id)
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']
        route = {
            'nexthop': port['fixed_ips'][0]['ip_address'],
            'destination': remote_subn
        }
        self._add_nuage_static_route(rtr_id, nuage_domain_id, route)
        nuage_port = self._get_reqd_nauge_vport_params(context, port)
        if nuage_port:
            self.nuageclient.update_mac_spoofing_on_vport(
                nuage_port['nuage_vport_id'], constants.ENABLED)

    def remove_rules_vpn_ping(self, context, rtr_id, remote_subn, nexthop):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, rtr_id)
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']

        if not ent_rtr_mapping:
            msg = _('router %s is not associated with '
                    'any net-partition') % rtr_id
            raise n_exc.BadRequest(resource='', msg=msg)

        route = {
            'nexthop': nexthop,
            'destination': remote_subn
        }
        self._delete_nuage_static_route(nuage_domain_id, route)

    def _get_reqd_nauge_vport_params(self, context, port, create_ipsec=True):
        l2dom_id = None
        l3dom_id = None
        sub_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, sub_id)
        netpart_id = subnet_mapping['net_partition_id']
        net_partition = nuagedb.get_net_partition_by_id(
            context.session, netpart_id)
        if subnet_mapping['nuage_l2dom_tmplt_id']:
            l2dom_id = subnet_mapping['nuage_subnet_id']
        else:
            l3dom_id = subnet_mapping['nuage_subnet_id']
        port_params = {
            'neutron_port_id': port['id'],
            'l2dom_id': l2dom_id,
            'l3dom_id': l3dom_id
        }
        subn = self.get_subnet(context, sub_id)
        nuage_port = (self.nuageclient.get_nuage_vport_by_id(port_params)
                      if create_ipsec
                      else self.nuageclient.get_nuage_port_by_id(port_params))
        nuage_port['net_partition'] = net_partition
        nuage_port['subn'] = subn
        nuage_port['l2dom_id'] = l2dom_id
        nuage_port['l3dom_id'] = l3dom_id
        return nuage_port

    def delete_dummy_vm_if(self, context, port):
        nuage_port = self._get_reqd_nauge_vport_params(context, port, False)
        if nuage_port:
            nuage_vif_id = nuage_port['nuage_vif_id']
            params = {
                'no_of_ports': 1,
                'netpart_name': nuage_port['net_partition']['name'],
                'mac': port['mac_address'],
                'tenant': port['tenant_id'],
                'nuage_vif_id': nuage_vif_id,
                'id': port['id'],
                'subn_tenant': nuage_port['subn']['tenant_id'],
                'l2dom_id': nuage_port['l2dom_id'],
                'l3dom_id': nuage_port['l3dom_id'],
                'portOnSharedSubn': nuage_port['subn']['shared']
            }
            self.nuageclient.delete_vms(params)

    def rtr_in_def_ent(self, context, rtr_id):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
            context.session, rtr_id)
        if ent_rtr_mapping['net_partition_id'] == self.default_np_id:
            return True
