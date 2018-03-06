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

import inspect
from oslo_config import cfg
from oslo_log import log as logging
import stevedore

from neutron._i18n import _
from neutron.extensions import securitygroup as ext_sg
from neutron.services.trunk import constants as t_const
from neutron_lib.api.definitions import port_security as portsecurity
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import api

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import ignore_no_update
from nuage_neutron.plugins.common.utils import ignore_not_found
from nuage_neutron.plugins.nuage_baremetal import portsecurity as psechandler
from nuage_neutron.plugins.nuage_baremetal import sg_callback
from nuage_neutron.plugins.nuage_baremetal import trunk_driver

LOG = logging.getLogger(__name__)
TRUNK_DEVICE_OWNER = t_const.TRUNK_SUBPORT_OWNER

driver_opts = [
    cfg.StrOpt('provisioning_driver',
               default='nuage_gateway_bridge',
               help=_("Network provisioning driver for "
                      "baremetal/sriov instances"))]

cfg.CONF.register_opts(driver_opts, "baremetal")


class NuageBaremetalMechanismDriver(base_plugin.RootNuagePlugin,
                                    api.MechanismDriver):
    """Ml2 Mechanism driver interface

    for provisioning baremetal instances.
    """

    def initialize(self):
        LOG.debug('Initializing driver')
        self.conf = cfg.CONF
        self.init_vsd_client()
        self._wrap_vsdclient()
        self._core_plugin = None
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}
        self.sec_handler = sg_callback.NuageBmSecurityGroupHandler(
            self.vsdclient)
        self.psec_handler = psechandler.NuagePortSecurityHandler(
            self.vsdclient)
        self.np_driver = self._load_driver()
        self.trunk_driver = trunk_driver.NuageTrunkDriver.create(self)
        LOG.debug('Initializing complete')

    def _load_driver(self):
        """Loads back end network provision driver from configuration."""
        driver_name = self.conf.baremetal.provisioning_driver
        try:
            extension_manager = stevedore.driver.DriverManager(
                'neutron.ml2.baremetal.provisioning_driver',
                driver_name,
                invoke_on_load=True)
        except RuntimeError:
            raise exceptions.NuageDriverNotFound(
                driver_name=driver_name)
        return extension_manager.driver

    def _wrap_vsdclient(self):
        """Wraps nuagecient methods with try-except to ignore certain errors.

        When updating an entity on the VSD and there is nothing to actually
        update because the values don't change, VSD will throw an error. This
        is not needed for neutron so all these exceptions are ignored.

        When VSD responds with a 404, this is sometimes good (for example when
        trying to update an entity). Yet sometimes this is not required to be
        an actual exception. When deleting an entity that does no longer exist
        it is fine for neutron. Also when trying to retrieve something from VSD
        having None returned is easier to work with than RESTProxy exceptions.
        """

        methods = inspect.getmembers(self.vsdclient,
                                     lambda x: inspect.ismethod(x))
        for m in methods:
            wrapped = ignore_no_update(m[1])
            if m[0].startswith('get_') or m[0].startswith('delete_'):
                wrapped = ignore_not_found(wrapped)
            setattr(self.vsdclient, m[0], wrapped)

    def _segmentation_id(self, context, port):
        # Calculate segmentation id to be used at port create
        if (port.get('device_owner') == TRUNK_DEVICE_OWNER and
                port.get(portbindings.PROFILE)):
            return port[portbindings.PROFILE]['vlan']

        network = self.core_plugin.get_network(context,
                                               port.get('network_id'))
        is_vlan_transparant = (network.get('vlan_transparent')
                               if network is not None else False)
        if is_vlan_transparant:
            return 4095
        else:
            return 0

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_precommit(self, context):
        port = context.current
        db_context = context._plugin_context
        if (port.get(portbindings.VNIC_TYPE, "")
                not in self._supported_vnic_types()):
            return
        self._validate_fixed_ip(context)
        self._validate_security_groups(context)
        self._validate_nuage_l2bridges(db_context, port)

    @handle_nuage_api_errorcode
    @utils.context_log
    def create_port_postcommit(self, context):
        """create_port_postcommit."""
        port = context.current
        if self._can_bind(context):
            if port['binding:host_id']:
                port_dict = self._make_port_dict(context)
                self.np_driver.create_port(port_dict)
                if (not port[portsecurity.PORTSECURITY]):
                    self.psec_handler.process_port_security(
                        context._plugin_context, port)

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_port_precommit(self, context):
        port = context.current
        original = context.original
        if (port.get(portbindings.VNIC_TYPE, "")
                not in self._supported_vnic_types()):
            return
        self._validate_fixed_ip(context)
        self._validate_security_groups(context)
        host_added = host_removed = vnic_type_changed = psec_changed = False
        if original['binding:host_id'] and not port['binding:host_id']:
            host_removed = True
        if not original['binding:host_id'] and port['binding:host_id']:
            host_added = True
        if (port.get(portbindings.VNIC_TYPE, "") !=
                original.get(portbindings.VNIC_TYPE, "")):
            vnic_type_changed = True
        if (original.get(portsecurity.PORTSECURITY) !=
                port.get(portsecurity.PORTSECURITY)):
            psec_changed = True
        if vnic_type_changed:
            port_dict = self._make_port_dict(context)
            self.np_driver.update_port(port_dict)
        if host_removed:
            if (context.original.get('binding:vif_type') not in
                    [portbindings.VIF_TYPE_BINDING_FAILED,
                     portbindings.VIF_TYPE_UNBOUND]):
                port_dict = self._make_port_dict(context,
                                                 port=context.original)
                self.np_driver.delete_port(port_dict)
        elif host_added:
            port_dict = self._make_port_dict(context)
            self.np_driver.create_port(port_dict)

        if ((psec_changed and port.get('binding:host_id')) or
                (host_added and not port[portsecurity.PORTSECURITY])):
            self.psec_handler.process_port_security(
                context._plugin_context, port)

    @utils.context_log
    def delete_port_precommit(self, context):
        """delete_port_postcommit."""
        if (context.current.get(portbindings.VNIC_TYPE, "")
                in self._supported_vnic_types()):
            try:
                vif_details = context.current.get('binding:vif_details')
                if vif_details:
                    port_dict = self._make_port_dict(context)
                    if port_dict:
                        self.np_driver.delete_port(port_dict)
            except Exception as e:
                raise e

    @utils.context_log
    def bind_port(self, context):
        """bind_port."""
        if context.binding_levels:
            return  # we've already got a top binding
        db_context = context._plugin_context
        port_id = context.current['id']
        for segment in context.segments_to_bind:
            if self._check_segment(segment, context):
                if self._can_bind(context):
                        vif_binding = self.vif_details
                        vif_binding['vlan'] = str(self._segmentation_id(
                            db_context, context.current))
                        context.set_binding(segment[api.ID],
                                            portbindings.VIF_TYPE_OTHER,
                                            vif_binding,
                                            status=n_const.PORT_STATUS_ACTIVE)
                        LOG.debug("port bind using segment for port %(port)s :"
                                  " %(vif_type)s",
                                  {'port': port_id,
                                   'vif_type': portbindings.VIF_TYPE_OTHER})
            else:
                LOG.debug("Ignoring segment %(seg)s  for port %(port)s",
                          {'seg': segment,
                           'port': port_id})

    def _validate_fixed_ip(self, context):
        port = context.current
        if len(port["fixed_ips"]) == 0:
            msg = ("Baremetal ports must belong to at least "
                   "one subnet.")
            raise exceptions.NuageBadRequest(msg=msg)

    def _validate_security_groups(self, context):
        port = context.current
        db_context = context._plugin_context
        subnet_id = port['fixed_ips'][0]['subnet_id']
        sg_ids = port[ext_sg.SECURITYGROUPS]
        if not sg_ids:
            return
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        subnet_id)
        if self._is_vsd_mgd(subnet_mapping):
            return
        normal_ports = nuagedb.get_port_bindings_for_sg(
            db_context.session,
            sg_ids,
            [portbindings.VNIC_NORMAL],
            bound_only=True)
        if len(normal_ports) > 0:
            msg = ("Security Groups for baremetal and normal ports "
                   "are mutualy exclusive")
            raise exceptions.NuageBadRequest(msg=msg)

        sg_rules = self.core_plugin.get_security_group_rules(
            db_context,
            {'security_group_id': sg_ids})
        bad_rule = next((rule for rule in sg_rules if rule['remote_group_id']),
                        None)
        if bad_rule:
            msg = ("Security Groups for baremetal ports can't have "
                   "rules with remote-group-id")
            raise exceptions.NuageBadRequest(msg=msg)

    def _check_segment(self, segment, context):
        """Verify a segment is valid for the current driver.

        Verify the requested segment is supported and return True or
        False to indicate this to callers.
        """
        network_type = segment[api.NETWORK_TYPE]
        return network_type in [n_const.TYPE_VXLAN]

    def _make_port_dict(self, context, port=None):
        """Get required info from neutron port.

        Combine everything to a single dict.
        """
        if not port:
            port = context.current
        port_id = port['id']
        network_id = port['network_id']
        subnet_mapping = self._validate_port(context._plugin_context,
                                             port)
        if not subnet_mapping:
            LOG.debug("_make_port_dict can not get subnet_mapping"
                      " for port %(port)s",
                      {'port': port})
            return None
        profile = self._get_binding_profile(port)
        host_id = port['binding:host_id']
        local_link_information = profile.get('local_link_information')
        port_dict = {'port':
                     {'id': port_id,
                      'name': port.get('name'),
                      'network_id': network_id,
                      'link_info': local_link_information,
                      'host_id': host_id,
                      'tenant_id': port['tenant_id'],
                      'fixed_ips': port['fixed_ips'],
                      'mac_address': port['mac_address'],
                      'port_security_enabled': port['port_security_enabled']
                      },
                     'subnet_mapping': subnet_mapping
                     }
        subnet = context._plugin.get_subnet(context._plugin_context,
                                            subnet_mapping['subnet_id'])
        port_dict['enable_dhcp'] = subnet['enable_dhcp']

        db_context = context._plugin_context
        port_dict['segmentation_id'] = self._segmentation_id(db_context,
                                                             port)

        LOG.debug("port dict  %(port_dict)s",
                  {'port_dict': port_dict})
        return port_dict

    def _get_binding_profile(self, port):
        profile = port.get(portbindings.PROFILE, {})
        if not profile:
            LOG.debug("Missing profile in port binding")
        return profile

    def _can_bind(self, context):
        """Check that all required binding info is present"""
        vnic_type = context.current.get(portbindings.VNIC_TYPE, "")
        if vnic_type not in self._supported_vnic_types():
            LOG.debug("Cannot bind due to unsupported vnic_type: %s",
                      vnic_type)
            return False
        binding_profile = self._get_binding_profile(context.current)
        if not binding_profile:
            return False
        local_link_information = binding_profile.get('local_link_information')
        if not local_link_information:
            LOG.debug("local_link_information list does not exist in profile")
            return False
        return True

    def _supported_vnic_types(self):
        """Vnic type current driver does handle"""
        return [portbindings.VNIC_BAREMETAL]

    def _validate_port(self, db_context, port):
        if 'fixed_ips' not in port or len(port.get('fixed_ips', [])) == 0:
            return False
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        subnet_id)
        return subnet_mapping

    def check_vlan_transparency(self, context):
        # Nuage baremetal vlan transparency support
        return True
