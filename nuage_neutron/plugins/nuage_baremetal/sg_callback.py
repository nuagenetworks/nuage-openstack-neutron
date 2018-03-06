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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.extensions import portbindings
from neutron.extensions import portsecurity
from neutron.extensions import securitygroup as ext_sg
from neutron.manager import NeutronManager

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.plugins.common.utils import SubnetUtilsBase

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

LOG = logging.getLogger(__name__)


class NuageBmSecurityGroupHandler(SubnetUtilsBase):

    _core_plugin = None

    def __init__(self, client):
        self.client = client
        self.subscribe()

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = NeutronManager.get_plugin()
        return self._core_plugin

    def _supported_vnic_types(self):
        """Vnic type current driver does handle"""
        return [portbindings.VNIC_BAREMETAL]

    def _get_nuage_vport(self, port, subnet_mapping, required=True):
        port_params = {'neutron_port_id': port['id']}
        if self._is_l2(subnet_mapping):
            port_params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            port_params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        return self.client.get_nuage_vport_by_neutron_id(
            port_params, required=required)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def pre_delete_security_group_rule(self, resource,
                                       event, trigger, **kwargs):
        context = kwargs['context']
        id = kwargs['security_group_rule_id']
        local_sg_rule = self.core_plugin.get_security_group_rule(context, id)
        self.client.delete_nuage_sgrule([local_sg_rule], constants.HARDWARE)

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def pre_create_security_group_rule(self, resource,
                                       event, trigger, **kwargs):
        self.client.validate_nuage_sg_rule_definition(
            kwargs['security_group_rule'])

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def post_create_security_group_rule(self, resource,
                                        event, trigger, **kwargs):
        remote_sg = None
        context = kwargs['context']
        sg_rule = kwargs['security_group_rule']
        sg_id = sg_rule['security_group_id']

        if sg_rule.get('remote_group_id'):
            remote_sg = self.core_plugin.get_security_group(
                context, sg_rule.get('remote_group_id'))
        try:
            nuage_policygroup = self.client.get_sg_policygroup_mapping(
                sg_id, sg_type=constants.HARDWARE)
            if nuage_policygroup:
                sg_params = {
                    'neutron_sg_rule': sg_rule,
                    'policygroup': nuage_policygroup,
                    'sg_type': constants.HARDWARE
                }
                if remote_sg:
                    sg_params['remote_group_name'] = remote_sg['name']
                self.client.create_nuage_sgrule(sg_params)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.core_plugin.delete_security_group_rule(context,
                                                            sg_rule['id'])

    @nuage_utils.handle_nuage_api_error
    @log_helpers.log_method_call
    def pre_delete_security_group(self, resource, event, trigger, **kwargs):
        self.client.delete_nuage_secgroup(kwargs['security_group_id'])

    def post_port_create(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        port = kwargs['port']
        if (port.get(portbindings.VNIC_TYPE, "")
                not in self._supported_vnic_types()):
            return

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if self._is_vsd_mgd(subnet_mapping):
            return

        if port[ext_sg.SECURITYGROUPS]:
            vsd_subnet = self.client.get_nuage_subnet_by_mapping(
                subnet_mapping)
            vport = self._get_nuage_vport(port, subnet_mapping,
                                          required=False)
            self._process_port_security_group(context,
                                              port,
                                              vport,
                                              port[ext_sg.SECURITYGROUPS],
                                              vsd_subnet)

    def post_port_update(self, context, port, original):
        update_sg = True
        if (port.get(portbindings.VNIC_TYPE)
                not in self._supported_vnic_types() and
                original.get(portbindings.VNIC_TYPE)
                not in self._supported_vnic_types()):
            return

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)

        if self._is_vsd_mgd(subnet_mapping):
            return

        new_sg = (set(port.get(ext_sg.SECURITYGROUPS)) if
                  port.get(ext_sg.SECURITYGROUPS) else set())
        orig_sg = (set(original.get(ext_sg.SECURITYGROUPS)) if
                   original.get(ext_sg.SECURITYGROUPS) else set())
        if not new_sg and new_sg == orig_sg:
            update_sg = False
        if update_sg:
            vsd_subnet = self.client.get_nuage_subnet_by_mapping(
                subnet_mapping)
            vport = self._get_nuage_vport(port, subnet_mapping,
                                          required=False)
            self._process_port_security_group(
                context,
                port,
                vport,
                port[ext_sg.SECURITYGROUPS],
                vsd_subnet)

            deleted_sg_ids = (set(original[ext_sg.SECURITYGROUPS]) -
                              set(port[ext_sg.SECURITYGROUPS]))
            self.client.check_unused_policygroups(deleted_sg_ids,
                                                  sg_type=constants.HARDWARE)
            self.client.check_unused_policygroups(
                set(original[ext_sg.SECURITYGROUPS]))

    def post_port_delete(self, resource, event, trigger, **kwargs):
        port = kwargs['port']
        if (port.get(portbindings.VNIC_TYPE, "")
                not in self._supported_vnic_types()):
            return
        context = kwargs['context']
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if self._is_vsd_mgd(subnet_mapping):
            return

        securitygroups = port.get(ext_sg.SECURITYGROUPS, [])
        self.client.check_unused_policygroups(securitygroups,
                                              sg_type=constants.HARDWARE)

    @log_helpers.log_method_call
    def _process_port_security_group(self, context, port, vport, sg_ids,
                                     vsd_subnet):
        if len(sg_ids) > 6:
            msg = ("Exceeds maximum num of security groups on a port "
                   "supported on nuage VSP")
            raise nuage_exc.NuageBadRequest(msg=msg)

        if not port.get('fixed_ips'):
            return
        vnic_type = port.get(portbindings.VNIC_TYPE, "")
        policygroup_ids = []
        for sg_id in sg_ids:
            sg = self.core_plugin._get_security_group(context, sg_id)
            sg_rules = self.core_plugin.get_security_group_rules(
                context,
                {'security_group_id': [sg_id]})
            sg_params = {
                'vsd_subnet': vsd_subnet,
                'sg': sg,
                'sg_rules': sg_rules,
                'sg_type': constants.HARDWARE
            }
            if vnic_type in self._supported_vnic_types():
                vsd_policygroup_id = (
                    self.client.process_port_create_security_group(
                        sg_params))
                policygroup_ids.append(vsd_policygroup_id)
        if vnic_type in self._supported_vnic_types():
            if vport and port.get(portsecurity.PORTSECURITY):
                self.client.update_vport_policygroups(
                    vport['ID'], policygroup_ids)

    def subscribe(self):
        registry.subscribe(self.post_port_create,
                           resources.PORT, events.AFTER_CREATE)
        registry.subscribe(self.post_port_delete,
                           resources.PORT, events.AFTER_DELETE)

        registry.subscribe(self.pre_delete_security_group,
                           resources.SECURITY_GROUP,
                           events.BEFORE_DELETE)
        registry.subscribe(self.pre_create_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.BEFORE_CREATE)
        registry.subscribe(self.post_create_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_CREATE)
        registry.subscribe(self.pre_delete_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.BEFORE_DELETE)
