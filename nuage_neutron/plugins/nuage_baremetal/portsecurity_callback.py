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

from neutron_lib.api.definitions import port_security as portsecurity
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NuagePortSecurityHandler(object):

    _core_plugin = None

    def __init__(self, client):
        self.client = client
        self.subscribe()

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    def _supported_vnic_types(self):
        return [portbindings.VNIC_BAREMETAL]

    def _get_nuage_vport(self, port, subnet_mapping, required=True):
        port_params = {'neutron_port_id': port['id']}
        if subnet_mapping['nuage_l2dom_tmplt_id']:
            port_params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            port_params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        return self.client.get_nuage_vport_by_neutron_id(
            port_params, required=required)

    def _process_port_security(self, context, port):
        if (port.get(portbindings.VNIC_TYPE, "")
                not in self._supported_vnic_types()):
            return

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        vport = self._get_nuage_vport(port, subnet_mapping, required=False)
        if not vport:
            return
        if port.get(portsecurity.PORTSECURITY):
            self.client.update_vport_policygroups(vport['ID'], [])
            return

        l2dom_id, l3dom_id = get_l2_and_l3_sub_id(subnet_mapping)
        rtr_id = None
        if l3dom_id:
            rtr_id = (self.client.
                      get_nuage_domain_id_from_subnet(l3dom_id))

        params = {'l2dom_id': l2dom_id,
                  'l3dom_id': l3dom_id,
                  'rtr_id': rtr_id,
                  'type': '',
                  'sg_type': constants.HARDWARE}
        policygroup_id = self.client.create_nuage_sec_grp_for_port_sec(params)
        params = {'sg_id': policygroup_id,
                  'l2dom_id': l2dom_id,
                  'l3dom_id': l3dom_id,
                  'rtr_id': rtr_id,
                  'sg_type': constants.HARDWARE}
        self.client.create_nuage_sec_grp_rule_for_port_sec(params)

        self.client.update_vport_policygroups(vport['ID'], [policygroup_id])

    def post_port_create(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        port = kwargs['port']
        self._process_port_security(context, port)

    def post_port_update(self, resource, event, trigger, **kwargs):
        original_port = kwargs['original_port']
        updated_port = kwargs['port']
        if (original_port.get(portsecurity.PORTSECURITY) ==
                updated_port.get(portsecurity.PORTSECURITY)):
            return
        context = kwargs['context']
        self._process_port_security(context, updated_port)

    def subscribe(self):
        registry.subscribe(self.post_port_create,
                           resources.PORT, events.AFTER_CREATE)
        registry.subscribe(self.post_port_update,
                           resources.PORT, events.AFTER_UPDATE)
