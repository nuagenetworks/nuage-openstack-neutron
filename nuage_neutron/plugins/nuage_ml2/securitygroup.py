# Copyright 2018 NOKIA
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

from neutron.db import securitygroups_db as sg_db
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import utils as nuage_utils

LOG = logging.getLogger(__name__)


class NuageSecurityGroup(base_plugin.BaseNuagePlugin,
                         sg_db.SecurityGroupDbMixin):
    def __init__(self):
        super(NuageSecurityGroup, self).__init__()
        self._l2_plugin = None

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    @registry.receives(resources.SECURITY_GROUP, [events.AFTER_UPDATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_security_group_postcommit(self, resource, event, trigger,
                                         payload):
        sg_id = payload.resource_id
        original_name = payload.states[0]['name']
        updated_name = payload.latest_state.get('name')
        if updated_name is not None and original_name != updated_name:
            # Update PG description
            updates = {
                'description': updated_name
            }
            self.vsdclient.update_security_group(sg_id, updates)

    @registry.receives(resources.SECURITY_GROUP, [events.AFTER_DELETE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def post_delete_security_group(self, resource, event, trigger, payload):
        self.vsdclient.delete_security_group(payload.resource_id)

    @registry.receives(resources.SECURITY_GROUP_RULE, [events.AFTER_CREATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def post_create_security_group_rule(self, resource, event, trigger,
                                        payload):
        context = payload.context
        sg_rule = payload.latest_state
        sg_id = sg_rule["security_group_id"]
        sg = self.core_plugin.get_security_group(context, sg_id)
        remote_sgs = []
        if sg_rule.get('remote_group_id'):
            remote_sgs = nuage_utils.collect_all_remote_security_groups(
                self.core_plugin, context,
                sg_rule.get('remote_group_id'), set())

        # There is no additional creation of this SG, only addition of this
        # rule + creation of remote_sgs in relevant domains if necessary.
        with nuage_utils.rollback() as on_exception:
            # Delete security group rule on exception
            on_exception(
                self.core_plugin.delete_security_group_rule, context,
                sg_rule['id'])
            self.vsdclient.create_security_group_rule(sg, sg_rule,
                                                      on_exception,
                                                      remote_sgs=remote_sgs)

    @registry.receives(resources.SECURITY_GROUP_RULE, [events.BEFORE_DELETE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_delete_security_group_rule(self, resource, event, trigger,
                                       payload):
        context = payload.context
        sgr_id = payload.resource_id
        sg_rule = self.core_plugin.get_security_group_rule(context, sgr_id)
        self.vsdclient.delete_security_group_rule(sg_rule)
