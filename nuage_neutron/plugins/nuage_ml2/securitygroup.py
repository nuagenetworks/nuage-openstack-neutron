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

from neutron.db.common_db_mixin import CommonDbMixin
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import uuidutils

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils

LOG = logging.getLogger(__name__)


class NuageSecurityGroup(base_plugin.BaseNuagePlugin,
                         CommonDbMixin,
                         sg_db.SecurityGroupDbMixin):
    def __init__(self):
        super(NuageSecurityGroup, self).__init__()
        self._l2_plugin = None
        self.stateful = None
        self.sg_name_before_update = None

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    @registry.receives(resources.SECURITY_GROUP, [events.BEFORE_CREATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_create_security_group(self, resource, event, trigger, **kwargs):
        session = kwargs['context'].session
        stateful = kwargs['security_group'].get('stateful', True)
        kwargs['security_group']['id'] = sg_id = \
            kwargs['security_group'].get('id') or uuidutils.generate_uuid()
        if not stateful:
            nuagedb.set_nuage_sg_parameter(session, sg_id, 'STATEFUL', '0')

    @registry.receives(resources.SECURITY_GROUP, [events.PRECOMMIT_DELETE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_security_group_precommit(self, resource, event, trigger,
                                        **kwargs):
        session = kwargs['context'].session
        sg_id = kwargs['security_group_id']
        nuagedb.delete_nuage_sg_parameter(session, sg_id, 'STATEFUL')

    @registry.receives(resources.SECURITY_GROUP, [events.BEFORE_UPDATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_update_security_group(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        sg_id = kwargs['security_group_id']
        current = self.get_security_group(context, sg_id)
        self.sg_name_before_update = current['name']
        sg = kwargs['security_group']
        if 'stateful' in sg and sg['stateful'] != current['stateful']:
            self._check_for_security_group_in_use(context, sg_id)
            self.stateful = kwargs['security_group']['stateful']

    @registry.receives(resources.SECURITY_GROUP, [events.PRECOMMIT_UPDATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_security_group_precommit(self, resource, event, trigger,
                                        payload):
        session = payload.context.session
        sg_id = payload.resource_id
        sg = payload.desired_state
        if self.stateful is not None:
            self._update_stateful_parameter(session, sg_id, self.stateful)
            sg['stateful'] = self.stateful
            self.stateful = None

    @registry.receives(resources.SECURITY_GROUP, [events.AFTER_UPDATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_security_group_postcommit(self, resource, event, trigger,
                                         **kwargs):
        sg_id = kwargs['security_group_id']
        original_name = kwargs['original_security_group']['name']
        updated_name = kwargs['security_group'].get('name')
        if updated_name is not None and original_name != updated_name:
            # Update PG description
            updates = {
                'description': kwargs['security_group']['name']
            }
            self.vsdclient.update_security_group(sg_id, updates)

    @registry.receives(resources.SECURITY_GROUP, [events.AFTER_DELETE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def post_delete_security_group(self, resource, event, trigger, **kwargs):
        self.vsdclient.delete_security_group(kwargs['security_group_id'])

    @registry.receives(resources.SECURITY_GROUP_RULE, [events.AFTER_CREATE])
    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def post_create_security_group_rule(self, resource, event, trigger,
                                        **kwargs):
        context = kwargs['context']
        sg_rule = kwargs['security_group_rule']
        sg_id = sg_rule['security_group_id']
        sg = self.core_plugin.get_security_group(context, sg_id)
        param = nuagedb.get_nuage_sg_parameter(
            context.session, sg['id'], 'STATEFUL')
        sg['stateful'] = not (param and param.parameter_value == '0')
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
                                       **kwargs):
        context = kwargs['context']
        id = kwargs['security_group_rule_id']
        sg_rule = self.core_plugin.get_security_group_rule(context, id)
        self.vsdclient.delete_security_group_rule(sg_rule)

    def _check_for_security_group_in_use(self, context, sg_id):
        filters = {'security_group_id': [sg_id]}
        bound_ports = self._get_port_security_group_bindings(context, filters)
        if bound_ports:
            raise ext_sg.SecurityGroupInUse(id=sg_id)

    @staticmethod
    def _update_stateful_parameter(session, sg_id, stateful):
        if stateful:
            nuagedb.delete_nuage_sg_parameter(session, sg_id, 'STATEFUL')
        else:
            nuagedb.set_nuage_sg_parameter(session, sg_id, 'STATEFUL', '0')
