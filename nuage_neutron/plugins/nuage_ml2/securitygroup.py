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

from neutron._i18n import _
from neutron.db.common_db_mixin import CommonDbMixin
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common import constants as nuage_constants
from nuage_neutron.vsdclient import restproxy

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

    def register(self):
        self.nuage_callbacks.subscribe(self.post_port_create,
                                       resources.PORT, constants.AFTER_CREATE)
        self.nuage_callbacks.subscribe(self.post_port_update,
                                       resources.PORT, constants.AFTER_UPDATE)
        self.nuage_callbacks.subscribe(self.post_port_delete,
                                       resources.PORT, constants.AFTER_DELETE)
        registry.subscribe(self.pre_create_security_group,
                           resources.SECURITY_GROUP,
                           events.BEFORE_CREATE)
        registry.subscribe(self.pre_delete_security_group,
                           resources.SECURITY_GROUP,
                           events.BEFORE_DELETE)
        registry.subscribe(self.delete_security_group_precommit,
                           resources.SECURITY_GROUP,
                           events.PRECOMMIT_DELETE)
        registry.subscribe(self.pre_update_security_group,
                           resources.SECURITY_GROUP,
                           events.BEFORE_UPDATE)
        registry.subscribe(self.update_security_group_precommit,
                           resources.SECURITY_GROUP,
                           events.PRECOMMIT_UPDATE)
        registry.subscribe(self.update_security_group_postcommit,
                           resources.SECURITY_GROUP,
                           events.AFTER_UPDATE)
        registry.subscribe(self.pre_create_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.BEFORE_CREATE)
        registry.subscribe(self.post_create_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_CREATE)
        registry.subscribe(self.pre_delete_security_group_rule,
                           resources.SECURITY_GROUP_RULE,
                           events.BEFORE_DELETE)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_create_security_group(self, resource, event, trigger, **kwargs):
        session = kwargs['context'].session
        stateful = kwargs['security_group'].get('stateful', True)
        kwargs['security_group']['id'] = sg_id = \
            kwargs['security_group'].get('id') or uuidutils.generate_uuid()
        if not stateful:
            nuagedb.set_nuage_sg_parameter(session, sg_id, 'STATEFUL', '0')

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_delete_security_group(self, resource, event, trigger, **kwargs):
        sg_id = kwargs['security_group_id']
        self.vsdclient.delete_nuage_secgroup(sg_id)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_security_group_precommit(self, resource, event, trigger,
                                        **kwargs):
        session = kwargs['context'].session
        sg_id = kwargs['security_group_id']
        nuagedb.delete_nuage_sg_parameter(session, sg_id, 'STATEFUL')

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

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_security_group_precommit(self, resource, event, trigger,
                                        **kwargs):
        if 'payload' in kwargs:
            session = kwargs['payload'].context.session
            sg_id = kwargs['payload'].resource_id
            sg = kwargs['payload'].desired_state
        else:
            session = kwargs['context'].session
            sg_id = kwargs['security_group_id']
            sg = kwargs['security_group']
        if self.stateful is not None:
            self._update_stateful_parameter(session, sg_id, self.stateful)
            sg['stateful'] = self.stateful
            self.stateful = None

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_security_group_postcommit(self, resource, event, trigger,
                                         **kwargs):
        sg_id = kwargs['security_group_id']
        if ('name' in kwargs['security_group'] and
                kwargs['security_group']['name'] !=
                self.sg_name_before_update):
            data = {
                'description': kwargs['security_group']['name']
            }
            nuage_policygroups = (
                self.vsdclient.get_sg_policygroup_by_external_id(sg_id))
            for nuage_policy in nuage_policygroups:
                self.vsdclient.update_policygroup(nuage_policy['ID'],
                                                  data)
            nuage_hw_policygroups = (
                self.vsdclient.get_sg_policygroup_by_external_id(
                    sg_id,
                    sg_type=constants.HARDWARE))
            for nuage_policy in nuage_hw_policygroups:
                self.vsdclient.update_policy_group(nuage_policy['ID'],
                                                   data)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_create_security_group_rule(self, resource, event, trigger,
                                       **kwargs):
        self.vsdclient.validate_nuage_sg_rule_definition(
            kwargs['security_group_rule'])

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def post_create_security_group_rule(self, resource, event, trigger,
                                        **kwargs):
        remote_sg = None
        context = kwargs['context']
        sg_rule = kwargs['security_group_rule']
        sg_id = sg_rule['security_group_id']

        if sg_rule.get('remote_group_id'):
            remote_sg = self.core_plugin.get_security_group(
                context, sg_rule.get('remote_group_id'))
        try:
            nuage_policygroup = self.vsdclient.get_sg_policygroup_mapping(
                sg_id)
            if nuage_policygroup:
                sg_params = {
                    'sg_id': sg_id,
                    'neutron_sg_rule': sg_rule,
                    'policygroup': nuage_policygroup,
                }
                if remote_sg:
                    sg_params['remote_group_name'] = remote_sg['name']
                self.vsdclient.create_nuage_sgrule(sg_params)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.core_plugin.delete_security_group_rule(context,
                                                            sg_rule['id'])

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def pre_delete_security_group_rule(self, resource, event, trigger,
                                       **kwargs):
        context = kwargs['context']
        id = kwargs['security_group_rule_id']
        local_sg_rule = self.core_plugin.get_security_group_rule(context, id)
        self.vsdclient.delete_nuage_sgrule([local_sg_rule])

    def post_port_create(self, resource, event, trigger, context, port, vport,
                         subnet_mapping, **kwargs):
        if self._is_vsd_mgd(subnet_mapping):
            return

        if port[ext_sg.SECURITYGROUPS]:
            vsd_subnet = self._find_vsd_subnet(context, subnet_mapping)
            if vsd_subnet:
                self._process_port_security_group(context,
                                                  port,
                                                  vport,
                                                  port[ext_sg.SECURITYGROUPS],
                                                  vsd_subnet,
                                                  subnet_mapping)

    def post_port_update(self, resource, event, trigger, context, port,
                         original_port, vport, rollbacks, subnet_mapping,
                         **kwargs):
        if self._is_vsd_mgd(subnet_mapping):
            return
        new_sg = (set(port.get(ext_sg.SECURITYGROUPS)) if
                  port.get(ext_sg.SECURITYGROUPS) else set())
        if (port.get(ext_sg.SECURITYGROUPS) !=
                original_port.get(ext_sg.SECURITYGROUPS)):
            vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                subnet_mapping)
            self._process_port_security_group(context,
                                              port,
                                              vport,
                                              new_sg,
                                              vsd_subnet,
                                              subnet_mapping)
            rollbacks.append((self._process_port_security_group,
                              [context, port, vport,
                               original_port[ext_sg.SECURITYGROUPS],
                               vsd_subnet, subnet_mapping],
                              {}))
            deleted_sg_ids = (set(original_port[ext_sg.SECURITYGROUPS]) -
                              set(port[ext_sg.SECURITYGROUPS]))
            self.vsdclient.check_unused_policygroups(deleted_sg_ids)

    def post_port_delete(self, resource, event, trigger, **kwargs):
        port = kwargs['port']
        subnet_mapping = kwargs['subnet_mapping']
        if self._is_vsd_mgd(subnet_mapping):
            return

        securitygroups = port.get(ext_sg.SECURITYGROUPS, [])
        successful = False
        attempt = 1
        while not successful:
            try:
                self.vsdclient.check_unused_policygroups(securitygroups)
                successful = True
            except restproxy.RESTProxyError as e:
                msg = e.msg.lower()
                if (e.code not in (404, 409) and 'policygroup' not in msg and
                        'policy group' not in msg):
                    raise
                elif attempt < 3:
                    attempt += 1
                else:
                    raise

    @log_helpers.log_method_call
    def _process_port_security_group(self, context, port, vport, sg_ids,
                                     vsd_subnet, subnet_mapping):
        if not port.get('fixed_ips'):
            return

        self._check_security_groups_per_port_limit(sg_ids)

        successful = False
        attempt = 1
        max_attempts = 4
        while not successful:
            try:
                policygroup_ids = []
                for sg_id in sg_ids:
                    vsd_policygroup = self._find_or_create_policygroup(
                        context, sg_id, vsd_subnet)
                    policygroup_ids.append(vsd_policygroup['ID'])

                self.vsdclient.update_vport_policygroups(vport['ID'],
                                                         policygroup_ids)
                successful = True
            except restproxy.RESTProxyError as e:
                LOG.debug("Policy group retry %s times.", attempt)
                msg = e.msg.lower()
                if (e.code not in (404, 409) and 'policygroup' not in msg and
                        'policy group' not in msg):
                    raise
                elif e.vsd_code in constants.NOT_SUPPORTED_NW_MACRO:
                    msg = e.msg.split(': ', 1)
                    if len(msg) > 1:
                        e.msg = ('{}: Non supported remote CIDR in security'
                                 ' rule: {}'.format(msg[0], msg[1]))
                    raise
                elif attempt < max_attempts:
                    attempt += 1
                    if e.vsd_code == nuage_constants.PG_VPORT_DOMAIN_CONFLICT:
                        vsd_subnet = self._find_vsd_subnet(context,
                                                           subnet_mapping)
                        if not vsd_subnet:
                            return
                else:
                    LOG.debug("Retry failed %s times.", max_attempts)
                    raise

    def _find_or_create_policygroup(self, context, security_group_id,
                                    vsd_subnet):
        external_id = cms_id_helper.get_vsd_external_id(security_group_id)
        policygroups = self.get_policygroups(external_id, vsd_subnet)
        if len(policygroups) > 1:
            msg = _("Found multiple policygroups with externalID %s")
            raise n_exc.Conflict(msg=msg % external_id)
        elif len(policygroups) == 1:
            return policygroups[0]
        else:
            return self._create_policygroup(context, security_group_id,
                                            vsd_subnet)

    def get_policygroups(self, external_id, vsd_subnet):
        if vsd_subnet['type'] == constants.L2DOMAIN:
            policygroups = self.vsdclient.get_nuage_l2domain_policy_groups(
                vsd_subnet['ID'],
                externalID=external_id)
        else:
            domain_id = self.vsdclient.get_router_by_domain_subnet_id(
                vsd_subnet['ID'])
            policygroups = self.vsdclient.get_nuage_domain_policy_groups(
                domain_id,
                externalID=external_id)
        return policygroups

    def _create_policygroup(self, context, security_group_id, vsd_subnet):
        security_group = self.core_plugin.get_security_group(context,
                                                             security_group_id)
        # pop rules, make empty policygroup first
        security_group_rules = security_group.pop('security_group_rules')
        try:
            policy_group = self.vsdclient.create_security_group(vsd_subnet,
                                                                security_group)
        except restproxy.RESTProxyError as e:
            if e.vsd_code == restproxy.REST_PG_EXISTS_ERR_CODE:
                # PG is being concurrently created
                external_id = cms_id_helper.get_vsd_external_id(
                    security_group_id)
                policygroups = self.get_policygroups(external_id, vsd_subnet)
                return policygroups[0]
            else:
                raise
        # Before creating rules, we might have to make other policygroups first
        # if the rule uses remote_group_id to have rule related to other PG.
        with nuage_utils.rollback() as on_exc:
            on_exc(self.vsdclient.delete_nuage_policy_group,
                   policy_group['ID'])
            remote_sg_ids = []
            for rule in security_group_rules:
                remote_sg_id = rule.get('remote_group_id')
                if remote_sg_id and remote_sg_id not in remote_sg_ids:
                    remote_sg_ids.append(remote_sg_id)
                    self._find_or_create_policygroup(context,
                                                     remote_sg_id,
                                                     vsd_subnet)

            self.vsdclient.create_security_group_rules(policy_group,
                                                       security_group_rules)
        return policy_group

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
