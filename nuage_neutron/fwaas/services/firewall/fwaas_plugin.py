# Copyright 2016 Alcatel-Lucent USA Inc.
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
import logging

from neutron._i18n import _
from neutron.db import api as db_api
from neutron.plugins.common import constants as const
from neutron.plugins.ml2 import config
from neutron_fwaas.services.firewall import fwaas_plugin as original
from neutron_lib import exceptions

from oslo_config import cfg
from oslo_log import helpers as log_helpers

from nuage_neutron.fwaas.db import fwaas_db
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils

LOG = logging.getLogger(__name__)
config.cfg.CONF.import_opt('router_distributed',
                           'neutron.db.l3_dvr_db')


class NuageNoOpAgent(original.FirewallAgentApi):
    """Nuage uses no l3 agent, so all actions are no-op."""
    def __init__(self):
        pass

    def update_firewall(self, context, firewall):
        pass

    def delete_firewall(self, context, firewall):
        pass

    def create_firewall(self, context, firewall):
        pass


class NuageFWaaSPlugin(base_plugin.BaseNuagePlugin,
                       original.FirewallPlugin,
                       fwaas_db.Firewall_db_mixin):
    """This class is the upstream implementation without the rpc calls.

    The rpc calls are done upstream to talk with the l3-agent but for nuage we
    will talk to the VSD via vsdclient instead.
    """
    def __init__(self):
        super(NuageFWaaSPlugin, self).__init__()
        from neutron.api import extensions as neutron_extensions
        from neutron_fwaas import extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        self.agent_rpc = NuageNoOpAgent()
        enterprise_name = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart_db = nuagedb.get_net_partition_by_name(db_api.get_session(),
                                                       enterprise_name)
        self.enterprise_id = netpart_db.id

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        """Overrides the upstream plugin's method just to reduce calls"""
        pass

    def _rpc_update_firewall(self, context, firewall_id):
        """Overrides the upstream plugin's method just to reduce calls"""
        pass

    def _ensure_update_firewall(self, context, firewall_id):
        """Upstream locking doesn't look good"""
        pass

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        """Upstream locking doesn't look good"""
        pass

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        """Upstream locking doesn't look good"""
        pass

    @contextlib.contextmanager
    def db_lock_by_rule(self, context, rule_id):
        with context.session.begin(subtransactions=True):
            self._lock_by_rule(context.session, rule_id)
            yield

    @contextlib.contextmanager
    def db_lock_by_policy(self, context, policy_id):
        with context.session.begin(subtransactions=True):
            self._lock_policy(context.session, policy_id)
            yield

    @contextlib.contextmanager
    def db_lock_by_firewall(self, context, firewall_id):
        with context.session.begin(subtransactions=True):
            self._lock_by_firewall(context.session, firewall_id)
            yield

    # Firewall Rule

    @log_helpers.log_method_call
    def create_firewall_rule(self, context, firewall_rule):
        with context.session.begin(subtransactions=True):
            fw_rule = super(NuageFWaaSPlugin, self).create_firewall_rule(
                context, firewall_rule)
            if fw_rule['enabled'] is True:
                self.vsdclient.create_firewall_rule(self.enterprise_id,
                                                    fw_rule)
        return fw_rule

    @log_helpers.log_method_call
    def update_firewall_rule(self, context, id, firewall_rule):
        with self.db_lock_by_rule(context, id):
            original_rule = self.get_firewall_rule(context, id)
            request = copy.deepcopy(firewall_rule)
            fw_rule = super(NuageFWaaSPlugin, self).update_firewall_rule(
                context, id, firewall_rule)
            self._validate_fwr_protocol_parameters(fw_rule)
            became_enabled = (original_rule['enabled'] is False and
                              fw_rule['enabled'] is True)
            became_disabled = (original_rule['enabled'] is True and
                               fw_rule['enabled'] is False)
            if became_enabled:
                self._enable_rule(context, fw_rule)
            elif became_disabled:
                self._disable_rule(context, fw_rule, id)
            elif fw_rule['enabled'] is True:
                self.vsdclient.update_firewall_rule(
                    self.enterprise_id, id, request['firewall_rule'])
            return fw_rule

    def _enable_rule(self, context, fw_rule):
        with utils.rollback() as on_exc:
            vsd_rule = self.vsdclient.create_firewall_rule(
                self.enterprise_id, fw_rule)
            on_exc(self.vsdclient.delete_vsd_firewallrule, vsd_rule['ID'])
            if fw_rule['firewall_policy_id']:
                self._update_policy_rules(context,
                                          fw_rule['firewall_policy_id'])

    def _disable_rule(self, context, fw_rule, id):
        with utils.rollback() as on_exc:
            if fw_rule['firewall_policy_id']:
                self.vsdclient.remove_rule(self.enterprise_id,
                                           fw_rule['firewall_policy_id'],
                                           {'firewall_rule_id': id})
                on_exc(self._update_policy_rules,
                       context, fw_rule['firewall_policy_id'])
            self.vsdclient.delete_firewall_rule(self.enterprise_id, id)

    @log_helpers.log_method_call
    def delete_firewall_rule(self, context, id):
        with self.db_lock_by_rule(context, id):
            super(NuageFWaaSPlugin, self).delete_firewall_rule(context, id)
            self.vsdclient.delete_firewall_rule(self.enterprise_id, id)

    def _update_policy_rules(self, context, policy_id, delete_rule=None):
        policy = self.get_firewall_policy(context, policy_id)
        rules = policy['firewall_rules']
        if delete_rule:
            rules.remove(delete_rule)
        self.vsdclient.update_firewall_policy(
            self.enterprise_id, policy['id'],
            {'firewall_rules': rules})

    # Firewall Policy

    @log_helpers.log_method_call
    def create_firewall_policy(self, context, firewall_policy):
        with context.session.begin(subtransactions=True):
            policy = super(NuageFWaaSPlugin, self).create_firewall_policy(
                context, firewall_policy)
            self.vsdclient.create_firewall_policy(self.enterprise_id, policy)

        return policy

    @log_helpers.log_method_call
    def update_firewall_policy(self, context, id, firewall_policy):
        with self.db_lock_by_policy(context, id):
            policy = super(NuageFWaaSPlugin, self).update_firewall_policy(
                context, id, firewall_policy)
            self.vsdclient.update_firewall_policy(self.enterprise_id,
                                                  id, firewall_policy)
        return policy

    @log_helpers.log_method_call
    def delete_firewall_policy(self, context, id):
        with context.session.begin(subtransactions=True):
            super(NuageFWaaSPlugin, self).delete_firewall_policy(context, id)
            self.vsdclient.delete_firewall_policy(self.enterprise_id, id)

    @log_helpers.log_method_call
    def remove_rule(self, context, id, rule_info):
        with self.db_lock_by_policy(context, id):
            policy = super(NuageFWaaSPlugin, self).remove_rule(
                context, id, rule_info)
        self.vsdclient.remove_rule(self.enterprise_id, id, rule_info)
        return policy

    @log_helpers.log_method_call
    def insert_rule(self, context, id, rule_info):
        with self.db_lock_by_policy(context, id):
            policy = super(NuageFWaaSPlugin, self).insert_rule(
                context, id, rule_info)
            self.vsdclient.insert_rule(self.enterprise_id, id, rule_info)
        return policy

    # Firewall

    @log_helpers.log_method_call
    def create_firewall(self, context, firewall):
        with context.session.begin(subtransactions=True):
            if firewall['firewall'].get('firewall_policy_id'):
                self._lock_policy(context.session,
                                  firewall['firewall']['firewall_policy_id'])
            fw = super(NuageFWaaSPlugin, self).create_firewall(context,
                                                               firewall)
            l3domain_ids = self.l3domain_ids_by_policy_id(
                context, fw.get('firewall_policy_id'))
            self.vsdclient.create_firewall(self.enterprise_id, fw,
                                           l3domain_ids)
            self._update_firewall_status(context, fw)
            return fw

    @log_helpers.log_method_call
    def update_firewall(self, context, id, firewall):
        with self.db_lock_by_firewall(context, id):
            if firewall['firewall'].get('firewall_policy_id'):
                self._lock_policy(context.session,
                                  firewall['firewall']['firewall_policy_id'])
            original_fw = self.get_firewall(context, id)
            original_l3domains = self.l3domain_ids_by_policy_id(
                context, original_fw['firewall_policy_id'])
            updated_fw = super(NuageFWaaSPlugin, self).update_firewall(
                context, id, firewall)
            policy_updated = (original_fw['firewall_policy_id'] !=
                              updated_fw['firewall_policy_id'])
            with utils.rollback() as on_exc:
                if policy_updated:
                    self.vsdclient.update_firewall(self.enterprise_id,
                                                   original_fw,
                                                   [])
                    on_exc(self.vsdclient.update_firewall,
                           self.enterprise_id, original_fw, original_l3domains)
                l3domain_ids = self.l3domain_ids_by_policy_id(
                    context, updated_fw['firewall_policy_id'])
                self.vsdclient.update_firewall(
                    self.enterprise_id, updated_fw, l3domain_ids)
                self._update_firewall_status(context, updated_fw)
                return updated_fw

    @log_helpers.log_method_call
    def delete_firewall(self, context, id):
        with self.db_lock_by_firewall(context, id):
            firewall = self.get_firewall(context, id)
            # The super plugin code does not delete FW when it has routers.
            # It will wait for rpc call.
            fwaas_db.Firewall_db_mixin.delete_firewall(self, context, id)
            l3domain_ids = self.l3domain_ids_by_policy_id(
                context, firewall.get('firewall_policy_id'))
            self.vsdclient.delete_firewall(
                self.enterprise_id, firewall, l3domain_ids)

    def l3domain_ids_by_policy_id(self, context, policy_id):
        router_ids = self.get_router_ids_by_fw_policy(context, policy_id)
        mappings = nuagedb.get_ent_rtr_mapping_by_rtrids(
            context.session, router_ids)
        if any([m.net_partition_id != self.enterprise_id for m in mappings]):
            msg = (_("Router(s) %s does not belong to the default "
                     "netpartition.")
                   % [str(m.router_id) for m in mappings
                      if m.net_partition_id != self.enterprise_id])
            raise exceptions.BadRequest(resource='firewall', msg=msg)
        return [m.nuage_router_id for m in mappings]

    def _update_firewall_status(self, context, fw):
        if fw.get('firewall_policy_id') and fw.get('router_ids'):
            fw['status'] = const.ACTIVE
        else:
            fw['status'] = const.CREATED

        with context.session.begin(subtransactions=True):
            fw_db = self._get_firewall(context, fw['id'])
            fw_db.status = fw['status']
