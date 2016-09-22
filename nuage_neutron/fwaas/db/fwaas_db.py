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

from neutron_fwaas.db.firewall.firewall_db import Firewall
from neutron_fwaas.db.firewall.firewall_db import Firewall_db_mixin as original
from neutron_fwaas.db.firewall.firewall_db import FirewallPolicy
from neutron_fwaas.db.firewall.firewall_db import FirewallRule
from neutron_fwaas.db.firewall.firewall_router_insertion_db \
    import FirewallRouterAssociation
from sqlalchemy.sql.expression import true


class Firewall_db_mixin(original):
    """Mixin class for Firewall DB implementation."""

    def get_router_ids_by_fw_policy(self, context, policy_id):
        if not policy_id:
            return []
        result = (
            context.session.query(FirewallRouterAssociation.router_id)
            .join(Firewall)
            .filter(
                Firewall.firewall_policy_id == policy_id,
                Firewall.admin_state_up == true())
        ).all()
        return [r.router_id for r in result]

    def _lock_by_rule(self, session, rule_id):
        # You can enable/disable rules which translates to deleting/creating
        # rules on the VSD. This may involve updating the rules of the policy
        # on the VSD. Therefor lock on both rule and policy.
        result = (
            session.query(FirewallPolicy.id)
            .join(FirewallRule)
            .filter(FirewallRule.id == rule_id)
            .with_for_update()
        ).all()
        if not result:
            (
                session.query(FirewallRule.id)
                .filter(FirewallRule.id == rule_id)
                .with_for_update()
            ).all()

    def _lock_policy(self, session, policy_id):
        (
            session.query(FirewallPolicy.id)
            .filter(FirewallPolicy.id == policy_id)
            .with_for_update()
        ).all()

    def _lock_by_firewall(self, session, firewall_id):
        # When updating the routers of 2 different firewalls, there may be
        # issues when these 2 firewalls use the same policy. So lock both
        # firewall and policy. If no policies, only the firewall.
        result = (
            session.query(FirewallPolicy.id)
            .join(Firewall)
            .filter(Firewall.id == firewall_id)
            .with_for_update()
        ).all()
        if not result:
            (
                session.query(Firewall.id)
                .filter(Firewall.id == firewall_id)
                .with_for_update()
            ).all()
