# Copyright 2020 Nokia.
# All Rights Reserved.
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

from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log as logging

from nuage_neutron.plugins.common import constants as nuage_constants
from nuage_neutron.plugins.common import nuagedb


LOG = logging.getLogger(__name__)

NUAGE_QOS = 'qos'

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [constants.EGRESS_DIRECTION]}
    }
}
VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL]


class NuageQosDriver(base.DriverBase):
    """Nuage driver for QoS.

    This driver manages the following objects:
    - QOS object on Network & port
    - PGs for DSCP marking, one per domain
        Creation is done at first usage in the domain
        Deletion of this PG is delayed until either domain or policy deletion
    - Adv Fwd Policy for DSCP marking, up to two per domain
        Creation is done at first usage in the domain
           Network: Rule with locationType L2Domain/L3Subnet
           Port: rule with locationType PG
        Deletion is delayed until either domain or policy(rule) deletion

    """

    def __init__(self):
        super(NuageQosDriver, self).__init__(
            'NuageQosDriver', VIF_TYPES, VNIC_TYPES, SUPPORTED_RULES,
            requires_rpc_notifications=False)

    @classmethod
    def create(cls, mech_driver, vsdclient):
        cls._mech_driver = mech_driver
        cls._vsdclient = vsdclient
        return cls()

    @property
    def is_loaded(self):
        return NUAGE_QOS in cfg.CONF.ml2.extension_drivers

    @staticmethod
    def _get_vsd_qos_options(db_context, policy_id):
        if policy_id is None:
            return {}
        vsd_qos_options = {}

        # The policy might not have any rules
        all_rules = qos_rule.get_rules(qos_policy.QosPolicy,
                                       db_context, policy_id)
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                vsd_qos_options['rateLimitingActive'] = True
                if rule.max_kbps:
                    vsd_qos_options['peak'] = float(rule.max_kbps) / 1000
                if rule.max_burst_kbps:
                    vsd_qos_options['burst'] = rule.max_burst_kbps
        return vsd_qos_options

    @staticmethod
    def _network_supports_qos(network):
        # No qos for external subnets
        return not network['router:external']

    @staticmethod
    def _get_parent_type(subnet_mapping):
        if bool(subnet_mapping['nuage_l2dom_tmplt_id']):
            parent_type = nuage_constants.L2DOMAIN
        else:
            parent_type = nuage_constants.SUBNET
        return parent_type

    @staticmethod
    def _get_network_qos_policy_id(db_context, network_id):
        network_policy = qos_policy.QosPolicy.get_network_policy(
            db_context, network_id)
        return network_policy.id if network_policy else None

    def update_policy(self, db_context, policy):
        vsd_options = self._get_vsd_qos_options(db_context, policy.id)
        l3subnet_ids = set()
        l2domain_ids = set()
        vport_ids = []
        for network_id in policy.get_bound_networks():
            subnets = self._mech_driver.core_plugin.get_subnets(
                db_context,
                filters={'network_id': [network_id]})
            for subnet in subnets:
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
                    db_context.session, subnet['id'])
                parent_type = self._get_parent_type(subnet_mapping)
                if parent_type == nuage_constants.L2DOMAIN:
                    l2domain_ids.add(subnet_mapping['nuage_subnet_id'])
                else:
                    l3subnet_ids.add(subnet_mapping['nuage_subnet_id'])
        for port_id in policy.get_bound_ports():
            subnet_mapping = nuagedb.get_subnet_l2dom_by_port_id(
                db_context.session, port_id)
            vport = self._mech_driver._get_nuage_vport({'id': port_id},
                                                       subnet_mapping)
            vport_ids.append(vport['ID'])

        self._vsdclient.bulk_update_existing_qos(
            policy.id, vsd_options,
            l3subnet_ids, l2domain_ids, vport_ids)

    def update_network(self, db_context, original, updated):
        if original.get('qos_policy_id') == updated.get('qos_policy_id'):
            # No update needed
            return
        if not self._network_supports_qos(updated):
            return

        subnets = self._mech_driver.core_plugin.get_subnets(
            db_context,
            filters={'network_id': [updated['id']]})

        vsd_qos_options = self._get_vsd_qos_options(
            db_context, updated['qos_policy_id'])

        # Do not process ipv4, ipv6 subnets for same vsd subnet twice
        vsd_subnets = []
        for subnet in subnets:
            # Call mech driver to update qos at l2domain/l3subnet
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                            subnet['id'])
            if (not subnet_mapping or
                    subnet_mapping['nuage_subnet_id'] in vsd_subnets):
                pass
            self._vsdclient.create_update_qos(
                parent_type=self._get_parent_type(subnet_mapping),
                parent_id=subnet_mapping['nuage_subnet_id'],
                qos_policy_id=updated['qos_policy_id'],
                qos_policy_options=vsd_qos_options,
                original_qos_policy_id=original['qos_policy_id'])
            vsd_subnets.append(subnet_mapping['nuage_subnet_id'])

    def create_subnet(self, context):
        db_context = context._plugin_context
        subnet = context.current

        network_qos_policy_id = self._get_network_qos_policy_id(
            context._plugin_context, subnet['network_id'])
        vsd_qos_options = self._get_vsd_qos_options(db_context,
                                                    network_qos_policy_id)
        if vsd_qos_options:
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                            subnet['id'])
            self._vsdclient.create_update_qos(
                parent_type=self._get_parent_type(subnet_mapping),
                parent_id=subnet_mapping['nuage_subnet_id'],
                qos_policy_id=network_qos_policy_id,
                qos_policy_options=vsd_qos_options)

    def create_update_port(self, db_context, port, nuage_vport,
                           original_port=None):
        original_qos_policy = (original_port.get('qos_policy_id')
                               if original_port else None)
        new_qos_policy = port.get('qos_policy_id')

        if not new_qos_policy and not original_port:
            # No QOS policy to create
            return
        if original_port and new_qos_policy == original_qos_policy:
            # No update required
            return

        vsd_qos_options = self._get_vsd_qos_options(db_context, new_qos_policy)
        self._vsdclient.create_update_qos(
            parent_type=nuage_constants.VPORT,
            parent_id=nuage_vport['ID'],
            qos_policy_id=new_qos_policy,
            qos_policy_options=vsd_qos_options,
            original_qos_policy_id=original_qos_policy)
