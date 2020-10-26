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
import collections

from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib.plugins import utils
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
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': constants.VALID_DSCP_MARKS}
    }
}
VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL, portbindings.VNIC_DIRECT]


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

    def validate_rule_for_port(self, context, rule, port):
        validated = super(NuageQosDriver, self).validate_rule_for_port(
            context, rule, port)
        if not validated:
            return False
        # This driver only supports DIRECT VNIC type with switchdev
        # capabilities, not SRIOV.
        port_binding = utils.get_port_binding_by_status_and_host(
            port.bindings, constants.ACTIVE, raise_if_not_found=True,
            port_id=port['id'])
        vnic_type = port_binding.vnic_type
        if vnic_type == portbindings.VNIC_DIRECT:
            # Reject when there are no switchdev capabilities
            profile = port_binding.get('profile')
            capabilities = profile.get('capabilities', []) if profile else []
            return 'switchdev' in capabilities
        else:
            return True

    @staticmethod
    def _get_vsd_qos_options(db_context, policy_id):
        vsd_qos_options = {
            'dscp_options': {},
            'bandwidth_options': {},
        }
        if policy_id is None:
            return vsd_qos_options

        # The policy might not have any rules
        all_rules = qos_rule.get_rules(qos_policy.QosPolicy,
                                       db_context, policy_id)
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                vsd_qos_options['bandwidth_options'][
                    'rateLimitingActive'] = True
                if rule.max_kbps:
                    vsd_qos_options['bandwidth_options'][
                        'peak'] = float(rule.max_kbps) / 1000
                if rule.max_burst_kbps:
                    vsd_qos_options['bandwidth_options'][
                        'burst'] = rule.max_burst_kbps
            elif isinstance(rule, qos_rule.QosDscpMarkingRule):
                vsd_qos_options['dscp_options']['dscp_mark'] = rule.dscp_mark

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

        self._vsdclient.bulk_update_existing_qos(
            policy.id, vsd_options['bandwidth_options'])
        self._vsdclient.bulk_update_existing_dscp(
            policy.id, vsd_options['dscp_options'])

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
        domain_adv_fwd_mapping = collections.defaultdict(dict)

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
                qos_policy_options=vsd_qos_options['bandwidth_options'],
                original_qos_policy_id=original['qos_policy_id'])
            # DSCP marking
            vsd_subnet = self._mech_driver._find_vsd_subnet(db_context,
                                                            subnet_mapping)
            domain_type, domain_id = (
                self._mech_driver._get_domain_type_id_from_vsd_subnet(
                    self._vsdclient, vsd_subnet))
            self._vsdclient.create_update_dscp_marking_subnet(
                domain_type=domain_type,
                domain_id=domain_id,
                vsd_subnet=vsd_subnet,
                domain_adv_fwd_mapping=domain_adv_fwd_mapping,
                qos_policy_id=updated['qos_policy_id'],
                dscp_mark=vsd_qos_options['dscp_options'].get('dscp_mark'),
                original_qos_policy_id=original['qos_policy_id'])

            vsd_subnets.append(subnet_mapping['nuage_subnet_id'])

    def create_subnet(self, context):
        db_context = context._plugin_context
        subnet = context.current

        network_qos_policy_id = self._get_network_qos_policy_id(
            context._plugin_context, subnet['network_id'])
        vsd_qos_options = self._get_vsd_qos_options(db_context,
                                                    network_qos_policy_id)
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                        subnet['id'])

        if vsd_qos_options['bandwidth_options']:
            self._vsdclient.create_update_qos(
                parent_type=self._get_parent_type(subnet_mapping),
                parent_id=subnet_mapping['nuage_subnet_id'],
                qos_policy_id=network_qos_policy_id,
                qos_policy_options=vsd_qos_options['bandwidth_options'])

        if vsd_qos_options['dscp_options']:
            vsd_subnet = self._mech_driver._find_vsd_subnet(db_context,
                                                            subnet_mapping)
            domain_type, domain_id = (
                self._mech_driver._get_domain_type_id_from_vsd_subnet(
                    self._vsdclient, vsd_subnet))
            self._vsdclient.create_update_dscp_marking_subnet(
                domain_type=domain_type,
                domain_id=domain_id,
                vsd_subnet=vsd_subnet,
                domain_adv_fwd_mapping=collections.defaultdict(dict),
                qos_policy_id=network_qos_policy_id,
                dscp_mark=vsd_qos_options['dscp_options'].get('dscp_mark'),
                original_qos_policy_id=None)

    def process_create_update_port(self, db_context, port, nuage_vport,
                                   domain_type, domain_id,
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

        # Update bandwidth options
        self._vsdclient.create_update_qos(
            parent_type=nuage_constants.VPORT,
            parent_id=nuage_vport['ID'],
            qos_policy_id=new_qos_policy,
            qos_policy_options=vsd_qos_options['bandwidth_options'],
            original_qos_policy_id=original_qos_policy)

        # Update DSCP options
        existing_pg = None
        new_pg = None
        if new_qos_policy != original_qos_policy and original_qos_policy:
            existing_pg = self._vsdclient.get_policygroup_in_domain(
                original_qos_policy, domain_type, domain_id)

        if vsd_qos_options['dscp_options']:
            # Create / Update PG
            new_pg = self._vsdclient.find_create_policygroup_for_qos(
                domain_type, domain_id, new_qos_policy,
                dscp_mark=vsd_qos_options['dscp_options']['dscp_mark']
            )
        # Update vPort Policygroups
        add_pgs = [new_pg['ID']] if new_pg else []
        remove_pgs = [existing_pg['ID']] if existing_pg else []
        self._vsdclient.update_vport_policygroups(
            vport_id=nuage_vport['ID'], add_policygroups=add_pgs,
            remove_policygroups=remove_pgs)
