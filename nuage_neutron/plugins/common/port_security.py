# Copyright 2020 NOKIA
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

from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as sg_extension
from neutron_lib.api.definitions import port_security as portsecurity
from neutron_lib import constants as neutron_constants
from neutron_lib.plugins import directory
from oslo_log import log as logging

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)


class NuagePortSecurityHandler(base_plugin.SubnetUtilsBase,
                               sg_db.SecurityGroupDbMixin):
    """NuagePortSecurityHandler

    Handles SecurityGroup events on Ports
    Handles Port Security events on Ports
    Handles addressSpoofing due to PortSecurity on Port update
    """

    _core_plugin = None

    def __init__(self, vsdclient, nuage_plugin):
        self.vsdclient = vsdclient
        self.nuage_plugin = nuage_plugin

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    def process_port_create(self, db_context, port, vport,
                            domain_type, domain_id,
                            subnet_mapping, pg_type):
        if self._is_vsd_mgd(subnet_mapping):
            # port security is only applicable to OS managed subnets
            return
        if port[sg_extension.SECURITYGROUPS]:
            added_sgs = port[sg_extension.SECURITYGROUPS]
            removed_sgs = []
            self._wrap_process_port_security_groups(db_context, pg_type,
                                                    added_sgs, removed_sgs,
                                                    subnet_mapping, vport,
                                                    domain_type, domain_id)
        elif not port.get(portsecurity.PORTSECURITY, True):
            self.process_pg_allow_all(db_context, pg_type, subnet_mapping,
                                      vport, domain_type, domain_id)

    def process_port_update(self, db_context, port, original_port, vport,
                            domain_type, domain_id,
                            subnet_mapping, pg_type=constants.SOFTWARE):

        if not self._is_vsd_mgd(subnet_mapping):
            # Security Groups are only applicable for os managed subnets
            original_sgs = original_port[sg_extension.SECURITYGROUPS]
            updated_sgs = port[sg_extension.SECURITYGROUPS]
            added_sgs = list(set(updated_sgs) - set(original_sgs))
            removed_sgs = list(set(original_sgs) - set(updated_sgs))
            if added_sgs or removed_sgs:
                self._wrap_process_port_security_groups(db_context, pg_type,
                                                        added_sgs, removed_sgs,
                                                        subnet_mapping, vport,
                                                        domain_type, domain_id)

        original_psec = original_port.get(portsecurity.PORTSECURITY, True)
        updated_psec = port.get(portsecurity.PORTSECURITY, True)
        if original_psec != updated_psec:
            if updated_psec:
                # Remove PG_ALLOW_ALL
                self.process_pg_allow_all(db_context, pg_type, subnet_mapping,
                                          vport, domain_type, domain_id,
                                          add=False)
            else:
                # Add PG_ALLOW_ALL
                self.process_pg_allow_all(db_context, pg_type, subnet_mapping,
                                          vport, domain_type, domain_id,
                                          add=True)
            status = (constants.DISABLED if updated_psec
                      else constants.ENABLED)
            self.vsdclient.update_mac_spoofing_on_vport(vport['ID'], status)

    def process_create_security_group_in_domain(self, db_context,
                                                sg_id,
                                                domain_id, domain_type,
                                                vsd_managed,
                                                pg_type=constants.SOFTWARE):
        domain_sg_pgs_mapping = self._wrap_process_port_security_groups(
            db_context, pg_type=pg_type, added_sg_ids=[sg_id],
            removed_sg_ids=[], subnet_mapping=None, vport=None,
            domain_id=domain_id, domain_type=domain_type,
            vsd_managed=vsd_managed)
        return domain_sg_pgs_mapping[domain_id][sg_id]['ID']

    def process_pg_allow_all(self, db_context, pg_type, subnet_mapping, vport,
                             domain_type, domain_id, add=True):
        if self._is_vsd_mgd(subnet_mapping):
            # PG_ALLOW_ALL is only set on OS managed subnets
            return
        if add:
            # Set PG_ALLOW_ALL
            # Create Fake SG and SGRule objects
            removed_sgs = []
            added_sgs = [vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL]
            self._wrap_process_port_security_groups(db_context, pg_type,
                                                    added_sgs, removed_sgs,
                                                    subnet_mapping, vport,
                                                    domain_type, domain_id)
        else:
            # Remove PG_ALLOW_ALL
            removed_sgs = [vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL]
            added_sgs = []
            self._wrap_process_port_security_groups(db_context, pg_type,
                                                    added_sgs, removed_sgs,
                                                    subnet_mapping, vport,
                                                    domain_type, domain_id)

    def _wrap_process_port_security_groups(self, db_context, pg_type,
                                           added_sg_ids, removed_sg_ids,
                                           subnet_mapping, vport,
                                           domain_type, domain_id,
                                           vsd_managed=False):
        attempts = 3
        # Due to concurrent create & delete of PG: add a retry
        for attempt in range(attempts):
            try:
                netpartition_id = (
                    subnet_mapping['net_partition_id']
                    if subnet_mapping else None)
                return self._process_port_security_groups(
                    db_context, vport, domain_id, domain_type,
                    added_sg_ids, removed_sg_ids, pg_type,
                    netpartition_id, vsd_managed)
            except restproxy.RESTProxyError as e:
                if attempt == attempts - 1:
                    # Last attempt
                    LOG.debug("Process Port Securitygroups retry"
                              " failed {} times.".format(attempts))
                    raise
                LOG.debug("Process Port Securitygroups retry")

                # Due to concurrent router-attach: find vsd subnet again
                if e.vsd_code == vsd_constants.PG_VPORT_DOMAIN_CONFLICT:
                    found_vsd_subnet = self.nuage_plugin._find_vsd_subnet(
                        db_context, subnet_mapping)
                    found_domain_type, found_domain_id = (
                        self._get_domain_type_id_from_vsd_subnet(
                            self.vsdclient, found_vsd_subnet))
                    if found_domain_id == domain_id:
                        raise  # No use retrying
                    else:
                        domain_type, domain_id = (found_domain_type,
                                                  found_domain_type)

                # Translate network macro error
                elif e.vsd_code in constants.NOT_SUPPORTED_NW_MACRO:
                    msg = str(e).split(': ', 1)
                    if len(msg) > 1:
                        e.msg = (
                            '{}: Non supported remote CIDR in security'
                            ' rule: {}'.format(msg[0], msg[1]))
                    raise

                elif e.code not in (404, 409):
                    LOG.debug("Unrecoverable error encountered during "
                              "processing port securitygroups")
                    raise

    def _process_port_security_groups(self, db_context, vport, domain_id,
                                      domain_type,
                                      added_sg_ids, removed_sg_ids, pg_type,
                                      netpartition_id, vsd_managed=False):
        # In VSD managed subnets we disregard the sg_rules of a sg
        if netpartition_id:
            domain_enterprise_mapping = {domain_id: netpartition_id}
        else:
            domain_enterprise_mapping = {}
        # domainID -> {'ingress': ACL_ID, 'egress': ACL_ID}
        domain_acl_mapping = collections.defaultdict(
            lambda: {'ingress': None, 'egress': None})
        # domainID -> SG_ID -> PG
        domain_sg_pg_mapping = collections.defaultdict(dict)

        analysed_securitygroup_ids = set()
        sgs = []
        for sg_id in added_sg_ids:
            if sg_id == vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL:
                # Handle PG allow all
                suffix = '_HARDWARE' if pg_type == constants.HARDWARE else ''
                sg_rules = [
                    {'id': vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                     'ethertype': ethertype,
                     'direction': direction}
                    for ethertype in [neutron_constants.IPv4,
                                      neutron_constants.IPv6]
                    for direction in neutron_constants.VALID_DIRECTIONS]
                sg = {
                    'id': vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                    'name': vsd_constants.NUAGE_PLCY_GRP_ALLOW_ALL + suffix,
                    'security_group_rules': sg_rules,
                    'stateful': False
                }
                sgs.append(sg)
            elif not vsd_managed:
                # consider all sg_rules in an os managed subnet
                sgs_to_add = nuage_utils.collect_all_remote_security_groups(
                    self.core_plugin, db_context, sg_id,
                    analysed_securitygroup_ids)
                sgs.extend(sgs_to_add)
            else:
                # Ignore sg_rules in vsd managed subnet
                sg = self.core_plugin.get_security_group(db_context,
                                                         sg_id)
                sg['security_group_rules'] = []
                sgs.append(sg)

        with nuage_utils.rollback() as on_exception:
            # Create PGs & ensure HW deny all rule
            self.vsdclient.find_create_security_groups(
                sgs, domain_type, domain_id, domain_enterprise_mapping,
                domain_sg_pg_mapping, domain_acl_mapping, on_exception,
                pg_type=pg_type,
                allow_non_ip=config.default_allow_non_ip_enabled())

            # Add & remove PGs to vPort
            # We cannot simply override the PG on the vPort
            if vport:
                added_pgs = [domain_sg_pg_mapping[domain_id][sg_id]['ID']
                             for sg_id in added_sg_ids]
                self.vsdclient.find_security_groups_in_domain(
                    removed_sg_ids, domain_type, domain_id,
                    domain_sg_pg_mapping, pg_type=pg_type)
                removed_pgs = [domain_sg_pg_mapping[domain_id][sg_id]['ID']
                               for sg_id in removed_sg_ids]
                self.vsdclient.update_vport_policygroups(
                    vport['ID'],
                    add_policygroups=added_pgs,
                    remove_policygroups=removed_pgs)
        return domain_sg_pg_mapping
