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

import logging

import six

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants as plugin_constants
from nuage_neutron.plugins.common.utils import SubnetUtilsBase
from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import gw_helper
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.resources import dhcpoptions
from nuage_neutron.vsdclient.resources import domain
from nuage_neutron.vsdclient.resources import gateway
from nuage_neutron.vsdclient.resources import l2domain
from nuage_neutron.vsdclient.resources import netpartition
from nuage_neutron.vsdclient.resources import policygroups
from nuage_neutron.vsdclient.resources import qos
from nuage_neutron.vsdclient.resources import trunk
from nuage_neutron.vsdclient.resources import vm
from nuage_neutron.vsdclient.resources import vmipreservation
from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.vsdclient import VsdClient

LOG = logging.getLogger(__name__)


@six.add_metaclass(helper.MemoizeClass)
class VsdClientImpl(VsdClient, SubnetUtilsBase):

    def __init__(self, cms_id, **kwargs):
        super(VsdClientImpl, self).__init__()
        self.restproxy = restproxy.RESTProxyServer(**kwargs)

        self.restproxy.generate_nuage_auth()

        self.verify_cms(cms_id)
        cms_id_helper.CMS_ID = cms_id

        self.qos = qos.NuageQos(self.restproxy)
        self.net_part = netpartition.NuageNetPartition(self.restproxy)
        self.policygroups = policygroups.NuagePolicyGroups(self.restproxy)
        self.redirecttargets = policygroups.NuageRedirectTargets(
            self.restproxy)
        self.l2domain = l2domain.NuageL2Domain(self.restproxy,
                                               self.policygroups)
        self.domain = domain.NuageDomain(self.restproxy,
                                         self.policygroups)
        self.vm = vm.NuageVM(self.restproxy, self)
        self.dhcp_options = dhcpoptions.NuageDhcpOptions(self.restproxy)
        self.nuagegw = gateway.NuageGateway(self.restproxy,
                                            self.policygroups)
        self.trunk = trunk.NuageTrunk(self.restproxy)
        self.vm_ipreservations = vmipreservation.NuageVMIpReservation(
            self.restproxy)

    def verify_cms(self, cms_id):
        cms = nuagelib.NuageCms(create_params={'cms_id': cms_id})
        self.restproxy.get(cms.get_resource(), required=True)

    def get_usergroup(self, tenant, net_partition_id):
        return helper.get_usergroup(self.restproxy, tenant, net_partition_id)

    def create_usergroup(self, tenant, net_partition_id):
        return helper.create_usergroup(self.restproxy,
                                       tenant, net_partition_id)

    def delete_user(self, id):
        if id is None:
            return
        nuageuser = nuagelib.NuageUser()
        self.restproxy.delete(nuageuser.delete_resource(id))
        LOG.debug('User %s deleted from VSD', id)

    def delete_group(self, id):
        if id is None:
            return
        nuagegroup = nuagelib.NuageGroup()
        self.restproxy.delete(nuagegroup.delete_resource(id))
        LOG.debug('Group %s deleted from VSD', id)

    def create_net_partition(self, params):
        return self.net_part.create_net_partition(params)

    def get_l2domain_fields_for_pg(self, parent_id, fields):
        return helper.get_l2domain_fields_for_pg(self.restproxy, parent_id,
                                                 fields)

    def get_l3domain_np_id(self, parent_id):
        return helper.get_l3domain_np_id(self.restproxy, parent_id)

    def delete_net_partition(self, id):
        self.net_part.delete_net_partition(id)

    def link_default_netpartition(self, params):
        return self.net_part.link_default_netpartition(params)

    def get_net_partitions(self):
        return self.net_part.get_net_partitions()

    def get_netpartition_by_name(self, name):
        return self.net_part.get_netpartition_by_name(name)

    def get_netpartition_data(self, ent_name):
        return self.net_part.get_netpartition_data(ent_name)

    def get_net_partition_name_by_id(self, ent_id):
        return self.net_part.get_net_partition_name_by_id(ent_id)

    def get_nuage_fip_by_id(self, neutron_fip_id):
        return self.net_part.get_nuage_fip_by_id(neutron_fip_id)

    def get_nuage_fip_pool_by_id(self, params):
        return self.net_part.get_nuage_fip_pool_by_id(params)

    def get_subnet_by_netpart(self, netpart_id):
        return self.l2domain.get_subnet_by_netpart(netpart_id)

    def create_subnet(self, ipv4_subnet, ipv6_subnet, params):
        mapping = params.get('mapping')
        if mapping:
            # There is already ipv4/ipv6,
            # Then we change l2domain/subnet to dualstack.
            if mapping['nuage_l2dom_tmplt_id']:
                return self.l2domain.update_subnet_to_dualstack(
                    ipv4_subnet, ipv6_subnet, params)
            else:
                return (self.domain.domainsubnet
                        .update_domain_subnet_to_dualstack(
                            ipv4_subnet, ipv6_subnet, params))
        else:
            return self.l2domain.create_subnet(ipv4_subnet, ipv6_subnet,
                                               params)

    def delete_subnet(self, mapping=None, l2dom_id=None, l3_vsd_subnet_id=None,
                      ipv4_subnet=None, ipv6_subnet=None):
        if l3_vsd_subnet_id:
            self.domain.domainsubnet.delete_l3domain_subnet(l3_vsd_subnet_id)
        elif l2dom_id:
            self.l2domain.delete_subnet(l2dom_id, mapping)
        else:  # eg. delete ipv6 or ipv4 only
            template_id = mapping['nuage_l2dom_tmplt_id']
            if template_id:
                self.l2domain.delete_subnet_from_dualstack(
                    mapping, ipv4_subnet, ipv6_subnet)
            else:
                self.domain.domainsubnet.update_domain_subnet_to_single_stack(
                    mapping, ipv4_subnet, ipv6_subnet)

    def update_l2domain_dhcp_options(self, nuage_subnet_id,
                                     neutron_subnet):
        self.l2domain.update_l2domain_dhcp_options(
            nuage_subnet_id, neutron_subnet)

    def update_l2domain_template(self, nuage_l2dom_tmplt_id, **kwargs):
        self.l2domain.update_l2domain_template(
            nuage_l2dom_tmplt_id=nuage_l2dom_tmplt_id, **kwargs)

    def update_l2domain(self, nuage_l2dom_id, **kwargs):
        self.l2domain.update_l2domain(
            nuage_l2dom_id=nuage_l2dom_id, **kwargs)

    def update_domain_subnet_dhcp_options(self, nuage_subnet_id,
                                          neutron_subnet):
        self.domain.domainsubnet.update_domain_subnet_dhcp_options(
            nuage_subnet_id, neutron_subnet)

    def update_domain_subnet(self, nuage_subnet_id, params):
        self.domain.domainsubnet.update_domain_subnet(
            nuage_subnet_id, params
        )

    def update_nuage_subnet(self, nuage_id, params):
        self.domain.domainsubnet.update_nuage_subnet(nuage_id, params)

    def attach_nuage_group_to_nuagenet(self, tenant, nuage_npid,
                                       nuage_subnetid, shared, tenant_name):
        return self.l2domain.attach_nuage_group_to_nuagenet(
            tenant, nuage_npid, nuage_subnetid, shared, tenant_name)

    def detach_nuage_group_to_nuagenet(
            self, tenants, nuage_subnetid, shared):
        return self.l2domain.detach_nuage_group_to_nuagenet(
            tenants, nuage_subnetid, shared)

    def get_gateway_ip_for_advsub(self, vsd_subnet):
        return self.l2domain.get_gateway_ip_for_advsub(vsd_subnet)

    def check_if_l2_dom_in_correct_ent(self, nuage_l2dom_id, nuage_netpart):
        return self.l2domain.check_if_l2_dom_in_correct_ent(nuage_l2dom_id,
                                                            nuage_netpart)

    def get_router_by_external(self, id):
        return self.domain.get_router_by_external(id)

    def move_l2domain_to_l3subnet(self, l2domain_id, l3subnetwork_id):
        self.l2domain.move_to_l3(l2domain_id, l3subnetwork_id)

    def confirm_router_interface_not_in_use(self, router_id, os_subnet):
        try:
            self.domain.confirm_router_interface_not_in_use(router_id,
                                                            os_subnet)
        except restproxy.ResourceNotFoundException:
            pass

    def create_l2domain_for_router_detach(self, ipv4_subnet, subnet_mapping,
                                          ipv6_subnet=None, ipv4_dhcp_ip=None,
                                          ipv6_dhcp_ip=None,
                                          allow_non_ip=False,
                                          enable_ingress_replication=False):
        subnet = ipv4_subnet or ipv6_subnet
        req_params = {
            'tenant_id': subnet['tenant_id'],
            'netpart_id': subnet_mapping['net_partition_id'],
            'shared': subnet['shared'],
            'network_name': subnet_mapping['network_name'],
            'allow_non_ip': allow_non_ip,
            'ingressReplicationEnabled': enable_ingress_replication
        }
        if ipv4_subnet:
            req_params['dhcp_ip'] = ipv4_dhcp_ip
        if ipv6_subnet:
            req_params['dhcpv6_ip'] = ipv6_dhcp_ip
        return self.l2domain.create_subnet(
            ipv4_subnet, ipv6_subnet, req_params)

    def move_l3subnet_to_l2domain(self, l3subnetwork_id, l2domain_id,
                                  ipv4_subnet_mapping,
                                  subnet, ipv6_subnet_mapping):
        self.domain.domainsubnet.move_to_l2(l3subnetwork_id, l2domain_id)

    def create_nuage_floatingip(self, params):
        return self.domain.create_nuage_floatingip(params)

    def get_nuage_floatingip(self, id, required=False, **filters):
        return self.domain.get_nuage_floatingip(id, required=required,
                                                **filters)

    def get_nuage_floatingips(self, required=False, **filters):
        return self.domain.get_nuage_floatingips(required=required, **filters)

    def get_nuage_domain_floatingips(self, domain_id, required=False,
                                     **filters):
        return self.domain.get_child_floatingips(
            nuagelib.NuageL3Domain.resource,
            domain_id, required=required, **filters)

    def update_vport(self, vport_id, data):
        helper.update_vport(self.restproxy, vport_id, data)

    def delete_nuage_floatingip(self, id):
        self.domain.delete_nuage_floatingip(id)

    def get_nuage_static_route(self, params):
        return self.domain.get_nuage_static_route(params)

    def create_nuage_staticroute(self, params):
        self.domain.create_nuage_staticroute(params)

    def delete_nuage_staticroute(self, params):
        self.domain.delete_nuage_staticroute(params)

    def validate_port_create_redirect_target(self, params):
        return self.domain.validate_port_create_redirect_target(params)

    # deprecated
    def delete_port_security_group_bindings(self, params):
        self.policygroups.delete_port_security_group_bindings(params)

    def check_unused_policygroups(self, securitygroup_ids, sg_type='SOFTWARE'):
        self.policygroups.check_unused_policygroups(securitygroup_ids, sg_type)

    def get_zone_by_domainid(self, domain_id):
        return self.domain.get_zone_by_domainid(domain_id)

    def get_zone_by_routerid(self, neutron_router_id, shared=False):
        return self.domain.get_zone_by_routerid(neutron_router_id, shared)

    def validate_zone_create(self, l3dom_id,
                             l3isolated, l3shared):
        return self.domain.validate_zone_create(l3dom_id, l3isolated, l3shared)

    def get_nuage_vm_interface_by_neutron_id(self, neutron_port_id):
        return helper.get_nuage_vm_interface_by_neutron_id(self.restproxy,
                                                           neutron_port_id)

    def get_routers_by_netpart(self, netpart_id):
        return self.domain.get_routers_by_netpart(netpart_id)

    def get_fip_underlay_enabled_domain_by_netpart(self, netpart_id):
        return self.domain.get_fip_underlay_enabled_domain_by_netpart(
            netpart_id)

    def get_domain_subnet_by_zone_id(self, zone_id):
        return self.domain.domainsubnet.get_domain_subnet_by_zone_id(
            zone_id)

    def get_domain_subnet_by_id(self, subnet_id):
        subnet = self.domain.domainsubnet.get_domain_subnet_by_id(subnet_id)
        subnet['type'] = constants.SUBNET
        return subnet

    def get_domain_subnet_by_ext_id_and_cidr(self, subnet):
        subnet = self.domain.domainsubnet.get_domain_subnet_by_ext_id_and_cidr(
            subnet)
        subnet['type'] = constants.SUBNET
        return subnet

    def get_l2domain_by_id(self, l2domain_id):
        l2domain = self.l2domain.get_subnet_by_id(l2domain_id)
        l2domain['type'] = constants.L2DOMAIN
        return l2domain

    def get_l2domain_by_ext_id_and_cidr(self, subnet):
        l2domain = self.l2domain.get_l2domain_by_ext_id_and_cidr(subnet)
        l2domain['type'] = constants.L2DOMAIN
        return l2domain

    def create_l3domain(self, neutron_router, router, net_partition,
                        tenant_name, allow_non_ip=False):
        return self.domain.create_l3domain(neutron_router, router,
                                           net_partition, tenant_name,
                                           allow_non_ip)

    def create_shared_l3domain(self, params):
        return self.domain.create_shared_l3domain(params)

    def delete_l3domain(self, domain_id):
        self.domain.delete_l3domain(domain_id)

    def get_l3domain_by_id(self, l3domain_id, required=False):
        l3domain = self.domain.get_router_by_id(l3domain_id, required)
        l3domain['type'] = 'domain'
        return l3domain

    def get_router_np_id(self, router_id):
        req_params = {
            'domain_id': router_id
        }
        nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
        l3_doms = self.restproxy.get(nuage_l3_domain.get_resource(),
                                     required=True)
        return l3_doms[0]['parentID'] if l3_doms else None

    def create_shared_subnet(self, vsd_zone_id, subnet, params):
        return self.domain.domainsubnet.create_shared_subnet(
            vsd_zone_id, subnet, params)

    def get_nuage_subnet_by_mapping(self, subnet_mapping, required=False):
        nuage_id = subnet_mapping['nuage_subnet_id']
        try:
            if self._is_l2(subnet_mapping):
                return self.get_l2domain_by_id(nuage_id)
            else:
                return self.get_domain_subnet_by_id(nuage_id)
        except restproxy.ResourceNotFoundException:
            if required:
                raise
            else:
                return None

    def get_nuage_subnet_by_id(self, nuage_id, subnet_type=None,
                               required=False):
        try:
            if subnet_type:
                # best case scenario : i know what i am looking for
                if subnet_type == constants.L2DOMAIN:
                    return self.get_l2domain_by_id(nuage_id)
                else:
                    return self.get_domain_subnet_by_id(nuage_id)
            else:
                # legacy case : i don't know what i am looking for
                try:
                    return self.get_l2domain_by_id(nuage_id)
                except restproxy.RESTProxyError:
                    return self.get_domain_subnet_by_id(nuage_id)

        except restproxy.ResourceNotFoundException:
            if required:
                raise
            else:
                return None

    def get_gw_from_dhcp_l2domain(self, nuage_id):
        return self.l2domain.get_gw_from_dhcp_options(nuage_id)

    def get_router_by_domain_subnet_id(self, dom_subn_id):
        return helper.get_domain_id_by_nuage_subnet_id(self.restproxy,
                                                       dom_subn_id)

    def get_nuage_vport_by_id(self, id, required=True):
        return helper.get_nuage_vport_by_id(self.restproxy, id,
                                            required=required)

    def get_nuage_vport_by_neutron_id(self, params, required=True):
        return helper.get_nuage_vport_by_neutron_id(self.restproxy, params,
                                                    required=required)

    def get_vports(self, parent, parent_id, **filters):
        if parent == constants.L2DOMAIN:
            parent = nuagelib.NuageL2Domain
        elif parent == constants.SUBNET:
            parent = nuagelib.NuageSubnet
        else:
            return []

        return helper.get_vports(self.restproxy, parent, parent_id, **filters)

    def get_vports_by_external_ids(self, parent, parent_id, external_ids):
        if parent == constants.L2DOMAIN:
            parent = nuagelib.NuageL2Domain.resource
        elif parent == constants.SUBNET:
            parent = nuagelib.NuageSubnet.resource
        nuage_vport = nuagelib.NuageVPort()
        return helper.get_by_field_values(
            self.restproxy, resource=nuage_vport,
            field_name='externalID', field_values=external_ids, parent=parent,
            parent_id=parent_id)

    def delete_nuage_vport(self, vport_id):
        helper.delete_nuage_vport(self.restproxy, vport_id)

    def delete_domain_subnet(self, vsd_subnet_id, os_subnet_id):
        self.domain.domainsubnet.delete_domain_subnet(vsd_subnet_id,
                                                      os_subnet_id)

    def create_domain_subnet(self, vsd_zone, ipv4_subnet, ipv6_subnet,
                             network_name, enable_ingress_replication=False):
        return self.domain.domainsubnet.create_domain_subnet(
            vsd_zone, ipv4_subnet, ipv6_subnet, network_name,
            enable_ingress_replication)

    def validate_create_domain_subnet(self, neutron_subn,
                                      nuage_subnet_id, nuage_rtr_id):
        return self.domain.domainsubnet.validate_create_domain_subnet(
            neutron_subn,
            nuage_subnet_id,
            nuage_rtr_id)

    def process_port_create_security_group(self, params):
        return self.policygroups.process_port_create_security_group(params)

    def create_security_group(self, vsd_subnet, os_security_group):
        if vsd_subnet['type'] == constants.L2DOMAIN:
            parent_id = vsd_subnet['ID']
            parent_resource = nuagelib.NuageL2Domain
        else:
            vsd_zone = self.get_nuage_zone_by_id(vsd_subnet['parentID'])
            parent_id = vsd_zone['nuage_parent_id']
            parent_resource = nuagelib.NuageL3Domain
        return self.policygroups.create_security_group(parent_resource,
                                                       parent_id,
                                                       os_security_group)

    def create_security_group_using_parent(self, parent_id, parent_type,
                                           os_security_group):
        if parent_type == constants.L2DOMAIN:
            parent_resource = nuagelib.NuageL2Domain
        else:
            parent_resource = nuagelib.NuageL3Domain
        return self.policygroups.create_security_group(parent_resource,
                                                       parent_id,
                                                       os_security_group)

    def create_security_group_rules(self, policygroup, security_group_rules):
        params = {'nuage_router_id': None,
                  'nuage_l2dom_id': None,
                  'nuage_policygroup_id': policygroup['ID'],
                  'sg_rules': security_group_rules}
        if policygroup['parentType'] == constants.L2DOMAIN:
            params['nuage_l2dom_id'] = policygroup['parentID']
        else:
            params['nuage_router_id'] = policygroup['parentID']
        self.policygroups._create_nuage_sgrules_bulk(params)

    def update_vport_policygroups(self, vport_id, policygroup_ids):
        self.policygroups.update_vport_policygroups(vport_id, policygroup_ids)

    def update_vports_in_policy_group(self, pg_id, vport_list):
        self.policygroups.update_vports_in_policy_group(pg_id, vport_list)

    def get_fip_qos(self, nuage_fip):
        return self.qos.get_fip_qos(nuage_fip)

    def create_update_fip_qos(self, neutron_fip, nuage_fip):
        self.qos.create_update_fip_qos(neutron_fip, nuage_fip)

    def bulk_update_existing_qos(self, qos_policy_id, qos_policy_options,
                                 l3subnet_ids, l2domain_ids, vport_ids):
        self.qos.bulk_update_existing_qos(
            qos_policy_id, qos_policy_options,
            l3subnet_ids, l2domain_ids, vport_ids)

    def delete_fip_qos(self, nuage_fip):
        self.qos.delete_fip_qos(nuage_fip)

    def create_update_qos(self, parent_type, parent_id, qos_policy_id,
                          qos_policy_options, original_qos_policy_id=None):
        self.qos.create_update_qos(parent_type, parent_id,
                                   qos_policy_id, qos_policy_options,
                                   original_qos_policy_id)

    def delete_qos(self, parent_type, parent_id, qos_policy_id):
        self.qos.delete_qos(parent_type, parent_id, qos_policy_id)

    def delete_nuage_sgrule(self, sg_rules, sg_type='SOFTWARE'):
        self.policygroups.delete_nuage_sgrule(sg_rules, sg_type)

    def delete_nuage_secgroup(self, id):
        self.policygroups.delete_policy_group(id)

    def delete_nuage_policy_group(self, nuage_policy_id):
        self.policygroups.delete_nuage_policy_group(nuage_policy_id)

    def validate_nuage_sg_rule_definition(self, sg_rule):
        self.policygroups.validate_nuage_sg_rule_definition(sg_rule)

    def get_sg_policygroup_mapping(self, sg_id, sg_type='SOFTWARE'):
        return self.policygroups.get_sg_policygroup_mapping(sg_id,
                                                            sg_type=sg_type)

    def create_in_adv_fwd_policy_template(self, parent_type, parent_id,
                                          params):
        return helper.create_in_adv_fwd_policy_template(self.restproxy,
                                                        parent_type,
                                                        parent_id,
                                                        params)

    def update_in_adv_fwd_policy_template(self, nuage_id, params):
        return helper.update_in_adv_fwd_policy_template(self.restproxy,
                                                        nuage_id,
                                                        params)

    def get_in_adv_fwd_policy_by_cmsid(self, parent_type, parent_id):
        return helper.get_in_adv_fwd_policy_by_cmsid(self.restproxy,
                                                     parent_type,
                                                     parent_id)

    def get_in_adv_fwd_policy_by_externalid(self, parent_type,
                                            parent_id, portchain_id):
        return helper.get_in_adv_fwd_policy_by_externalid(self.restproxy,
                                                          parent_type,
                                                          parent_id,
                                                          portchain_id)

    def delete_in_adv_fwd_policy_template(self, tmplt_id):
        helper.delete_in_adv_fwd_policy_template(self.restproxy, tmplt_id)

    def create_nuage_sgrule(self, params):
        return self.policygroups.create_nuage_sgrule(params)

    def create_nuage_redirect_target(self, redirect_target, l2dom_id=None,
                                     domain_id=None):
        return self.redirecttargets.create_nuage_redirect_target(
            redirect_target, l2dom_id, domain_id)

    def get_nuage_redirect_target(self, rtarget_id):
        return self.redirecttargets.get_nuage_redirect_target(rtarget_id)

    def get_nuage_redirect_targets(self, params):
        return self.redirecttargets.get_nuage_redirect_targets(params)

    def get_nuage_redirect_targets_by_single_filter(self, filters,
                                                    required=False):
        return (
            self.redirecttargets.get_nuage_redirect_targets_by_single_filter(
                filters, required))

    def delete_nuage_redirect_target(self, rtarget_id):
        self.redirecttargets.delete_nuage_redirect_target(rtarget_id)

    def delete_port_redirect_target_bindings(self, params):
        self.redirecttargets.delete_port_redirect_target_bindings(params)

    def update_nuage_vport_redirect_target(self, rtarget_id, vport_id):
        self.redirecttargets.update_nuage_vport_redirect_target(rtarget_id,
                                                                vport_id)

    def update_redirect_target_vports(self, redirect_target_id,
                                      nuage_port_id_list):
        self.redirecttargets.update_redirect_target_vports(
            redirect_target_id,
            nuage_port_id_list)

    def create_virtual_ip(self, rtarget_id, vip, vip_port_id):
        return self.redirecttargets.create_virtual_ip(rtarget_id, vip,
                                                      vip_port_id)

    def delete_nuage_redirect_target_vip(self, rtarget_vip_id):
        self.redirecttargets.delete_nuage_redirect_target_vip(rtarget_vip_id)

    def create_nuage_redirect_target_rule(self, params, rt=None):
        return self.redirecttargets.create_nuage_redirect_target_rule(params,
                                                                      rt)

    def add_nuage_sfc_rule(self, tmplt, rule_params, np_id):
        return self.redirecttargets.add_nuage_sfc_rule(tmplt, rule_params,
                                                       np_id)

    def get_nuage_redirect_target_rules(self, params):
        return self.redirecttargets.get_nuage_redirect_target_rules(params)

    def get_nuage_redirect_target_rules_by_external_id(self, neutron_id):
        return (self.redirecttargets.
                get_nuage_redirect_target_rules_by_external_id(neutron_id))

    def get_nuage_redirect_target_rule(self, rtarget_rule_id):
        return self.redirecttargets.get_nuage_redirect_target_rule(
            rtarget_rule_id)

    def delete_nuage_redirect_target_rule(self, rtarget_rule_id):
        self.redirecttargets.delete_nuage_redirect_target_rule(rtarget_rule_id)

    def get_redirect_target_vports(self, rtarget_id, required=False):
        return self.redirecttargets.get_redirect_target_vports(
            rtarget_id, required=required)

    def create_nuage_external_security_group(self, params):
        return self.policygroups.create_nuage_external_security_group(params)

    def create_nuage_sec_grp_for_no_port_sec(self, params):
        return self.policygroups.create_nuage_sec_grp_for_no_port_sec(params)

    def create_nuage_sec_grp_for_sfc(self, params):
        return self.policygroups.create_nuage_sec_grp_for_sfc(params)

    def get_policygroup_vport_mapping_by_port_id(self, vport_id):
        return self.policygroups.get_policygroup_vport_mapping_by_port_id(
            vport_id)

    def get_nuage_external_security_group(self, ext_sg_id):
        return self.policygroups.get_nuage_external_security_group(ext_sg_id)

    def get_nuage_external_security_groups(self, params):
        return self.policygroups.get_nuage_external_security_groups(params)

    def delete_nuage_external_security_group(self, ext_sg_id):
        self.policygroups.delete_nuage_external_security_group(ext_sg_id)

    def create_nuage_external_sg_rule(self, params):
        return self.policygroups.create_nuage_external_sg_rule(params)

    def get_nuage_external_sg_rule(self, ext_rule_id):
        return self.policygroups.get_nuage_external_sg_rule(ext_rule_id)

    def get_nuage_external_sg_rules(self, params):
        return self.policygroups.get_nuage_external_sg_rules(params)

    def delete_nuage_external_sg_rule(self, ext_rule_id):
        self.policygroups.delete_nuage_external_sg_rule(ext_rule_id)

    def nuage_redirect_targets_on_l2domain(self, l2domid):
        return self.redirecttargets.nuage_redirect_targets_on_l2domain(l2domid)

    def vms_on_l2domain(self, l2dom_id):
        return self.vm.vms_on_l2domain(l2dom_id)

    def vms_on_subnet(self, subnet_id):
        return self.vm.vms_on_subnet(subnet_id)

    def create_vms(self, params):
        return self.vm.create_vms(params)

    def delete_vms(self, params):
        self.vm.delete_vms(params)

    def delete_vm_by_external_id(self, params):
        self.vm.delete_vm_by_external_id(params)

    def delete_vm_by_id(self, params):
        self.vm.delete_vm_by_id(params)

    def update_nuage_vm_vport(self, params):
        self.vm.update_nuage_vm_vport(params)

    def get_nuage_vm_if_by_vport_id(self, vport_id):
        return self.vm.get_nuage_vm_if_by_vport_id(vport_id)

    def update_nuage_vm_if(self, params):
        self.vm.update_nuage_vm_if(params)

    def create_vport(self, params):
        return self.vm.create_vport(params)

    def nuage_vports_on_l2domain(self, l2dom_id):
        return self.vm.nuage_vports_on_l2domain(l2dom_id)

    def nuage_vports_on_subnet(self, subnet_id):
        return self.vm.nuage_vports_on_subnet(subnet_id)

    def crt_or_updt_vport_dhcp_option(self, extra_dhcp_opt, resource_id,
                                      external_id):
        return self.dhcp_options.create_update_extra_dhcp_option_on_vport(
            extra_dhcp_opt, resource_id, external_id)

    def delete_vport_nuage_dhcp(self, dhcp_opt, vport_id):
        return self.dhcp_options.delete_vport_nuage_dhcp(dhcp_opt, vport_id)

    def delete_vport_dhcp_option(self, dhcp_id, ip_version, on_rollback):
        return self.dhcp_options.delete_nuage_extra_dhcp_option(dhcp_id,
                                                                ip_version,
                                                                on_rollback)

    def update_router(self, nuage_domain_id, router, updates):
        self.domain.update_router(nuage_domain_id, router, updates)

    def get_gateway(self, tenant_id, gw_id):
        try:
            resp = gw_helper.get_gateway(self.restproxy, gw_id)
            return gw_helper.make_gateway_dict(resp)
        except Exception as e:
            if e.code == constants.RES_NOT_FOUND:
                return []
            raise

    def get_gateways(self, tenant_id, filters):
        gws = self.nuagegw.get_gateways(tenant_id, filters)
        gw_list = []
        for gw in gws:
            ret = gw_helper.make_gateway_dict(gw)
            gw_list.append(ret)

        return gw_list

    def get_gateway_ports(self, tenant_id, filters):
        ports = self.nuagegw.get_gateway_ports(tenant_id, filters)
        port_list = []
        for port in ports:
            ret = gw_helper.make_gw_port_dict(port)
            port_list.append(ret)

        return port_list

    def get_gateway_port(self, tenant_id, gw_port_id):
        resp = gw_helper.get_gateway_port(self.restproxy,
                                          gw_port_id)
        if resp:
            return gw_helper.make_gw_port_dict(resp)
        else:
            return []

    def get_gateway_port_vlans(self, tenant_id, netpart_id, filters):
        vlans = self.nuagegw.get_gateway_port_vlans(tenant_id, netpart_id,
                                                    filters)
        vlan_list = []
        for vlan in vlans:
            ret = gw_helper.make_gw_vlan_dict(vlan)
            vlan_list.append(ret)

        return vlan_list

    def get_gateway_port_vlan(self, tenant_id, gw_intf_id):
        try:
            vlan = gw_helper.get_gateway_port_vlan(self.restproxy,
                                                   gw_intf_id)

            # Get the perm if it exists
            perm = gw_helper.get_tenant_perm(self.restproxy, gw_intf_id)
            if perm:
                vlan['assignedTo'] = perm['permittedEntityName']

            ret = gw_helper.make_gw_vlan_dict(vlan)
            return ret
        except Exception as e:
            if e.code == constants.RES_NOT_FOUND:
                return []
            raise

    def create_gateway_port_vlan(self, vlan_dict):
        resp = self.nuagegw.create_gateway_port_vlan(vlan_dict)
        return gw_helper.make_gw_vlan_dict(resp[0])

    def create_gateway_vlan(self, vlan_dict):
        return self.nuagegw.create_gateway_vlan(vlan_dict)

    def delete_gateway_port_vlan(self, vlan_id):
        return self.nuagegw.delete_gateway_port_vlan(vlan_id)

    def update_gateway_port_vlan(self, tenant_id, id, params):
        return self.nuagegw.update_gateway_port_vlan(tenant_id, id, params)

    def create_gateway_vport(self, tenant_id, vport_dict):
        return self.nuagegw.create_gateway_vport(tenant_id, vport_dict)

    def create_gateway_vport_no_usergroup(self, tenant_id, vport_dict,
                                          create_policy_group=False):
        return self.nuagegw.create_gateway_vport_no_usergroup(
            tenant_id,
            vport_dict,
            create_policy_group)

    def delete_nuage_gateway_vport(self, context, id, def_netpart_id):
        return self.nuagegw.delete_nuage_gateway_vport(context,
                                                       id,
                                                       def_netpart_id)

    def delete_nuage_gateway_vport_no_usergroup(self, tenant_id, vport):
        return self.nuagegw.delete_nuage_gateway_vport_no_usergroup(tenant_id,
                                                                    vport)

    def get_gateway_vport(self, context, tenant_id, netpart_id,
                          nuage_vport_id):
        return self.nuagegw.get_gateway_vport(context, tenant_id, netpart_id,
                                              nuage_vport_id)

    def get_gateway_vports(self, context, tenant_id, netpart_id, filters):
        return self.nuagegw.get_gateway_vports(context,
                                               tenant_id,
                                               netpart_id,
                                               filters)

    def get_host_and_bridge_vports(self, subnet_id, subnet_type):
        if subnet_type == constants.L2DOMAIN:
            parent = nuagelib.NuageL2Domain
        elif subnet_type == constants.SUBNET:
            parent = nuagelib.NuageSubnet
        else:
            return []
        vport = nuagelib.NuageVPort()
        return helper.get_vports(self.restproxy, parent=parent,
                                 parent_id=subnet_id,
                                 headers=vport.extra_headers_host_or_bridge())

    def get_nuage_prefix_macro(self, net_macro_id):
        return helper.get_nuage_prefix_macro(self.restproxy, net_macro_id)

    def get_nuage_fip(self, nuage_fip_id):
        return helper.get_nuage_fip(self.restproxy, nuage_fip_id)

    def get_vport_assoc_with_fip(self, nuage_fip_id):
        return helper.get_vport_assoc_with_fip(self.restproxy,
                                               nuage_fip_id)

    def create_vip(self, params):
        return self.vm.process_vip(params)

    def get_vips(self, vport_id):
        return self.vm.get_vips_on_vport(vport_id)

    def delete_vips(self, vport_id, vip_dict, vips):
        self.vm.delete_vips(vport_id, vip_dict, vips)

    def update_fip_to_vips(self, neutron_subnet_id, vip, vsd_fip_id):
        self.vm.update_fip_to_vips(neutron_subnet_id, vip, vsd_fip_id)

    def create_vip_on_vport(self, params):
        self.vm.create_vip_on_vport(params)

    def process_deleted_addr_pair(self, params):
        self.vm.process_deleted_addr_pair(params)

    def change_perm_of_subns(self, nuage_npid, nuage_subnetid, shared,
                             tenant_id, remove_everybody=False):
        helper.change_perm_of_subns(self.restproxy, nuage_npid,
                                    nuage_subnetid, shared,
                                    tenant_id,
                                    remove_everybody=remove_everybody)

    def update_mac_spoofing_on_vport(self, nuage_vport_id, status):
        self.vm.update_mac_spoofing_on_vport({'vport_id': nuage_vport_id},
                                             status)

    # VM IP Reservations

    def create_vm_ip_reservation(self, is_l2, parent_id, ip_type,
                                 ipv4_address=None, ipv6_address=None,
                                 allocation_pools=None):
        return self.vm_ipreservations.create_vm_ip_reservation(
            is_l2, parent_id, ip_type, ipv4_address, ipv6_address,
            allocation_pools)

    def update_vm_ip_reservation_state(self, vmipreservation_id,
                                       target_state=''):
        return self.vm_ipreservations.update_vm_ip_reservation_state(
            vmipreservation_id, target_state)

    def delete_vm_ip_reservation(self, is_l2, parent_id,
                                 ipv4_address=None, ipv6_address=None):
        return self.vm_ipreservations.delete_vm_ip_reservation(is_l2,
                                                               parent_id,
                                                               ipv4_address,
                                                               ipv6_address)

    def get_vm_ip_reservation(self, is_l2, parent_id, ipv4_address=None,
                              ipv6_address=None):
        return self.vm_ipreservations.get_vm_ip_reservation(is_l2, parent_id,
                                                            ipv4_address,
                                                            ipv6_address)

    def get_nuage_zone_by_id(self, zone_id):
        return helper.get_nuage_zone_by_id(self.restproxy, zone_id)

    def get_nuage_domain_id_from_subnet(self, dom_subn_id):
        return helper._get_nuage_domain_id_from_subnet(
            self.restproxy, dom_subn_id)

    def get_nuage_domain_by_zoneid(self, zone_id):
        return helper.get_nuage_domain_by_zoneid(
            self.restproxy, zone_id)

    def get_nuage_vport_for_port_sec(self, params, required=True):
        return helper.get_nuage_vport_by_neutron_id(self.restproxy, params,
                                                    required)

    def get_nuage_policy_group(self, id, required=False, **filters):
        return self.policygroups.get_policy_group(id, required=required,
                                                  **filters)

    def get_sg_policygroup_by_external_id(self, sg_id,
                                          sg_type=constants.SOFTWARE,
                                          required=False):
        return self.policygroups.get_sg_policygroup_by_external_id(
            sg_id,
            sg_type=sg_type,
            required=required
        )

    def update_policygroup(self, policygroup_id, data):
        return self.policygroups.update_policygroup(policygroup_id, data)

    def get_nuage_policy_groups(self, required=False, **filters):
        return self.policygroups.get_policy_groups(required=required,
                                                   **filters)

    def get_policy_groups_by_single_filter(self, filters, required=False):
        return self.policygroups.get_policy_groups_by_single_filter(filters,
                                                                    required)

    def get_nuage_vport_policy_groups(self, vport_id, required=False,
                                      **filters):
        return self.policygroups.get_child_policy_groups(
            nuagelib.NuageVPort.resource, vport_id,
            required=required, **filters)

    def get_nuage_l2domain_policy_groups(self, l2domain_id, required=False,
                                         **filters):
        return self.policygroups.get_child_policy_groups(
            nuagelib.NuageL2Domain.resource, l2domain_id,
            required=required, **filters)

    def get_nuage_domain_policy_groups(self, domain_id, required=False,
                                       **filters):
        return self.policygroups.get_child_policy_groups(
            nuagelib.NuageL3Domain.resource, domain_id,
            required=required, **filters)

    def get_nuage_policy_group_vports(self, policygroup_id, required=False,
                                      **filters):
        return helper.get_child_vports(
            self.restproxy, nuagelib.NuagePolicygroup.resource,
            policygroup_id, required=required, **filters)

    def get_nuage_vport_redirect_targets(self, vport_id, required=False,
                                         **filters):
        return self.redirecttargets.get_child_redirect_targets(
            nuagelib.NuageVPort.resource, vport_id, required=required,
            **filters)

    def get_nuage_plugin_stats(self):
        stats = {}
        if nuage_config.is_enabled(plugin_constants.DEBUG_API_STATS):
            stats['api_count'] = self.restproxy.api_count
        return stats

    # Trunk

    def create_trunk(self, os_trunk, subnet_mapping):
        params = {
            'neutron_port_id': os_trunk.port_id,
            'l2dom_id': subnet_mapping.get('nuage_subnet_id'),
            'l3dom_id': subnet_mapping.get('nuage_subnet_id')
        }
        vport = self.get_nuage_vport_by_neutron_id(params, required=True)
        subnet_mapping['nuage_vport_id'] = vport['ID']
        self.trunk.create_trunk(os_trunk, subnet_mapping)

    def delete_trunk(self, os_trunk, subnet_mapping):
        self.trunk.delete_trunk(os_trunk, subnet_mapping)

    def add_subport(self, os_trunk_id, os_subport, data):
        params = {
            'neutron_port_id': os_subport.port_id,
            'l2dom_id': data.get('nuage_subnet_id'),
            'l3dom_id': data.get('nuage_subnet_id')
        }
        vport = self.get_nuage_vport_by_neutron_id(params, required=True)
        self.trunk.add_subport(os_trunk_id, os_subport,
                               vport['ID'], data)

    def remove_subport(self, os_port, subnet_mapping):
        params = {
            'neutron_port_id': os_port['id'],
            'l2dom_id': subnet_mapping.get('nuage_subnet_id'),
            'l3dom_id': subnet_mapping.get('nuage_subnet_id')
        }
        vport = self.get_nuage_vport_by_neutron_id(params, required=True)
        self.trunk.remove_subport(os_port, vport)

    def update_subport(self, os_port, vport, data):
        self.trunk.update_subport(os_port, vport, data)
