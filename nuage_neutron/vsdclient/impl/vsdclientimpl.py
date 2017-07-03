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

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants as plugin_constants
from nuage_neutron.plugins.common.time_tracker import TimeTracker

from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import gw_helper
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.common import pnet_helper
from nuage_neutron.vsdclient.resources import dhcpoptions
from nuage_neutron.vsdclient.resources import domain
from nuage_neutron.vsdclient.resources import fwaas
from nuage_neutron.vsdclient.resources import gateway
from nuage_neutron.vsdclient.resources import l2domain
from nuage_neutron.vsdclient.resources import netpartition
from nuage_neutron.vsdclient.resources import policygroups
from nuage_neutron.vsdclient.resources import trunk
from nuage_neutron.vsdclient.resources import vm
from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.vsdclient import VsdClient

LOG = logging.getLogger(__name__)


class VsdClientImpl(VsdClient):
    __metaclass__ = helper.MemoizeClass   # noqa H236

    def __init__(self, cms_id, **kwargs):
        super(VsdClientImpl, self).__init__()
        self.restproxy = restproxy.RESTProxyServer(**kwargs)

        self.restproxy.generate_nuage_auth()
        self.get_cms(cms_id)
        cms_id_helper.CMS_ID = cms_id

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
        self.fwaas = fwaas.NuageFwaas(self.restproxy)
        self.trunk = trunk.NuageTrunk(self.restproxy)

    def create_cms(self, name):
        cms = nuagelib.NuageCms(create_params={'name': name})
        response = self.restproxy.rest_call('POST', cms.post_resource(),
                                            cms.post_data())
        if not cms.validate(response):
            LOG.error('Error creating cms %s', name)
            raise restproxy.RESTProxyError(cms.error_msg)
        return cms.get_response_obj(response)

    def get_cms(self, id):
        cms = nuagelib.NuageCms(create_params={'cms_id': id})
        response = self.restproxy.rest_call('GET', cms.get_resource(), '')
        if not cms.get_validate(response):
            LOG.error('CMS with id %s not found on vsd', id)
            raise restproxy.RESTProxyError(cms.error_msg)
        return cms.get_response_obj(response)

    def get_usergroup(self, tenant, net_partition_id):
        return helper.get_usergroup(self.restproxy, tenant, net_partition_id)

    def create_usergroup(self, tenant, net_partition_id):
        return helper.create_usergroup(self.restproxy,
                                       tenant, net_partition_id)

    def delete_user(self, id):
        if id is None:
            return
        nuageuser = nuagelib.NuageUser()
        response = self.restproxy.rest_call('DELETE',
                                            nuageuser.delete_resource(id), '')
        if not nuageuser.delete_validate(response):
            LOG.error('Error in deleting user %s', id)
            raise restproxy.RESTProxyError(nuageuser.error_msg)
        LOG.debug('User %s deleted from VSD', id)

    def delete_group(self, id):
        if id is None:
            return
        nuagegroup = nuagelib.NuageGroup()
        response = self.restproxy.rest_call('DELETE',
                                            nuagegroup.delete_resource(id), '')
        if not nuagegroup.delete_validate(response):
            LOG.error('Error in deleting group %s', id)
            raise restproxy.RESTProxyError(nuagegroup.error_msg)
        LOG.debug('Group %s deleted from VSD', id)

    def create_net_partition(self, params):
        return self.net_part.create_net_partition(params)

    def set_external_id_for_netpart_rel_elems(self, net_partition_dict):
        return self.net_part.set_external_id_for_netpart_rel_elems(
            net_partition_dict)

    def delete_net_partition(self, id):
        self.net_part.delete_net_partition(id)

    def link_default_netpartition(self, params):
        return (self.net_part.link_default_netpartition(params))

    def check_del_def_net_partition(self, ent_name):
        self.net_part.check_del_def_net_partition(ent_name)

    def get_net_partitions(self):
        return self.net_part.get_net_partitions()

    def get_netpartition_by_name(self, name):
        return self.net_part.get_netpartition_by_name(name)

    def get_netpartition_data(self, ent_name):
        return self.net_part.get_netpartition_data(ent_name)

    def get_net_partition_name_by_id(self, ent_id):
        return self.net_part.get_net_partition_name_by_id(ent_id)

    def get_nuage_fip_by_id(self, params):
        return self.net_part.get_nuage_fip_by_id(params)

    def get_nuage_fip_pool_by_id(self, params):
        return self.net_part.get_nuage_fip_pool_by_id(params)

    def set_fip_quota_at_ent_profile(self, fip_quota):
        self.net_part.set_fip_quota_at_ent_profile(fip_quota)

    def get_subnet_by_netpart(self, netpart_id):
        return self.l2domain.get_subnet_by_netpart(netpart_id)

    def create_subnet(self, neutron_subnet, params):
        return self.l2domain.create_subnet(neutron_subnet, params)

    def delete_subnet(self, id):
        self.l2domain.delete_subnet(id)

    def update_subnet(self, neutron_subnet, params):
        self.l2domain.update_subnet(neutron_subnet, params)

    def get_nuage_sharedresource(self, id):
        return self.l2domain.get_nuage_sharedresource(id)

    def get_sharedresource(self, neutron_id):
        return self.l2domain.get_sharedresource(neutron_id)

    def create_nuage_sharedresource(self, params):
        return self.l2domain.create_nuage_sharedresource(params)

    def update_nuage_sharedresource(self, neutron_id, params):
        return self.l2domain.update_nuage_sharedresource(neutron_id, params)

    def delete_nuage_sharedresource(self, id):
        self.l2domain.delete_nuage_sharedresource(id)

    def get_nuage_cidr(self, nuage_subnetid):
        return self.l2domain.get_nuage_cidr(nuage_subnetid)

    def attach_nuage_group_to_nuagenet(self, tenant, nuage_npid,
                                       nuage_subnetid, shared):
        return self.l2domain.attach_nuage_group_to_nuagenet(
            tenant, nuage_npid, nuage_subnetid, shared)

    def detach_nuage_group_to_nuagenet(
            self, tenants, nuage_subnetid, shared):
        return self.l2domain.detach_nuage_group_to_nuagenet(
            tenants, nuage_subnetid, shared)

    def get_gateway_ip_for_advsub(self, vsd_subnet):
        return self.l2domain.get_gateway_ip_for_advsub(vsd_subnet)

    def check_if_l2Dom_in_correct_ent(self, nuage_l2dom_id, nuage_netpart):
        return self.l2domain.check_if_l2Dom_in_correct_ent(nuage_l2dom_id,
                                                           nuage_netpart)

    def get_router_by_external(self, id):
        return self.domain.get_router_by_external(id)

    def create_router(self, neutron_router, router, params):
        return self.domain.create_router(neutron_router, router, params)

    def delete_router(self, id):
        self.domain.delete_router(id)

    def move_l2domain_to_l3subnet(self, l2domain_id, l3subnetwork_id):
        self.l2domain.move_to_l3(l2domain_id, l3subnetwork_id)

    def confirm_router_interface_not_in_use(self, router_id, os_subnet):
        try:
            self.domain.confirm_router_interface_not_in_use(router_id,
                                                            os_subnet)
        except restproxy.ResourceNotFoundException:
            pass

    def create_l2domain_for_router_detach(self, os_subnet, subnet_mapping):
        req_params = {
            'tenant_id': os_subnet['tenant_id'],
            'netpart_id': subnet_mapping['net_partition_id'],
            'pnet_binding': None,
            'dhcp_ip': os_subnet['allocation_pools'][-1]['end'],
            'shared': os_subnet['shared']
        }
        return self.l2domain.create_subnet(os_subnet, req_params)

    def move_l3subnet_to_l2domain(self, l3subnetwork_id, l2domain_id,
                                  subnet_mapping, pnet_binding):
        self.domain.domainsubnet.move_to_l2(l3subnetwork_id, l2domain_id)
        if pnet_binding:
            pnet_params = {
                'pnet_binding': pnet_binding,
                'netpart_id': subnet_mapping['net_partition_id'],
                'l2domain_id': l2domain_id,
                'neutron_subnet_id': subnet_mapping['subnet_id']
            }
            pnet_helper.process_provider_network(self.restproxy,
                                                 self.policygroups,
                                                 pnet_params)

    def create_nuage_floatingip(self, params):
        return self.domain.create_nuage_floatingip(params)

    def create_nuage_floatingip_details(self, params):
        return self.domain.create_nuage_floatingip_details(params)

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

    def check_unused_policygroups(self, securitygroup_ids):
        self.policygroups.check_unused_policygroups(securitygroup_ids)

    def get_zone_by_domainid(self, domain_id):
        return self.domain.get_zone_by_domainid(domain_id)

    def get_zone_by_routerid(self, neutron_router_id, shared=False):
        return self.domain.get_zone_by_routerid(neutron_router_id, shared)

    def validate_zone_create(self, l3dom_id,
                             l3isolated, l3shared):
        return self.domain.validate_zone_create(l3dom_id, l3isolated, l3shared)

    def get_nuage_port_by_id(self, params):
        return helper.get_nuage_port_by_id(self.restproxy, params)

    def get_routers_by_netpart(self, netpart_id):
        return self.domain.get_routers_by_netpart(netpart_id)

    def get_domain_subnet_by_zone_id(self, zone_id):
        return self.domain.domainsubnet.get_domain_subnet_by_zone_id(
            zone_id)

    def get_domain_subnet_by_id(self, subnet_id):
        subnet = self.domain.domainsubnet.get_domain_subnet_by_id(subnet_id)
        subnet['type'] = constants.SUBNET
        return subnet

    def get_l2domain_by_id(self, l2domain_id):
        l2domain = self.l2domain.get_subnet_by_id(l2domain_id)
        l2domain['type'] = constants.L2DOMAIN
        return l2domain

    def get_router_np_id(self, router_id):
        req_params = {
            'domain_id': router_id
        }
        nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
        response = self.restproxy.rest_call(
            'GET', nuage_l3_domain.get_resource(), '')

        if not nuage_l3_domain.validate(response):
            raise restproxy.RESTProxyError(nuage_l3_domain.error_msg)

        if response[3]:
            return response[3][0]['parentID']

    def get_nuage_subnet_by_id(self, subnet_mapping, required=False):
        nuage_id = subnet_mapping['nuage_subnet_id']
        try:
            if subnet_mapping['nuage_l2dom_tmplt_id']:
                return self.get_l2domain_by_id(nuage_id)
            else:
                return self.get_domain_subnet_by_id(nuage_id)
        except restproxy.ResourceNotFoundException:
            if required:
                raise
            else:
                return None

    def get_subnet_or_domain_subnet_by_id(self, nuage_id, required=False):
        try:
            return self.get_l2domain_by_id(nuage_id)
        except restproxy.RESTProxyError:
            try:
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

    def delete_nuage_vport(self, vport_id):
        helper.delete_nuage_vport(self.restproxy, vport_id)

    def delete_domain_subnet(self, vsd_subnet_id, os_subnet_id, pnet_binding):
        self.domain.domainsubnet.delete_domain_subnet(vsd_subnet_id,
                                                      os_subnet_id,
                                                      pnet_binding)

    def create_domain_subnet(self, vsd_zone, neutron_subnet, pnet_binding):
        return self.domain.domainsubnet.create_domain_subnet(
            vsd_zone, neutron_subnet, pnet_binding)

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

    def get_rate_limit(self, vport_id, neutron_fip_id):
        return self.policygroups.get_rate_limit(vport_id, neutron_fip_id)

    def create_update_rate_limiting(self, rate_limit, vport_id,
                                    neutron_fip_id):
        self.policygroups.create_update_rate_limiting(rate_limit, vport_id,
                                                      neutron_fip_id)

    def delete_rate_limiting(self, vport_id, neutron_fip_id):
        self.policygroups.delete_rate_limiting(vport_id, neutron_fip_id)

    def delete_nuage_sgrule(self, sg_rules):
        self.policygroups.delete_nuage_sgrule(sg_rules)

    def delete_nuage_secgroup(self, id):
        self.policygroups.delete_policy_group(id)

    def validate_nuage_sg_rule_definition(self, sg_rule):
        self.policygroups.validate_nuage_sg_rule_definition(sg_rule)

    def get_sg_policygroup_mapping(self, sg_id):
        return self.policygroups.get_sg_policygroup_mapping(sg_id)

    def create_nuage_sgrule(self, params):
        return self.policygroups.create_nuage_sgrule(params)

    def create_nuage_redirect_target(self, redirect_target, subnet_id=None,
                                     domain_id=None):
        return self.redirecttargets.create_nuage_redirect_target(
            redirect_target, subnet_id, domain_id)

    def get_nuage_redirect_target(self, rtarget_id):
        return self.redirecttargets.get_nuage_redirect_target(rtarget_id)

    def get_nuage_redirect_targets(self, params):
        return self.redirecttargets.get_nuage_redirect_targets(params)

    def delete_nuage_redirect_target(self, rtarget_id):
        self.redirecttargets.delete_nuage_redirect_target(rtarget_id)

    def delete_port_redirect_target_bindings(self, params):
        self.redirecttargets.delete_port_redirect_target_bindings(params)

    def update_nuage_vport_redirect_target(self, rtarget_id, vport_id):
        self.redirecttargets.update_nuage_vport_redirect_target(rtarget_id,
                                                                vport_id)

    def create_virtual_ip(self, rtarget_id, vip, vip_port_id):
        return self.redirecttargets.create_virtual_ip(rtarget_id, vip,
                                                      vip_port_id)

    def delete_nuage_redirect_target_vip(self, rtarget_vip_id):
        self.redirecttargets.delete_nuage_redirect_target_vip(rtarget_vip_id)

    def create_nuage_redirect_target_rule(self, params):
        return self.redirecttargets.create_nuage_redirect_target_rule(params)

    def get_nuage_redirect_target_rules(self, params):
        return self.redirecttargets.get_nuage_redirect_target_rules(params)

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

    def create_nuage_sec_grp_for_port_sec(self, params):
        return self.policygroups.create_nuage_sec_grp_for_port_sec(params)

    def create_nuage_sec_grp_rule_for_port_sec(self, params):
        return self.policygroups.create_nuage_sec_grp_rule_for_port_sec(params)

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

    def update_nuage_vm_vport(self, params):
        self.vm.update_nuage_vm_vport(params)

    def create_vport(self, params):
        return self.vm.create_vport(params)

    def nuage_vports_on_l2domain(self, l2dom_id, pnet_binding):
        return self.vm.nuage_vports_on_l2domain(l2dom_id, pnet_binding)

    def nuage_vports_on_subnet(self, subnet_id, pnet_binding):
        return self.vm.nuage_vports_on_subnet(subnet_id, pnet_binding)

    def crt_or_updt_vport_dhcp_option(self, extra_dhcp_opt, resource_id,
                                      external_id):
        return self.dhcp_options.nuage_extra_dhcp_option(extra_dhcp_opt,
                                                         resource_id,
                                                         external_id)

    def delete_vport_dhcp_option(self, dhcp_id, on_rollback):
        return self.dhcp_options.delete_nuage_extra_dhcp_option(dhcp_id,
                                                                on_rollback)

    def validate_provider_network(self, network_type, physical_network,
                                  vlan_id):
        pnet_helper.validate_provider_network(self.restproxy, network_type,
                                              physical_network, vlan_id)

    def update_router(self, nuage_domain_id, router, params):
        self.domain.update_router(nuage_domain_id, router, params)

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

    def delete_nuage_gateway_vport(self, context, id, def_netpart_id):
        return self.nuagegw.delete_nuage_gateway_vport(context,
                                                       id,
                                                       def_netpart_id)

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

    def set_subn_external_id(self, neutron_subn_id, nuage_subn_id):
        return helper.set_subn_external_id(self.restproxy, neutron_subn_id,
                                           nuage_subn_id)

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

    def associate_fip_to_vips(self, neutron_subnet_id, vip, vsd_fip_id):
        self.vm.associate_fip_to_vips(neutron_subnet_id, vip, vsd_fip_id)

    def disassociate_fip_from_vips(self, neutron_subnet_id, vip):
        self.vm.disassociate_fip_from_vips(neutron_subnet_id, vip)

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

    def get_nuage_zone_by_id(self, zone_id):
        return helper.get_nuage_zone_by_id(self.restproxy, zone_id)

    def get_nuage_domain_id_from_subnet(self, dom_subn_id):
        return helper._get_nuage_domain_id_from_subnet(
            self.restproxy, dom_subn_id)

    def get_nuage_vport_for_port_sec(self, params):
        return helper.get_nuage_vport_by_neutron_id(self.restproxy, params)

    def get_nuage_policy_group(self, id, required=False, **filters):
        return self.policygroups.get_policy_group(id, required=required,
                                                  **filters)

    def get_nuage_policy_groups(self, required=False, **filters):
        return self.policygroups.get_policy_groups(required=required,
                                                   **filters)

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

    def create_nuage_fip_for_vpnaas(self, params):
        return self.domain.create_nuage_fip_for_vpnaas(params)

    # Firewall

    def create_firewall_rule(self, enterprise_id, os_rule):
        return self.fwaas.create_firewall_rule(enterprise_id, os_rule)

    def update_firewall_rule(self, enterprise_id, id, os_rule):
        self.fwaas.update_firewall_rule(enterprise_id, id, os_rule)

    def delete_firewall_rule(self, enterprise_id, id):
        self.fwaas.delete_firewall_rule(enterprise_id, id)

    def delete_vsd_firewallrule(self, id):
        self.fwaas.delete_vsd_firewallrule(id)

    def create_firewall_policy(self, enterprise_id, os_policy):
        return self.fwaas.create_firewall_policy(enterprise_id, os_policy)

    def update_firewall_policy(self, enterprise_id, id, os_policy):
        self.fwaas.update_firewall_policy(enterprise_id, id, os_policy)

    def delete_firewall_policy(self, enterprise_id, id):
        self.fwaas.delete_firewall_policy(enterprise_id, id)

    def insert_rule(self, enterprise_id, os_policy_id, os_rule_info):
        self.fwaas.insert_rule(enterprise_id, os_policy_id, os_rule_info)

    def remove_rule(self, enterprise_id, os_policy_id, os_rule_info):
        self.fwaas.remove_rule(enterprise_id, os_policy_id, os_rule_info)

    def create_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self.fwaas.create_firewall(enterprise_id, os_firewall, l3domain_ids)

    def update_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self.fwaas.update_firewall(enterprise_id, os_firewall, l3domain_ids)

    def delete_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        self.fwaas.delete_firewall(enterprise_id, os_firewall, l3domain_ids)

    def get_nuage_plugin_stats(self):
        stats = {}
        if nuage_config.is_enabled(plugin_constants.DEBUG_API_STATS):
            stats['api_count'] = self.restproxy.api_count
        if nuage_config.is_enabled(plugin_constants.DEBUG_TIMING_STATS):
            stats['time_spent_in_nuage'] = TimeTracker.get_time_tracked()
            stats['time_spent_in_core'] = TimeTracker.get_time_not_tracked()
            stats["total_time_spent"] = TimeTracker.get_time_tracked() + \
                TimeTracker.get_time_not_tracked()

        return stats

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
