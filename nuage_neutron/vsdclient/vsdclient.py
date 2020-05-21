# Copyright 2016 NOKIA
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

from abc import abstractmethod


class VsdClient(object):

    def __init__(self):
        pass

    @abstractmethod
    def verify_cms(self, id):
        pass

    @abstractmethod
    def get_usergroup(self, tenant, net_partition_id):
        pass

    @abstractmethod
    def create_usergroup(self, tenant, net_partition_id):
        pass

    @abstractmethod
    def delete_user(self, id):
        pass

    @abstractmethod
    def delete_group(self, id):
        pass

    def create_net_partition(self, params):
        pass

    def get_l2domain_fields_for_pg(self, parent_id, fields):
        pass

    def get_l3domain_np_id(self, parent_id):
        pass

    def delete_net_partition(self, id):
        pass

    def link_default_netpartition(self, params):
        pass

    def get_net_partitions(self):
        pass

    def get_netpartition_by_name(self, name):
        pass

    def get_netpartition_data(self, ent_name):
        pass

    def get_net_partition_name_by_id(self, ent_id):
        pass

    def get_nuage_fip_by_id(self, params):
        pass

    def get_nuage_fip_pool_by_id(self, params):
        pass

    def set_fip_quota_at_ent_profile(self, fip_quota):
        pass

    def get_subnet_by_netpart(self, netpart_id):
        pass

    def create_subnet(self, ipv4_subnet, ipv6_subnet, params):
        pass

    def delete_subnet(self, mapping=None, l2dom_id=None, l3_vsd_subnet_id=None,
                      ipv4_subnet=None, ipv6_subnet=None):
        pass

    def update_l2domain_dhcp_options(self, nuage_subnet_id,
                                     neutron_subnet):
        pass

    def update_l2domain_template(self, nuage_l2dom_tmplt_id, **kwargs):
        pass

    def update_l2domain(self, nuage_l2dom_id, **kwargs):
        pass

    def update_domain_subnet_dhcp_options(self, nuage_subnet_id,
                                          neutron_subnet):
        pass

    def update_domain_subnet(self, nuage_subnet_id, params):
        pass

    def update_nuage_subnet(self, nuage_id, params):
        pass

    def attach_nuage_group_to_nuagenet(self, tenant, nuage_npid,
                                       subnet_mapping, shared, tenant_name):
        pass

    def detach_nuage_group_to_nuagenet(
            self, tenants, nuage_subnetid, shared):
        pass

    def get_gateway_ip_for_advsub(self, vsd_subnet):
        pass

    def check_if_l2_dom_in_correct_ent(self, nuage_l2dom_id, nuage_netpart):
        pass

    def get_router_by_external(self, id):
        pass

    def move_l2domain_to_l3subnet(self, l2domain_id, l3subnetwork_id):
        pass

    def confirm_router_interface_not_in_use(self, router_id, os_subnet):
        pass

    def create_l2domain_for_router_detach(self, os_subnet, subnet_mapping,
                                          ipv6_subnet=None, ipv4_dhcp_ip=None,
                                          ipv6_dhcp_ip=None):
        pass

    def move_l3subnet_to_l2domain(self, l3subnetwork_id, l2domain_id,
                                  ipv4_subnet_mapping,
                                  subnet, ipv6_subnet_mapping):
        pass

    def create_nuage_floatingip(self, params):
        pass

    def create_nuage_floatingip_details(self, params):
        pass

    def get_nuage_floatingip(self, id, required=False, **filters):
        pass

    def get_nuage_floatingips(self, required=False, **filters):
        pass

    def get_nuage_domain_floatingips(self, domain_id, required=False,
                                     **filters):
        pass

    def update_vport(self, vport_id, data):
        pass

    def delete_nuage_floatingip(self, id):
        pass

    def get_nuage_static_route(self, params):
        pass

    def create_nuage_staticroute(self, params):
        pass

    def delete_nuage_staticroute(self, params):
        pass

    def validate_port_create_redirect_target(self, params):
        pass

    def check_unused_policygroups(self, securitygroup_ids, sg_type='SOFTWARE'):
        pass

    def get_zone_by_domainid(self, domain_id):
        pass

    def get_zone_by_routerid(self, neutron_router_id, shared=False):
        pass

    def validate_zone_create(self, l3dom_id,
                             l3isolated, l3shared):
        pass

    def get_nuage_port_by_id(self, params):
        pass

    def get_routers_by_netpart(self, netpart_id):
        pass

    def get_fip_underlay_enabled_domain_by_netpart(self, netpart_id):
        pass

    def get_domain_subnet_by_zone_id(self, zone_id):
        pass

    def get_domain_subnet_by_id(self, subnet_id):
        pass

    def get_domain_subnet_by_ext_id_and_cidr(self, subnet):
        pass

    def get_l2domain_by_id(self, l2domain_id):
        pass

    def get_l2domain_by_ext_id_and_cidr(self, subnet):
        pass

    def create_l3domain(self, neutron_router, router, net_partition,
                        tenant_name):
        pass

    def create_shared_l3domain(self, params):
        pass

    def delete_l3domain(self, domain_id):
        pass

    def get_l3domain_by_id(self, l3domain_id, required=False):
        pass

    def get_router_np_id(self, router_id):
        pass

    def create_shared_subnet(self, vsd_zone_id, subnet, params):
        pass

    def get_nuage_subnet_by_id(self, nuage_id, subnet_type=None,
                               required=False):
        pass

    def get_nuage_subnet_by_mapping(self, subnet_mapping, required=False):
        pass

    def get_gw_from_dhcp_l2domain(self, nuage_id):
        pass

    def get_router_by_domain_subnet_id(self, dom_subn_id):
        pass

    def get_nuage_vport_by_id(self, id, required=True):
        pass

    def get_nuage_vport_by_neutron_id(self, params, required=True):
        pass

    def get_vports(self, parent, parent_id, **filters):
        pass

    def get_vports_by_external_ids(self, parent, parent_id, external_ids):
        pass

    def delete_nuage_vport(self, vport_id):
        pass

    def delete_domain_subnet(self, vsd_subnet_id, os_subnet_id):
        pass

    def create_domain_subnet(self, vsd_zone, ipv4_subnet, ipv6_subnet,
                             network_name):
        pass

    def validate_create_domain_subnet(self, neutron_subn,
                                      nuage_subnet_id, nuage_rtr_id):
        pass

    def process_port_create_security_group(self, params):
        pass

    def create_security_group(self, vsd_subnet, os_security_group):
        pass

    def create_security_group_using_parent(self, parent_id, parent_type,
                                           os_security_group):
        pass

    def create_security_group_rules(self, policygroup, security_group_rules):
        pass

    def update_vports_in_policy_group(self, pg_id, vport_list):
        pass

    def update_vport_policygroups(self, vport_id, policygroup_ids):
        pass

    def get_rate_limit(self, vport_id, neutron_fip_id):
        pass

    def create_update_rate_limiting(self, rate_limit, vport_id,
                                    neutron_fip_id):
        pass

    def delete_rate_limiting(self, vport_id, neutron_fip_id):
        pass

    def delete_nuage_sgrule(self, sg_rules, sg_type='SOFTWARE'):
        pass

    def delete_nuage_secgroup(self, id):
        pass

    def delete_nuage_policy_group(self, policy_id):
        pass

    def validate_nuage_sg_rule_definition(self, sg_rule):
        pass

    def get_sg_policygroup_by_external_id(self, sg_id,
                                          sg_type='SOFTWARE',
                                          required=False):
        pass

    def update_policygroup(self, policygroup_id, data):
        pass

    def get_sg_policygroup_mapping(self, sg_id, sg_type='SOFTWARE'):
        pass

    def create_nuage_sgrule(self, params):
        pass

    def create_in_adv_fwd_policy_template(self, parent_type,
                                          parent_id, params):
        pass

    def update_in_adv_fwd_policy_template(self, nuage_id, params):
        pass

    def delete_in_adv_fwd_policy_template(self, tmplt_id):
        pass

    def get_in_adv_fwd_policy_by_cmsid(self, parent_type, parent_id):
        pass

    def get_in_adv_fwd_policy_by_externalid(self, parent_type,
                                            parent_id,
                                            portchain_id):
        pass

    def create_nuage_redirect_target(self, redirect_target, l2dom_id=None,
                                     domain_id=None):
        pass

    def get_nuage_redirect_target(self, rtarget_id):
        pass

    def get_nuage_redirect_targets(self, params):
        pass

    def get_nuage_redirect_targets_by_single_filter(self, filters,
                                                    required=False):
        pass

    def delete_nuage_redirect_target(self, rtarget_id):
        pass

    def delete_port_redirect_target_bindings(self, params):
        pass

    def update_nuage_vport_redirect_target(self, rtarget_id, vport_id):
        pass

    def update_redirect_target_vports(self, redirect_target_id,
                                      nuage_port_id_list):
        pass

    def create_virtual_ip(self, rtarget_id, vip, vip_port_id):
        pass

    def delete_nuage_redirect_target_vip(self, rtarget_vip_id):
        pass

    def create_nuage_redirect_target_rule(self, params, rt=None):
        pass

    def add_nuage_sfc_rule(self, tmplt, rule_params, np_id):
        pass

    def get_nuage_redirect_target_rules(self, params):
        pass

    def get_nuage_redirect_target_rules_by_external_id(self, neutron_id):
        pass

    def get_nuage_redirect_target_rule(self, rtarget_rule_id):
        pass

    def delete_nuage_redirect_target_rule(self, rtarget_rule_id):
        pass

    def get_redirect_target_vports(self, rtarget_id, required=False):
        pass

    def create_nuage_external_security_group(self, params):
        pass

    def create_nuage_sec_grp_for_no_port_sec(self, params):
        pass

    def create_nuage_sec_grp_for_sfc(self, params):
        pass

    def get_policygroup_vport_mapping_by_port_id(self, vport_id):
        pass

    def get_nuage_external_security_group(self, ext_sg_id):
        pass

    def get_nuage_external_security_groups(self, params):
        pass

    def delete_nuage_external_security_group(self, ext_sg_id):
        pass

    def create_nuage_external_sg_rule(self, params):
        pass

    def get_nuage_external_sg_rule(self, ext_rule_id):
        pass

    def get_nuage_external_sg_rules(self, params):
        pass

    def delete_nuage_external_sg_rule(self, ext_rule_id):
        pass

    def nuage_redirect_targets_on_l2domain(self, l2domid):
        pass

    def vms_on_l2domain(self, l2dom_id):
        pass

    def vms_on_subnet(self, subnet_id):
        pass

    def create_vms(self, params):
        pass

    def delete_vms(self, params):
        pass

    def delete_vm_by_external_id(self, params):
        pass

    def delete_vm_by_id(self, params):
        pass

    def update_nuage_vm_vport(self, params):
        pass

    def get_nuage_vm_if_by_vport_id(self, vport_id):
        pass

    def update_nuage_vm_if(self, params):
        pass

    def create_vport(self, params):
        pass

    def nuage_vports_on_l2domain(self, l2dom_id):
        pass

    def nuage_vports_on_subnet(self, subnet_id):
        pass

    def crt_or_updt_vport_dhcp_option(self, extra_dhcp_opt, resource_id,
                                      external_id):
        pass

    def delete_vport_nuage_dhcp(self, dhcp_opt, vport_id):
        pass

    def delete_vport_dhcp_option(self, dhcp_id, ip_version, on_rollback):
        pass

    def update_router(self, nuage_domain_id, router, updates):
        pass

    def get_gateway(self, tenant_id, gw_id):
        pass

    def get_gateways(self, tenant_id, filters):
        pass

    def get_gateway_ports(self, tenant_id, filters):
        pass

    def get_gateway_port(self, tenant_id, gw_port_id):
        pass

    # JvB added
    def update_gateway_port(self, gw_port_id, port_dict):
        pass

    def get_gateway_port_vlans(self, tenant_id, netpart_id, filters):
        pass

    def get_gateway_port_vlan(self, tenant_id, gw_intf_id):
        pass

    def create_gateway_port_vlan(self, vlan_dict):
        pass

    def create_gateway_vlan(self, vlan_dict):
        pass

    def delete_gateway_port_vlan(self, vlan_id):
        pass

    def update_gateway_port_vlan(self, tenant_id, id, params):
        pass

    def create_gateway_vport(self, tenant_id, vport_dict):
        pass

    def create_gateway_vport_no_usergroup(self, tenant_id, vport_dict,
                                          create_policy_group=False):
        pass

    def delete_nuage_gateway_vport(self, context, id, def_netpart_id):
        pass

    def delete_nuage_gateway_vport_no_usergroup(self, tenant_id, vport):
        pass

    def get_gateway_vport(self, context, tenant_id, netpart_id,
                          nuage_vport_id):
        pass

    def get_gateway_vports(self, context, tenant_id, netpart_id, filters):
        pass

    def get_host_and_bridge_vports(self, subnet_id, subnet_type):
        pass

    def get_nuage_prefix_macro(self, net_macro_id):
        pass

    def get_nuage_fip(self, nuage_fip_id):
        pass

    def get_vport_assoc_with_fip(self, nuage_fip_id):
        pass

    def create_vip(self, params):
        pass

    def get_vips(self, vport_id):
        pass

    def create_vip_on_vport(self, params):
        pass

    def delete_vips(self, vport_id, vip_dict, vips):
        pass

    def update_fip_to_vips(self, neutron_subnet_id, vip, vsd_fip_id):
        pass

    def process_deleted_addr_pair(self, params):
        pass

    def change_perm_of_subns(self, nuage_npid, nuage_subnetid, shared,
                             tenant_id, remove_everybody=False):
        pass

    def update_mac_spoofing_on_vport(self, nuage_vport_id, status):
        pass

    def get_nuage_zone_by_id(self, zone_id):
        pass

    def get_nuage_domain_id_from_subnet(self, dom_subn_id):
        pass

    def get_nuage_domain_by_zoneid(self, zone_id):
        pass

    def get_nuage_vport_for_port_sec(self, params, required=True):
        pass

    def get_nuage_policy_group(self, id, required=False, **filters):
        pass

    def get_nuage_policy_groups(self, required=False, **filters):
        pass

    def get_policy_groups_by_single_filter(self, filters, required=False):
        pass

    def get_nuage_vport_policy_groups(self, vport_id, required=False,
                                      **filters):
        pass

    def get_nuage_l2domain_policy_groups(self, l2domain_id, required=False,
                                         **filters):
        pass

    def get_nuage_domain_policy_groups(self, domain_id, required=False,
                                       **filters):
        pass

    def get_nuage_policy_group_vports(self, policygroup_id, required=False,
                                      **filters):
        pass

    def get_nuage_vport_redirect_targets(self, vport_id, required=False,
                                         **filters):
        pass

    def create_nuage_fip_for_vpnaas(self, params):
        pass

    # Firewall

    def create_firewall_rule(self, enterprise_id, os_rule):
        pass

    def update_firewall_rule(self, enterprise_id, id, os_rule):
        pass

    def delete_firewall_rule(self, enterprise_id, id):
        pass

    def delete_vsd_firewallrule(self, id):
        pass

    def create_firewall_policy(self, enterprise_id, os_policy):
        pass

    def update_firewall_policy(self, enterprise_id, id, os_policy):
        pass

    def delete_firewall_policy(self, enterprise_id, id):
        pass

    def insert_rule(self, enterprise_id, os_policy_id, os_rule_info):
        pass

    def remove_rule(self, enterprise_id, os_policy_id, os_rule_info):
        pass

    def create_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        pass

    def update_firewall(self, enterprise_id, os_firewall, l3domain_ids,
                        handle_block_acl, routers_updated):
        pass

    def delete_firewall(self, enterprise_id, os_firewall, l3domain_ids):
        pass

    # Plugin stats

    def get_nuage_plugin_stats(self):
        pass

    def create_trunk(self, os_trunk, subnet_mapping):
        pass

    def delete_trunk(self, os_trunk, subnet_mapping):
        pass

    def add_subport(self, os_trunk_id, os_subport, data):
        pass

    def remove_subport(self, os_port, subnet_mapping):
        pass

    def update_subport(self, os_port, vport, params):
        pass
