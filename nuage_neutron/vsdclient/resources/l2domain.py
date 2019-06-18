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

import logging

import netaddr

from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.resources import dhcpoptions
from nuage_neutron.vsdclient import restproxy

CONFLICT_ERR_CODE = constants.VSD_RESP_OBJ
VSD_RESP_OBJ = constants.VSD_RESP_OBJ
RES_EXISTS_INTERNAL_ERR_CODE = constants.RES_EXISTS_INTERNAL_ERR_CODE

LOG = logging.getLogger(__name__)


class NuageL2Domain(object):
    def __init__(self, restproxy, policygroups):
        self.restproxy = restproxy
        self.policygroups = policygroups

    def get_subnet_by_netpart(self, netpart_id):
        nuagel2dom = nuagelib.NuageL2Domain({'net_partition_id': netpart_id})
        response = self.restproxy.rest_call(
            'GET', nuagel2dom.get_all_resources_in_ent(), '')
        if not nuagel2dom.validate(response):
            raise nuagel2dom.get_rest_proxy_error()
        res = []
        for l2dom in nuagel2dom.get_response_objlist(response):
            np_dict = dict()
            np_dict['name'] = l2dom['name']
            np_dict['ID'] = l2dom['ID']
            np_dict['subnet_os_id'] = strip_cms_id(l2dom['externalID'])
            np_dict['dhcp_managed'] = l2dom['DHCPManaged']
            np_dict['IPType'] = l2dom['IPType']
            np_dict['ipv4_cidr'] = \
                str(netaddr.IPNetwork("{}/{}".format(l2dom['address'],
                                                     l2dom['netmask'])))\
                if l2dom.get('address') else ""
            np_dict['IPv6Address'] = l2dom['IPv6Address']
            np_dict['ipv4_gateway'] = \
                self.get_gw_from_dhcp_options(l2dom['ID'])
            np_dict['IPv6Gateway'] = l2dom['IPv6Gateway']
            np_dict['net_partition_id'] = netpart_id

            res.append(np_dict)
        return res

    def get_subnet_by_id(self, nuage_id):
        nuagel2dom = nuagelib.NuageL2Domain()
        return self.restproxy.get(nuagel2dom.get_resource(nuage_id),
                                  required=True)[0]

    def update_subnet_to_dualstack(self, ipv4_subnet, ipv6_subnet, params):
        mapping = params['mapping']
        data = helper.get_subnet_update_data(ipv4_subnet, ipv6_subnet, params)
        self.update_l2domain_for_stack_exchange(mapping, **data)
        nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
        if mapping['subnet_id'] == ipv4_subnet['id']:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv6_subnet,
                parent_id=mapping['nuage_subnet_id'],
                network_type=constants.NETWORK_TYPE_L2)
        if mapping['subnet_id'] == ipv6_subnet['id']:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv4_subnet,
                parent_id=mapping['nuage_subnet_id'],
                network_type=constants.NETWORK_TYPE_L2)

    def update_l2domain_for_stack_exchange(self, mapping, **data):
        nuagel2domtmplt = nuagelib.NuageL2DomTemplate()
        self.restproxy.put(
            nuagel2domtmplt.put_resource(mapping['nuage_l2dom_tmplt_id']),
            data)
        # update the name/descrition for l2domain
        nuagel2dom = nuagelib.NuageL2Domain()
        l2dom_data = {'name': data['name']}
        if data.get('description'):
            l2dom_data['description'] = data['description']
        self.restproxy.put(
            nuagel2dom.put_resource(mapping['nuage_subnet_id']),
            l2dom_data)

    def create_subnet(self, ipv4_subnet, ipv6_subnet, params):
        subnet = ipv4_subnet or ipv6_subnet
        req_params = {'net_partition_id': params['netpart_id'],
                      'name': helper.get_subnet_name(subnet)}
        ext_params = {
            'externalID': helper.get_subnet_external_id(subnet),
            'DHCPManaged': True,
            'dualStackDynamicIPAllocation': False
        }

        if ipv4_subnet:
            net = netaddr.IPNetwork(ipv4_subnet['cidr'])
            ext_params.update({
                'address': str(net.ip),
                'netmask': str(net.netmask),
                'gateway': params['dhcp_ip'],
                'IPType': constants.IPV4,
                'enableDHCPv4': ipv4_subnet['enable_dhcp']
            })
        elif ipv6_subnet:
            net = netaddr.IPNetwork(ipv6_subnet['cidr'])
            ext_params.update({
                'IPv6Address': str(net.cidr),
                'IPv6Gateway': params['dhcpv6_ip'],
                'IPType': constants.IPV6,
                'enableDHCPv6': ipv6_subnet['enable_dhcp']
            })
        description = None
        if ipv4_subnet and ipv6_subnet:
            params.update({'network_id': subnet['network_id']})
            ext_params.update(
                helper.get_subnet_update_data(ipv4_subnet=ipv4_subnet,
                                              ipv6_subnet=ipv6_subnet,
                                              params=params))
            req_params['name'] = ext_params.pop('name')
            description = ext_params.pop('description')

        nuagel2domtmplt = nuagelib.NuageL2DomTemplate(create_params=req_params,
                                                      extra_params=ext_params)
        nuagel2domtemplate = self.restproxy.post(
            nuagel2domtmplt.post_resource(),
            nuagel2domtmplt.post_data(),
            on_res_exists=self.restproxy.retrieve_by_ext_id_and_cidr)[0]

        l2dom_tmplt_id = nuagel2domtemplate['ID']

        req_params['template'] = l2dom_tmplt_id
        req_params['externalID'] = ext_params['externalID']

        if not description:
            description = helper.get_subnet_description(subnet)
        ext_params = {
            'address': ext_params.get('address'),
            'IPv6Address': ext_params.get('IPv6Address'),
            'description': description,
            'IPType': ext_params['IPType']
        }
        nuagel2domain = nuagelib.NuageL2Domain(create_params=req_params,
                                               extra_params=ext_params)
        try:
            l2domain = self.restproxy.post(
                nuagel2domain.post_resource(),
                nuagel2domain.post_data(),
                on_res_exists=self.restproxy.retrieve_by_ext_id_and_cidr)[0]
        except Exception:
            self.restproxy.delete(
                nuagel2domtmplt.delete_resource(nuagel2domtemplate['ID']))
            raise

        l2domain_id = l2domain['ID']
        subnet_dict = {
            'nuage_l2template_id': l2dom_tmplt_id,
            'nuage_l2domain_id': l2domain_id,
            'nuage_external_id': strip_cms_id(l2domain['externalID']),
            'nuage_parent_id': l2domain['parentID']
        }

        nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
        if ipv4_subnet:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv4_subnet,
                parent_id=l2domain_id,
                network_type=constants.NETWORK_TYPE_L2)
        if ipv6_subnet:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv6_subnet,
                parent_id=l2domain_id,
                network_type=constants.NETWORK_TYPE_L2)

        nuage_userid, nuage_groupid = helper.create_usergroup(
            self.restproxy,
            params['tenant_id'],
            params['netpart_id'],
            params.get('tenant_name'))
        subnet_dict['nuage_userid'] = nuage_userid
        subnet_dict['nuage_groupid'] = nuage_groupid

        self._attach_nuage_group_to_l2domain(nuage_groupid,
                                             l2domain_id,
                                             params['netpart_id'],
                                             params.get('shared'),
                                             params['tenant_id'])
        self._create_nuage_def_l2domain_acl(l2domain_id, subnet)
        self._create_nuage_def_l2domain_adv_fwd_template(l2domain_id,
                                                         subnet)

        return subnet_dict

    def delete_subnet_from_dualstack(self, mapping, ipv4_subnet=None,
                                     ipv6_subnet=None):
        try:
            data = helper.get_subnet_update_data(
                ipv4_subnet, ipv6_subnet, params=None)
            self.update_l2domain_for_stack_exchange(mapping, **data)
            # Delete dhcp options:
            nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
            if ipv4_subnet:
                # Delete ipv6 dhcp options
                nuagedhcpoptions.clear_nuage_dhcp_for_ip_version(
                    constants.IPV6_VERSION, mapping['nuage_subnet_id'],
                    constants.NETWORK_TYPE_L2)
            else:
                nuagedhcpoptions.clear_nuage_dhcp_for_ip_version(
                    constants.IPV4_VERSION, mapping['nuage_subnet_id'],
                    constants.NETWORK_TYPE_L2)
        except restproxy.RESTProxyError as e:
            if e.code != constants.RES_NOT_FOUND:
                raise

    def get_l2domain_by_ext_id_and_cidr(self, subnet):
        params = {
            'externalID': helper.get_subnet_external_id(subnet),
            'cidr': netaddr.IPNetwork(subnet['cidr']),
            'ip_type': subnet['ip_version']
        }
        nuagel2domain = nuagelib.NuageL2Domain(create_params=params)
        l2domain = self.restproxy.get(
            nuagel2domain.get_all_resources(),
            extra_headers=nuagel2domain.extra_headers_ext_id_and_cidr_get())
        if l2domain:
            return l2domain[0]
        else:
            msg = ("Cannot find subnet with externalID {} and cidr {}"
                   " in L2domains on VSD").format(params['externalID'],
                                                  params['cidr'])
            raise restproxy.ResourceNotFoundException(msg)

    def delete_subnet(self, l2dom_id, mapping):
        nuagel2domain = nuagelib.NuageL2Domain()
        l2dom = self.restproxy.get(nuagel2domain.get_resource(l2dom_id))[0]
        nuagel2domtemplate = nuagelib.NuageL2DomTemplate()
        if l2dom:
            template_id = l2dom['templateID']
            template = self.restproxy.get(
                nuagel2domtemplate.get_resource(template_id))[0]
            l2domain_id = l2dom['ID']

            # delete subnet
            self.restproxy.delete(nuagel2domain.delete_resource(l2domain_id))

            if template and l2dom['name'] == template['name']:
                self.restproxy.delete(
                    nuagel2domtemplate.delete_resource(template_id))

        elif mapping and mapping['nuage_l2dom_tmplt_id']:
            # Delete hanging l2dom_template
            self.restproxy.delete(
                nuagel2domtemplate.delete_resource(
                    mapping['nuage_l2dom_tmplt_id']))

    def update_subnet(self, neutron_subnet, params):
        if params.get('dhcp_opts_changed'):
            nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
            nuagedhcpoptions.update_nuage_dhcp(
                neutron_subnet, parent_id=params['parent_id'],
                network_type=constants.NETWORK_TYPE_L2)

        if params['dhcp_enable_changed']:
            if params.get('ip_type') == constants.IPV4:
                data = {
                    "enableDHCPv4": neutron_subnet.get('enable_dhcp')
                }
                if neutron_subnet.get('enable_dhcp'):
                    data["gateway"] = params['dhcp_ip']
                else:
                    data["gateway"] = None
            else:
                data = {
                    'enableDHCPv6': neutron_subnet.get('enable_dhcp')
                }
                if neutron_subnet.get('enable_dhcp'):
                    data["IPv6Gateway"] = params['dhcp_ip']
                else:
                    data["IPv6Gateway"] = None
            nuagel2domtemplate = nuagelib.NuageL2DomTemplate()
            self.restproxy.put(
                nuagel2domtemplate.put_resource(
                    params['l2dom_template_id']), data)
            nuagel2domain = nuagelib.NuageL2Domain()
            self.restproxy.put(
                nuagel2domain.put_resource(params['l2dom_id']), data)

        new_name = helper.get_subnet_description(neutron_subnet,
                                                 params.get('network_name'))
        if new_name:
            # update the description on the VSD for this subnet if required
            # If a subnet is updated from horizon, we get the name of the
            # subnet as well in the subnet dict for update.
            nuagel2domain = nuagelib.NuageL2Domain()
            l2domain = self.restproxy.get(
                nuagel2domain.get_resource(params['parent_id']),
                required=True)[0]
            # For single stack, subnet name change will make description change
            # For dualstack, network name change will make description change
            if (l2domain['description'] != new_name and
                    not params.get('dualstack')):
                self.restproxy.put(
                    nuagel2domain.put_resource(params['parent_id']),
                    {'description': new_name})

    def update_subnet_description(self, nuage_id, new_description):
        nuagel2domain = nuagelib.NuageL2Domain()
        l2domain = self.restproxy.get(
            nuagel2domain.get_resource(nuage_id),
            required=True)[0]
        if l2domain['description'] != new_description:
            self.restproxy.put(
                nuagel2domain.put_resource(nuage_id),
                {'description': new_description})

    def _attach_nuage_group_to_l2domain(self, nuage_groupid,
                                        nuage_subnetid, nuage_npid,
                                        shared,
                                        neutron_tenant_id):
        if shared:
            params = {
                'net_partition_id': nuage_npid
            }
            nuagegroup = nuagelib.NuageGroup(create_params=params)
            response = self.restproxy.rest_call(
                'GET', nuagegroup.list_resource(), '',
                nuagegroup.extra_headers_get_for_everybody())
            if not nuagegroup.validate(response):
                raise nuagegroup.get_rest_proxy_error()
            nuage_groupid = nuagegroup.get_groupid(response)

        nuage_permission = nuagelib.NuagePermission()
        post_data = nuage_permission.perm_create_data(
            nuage_groupid,
            constants.NUAGE_PERMISSION_USE,
            neutron_tenant_id)
        resp = self.restproxy.rest_call(
            'POST',
            nuage_permission.post_resource_by_parent_id(
                'l2domains', nuage_subnetid), post_data)
        if not nuage_permission.validate(resp):
            if (nuage_permission.error_code !=
                    constants.CONFLICT_ERR_CODE):
                raise nuage_permission.get_rest_proxy_error()

    def _create_nuage_def_l2domain_acl(self, id, neutron_subnet):
        helper.create_nuage_l2dom_ingress_tmplt(self.restproxy,
                                                id,
                                                neutron_subnet)
        helper.create_nuage_l2dom_egress_tmplt(self.restproxy,
                                               id,
                                               neutron_subnet)

    def _create_nuage_def_l2domain_adv_fwd_template(self, l2dom_id,
                                                    neutron_subnet):
        nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
        external_id = helper.get_subnet_external_id(neutron_subnet)
        response = self.restproxy.post(
            nuageadvfwdtmplt.post_resource_l2(l2dom_id),
            nuageadvfwdtmplt.post_data_default_l2(l2dom_id, external_id),
            ignore_err_codes=[restproxy.REST_DUPLICATE_ACL_PRIORITY])
        return response[0]['ID']

    def attach_nuage_group_to_nuagenet(self, tenant, nuage_npid,
                                       nuage_subnetid, shared, tenant_name):
        nuage_uid, nuage_gid = helper.create_usergroup(self.restproxy, tenant,
                                                       nuage_npid, tenant_name)
        nuagesubn = nuagelib.NuageSubnet()
        nuagegroup = nuagelib.NuageGroup()

        if shared:
            # Get the id for grp 'everybody'
            params = {
                'net_partition_id': nuage_npid
            }
            nuagegroup = nuagelib.NuageGroup(create_params=params)
            response = self.restproxy.rest_call(
                'GET', nuagegroup.list_resource(), '',
                nuagegroup.extra_headers_get_for_everybody())
            if not nuagegroup.validate(response):
                raise nuagegroup.get_rest_proxy_error()
            nuage_all_groupid = nuagegroup.get_groupid(response)

        response = self.restproxy. \
            rest_call('GET', nuagesubn.get_resource(nuage_subnetid),
                      '')
        if not nuagesubn.validate(response):
            nuagel2dom = nuagelib.NuageL2Domain()
            response = self.restproxy. \
                rest_call('GET', nuagel2dom.get_resource(nuage_subnetid),
                          '')
            if not nuagel2dom.validate(response):
                raise nuagel2dom.get_rest_proxy_error()
            if shared:
                self.create_permission(nuage_subnetid,
                                       nuage_all_groupid, tenant,
                                       perm_on='l2domains')
            else:
                self.create_permission(nuage_subnetid,
                                       nuage_gid, tenant,
                                       perm_on='l2domains')
            return nuage_uid, nuage_gid
        else:
            if shared:
                self.create_permission(nuagesubn.get_parentzone(response),
                                       nuage_all_groupid, tenant)
            else:
                self.create_permission(nuagesubn.get_parentzone(response),
                                       nuage_gid, tenant)
            return nuage_uid, nuage_gid

    def create_permission(self, nuage_id, nuage_groupid,
                          tenant, perm_on='zones'):
        nuage_permission = nuagelib.NuagePermission()
        resource = nuage_permission.post_resource_by_parent_id(
            perm_on, nuage_id)
        post_data = nuage_permission.perm_create_data(
            nuage_groupid,
            constants.NUAGE_PERMISSION_USE,
            tenant)
        resp = self.restproxy.rest_call(
            'POST', resource, post_data)
        if not nuage_permission.validate(resp):
            if (nuage_permission.get_error_code(resp) !=
                    constants.CONFLICT_ERR_CODE):
                raise nuage_permission.get_rest_proxy_error()

    def detach_nuage_group_to_nuagenet(
            self, tenants, nuage_subnetid, shared):
        nuagesubn = nuagelib.NuageSubnet()

        response = self.restproxy.rest_call('GET',
                                            nuagesubn.get_resource(
                                                nuage_subnetid), '')
        if not nuagesubn.validate(response):
            nuagel2dom = nuagelib.NuageL2Domain()
            response = self.restproxy.rest_call('GET',
                                                nuagel2dom.get_resource(
                                                    nuage_subnetid), '')
            if not nuagel2dom.validate(response):
                # This is the case where the VSD-Managed subnet is deleted
                # from VSD first and then neutron subnet-delete operation
                # is performed from openstack
                # for both l2/l3 case we'll return form here
                return
            params = {
                'l2dom_id': nuage_subnetid
            }
            nuagepermission = nuagelib.NuagePermission(create_params=params)
            resource = nuagepermission.get_resource_by_l2dom_id()
        else:
            zone_id = nuagesubn.get_parentzone(response)
            params = {
                'zone_id': zone_id
            }
            nuagepermission = nuagelib.NuagePermission(create_params=params)
            resource = nuagepermission.get_resource_by_zone_id()
            nuage_dom = helper.get_nuage_domain_by_zoneid(self.restproxy,
                                                          zone_id)

            if nuage_dom['externalID']:
                # The perm. attached to the zone when the router is deleted
                # from openstack
                return

        response = self.restproxy.rest_call('GET', resource, '')
        if not nuagepermission.validate(response):
            if response[0] == constants.RES_NOT_FOUND:
                return
            raise nuagepermission.get_rest_proxy_error()

        permissions = response[3]
        if shared:
            tenants.append("Everybody")
        for permission in permissions:
            if permission['permittedEntityName'] in tenants:
                self.restproxy.delete(
                    nuagepermission.delete_resource(permission['ID']))

    def get_gateway_ip_for_advsub(self, vsd_subnet):
        LOG.debug("vsdclient.get_gateway_ip_for_advsub() called")
        if vsd_subnet['type'] == constants.SUBNET:
            return vsd_subnet['gateway']
        else:
            nuagel2dom = nuagelib.NuageL2Domain()
            dhcpoptions = self.restproxy.get(
                nuagel2dom.dhcp_get_resource(vsd_subnet['ID']))
            # dhcp_port_exist will exist in case for adv. subnet when it is
            # set via rest call on VSD
            gw_ip = None
            for dhcpoption in dhcpoptions:
                if dhcpoption['type'] == constants.DHCP_ROUTER_OPTION:
                    gw_ip = nuagel2dom.get_gwIp_set_via_dhcp(dhcpoption)
            return gw_ip

    def check_if_l2_dom_in_correct_ent(self, nuage_l2dom_id, nuage_netpart):
        nuagesubn = nuagelib.NuageSubnet()
        resp_subn = self.restproxy.rest_call(
            'GET',
            nuagesubn.get_resource(nuage_l2dom_id),
            '')
        if not nuagesubn.validate(resp_subn):
            nuagel2dom = nuagelib.NuageL2Domain()
            response = self.restproxy.rest_call(
                'GET', nuagel2dom.get_resource(nuage_l2dom_id), '')

            if not nuagel2dom.validate(response):
                raise nuagel2dom.get_rest_proxy_error()
            else:
                if response[3][0]['parentID'] == nuage_netpart['id']:
                    return True
                return False
        else:
            req_params = {
                'zone_id': resp_subn[3][0]['parentID']
            }
            nuagezone = nuagelib.NuageZone(create_params=req_params)
            resp_zone = self.restproxy.rest_call(
                'GET', nuagezone.get_resource(), '')

            if not nuagezone.validate(resp_zone):
                raise nuagezone.get_rest_proxy_error()

            req_params = {
                'domain_id': resp_zone[3][0]['parentID']
            }
            nuage_l3domain = nuagelib.NuageL3Domain(create_params=req_params)
            dom_resp = self.restproxy.rest_call(
                'GET', nuage_l3domain.get_resource(), '')

            if not nuage_l3domain.validate(dom_resp):
                raise nuage_l3domain.get_rest_proxy_error()

            if dom_resp[3][0]['parentID'] == nuage_netpart['id']:
                return True
            return False

    def get_gw_from_dhcp_options(self, nuage_id):
        l2domain = nuagelib.NuageL2Domain()
        dhcpoptions = self.restproxy.get(l2domain.dhcp_get_resource(nuage_id))
        for dhcpoption in dhcpoptions:
            if dhcpoption['type'] == constants.DHCP_ROUTER_OPTION:
                return l2domain.get_gwIp_set_via_dhcp(dhcpoption)

    def move_to_l3(self, l2domain_id, subnet_id):
        url = nuagelib.Job.post_url(parent=nuagelib.NuageL2Domain.resource,
                                    parent_id=l2domain_id)
        self.restproxy.post(url, {
            'command': 'ATTACH',
            'parameters': {'destinationSubnetID': subnet_id}
        })
