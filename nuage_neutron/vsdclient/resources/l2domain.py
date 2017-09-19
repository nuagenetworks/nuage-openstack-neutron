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

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.common import pnet_helper
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
            raise restproxy.RESTProxyError(nuagel2dom.error_msg)
        res = []
        for l2dom in nuagel2dom.get_response_objlist(response):
            np_dict = dict()
            np_dict['domain_name'] = l2dom['name']
            np_dict['domain_id'] = l2dom['ID']
            np_dict['subnet_os_id'] = strip_cms_id(l2dom['externalID'])
            res.append(np_dict)
        return res

    def get_subnet_by_id(self, nuage_id):
        nuagel2dom = nuagelib.NuageL2Domain()
        return self.restproxy.get(nuagel2dom.get_resource(nuage_id),
                                  required=True)[0]

    def update_subnet_ipv6(self, ipv6_subnet, mapping):
        data = helper.get_ipv6_vsd_data(ipv6_subnet)
        self.update_l2domain_template(mapping['nuage_l2dom_tmplt_id'], **data)

    def update_l2domain_template(self, template_id, **data):
        nuagel2domtmplt = nuagelib.NuageL2DomTemplate()
        self.restproxy.put(nuagel2domtmplt.put_resource(template_id), data)

    def create_subnet(self, ipv4_subnet, params, ipv6_subnet=None):
        net = netaddr.IPNetwork(ipv4_subnet['cidr'])
        req_params = {
            'net_partition_id': params['netpart_id'],
            'name': ipv4_subnet['id'],
        }
        ext_params = {
            'DHCPManaged': ipv4_subnet['enable_dhcp'],
            'address': str(net.ip),
            'netmask': str(net.netmask),
            'gateway': params['dhcp_ip'],
            'externalID': get_vsd_external_id(ipv4_subnet['id']),
            'dynamicIpv6Address': False
        }
        ext_params.update(helper.get_ipv6_vsd_data(ipv6_subnet))
        l2domain = helper.get_subnet_by_externalID(
            self.restproxy, ext_params["externalID"])
        nuagel2domtmplt = nuagelib.NuageL2DomTemplate(create_params=req_params,
                                                      extra_params=ext_params)
        nuagel2domtemplate = self.restproxy.post(
            nuagel2domtmplt.post_resource(),
            nuagel2domtmplt.post_data(),
            on_res_exists=self.restproxy.retrieve_by_name)[0]

        l2dom_tmplt_id = nuagel2domtemplate['ID']

        req_params = {
            'net_partition_id': params['netpart_id'],
            'name': ipv4_subnet['id'],
            'template': l2dom_tmplt_id,
            'externalID': get_vsd_external_id(ipv4_subnet['id'])
        }
        ext_params = {
            'description': ipv4_subnet['name']
        }
        nuagel2domain = nuagelib.NuageL2Domain(create_params=req_params,
                                               extra_params=ext_params)
        try:
            l2domain = self.restproxy.post(nuagel2domain.post_resource(),
                                           nuagel2domain.post_data())[0]
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
        nuagedhcpoptions.create_nuage_dhcp(
            ipv4_subnet,
            parent_id=l2domain_id,
            network_type=constants.NETWORK_TYPE_L2)

        nuage_userid, nuage_groupid = \
            helper.create_usergroup(self.restproxy,
                                    params['tenant_id'],
                                    params['netpart_id'])
        subnet_dict['nuage_userid'] = nuage_userid
        subnet_dict['nuage_groupid'] = nuage_groupid

        self._attach_nuage_group_to_l2domain(nuage_groupid,
                                             l2domain_id,
                                             params['netpart_id'],
                                             params.get('shared'),
                                             params['tenant_id'])
        self._create_nuage_def_l2domain_acl(l2domain_id, ipv4_subnet['id'])
        self._create_nuage_def_l2domain_adv_fwd_template(l2domain_id,
                                                         ipv4_subnet['id'])

        pnet_binding = params.get('pnet_binding', None)
        if pnet_binding:
            pnet_params = {
                'pnet_binding': pnet_binding,
                'netpart_id': params['netpart_id'],
                'l2domain_id': l2domain_id,
                'neutron_subnet_id': ipv4_subnet['id']
            }
            try:
                pnet_helper.process_provider_network(self.restproxy,
                                                     self.policygroups,
                                                     pnet_params)
            except Exception:
                self.delete_subnet(ipv4_subnet['id'])
                raise

        return subnet_dict

    def delete_subnet_ipv6(self, mapping):
        data = helper.get_ipv6_vsd_data(None)
        self.update_l2domain_template(mapping['nuage_l2dom_tmplt_id'], **data)

    def delete_subnet(self, id):
        params = {
            'externalID': get_vsd_external_id(id)
        }
        nuagel2domain = nuagelib.NuageL2Domain(create_params=params)
        response = self.restproxy.rest_call(
            'GET', nuagel2domain.get_resource_with_ext_id(), '',
            extra_headers=nuagel2domain.extra_headers_get())

        if nuagel2domain.get_validate(response):
            nuagel2domtemplates = nuagelib.NuageL2DomTemplate()
            template_id = nuagel2domain.get_template_id(response)
            resp_temp = self.restproxy.rest_call(
                'GET', nuagel2domtemplates.get_resource(template_id), '')
            if not nuagel2domtemplates.validate(resp_temp):
                raise restproxy.RESTProxyError(nuagel2domtemplates.error_msg)
            l2domain_id = nuagel2domain.get_domainid(response)

            try:
                # Delete bridge_interface and bridge vport if it is subnet
                # created for providernet
                pnet_helper.delete_resources_created_for_l2dom_providernet(
                    self.restproxy, l2domain_id)
                # delete subnet
                l2dom_delete_response = self.restproxy.rest_call(
                    'DELETE', nuagel2domain.delete_resource(l2domain_id), '')
                if not nuagel2domain.delete_validate(l2dom_delete_response):
                    code = nuagel2domain.get_error_code(l2dom_delete_response)
                    raise restproxy.RESTProxyError(nuagel2domain.error_msg,
                                                   error_code=code)
            except Exception:
                raise

            if response[3][0]['name'] == resp_temp[3][0]['name']:
                try:
                    self.restproxy.rest_call(
                        'DELETE',
                        nuagel2domtemplates.delete_resource(template_id),
                        '')
                except Exception:
                    raise

    def update_subnet(self, neutron_subnet, params):
        type = constants.NETWORK_TYPE_L3
        new_name = neutron_subnet.get('name')
        if params['type']:
            type = constants.NETWORK_TYPE_L2

        if params.get('dhcp_opts_changed'):
            nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
            nuagedhcpoptions.update_nuage_dhcp(neutron_subnet,
                                               parent_id=params['parent_id'],
                                               network_type=type)

        if type == constants.NETWORK_TYPE_L2 and 'dhcp_ip' in params:
            nuagel2domtemplate = nuagelib.NuageL2DomTemplate()
            if neutron_subnet.get('enable_dhcp'):
                # Enable dhcpmanaged on the l2domain template
                net = params['net']
                data = {
                    "DHCPManaged": neutron_subnet['enable_dhcp'],
                    "address": str(net.ip),
                    "netmask": str(net.netmask),
                    "gateway": params['dhcp_ip'],
                }
                response = self.restproxy.rest_call(
                    'PUT',
                    nuagel2domtemplate.put_resource(params['type']),
                    data
                )
            else:
                # Disable dhcpmanaged on the l2domain template
                response = self.restproxy.rest_call(
                    'PUT',
                    nuagel2domtemplate.put_resource(params['type']),
                    {'DHCPManaged': False}
                )
            if not nuagel2domtemplate.validate(response):
                raise restproxy.RESTProxyError(
                    nuagel2domtemplate.error_msg)

        # If we update IPv6 gateway then we should handle it here.
        if type == constants.NETWORK_TYPE_L2 and 'mapping' in params:
            self.update_subnet_ipv6(neutron_subnet, params['mapping'])

        if new_name:
            if neutron_subnet['ip_version'] == constants.IPV6_VERSION:
                # We don't change if IPv6 description is changed by user.
                return
            # update the description on the VSD for this subnet if required
            # If a subnet is updated from horizon, we get the name of the
            # subnet as well in the subnet dict for update.
            if type == constants.NETWORK_TYPE_L2:
                nuagel2domain = nuagelib.NuageL2Domain()
                l2dom = self.restproxy.rest_call(
                    'GET', nuagel2domain.get_resource(params['parent_id']), '')
                if not nuagel2domain.validate(l2dom):
                    raise restproxy.RESTProxyError(nuagel2domain.error_msg)
                if nuagel2domain.get_description(l2dom) != new_name:
                    response = self.restproxy.rest_call(
                        'PUT', nuagel2domain.put_resource(params['parent_id']),
                        {'description': neutron_subnet['name']})
                    if not nuagel2domain.validate(response):
                        raise restproxy.RESTProxyError(nuagel2domain.error_msg)
            else:
                nuagesubn = nuagelib.NuageSubnet()
                l3dom = self.restproxy.rest_call(
                    'GET', nuagesubn.get_resource(params['parent_id']), '')
                if not nuagesubn.validate(l3dom):
                    raise restproxy.RESTProxyError(nuagesubn.error_msg)
                if nuagesubn.get_description(l3dom) != new_name:
                    response = self.restproxy.rest_call(
                        'PUT', nuagesubn.put_resource(params['parent_id']),
                        {'description': neutron_subnet['name']})
                    if not nuagesubn.validate(response):
                        raise restproxy.RESTProxyError(nuagesubn.error_msg)

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
                raise restproxy.RESTProxyError(nuagegroup.error_msg)
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
            if (nuage_permission.get_error_code(resp) !=
                    constants.CONFLICT_ERR_CODE):
                raise restproxy.RESTProxyError(nuage_permission.error_msg)

    def _create_nuage_def_l2domain_acl(self, id, neutron_subnet_id):
        helper.create_nuage_l2dom_ingress_tmplt(self.restproxy,
                                                id,
                                                neutron_subnet_id)
        helper.create_nuage_l2dom_egress_tmplt(self.restproxy,
                                               id,
                                               neutron_subnet_id)

    def _create_nuage_def_l2domain_adv_fwd_template(self, l2dom_id,
                                                    neutron_subnet_id):
        nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
        response = self.restproxy.rest_call(
            'POST',
            nuageadvfwdtmplt.post_resource_l2(l2dom_id),
            nuageadvfwdtmplt.post_data_default_l2(
                l2dom_id, get_vsd_external_id(neutron_subnet_id)))
        if not nuageadvfwdtmplt.validate(response):
            raise restproxy.RESTProxyError(nuageadvfwdtmplt.error_msg)
        return nuageadvfwdtmplt.get_response_objid(response)

    def get_nuage_cidr(self, nuage_subnetid):
        nuagesubn = nuagelib.NuageSubnet()
        response = self.restproxy.rest_call(
            'GET',
            nuagesubn.get_resource(nuage_subnetid),
            '')
        if not nuagesubn.validate(response):
            nuagel2dom = nuagelib.NuageL2Domain()
            response = self.restproxy.rest_call(
                'GET',
                nuagel2dom.get_resource(nuage_subnetid),
                '')
            if not nuagel2dom.validate(response):
                raise restproxy.RESTProxyError(nuagel2dom.error_msg)
            return nuagel2dom.get_cidr_info(response)
        else:
            return nuagesubn.get_cidr_info(response)

    def attach_nuage_group_to_nuagenet(self, tenant, nuage_npid,
                                       nuage_subnetid, shared):
        nuage_uid, nuage_gid = helper.create_usergroup(self.restproxy, tenant,
                                                       nuage_npid)
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
                raise restproxy.RESTProxyError(nuagegroup.error_msg)
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
                raise restproxy.RESTProxyError(nuagel2dom.error_msg)
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
                raise restproxy.RESTProxyError(
                    nuage_permission.error_msg)

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
            raise restproxy.RESTProxyError(nuagepermission.error_msg,
                                           nuagepermission.vsd_error_code)

        permissions = response[3]
        if shared:
            tenants.append("Everybody")
        for permission in permissions:
            if permission['permittedEntityName'] in tenants:
                self.restproxy.delete(
                    nuagepermission.delete_resource(permission['ID']))

    def get_nuage_sharedresource(self, id):
        nuage_sharedresource = nuagelib.NuageSharedResources()
        response = self.restproxy.rest_call(
            'GET', nuage_sharedresource.get_resource_by_id(id), '')
        if not nuage_sharedresource.get_validate(response):
            raise restproxy.RESTProxyError(
                nuage_sharedresource.error_msg,
                nuage_sharedresource.vsd_error_code)
        return nuage_sharedresource.get_response_obj(response)

    def get_sharedresource(self, neutron_id):
        return self._get_sharedresource_by_external(neutron_id)

    def create_nuage_sharedresource(self, params):
        subnet = params['neutron_subnet']
        req_params = {
            'name': subnet['id'],
            'gateway_ip': subnet['gateway_ip'],
            'net': params['net'],
            'type': params['type'],
            'net_id': params['net_id'],
            'externalID': get_vsd_external_id(subnet['id'])
        }
        desc_str = params['net_id'] + '_' + subnet.get('name', subnet['id'])

        extra_params = {
            'description': desc_str
        }
        if params.get('underlay_config'):
            extra_params['underlay'] = True
        if params.get('underlay') is not None:
            extra_params['underlay'] = params['underlay']
        if params.get('nuage_uplink'):
            extra_params['sharedResourceParentID'] = params['nuage_uplink']

        nuage_sharedresource = nuagelib.NuageSharedResources(
            create_params=req_params, extra_params=extra_params)
        response = self.restproxy.rest_call(
            'POST',
            nuage_sharedresource.post_resource(),
            nuage_sharedresource.post_data())
        if not nuage_sharedresource.validate(response):
            code = nuage_sharedresource.get_error_code(response)
            raise restproxy.RESTProxyError(nuage_sharedresource.error_msg,
                                           code)
        return nuage_sharedresource.get_sharedresource_id(response)

    def _get_sharedresource_by_external(self, neutron_id):
        create_params = {
            'externalID': get_vsd_external_id(neutron_id)
        }
        nuage_sharedresource = nuagelib.NuageSharedResources(create_params)
        url = nuage_sharedresource.get_resource()
        extra_headers = nuage_sharedresource.extra_headers_get_by_externalID()
        shared_resouces = self.restproxy.get(url, extra_headers=extra_headers)
        if not shared_resouces:
            raise restproxy.ResourceNotFoundException(
                "Cannot find sharednetworkresource with externalID '%s'"
                % create_params['externalID'])
        return shared_resouces[0]

    def update_nuage_sharedresource(self, neutron_id, params):
        nuage_id = self._get_sharedresource_by_external(neutron_id)['ID']

        req_params = {}
        if params.get('net_id') and params.get('subnet_name'):
            description = params['net_id'] + '_' + params['subnet_name']
            req_params['description'] = description
        if params.get('gateway_ip'):
            req_params['gateway'] = params.get('gateway_ip')
        if not req_params:
            return

        create_params = {
            'id': nuage_id
        }
        nuage_sharedresource = nuagelib.NuageSharedResources(create_params, )
        url = nuage_sharedresource.put_resource()
        self.restproxy.rest_call('PUT', url, req_params)

    def delete_nuage_sharedresource(self, id):
        req_params = {
            'name': id
        }
        nuage_sharedresource = nuagelib.NuageSharedResources(
            create_params=req_params)
        sharedresource = self.restproxy.get(
            nuage_sharedresource.get_resource(),
            extra_headers=nuage_sharedresource.extra_headers_get_by_name())
        if sharedresource:
            self._delete_nuage_sharedresource(sharedresource[0]['ID'])

    def _delete_nuage_sharedresource(self, id):
        nuage_sharedresource = nuagelib.NuageSharedResources()
        resp = self.restproxy.rest_call(
            'DELETE', nuage_sharedresource.delete_resource(id), '')
        if not nuage_sharedresource.validate(resp):
            code = nuage_sharedresource.get_error_code(resp)
            raise restproxy.RESTProxyError(nuage_sharedresource.error_msg,
                                           error_code=code)

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

    def check_if_l2Dom_in_correct_ent(self, nuage_l2dom_id, nuage_netpart):
        nuagesubn = nuagelib.NuageSubnet()
        resp_subn = self.restproxy.rest_call(
            'GET',
            nuagesubn.get_resource(nuage_l2dom_id),
            '')
        if not nuagesubn.validate(resp_subn):
            nuagel2dom = nuagelib.NuageL2Domain()
            response = self.restproxy.rest_call(
                'GET',
                nuagel2dom.get_resource(nuage_l2dom_id),
                '')
            if not nuagel2dom.validate(response):
                raise restproxy.RESTProxyError(nuagel2dom.error_msg)
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
                raise restproxy.RESTProxyError(nuagezone.error_msg)

            req_params = {
                'domain_id': resp_zone[3][0]['parentID']
            }
            nuage_l3domain = nuagelib.NuageL3Domain(create_params=req_params)
            dom_resp = self.restproxy.rest_call(
                'GET', nuage_l3domain.get_resource(), '')

            if not nuage_l3domain.validate(dom_resp):
                raise restproxy.RESTProxyError(nuage_l3domain.error_msg)
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
