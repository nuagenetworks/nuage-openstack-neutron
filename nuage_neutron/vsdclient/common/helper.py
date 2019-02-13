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

import contextlib
import functools
import itertools
import logging
import netaddr
import re

try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _
from neutron_lib.db import api as lib_db_api

from nuage_neutron.vsdclient.common.cms_id_helper import extra_headers_get
from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

from nuage_neutron.plugins.common import nuagedb

CONFLICT_ERR_CODE = constants.CONFLICT_ERR_CODE
VSD_RESP_OBJ = constants.VSD_RESP_OBJ

LOG = logging.getLogger(__name__)

# This is global defination of the local cache that we gonna keep
cache = {}


class MemoizeClass(type):
    """This is singleton class with memoize logic

    Memoization effectively refers to remembering
    ("memoization" -> "memorandum" -> to be remembered) results of
    method calls based on the method inputs and then returning the
    remembered result rather than computing the result again.
    You can think of it as a cache for method results.

    It returns the values from the cache if the called with
    same arguments.
    """
    global cache

    def __call__(cls, *args, **kwargs):
        """Cache lookup

        Here I am making this key unique so that even it treats
        the cache of different class called with same arguments as
        different entry and adds it to the cache
        """
        key = str(cls) + str(args) + str(kwargs)
        if key not in cache:
            cache[key] = super(MemoizeClass, cls).__call__(*args, **kwargs)
        return cache[key]


def get_l3domid_for_netpartition(restproxy_serv, np_id, name):
    req_params = {
        'net_partition_id': np_id,
        'name': name
    }
    nuagel3domtemplate = \
        nuagelib.NuageL3DomTemplate(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET',
        nuagel3domtemplate.list_resource(),
        '',
        nuagel3domtemplate.extra_headers_get())

    if not nuagel3domtemplate.validate(response):
        raise nuagel3domtemplate.get_rest_proxy_error()
    return nuagel3domtemplate.get_templateid(response)


def get_l2domid_for_netpartition(restproxy_serv, np_id, name):
    req_params = {
        'net_partition_id': np_id,
        'name': name
    }
    nuagel2domtemplate = \
        nuagelib.NuageL2DomTemplate(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET',
        nuagel2domtemplate.list_resource(),
        '',
        nuagel2domtemplate.extra_headers_get())

    if not nuagel2domtemplate.validate(response):
        raise nuagel2domtemplate.get_rest_proxy_error()
    return nuagel2domtemplate.get_templateid(response)


def create_nuage_l2dom_ingress_tmplt(restproxy_serv, id, neutron_subnet):
    req_params = {
        'parent_id': id,
        'name': id,
        'externalID': get_subnet_external_id(neutron_subnet)
    }
    nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
    restproxy_serv.post(
        nuageibacl.post_resource_l2(),
        nuageibacl.post_data_default_l2(),
        ignore_err_codes=[restproxy.REST_DUPLICATE_ACL_PRIORITY])


def create_nuage_l2dom_egress_tmplt(restproxy_serv, id, neutron_subnet):
    req_params = {
        'parent_id': id,
        'name': id,
        'externalID': get_subnet_external_id(neutron_subnet)
    }
    nuageobacl = nuagelib.NuageOutboundACL(create_params=req_params)
    restproxy_serv.post(
        nuageobacl.post_resource_l2(),
        nuageobacl.post_data_default_l2(),
        ignore_err_codes=[restproxy.REST_DUPLICATE_ACL_PRIORITY])


def create_usergroup(restproxy_serv, tenant, net_partition_id,
                     tenant_name=None):
    result = _get_usergroup_details(restproxy_serv, tenant, net_partition_id)

    if result:
        user_details, group_details = result
        if not user_details['externalID']:
            nuageuser = nuagelib.NuageUser()
            restproxy_serv.put(
                nuageuser.user_resource(user_details.get('ID')) +
                "?responseChoice=1",
                nuageuser.update_data('externalID', tenant + '@openstack'))
        if not group_details['externalID']:
            nuagegroup = nuagelib.NuageGroup()
            restproxy_serv.put(
                nuagegroup.group_resource(group_details.get('ID')) +
                "?responseChoice=1",
                nuagegroup.update_data('externalID', tenant + '@openstack'))
        if tenant_name is not None and (not group_details['description'] or
                                        group_details['description']
                                        != tenant_name):
            nuagegroup = nuagelib.NuageGroup()
            restproxy_serv.put(
                nuagegroup.group_resource(group_details.get('ID')) +
                "?responseChoice=1",
                nuagegroup.update_data('description', tenant_name))
        return user_details.get('ID'), group_details.get('ID')
    else:
        req_params = {
            'net_partition_id': net_partition_id,
            'name': tenant,
            'externalID': tenant + '@openstack',
            'description': tenant_name,
        }
        nuagegroup = nuagelib.NuageGroup(create_params=req_params)
        nuageuser = nuagelib.NuageUser(create_params=req_params)
        nuage_userid_list = []
        user_resp = restproxy_serv.rest_call('POST',
                                             nuageuser.ent_post_resource(),
                                             nuageuser.post_data())

        if not nuageuser.validate(user_resp):
            if nuageuser.error_code != constants.CONFLICT_ERR_CODE:
                raise nuageuser.get_rest_proxy_error()

            user_id = get_user_id(restproxy_serv, tenant, '',
                                  net_partition_id, False)
            LOG.debug('User %s already exists in VSD', user_id)
        else:
            user_id = nuageuser.get_userid(user_resp)
            LOG.debug('User %s created in VSD', user_id)

        nuage_userid_list.append(user_id)

        # Add tenant as a group
        group_resp = restproxy_serv.rest_call('POST',
                                              nuagegroup.post_resource(),
                                              nuagegroup.post_data())
        if not nuagegroup.validate(group_resp):
            if nuagegroup.error_code != constants.CONFLICT_ERR_CODE:
                raise nuagegroup.get_rest_proxy_error()
            group_id = get_group_id(restproxy_serv, tenant, net_partition_id)
            LOG.debug('Group %s already exists in VSD', group_id)

            # Group exists, so add the user to the existing user list
            ext_user_list = get_user_list(restproxy_serv, group_id,
                                          net_partition_id)
            if ext_user_list:
                LOG.debug('Group %(grp)s has users %(usr)s associated',
                          {'grp': group_id,
                           'usr': ext_user_list})
                nuage_userid_list.extend(ext_user_list)
        else:
            group_id = nuagegroup.get_groupid(group_resp)
            LOG.debug('Group %s created in VSD', group_id)

        # Add user to the group
        nuageuser.set_group_id(group_id)
        data = nuage_userid_list
        restproxy_serv.rest_call('PUT', nuageuser.group_post_resource(), data)

        return user_id, group_id


def create_in_adv_fwd_policy_template(rest_proxy, parent_type,
                                      parent_id, params):
    params['externalID'] = get_vsd_external_id(params['externalID'])
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        response = rest_proxy.post(adv_fwd_tmplt.post_resource_l2(parent_id),
                                   params)
    else:
        response = rest_proxy.post(adv_fwd_tmplt.post_resource_l3(parent_id),
                                   params)
    return response[0]


def update_in_adv_fwd_policy_template(rest_proxy, nuage_id, params):
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    return rest_proxy.put(
        adv_fwd_tmplt.get_resource(nuage_id) + '?responseChoice=1',
        params)


def delete_in_adv_fwd_policy_template(rest_proxy, tmplt_id, required=False):
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    rest_proxy.delete(adv_fwd_tmplt.get_resource(
        tmplt_id) + '?responseChoice=1', required)


def get_user_list(restproxy_serv, group_id, net_partition_id):
    req_params = {
        'group_id': group_id,
        'net_partition_id': net_partition_id
    }
    nuageuser = nuagelib.NuageUser(create_params=req_params)
    user_resp = restproxy_serv.rest_call('GET',
                                         nuageuser.group_post_resource(),
                                         '')
    return nuageuser.user_list(user_resp)


def get_user_id(restproxy_serv, tenant, group_id, net_partition_id,
                assoc=True):
    # assoc indicates that the user is associated with the group
    req_params = {
        'group_id': group_id,
        'net_partition_id': net_partition_id
    }
    extra_params = {
        'userName': tenant
    }
    nuageuser = nuagelib.NuageUser(create_params=req_params,
                                   extra_params=extra_params)
    nuage_usr_extra_headers = nuageuser.extra_headers_get_by_username()
    if assoc:
        res_url = nuageuser.group_post_resource()
    else:
        res_url = nuageuser.ent_post_resource()

    usr_resp = restproxy_serv.rest_call(
        'GET', res_url, '', extra_headers=nuage_usr_extra_headers)

    # only if we have a response find the usrID else return None
    if nuageuser.get_validate(usr_resp):
        return nuageuser.get_userid(usr_resp)


def get_usergroup(restproxy_serv, tenant, net_partition_id):
    group_id = get_group_id(restproxy_serv, tenant, net_partition_id)
    if group_id is not None:
        user_id = get_user_id(restproxy_serv, tenant, group_id,
                              net_partition_id)
        if user_id is not None:
            return user_id, group_id
    return None, None


def _get_usergroup_details(restproxy_serv, tenant, net_partition_id):
    group_details = get_group_details(restproxy_serv, tenant,
                                      net_partition_id)
    if group_details is not None:
        user_details = get_user_details(restproxy_serv, tenant,
                                        group_details.get('ID'),
                                        net_partition_id)
        if user_details is not None:
            return user_details, group_details


def get_group_details(restproxy_serv, tenant, net_partition_id):
    req_params = {
        'net_partition_id': net_partition_id,
        'name': tenant
    }
    nuagegroup = nuagelib.NuageGroup(create_params=req_params)
    nuage_grp_extra_headers = nuagegroup.extra_headers_get_by_name()
    grp_resp = restproxy_serv.rest_call(
        'GET', nuagegroup.post_resource(), '',
        extra_headers=nuage_grp_extra_headers)
    # only if we have a response find the grp else return None
    if nuagegroup.get_validate(grp_resp):
        return grp_resp[3][0]


def get_user_details(restproxy_serv, tenant, group_id, net_partition_id,
                     assoc=True):
    # assoc indicates that the user is associated with the group
    req_params = {
        'group_id': group_id,
        'net_partition_id': net_partition_id
    }
    extra_params = {
        'userName': tenant
    }
    nuageuser = nuagelib.NuageUser(create_params=req_params,
                                   extra_params=extra_params)
    nuage_usr_extra_headers = nuageuser.extra_headers_get_by_username()
    if assoc:
        res_url = nuageuser.group_post_resource()
    else:
        res_url = nuageuser.ent_post_resource()

    usr_resp = restproxy_serv.rest_call(
        'GET', res_url, '', extra_headers=nuage_usr_extra_headers)

    # only if we have a response find the usr else return None
    if nuageuser.get_validate(usr_resp):
        return usr_resp[3][0]


def get_group_id(restproxy_serv, tenant, net_partition_id):
    req_params = {
        'net_partition_id': net_partition_id,
        'name': tenant
    }
    nuagegroup = nuagelib.NuageGroup(create_params=req_params)
    nuage_grp_extra_headers = nuagegroup.extra_headers_get_by_name()
    grp_resp = restproxy_serv.rest_call(
        'GET', nuagegroup.post_resource(), '',
        extra_headers=nuage_grp_extra_headers)
    # only if we have a response find the grpID else return None
    if nuagegroup.get_validate(grp_resp):
        return nuagegroup.get_group_id(grp_resp)


def get_l3domain_np_id(restproxy_serv, l3dom_id):
    req_params = {
        'domain_id': l3dom_id
    }
    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_l3_domain.get_resource(), '')

    if not nuage_l3_domain.validate(response):
        raise nuage_l3_domain.get_rest_proxy_error()

    if response[3]:
        return response[3][0]['parentID']


def get_l2domain_np_id(restproxy_serv, l2dom_id):
    req_params = {
        'domain_id': l2dom_id
    }
    nuage_l2_domain = nuagelib.NuageL2Domain(create_params=req_params)
    response = restproxy_serv.rest_call('GET',
                                        nuage_l2_domain.get_resource(l2dom_id),
                                        '')

    if not nuage_l2_domain.validate(response):
        raise nuage_l2_domain.get_rest_proxy_error()

    if response[3]:
        return response[3][0]['parentID']


def get_l3dom_by_router_id(restproxy_serv, rtr_id):
    req_params = {
        'externalID': get_vsd_external_id(rtr_id)
    }

    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET',
        nuage_l3_domain.get_all_resources(),
        '',
        extra_headers=nuage_l3_domain.extra_headers_get())

    if not nuage_l3_domain.validate(response):
        raise nuage_l3_domain.get_rest_proxy_error()

    return (nuage_l3_domain, response)


def get_l3domid_by_router_id(restproxy_serv, rtr_id):
    nuage_l3_domain, response = get_l3dom_by_router_id(
        restproxy_serv, rtr_id)

    # response body will be '' when no domain is found
    if not nuage_l3_domain.check_response_exist(response):
        msg = _("No domain found for router %s") % rtr_id
        raise restproxy.ResourceNotFoundException(msg)

    return nuage_l3_domain.get_domainid(response)


def get_l3dom_template_id_by_dom_id(restproxy_serv, dom_id):
    req_params = {
        'domain_id': dom_id
    }

    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    response = restproxy_serv.rest_call(
        'GET', nuage_l3_domain.get_resource(), '', '')

    if not nuage_l3_domain.validate(response):
        raise nuage_l3_domain.get_rest_proxy_error()

    if response[VSD_RESP_OBJ]:
        return response[VSD_RESP_OBJ][0]['templateID']


def get_first_zone_by_nuage_router_id(restproxy_serv, nuage_router_id):
    req_params = {
        'domain_id': nuage_router_id
    }
    nuage_zone = nuagelib.NuageZone(req_params)

    response = restproxy_serv.rest_call('GET', nuage_zone.list_resource(), '')
    if not nuage_zone.validate(response):
        raise nuage_zone.get_rest_proxy_error()

    for (counter, zone) in enumerate(nuage_zone.zone_list(response)):
        if counter == 0:
            ret = {
                'nuage_zone_id': zone['ID']
            }
            return ret


def get_nuage_port_by_id(restproxy_serv, params):
    req_params = {
        'externalID': get_vsd_external_id(params['neutron_port_id'])
    }

    vport_type = params.get('nuage_vport_type')
    if vport_type == constants.HOST_VPORT_TYPE:
        req_params['vport_id'] = params['nuage_vport_id']
        nuage_intf = nuagelib.NuageHostInterface(create_params=req_params)
        nuage_extra_headers = nuage_intf.extra_headers_by_externalid()
    else:
        nuage_intf = nuagelib.NuageVMInterface(create_params=req_params)
        nuage_extra_headers = nuage_intf.extra_headers_for_all_vmifs()

    response = restproxy_serv.rest_call('GET', nuage_intf.get_all_resource(),
                                        '', extra_headers=nuage_extra_headers)

    if not nuage_intf.validate(response):
        raise nuage_intf.get_rest_proxy_error()

    if len(response[3]) > 0:
        port = response[3][0]
        req_params = {'vport_id': port['VPortID']}
        nuage_vport = nuagelib.NuageVPort(create_params=req_params)
        vport_resp = restproxy_serv.rest_call(
            'GET', nuage_vport.get_resource(), '')
        if not nuage_vport.validate(vport_resp):
            raise nuage_vport.get_rest_proxy_error()
        vport = vport_resp[3][0]
        vport['nuage_vif_id'] = port['ID']
        return vport


def get_nuage_vport_by_id(restproxy_serv, id, required=True):
    vportlib = nuagelib.NuageVPort()
    vports = restproxy_serv.get(vportlib.get_by_id(id), required=required)
    if vports:
        return vports[0]


def get_nuage_vport_by_neutron_id(restproxy_serv, params, required=True):
    req_params = {
        'externalID': get_vsd_external_id(params['neutron_port_id'])
    }
    l2domid = params.get('l2dom_id')
    l3domid = params.get('l3dom_id')
    vports = ''

    if l2domid:
        nuagel2domain = nuagelib.NuageL2Domain(create_params=req_params)
        vports = restproxy_serv.get(
            nuagel2domain.get_all_vports(l2domid),
            extra_headers=nuagel2domain.extra_headers_get())

    if not vports and l3domid:
        nuagel3domsub = nuagelib.NuageSubnet(create_params=req_params)
        vports = restproxy_serv.get(
            nuagel3domsub.get_all_vports(l3domid),
            extra_headers=nuagel3domsub.extra_headers_get())

    if not vports and required:
        raise restproxy.ResourceNotFoundException(
            "vport for port '%s' not found" % params['neutron_port_id'])
    if vports:
        return vports[0]


def get_vports(restproxy_serv, parent, parent_id, headers=None, **filters):
    nuagevport = nuagelib.NuageVPort()
    if headers is None:
        headers = {}
    generated_header = nuagevport.extra_header_filter(**filters)
    if generated_header is not None:
        headers.update(generated_header)
    return restproxy_serv.get(
        nuagevport.get_child_resource(parent.resource, parent_id),
        extra_headers=headers)


def update_vport(restproxy_serv, id, data):
    vport = nuagelib.NuageVPort(create_params={'vport_id': id})
    restproxy_serv.put(vport.put_resource(), data)


def delete_nuage_vport(restproxy_serv, vport_id):
    # Delete vport
    nuage_vport = nuagelib.NuageVPort()
    del_resp = restproxy_serv.rest_call('DELETE',
                                        nuage_vport.del_vport(vport_id), '')
    if not nuage_vport.delete_validate(del_resp):
        raise nuage_vport.get_rest_proxy_error()


def get_l2dom(restproxy_serv, nuage_id, required=False):
    nuagel2dom = nuagelib.NuageL2Domain()
    l2domains = restproxy_serv.get(nuagel2dom.get_resource(nuage_id),
                                   required=required)
    if l2domains:
        return l2domains[0]


def get_l3subnet(restproxy_serv, nuage_id, required=False):
    nuagesubnet = nuagelib.NuageSubnet()
    subnets = restproxy_serv.get(nuagesubnet.get_resource(nuage_id),
                                 required=required)
    if subnets:
        return subnets[0]


def get_nuage_subnet(restproxy_serv, subnet_mapping):
    if subnet_mapping is None:
        return None
    nuage_subnet_id = subnet_mapping["nuage_subnet_id"]
    if subnet_mapping['nuage_l2dom_tmplt_id']:
        resource_class = nuagelib.NuageL2Domain()
    else:
        resource_class = nuagelib.NuageSubnet()
    try:
        response = restproxy_serv.get(resource_class.get_resource(
            nuage_subnet_id))
        return response[0]
    except restproxy.RESTProxyError:
        return None


def get_domain_subnet_by_ext_id_and_cidr(restproxy_serv, neutron_subnet):
    params = {
        'externalID': get_subnet_external_id(neutron_subnet),
        'cidr': netaddr.IPNetwork(neutron_subnet['cidr']),
        'ip_type': neutron_subnet['ip_version']
    }
    nuagesubnet = nuagelib.NuageSubnet(create_params=params)
    subnet = restproxy_serv.get(
        nuagesubnet.get_all_resources(),
        extra_headers=nuagesubnet.extra_headers_ext_id_and_cidr_get())
    if subnet:
        return subnet[0]
    else:
        msg = ("Cannot find subnet with externalID {} and cidr {}"
               " in L3domains on VSD").format(params['externalID'],
                                              params['cidr'])
        raise restproxy.ResourceNotFoundException(message=msg)


def _get_nuage_domain_id_from_subnet(restproxy_serv, nuage_subnet_id):
    nuagesubn = nuagelib.NuageSubnet()
    nuage_subnet = restproxy_serv.rest_call(
        'GET', nuagesubn.get_resource(nuage_subnet_id), '')
    if not nuagesubn.validate(nuage_subnet):
        raise nuagesubn.get_rest_proxy_error()
    nuage_zone_id = nuagesubn.get_parentzone(nuage_subnet)

    req_params = {
        'zone_id': nuage_zone_id
    }
    nuagezone = nuagelib.NuageZone(create_params=req_params)
    nuage_zone = restproxy_serv.rest_call(
        'GET', nuagezone.get_resource(), '')
    if not nuagezone.validate(nuage_zone):
        raise nuage_zone.get_rest_proxy_error()
    nuage_domain_id = nuagezone.get_response_parentid(nuage_zone)

    return nuage_domain_id


def get_nuage_zone_by_id(restproxy_serv, id):
    req_params = {
        'zone_id': id
    }
    nuage_zone = nuagelib.NuageZone(create_params=req_params)
    response = restproxy_serv.rest_call('GET', nuage_zone.get_resource(), '')
    if not nuage_zone.validate(response):
        raise nuage_zone.get_rest_proxy_error()

    if len(response[3]) > 0:
        ret = {
            'nuage_zone_id': response[3][0]['ID'],
            'nuage_parent_id': response[3][0]['parentID'],
            'nuage_external_id': response[3][0]['externalID']
        }

        return ret


def get_nuage_domain_by_zoneid(restproxy_serv, zone_id):
    nuage_dom = get_nuage_zone_by_id(restproxy_serv, zone_id)
    req_params = {
        'domain_id': nuage_dom['nuage_parent_id']
    }
    nuage_l3domain = nuagelib.NuageL3Domain(create_params=req_params)
    dom_resp = restproxy_serv.rest_call(
        'GET', nuage_l3domain.get_resource(), '')

    if not nuage_l3domain.validate(dom_resp):
        raise nuage_l3domain.get_rest_proxy_error()

    if len(dom_resp[3]) > 0:
        ret = {
            'nuage_domain_id': dom_resp[3][0]['ID'],
            'externalID': None
        }
        if dom_resp[3][0]['externalID']:
            ret['externalID'] = strip_cms_id(dom_resp[3][0]['externalID'])

        return ret


def get_net_partition_id_by_name(restproxy_serv, ent_name):
    req_params = {
        'name': ent_name
    }
    nuagenet_partition = nuagelib.NuageNetPartition(create_params=req_params)
    nuage_ent_extra_headers = nuagenet_partition.extra_headers_get()
    response = restproxy_serv.rest_call(
        'GET', nuagenet_partition.get_resource(), '',
        extra_headers=nuage_ent_extra_headers)
    if nuagenet_partition.get_validate(response):
        ent_id = nuagenet_partition.get_net_partition_id(response)
        return ent_id
    return None


def get_l2domain_fields_for_pg(restproxy_serv, l2dom_id, fields):
    """This method will fetch an l2domain even if it is MARKED_FOR_DELETION.

    Policygroup code actulally needs this because it is the only way to find
    the netpartition for a given policygroup when the policygroup is part of
    such a marked l2domain.
    """
    nuage_l2_domain = nuagelib.NuageL2Domain()

    response = restproxy_serv._get_ignore_marked_for_deletion(
        nuage_l2_domain.get_resource(l2dom_id))

    l2dom = {}
    if response:
        for field in fields:
            l2dom[field] = response[0][field]

    return l2dom


def get_domain_id_by_nuage_subnet_id(restproxy_serv, nuage_subn_id,
                                     required=False):
    nuagel3domsub = nuagelib.NuageSubnet()
    nuage_subn = restproxy_serv.get(
        nuagel3domsub.get_resource(nuage_subn_id), required=required)
    if not nuage_subn:
        return

    params = {'zone_id': nuage_subn[0]['parentID']}
    nuagezone = nuagelib.NuageZone(create_params=params)
    nuage_zone = restproxy_serv.get(nuagezone.get_resource(),
                                    required=required)
    if not nuage_zone:
        return
    return nuage_zone[0]['parentID']


def delete_resource(restproxy_serv, resource, resource_id):
    delete_uri = '/%s/%s?responseChoice=1' % (resource, resource_id)
    restproxy_serv.rest_call('DELETE', delete_uri, '')


def process_rollback(restproxy_serv, rollback_list):
    while rollback_list:
        entry = rollback_list.pop()
        resource = entry.get('resource')
        resource_id = entry.get('resource_id')
        delete_resource(restproxy_serv, resource, resource_id)


def make_subnet_dict(subnet):
    res = dict()
    res['subnet_id'] = subnet['ID']
    res['subnet_name'] = subnet['name']
    res['subnet_os_id'] = strip_cms_id(subnet['externalID'])
    res['subnet_shared_net_id'] = \
        subnet['associatedSharedNetworkResourceID']
    res['subnet_address'] = subnet['address']
    res['subnet_netmask'] = subnet['netmask']
    res['subnet_gateway'] = subnet['gateway']
    res['subnet_iptype'] = subnet['IPType']
    return res


def get_in_adv_fwd_policy(restproxy_serv, parent_type, parent_id):
    response = None
    nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        response = restproxy_serv.rest_call('GET',
                                            nuageadvfwdtmplt.get_resource_l2(
                                                parent_id),
                                            '')
    elif parent_type == constants.DOMAIN:
        response = restproxy_serv.rest_call('GET',
                                            nuageadvfwdtmplt.get_resource_l3(
                                                parent_id),
                                            '')
    if not nuageadvfwdtmplt.validate(response):
        raise nuageadvfwdtmplt.get_rest_proxy_error()

    if not response[3]:
        msg = ("%s %s does not have default advanced forwarding template"
               % (parent_type, parent_id))
        raise restproxy.ResourceConflictException(msg)

    return nuageadvfwdtmplt.get_response_objid(response)


def get_in_adv_fwd_policy_by_cmsid(restproxy_serv, parent_type, parent_id):
    nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        response = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l2(parent_id),
            extra_headers=extra_headers_get())
    else:
        response = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l3(parent_id),
            extra_headers=extra_headers_get())
    return response


def get_in_adv_fwd_policy_by_externalid(restproxy_serv, parent_type, parent_id,
                                        neutron_id):
    headers = {'X-NUAGE-FilterType': "predicate",
               'X-Nuage-Filter':
                   "externalID IS '%s'" % get_vsd_external_id(neutron_id)}
    nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        response = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l2(parent_id),
            extra_headers=headers)
    else:
        response = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l3(parent_id),
            extra_headers=headers)
    return response


def get_nuage_prefix_macro(restproxy_serv, net_macro_id):
    nuage_np_net = nuagelib.NuageNetPartitionNetwork()
    response = restproxy_serv.rest_call(
        'GET', nuage_np_net.get_resource_by_id(net_macro_id), '')
    if not nuage_np_net.validate(response):
        raise nuage_np_net.get_rest_proxy_error()
    return response[3][0]


def is_valid_uuid(uid):
    return re.match(constants.UUID_PATTERN, uid)


def is_vlan_valid(vlan_val):
    try:
        vlan_val = int(vlan_val)
    except ValueError:
        LOG.error("Vlan value %s is not valid", vlan_val)
        return False

    if vlan_val not in range(0, 4096):
        LOG.error("Vlan value %s is not in 0-4095 range", vlan_val)
        return False
    return True


def set_external_id_only(restproxy_serv, resource, id):
    update_params = {"externalID": get_vsd_external_id(id)}
    response = restproxy_serv.rest_call('PUT', resource, update_params)
    return response


def set_external_id_with_openstack(restproxy_serv, resource, id):
    update_params = {"externalID": id + '@openstack'}
    response = restproxy_serv.rest_call('PUT', resource, update_params)
    return response


def get_nuage_fip(restproxy_serv, nuage_fip_id):
    req_params = {'fip_id': nuage_fip_id}
    nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
    resp = restproxy_serv.rest_call(
        'GET', nuage_fip.get_fip_resource(), '')
    if not nuage_fip.validate(resp):
        raise nuage_fip.get_rest_proxy_error()
    return nuage_fip.get_response_obj(resp)


def get_vport_assoc_with_fip(restproxy_serv, nuage_fip_id):
    req_params = {'fip_id': nuage_fip_id}
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    resp = restproxy_serv.rest_call(
        'GET', nuage_vport.get_vport_for_fip(), '')
    if not nuage_vport.validate(resp):
        raise nuage_vport.get_rest_proxy_error()
    if nuage_vport.check_response_exist(resp):
        return nuage_vport.get_response_obj(resp)


def change_perm_of_subns(restproxy_serv, nuage_npid, nuage_subnetid,
                         shared, tenant_id, remove_everybody=False):
    if shared:
        params = {
            'net_partition_id': nuage_npid
        }
        nuagegroup = nuagelib.NuageGroup(create_params=params)
        response = restproxy_serv.rest_call(
            'GET', nuagegroup.list_resource(), '',
            nuagegroup.extra_headers_get_for_everybody())
        if not nuagegroup.validate(response):
            raise nuagegroup.get_rest_proxy_error()
        nuage_groupid = nuagegroup.get_groupid(response)
    else:
        nuage_userid, nuage_groupid = \
            create_usergroup(restproxy_serv, tenant_id, nuage_npid)
        if remove_everybody:
            params = {
                'l2dom_id': nuage_subnetid
            }
            nuagepermission = nuagelib.NuagePermission(create_params=params)
            resource = nuagepermission.get_resource_by_l2dom_id()
            response = restproxy_serv.rest_call('GET', resource, '')
            if not nuagepermission.validate(response):
                if response[0] == constants.RES_NOT_FOUND:
                    return
                raise nuagepermission.get_rest_proxy_error()

            permissions = response[3]
            for permission in permissions:
                if permission['permittedEntityName'] == "Everybody":
                    restproxy_serv.delete(
                        nuagepermission.delete_resource(permission['ID']))
                    break

    nuage_permission = nuagelib.NuagePermission()
    post_data = nuage_permission.perm_create_data(
        nuage_groupid,
        constants.NUAGE_PERMISSION_USE,
        tenant_id)
    resp = restproxy_serv.rest_call(
        'POST',
        nuage_permission.post_resource_by_parent_id(
            'l2domains', nuage_subnetid), post_data)
    if not nuage_permission.validate(resp):
        if (nuage_permission.get_error_code(resp) !=
                constants.CONFLICT_ERR_CODE):
            raise nuage_permission.get_rest_proxy_error()


# function to be able to convert the value in to a VSD supported hex format
def convert_to_hex(value):
    if str(value[:2]).lower() != '0x':
        raise ValueError('Malformed hex value: %s' % value)
    hex_val = str(value[2:])
    if len(hex_val) % 2 != 0:
        length = len(hex_val) + 1
    else:
        length = len(hex_val)
    hex_val = hex_val.zfill(length)
    return hex_val


def get_child_vports(restproxy_serv, parent_resource, parent_id,
                     required=False, **filters):
    nuage_vport = nuagelib.NuageVPort()
    return restproxy_serv.get(
        nuage_vport.get_child_resource(parent_resource, parent_id),
        extra_headers=nuage_vport.extra_header_filter(**filters),
        required=required)


def add_rollback(rollbacks, method, *args, **kwargs):
    rollbacks.append(functools.partial(method, *args, **kwargs))


@contextlib.contextmanager
def rollback():
    rollbacks = []
    log = logging.getLogger()
    try:
        yield functools.partial(add_rollback, rollbacks)
    except Exception as e:
        for action in reversed(rollbacks):
            try:
                action()
            except Exception:
                log.exception("Rollback failed.")
        raise e


def get_l2_and_l3_sub_id(subnet_mapping):
    if subnet_mapping['nuage_l2dom_tmplt_id']:
        l2_id = subnet_mapping['nuage_subnet_id']  # l2 dom id
        l3_id = None
    else:
        l2_id = None
        l3_id = subnet_mapping['nuage_subnet_id']  # the l3 subnet id in l3 dom
    return l2_id, l3_id


def get_ipv6_vsd_data(ipv6_subnet):
    if ipv6_subnet:
        ip_network = netaddr.IPNetwork(ipv6_subnet['cidr'])
        return {
            'IPv6Address': str(ip_network.cidr),
            'IPType': constants.DUALSTACK,
            'IPv6Gateway': ipv6_subnet['gateway_ip']}
    else:
        return {
            'IPv6Address': None,
            'IPType': constants.IPV4,
            'IPv6Gateway': None,
        }


def get_pnet_params(pnet_binding, vsd_subnet_id, np_id, subnet):
    pnet_params = {
        'pnet_binding': pnet_binding,
        'nuage_subnet_id': vsd_subnet_id,
        'netpart_id': np_id,
        'neutron_subnet': subnet,
    }
    return pnet_params


def get_external_id_based_on_subnet_id(subnet):
    if not subnet:
        raise restproxy.ResourceConflictException(
            "Unable to calculate external ID based on subnet.")
    neutron_id = subnet['nuage_l2bridge'] or subnet['id']
    return get_vsd_external_id(neutron_id)


def get_subnet_external_id(subnet):
    if not subnet:
        raise restproxy.ResourceConflictException(
            "Unable to calculate external ID for subnet.")
    neutron_id = subnet['nuage_l2bridge'] or subnet['network_id']
    return get_vsd_external_id(neutron_id)


def get_subnet_name(subnet):
    return subnet['nuage_l2bridge'] or subnet['id']


def get_subnet_description(subnet):
    if subnet['nuage_l2bridge']:
        session = lib_db_api.get_reader_session()
        return nuagedb.get_nuage_l2bridge(session,
                                          subnet['nuage_l2bridge'])['name']
    else:
        return subnet['name']
