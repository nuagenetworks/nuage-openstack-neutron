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
import re

import netaddr
try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _
from neutron.db import api as db_api

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

# This is global definition of the local cache that we gonna keep
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
    nuagel3domtemplate = nuagelib.NuageL3DomTemplate(create_params=req_params)
    l3_template = restproxy_serv.get(
        nuagel3domtemplate.list_resource(),
        extra_headers=nuagel3domtemplate.extra_headers_get(),
        required=True)
    return l3_template[0]['ID'] if l3_template else None


def get_l2domid_for_netpartition(restproxy_serv, np_id, name):
    req_params = {
        'net_partition_id': np_id,
        'name': name
    }
    nuagel2domtemplate = nuagelib.NuageL2DomTemplate(create_params=req_params)
    l2_template = restproxy_serv.get(
        nuagel2domtemplate.list_resource(),
        extra_headers=nuagel2domtemplate.extra_headers_get(),
        required=True)
    return l2_template[0]['ID'] if l2_template else None


def create_nuage_l2dom_ingress_tmplt(restproxy_serv, id, neutron_subnet,
                                     allow_non_ip=False):
    req_params = {
        'parent_id': id,
        'name': id,
        'externalID': get_subnet_external_id(neutron_subnet),
        'defaultAllowNonIP': allow_non_ip
    }
    nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
    restproxy_serv.post(
        nuageibacl.post_resource_l2(),
        nuageibacl.post_data_default_l2(),
        ignore_err_codes=[restproxy.REST_DUPLICATE_ACL_PRIORITY])


def create_nuage_l2dom_egress_tmplt(restproxy_serv, id, neutron_subnet,
                                    allow_non_ip=False):
    req_params = {
        'parent_id': id,
        'name': id,
        'externalID': get_subnet_external_id(neutron_subnet),
        'defaultAllowNonIP': allow_non_ip
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
                nuagegroup.update_data(
                    'externalID', tenant + '@openstack'))
        if tenant_name is not None and (not group_details['description'] or
                                        group_details['description'] !=
                                        tenant_name):
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
        try:
            user = restproxy_serv.post(nuageuser.ent_post_resource(),
                                       nuageuser.post_data())[0]
            user_id = user['ID']
            LOG.debug('User %s created in VSD', user_id)
            nuage_userid_list.append(user_id)
        except restproxy.RESTProxyError as e:
            if e.code != constants.CONFLICT_ERR_CODE:
                raise
            else:
                user_id = get_user_id(restproxy_serv, tenant, '',
                                      net_partition_id, False)
                LOG.debug('User %s already exists in VSD', user_id)

        # Add tenant as a group
        try:
            group = restproxy_serv.post(nuagegroup.post_resource(),
                                        nuagegroup.post_data())[0]
            group_id = group['ID']
            LOG.debug('Group %s created in VSD', group_id)
        except restproxy.RESTProxyError as e:
            if e.code != constants.CONFLICT_ERR_CODE:
                raise
            else:
                group_id = get_group_id(restproxy_serv,
                                        tenant, net_partition_id)
                LOG.debug('Group %s already exists in VSD', group_id)

                # Group exists, so add the user to the existing user list
                ext_user_list = get_user_id_list(restproxy_serv, group_id,
                                                 net_partition_id)
                if ext_user_list:
                    LOG.debug('Group %(grp)s has users %(usr)s associated',
                              {'grp': group_id,
                               'usr': ext_user_list})
                    nuage_userid_list.extend(ext_user_list)

        # Add user to the group
        nuageuser.set_group_id(group_id)
        data = nuage_userid_list
        restproxy_serv.put(nuageuser.group_post_resource(), data)
        return user_id, group_id


def create_in_adv_fwd_policy_template(rest_proxy, parent_type,
                                      parent_id, params):
    params['externalID'] = get_vsd_external_id(params['externalID'])
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        return rest_proxy.post(adv_fwd_tmplt.post_resource_l2(parent_id),
                               params)[0]
    else:
        return rest_proxy.post(adv_fwd_tmplt.post_resource_l3(parent_id),
                               params)[0]


def update_in_adv_fwd_policy_template(rest_proxy, nuage_id, params):
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    return rest_proxy.put(
        adv_fwd_tmplt.get_resource(nuage_id) + '?responseChoice=1',
        params)


def delete_in_adv_fwd_policy_template(rest_proxy, tmplt_id, required=False):
    adv_fwd_tmplt = nuagelib.NuageInAdvFwdTemplate()
    rest_proxy.delete(adv_fwd_tmplt.get_resource(
        tmplt_id) + '?responseChoice=1', required)


def get_user_id_list(restproxy_serv, group_id, net_partition_id):
    req_params = {
        'group_id': group_id,
        'net_partition_id': net_partition_id
    }
    nuageuser = nuagelib.NuageUser(create_params=req_params)
    users_in_group = restproxy_serv.get(nuageuser.group_post_resource())
    return [user_detail['ID'] for user_detail in users_in_group]


def get_user_id(restproxy_serv, tenant, group_id, net_partition_id,
                assoc=True):
    user = get_user_details(restproxy_serv, tenant, group_id, net_partition_id,
                            assoc=assoc)
    return user['ID'] if user else None


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
    groups = restproxy_serv.get(nuagegroup.post_resource(),
                                extra_headers=nuage_grp_extra_headers)
    # only if we have a response find the grp else return None
    return groups[0] if groups else None


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
    users = restproxy_serv.get(res_url,
                               extra_headers=nuage_usr_extra_headers)
    # only if we have a response find the usr else return None
    return users[0] if users else None


def get_group_id(restproxy_serv, tenant, net_partition_id):
    group = get_group_details(restproxy_serv, tenant, net_partition_id)
    # only if we have a response find the group, else return None
    return group['ID'] if group else None


def get_l3domain_np_id(restproxy_serv, l3dom_id):
    req_params = {
        'domain_id': l3dom_id
    }
    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    return restproxy_serv.get(nuage_l3_domain.get_resource(),
                              required=True)[0]['parentID']


def get_l2domain_np_id(restproxy_serv, l2dom_id):
    req_params = {
        'domain_id': l2dom_id
    }
    nuage_l2_domain = nuagelib.NuageL2Domain(create_params=req_params)
    return restproxy_serv.get(nuage_l2_domain.get_resource(l2dom_id),
                              required=True)[0]['parentID']


def get_l3dom_by_router_id(restproxy_serv, rtr_id):
    req_params = {
        'externalID': get_vsd_external_id(rtr_id)
    }
    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    l3domain = restproxy_serv.get(
        nuage_l3_domain.get_all_resources(),
        extra_headers=nuage_l3_domain.extra_headers_get(),
        required=True)
    return l3domain[0] if l3domain else None


def get_l3domid_by_router_id(restproxy_serv, rtr_id):
    l3domain = get_l3dom_by_router_id(restproxy_serv, rtr_id)

    if not l3domain:
        msg = _("No domain found for router %s") % rtr_id
        raise restproxy.ResourceNotFoundException(msg)
    return l3domain['ID']


def get_l3dom_template_id_by_dom_id(restproxy_serv, dom_id):
    req_params = {
        'domain_id': dom_id
    }
    nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)
    l3domain_template = restproxy_serv.get(nuage_l3_domain.get_resource(),
                                           required=True)[0]
    return l3domain_template['templateID']


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

    interfaces = restproxy_serv.get(nuage_intf.get_all_resource(),
                                    extra_headers=nuage_extra_headers,
                                    required=True)
    if interfaces:
        interface = interfaces[0]
        req_params = {'vport_id': interface['VPortID']}
        nuage_vport = nuagelib.NuageVPort(create_params=req_params)
        vport = restproxy_serv.get(nuage_vport.get_resource(),
                                   required=True)[0]
        vport['nuage_vif_id'] = interface['ID']
        return vport
    return None


def get_nuage_vport_by_id(restproxy_serv, id, required=True):
    vportlib = nuagelib.NuageVPort()
    vports = restproxy_serv.get(vportlib.get_by_id(id),
                                required=required)
    return vports[0] if vports else None


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
    return vports[0] if vports else None


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
    restproxy_serv.delete(nuage_vport.del_vport(vport_id))


def get_l2dom(restproxy_serv, nuage_id, required=False):
    nuagel2dom = nuagelib.NuageL2Domain()
    l2domains = restproxy_serv.get(nuagel2dom.get_resource(nuage_id),
                                   required=required)
    return l2domains[0] if l2domains else None


def get_l3subnet(restproxy_serv, nuage_id, required=False):
    nuagesubnet = nuagelib.NuageSubnet()
    subnets = restproxy_serv.get(nuagesubnet.get_resource(nuage_id),
                                 required=required)
    return subnets[0] if subnets else None


def get_nuage_subnet(restproxy_serv, subnet_mapping):
    if subnet_mapping is None:
        return None
    nuage_subnet_id = subnet_mapping["nuage_subnet_id"]
    if subnet_mapping['nuage_l2dom_tmplt_id']:
        resource_class = nuagelib.NuageL2Domain()
    else:
        resource_class = nuagelib.NuageSubnet()
    subnets = restproxy_serv.get(resource_class.get_resource(nuage_subnet_id))
    return subnets[0] if subnets else None


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
        raise restproxy.ResourceNotFoundException(msg)


def _get_nuage_domain_id_from_subnet(restproxy_serv, nuage_subnet_id):
    nuagesubn = nuagelib.NuageSubnet()
    l3subnet = restproxy_serv.get(nuagesubn.get_resource(nuage_subnet_id),
                                  required=True)[0]
    nuage_zone_id = l3subnet['parentID']
    req_params = {'zone_id': nuage_zone_id}
    nuagezone = nuagelib.NuageZone(create_params=req_params)
    zone = restproxy_serv.get(nuagezone.get_resource(),
                              required=True)[0]
    return zone['parentID']


def get_nuage_zone_by_id(restproxy_serv, id):
    req_params = {
        'zone_id': id
    }
    nuage_zone = nuagelib.NuageZone(create_params=req_params)
    zone = restproxy_serv.get(nuage_zone.get_resource(),
                              required=True)[0]
    return {'nuage_zone_id': zone['ID'],
            'nuage_parent_id': zone['parentID'],
            'nuage_external_id': zone['externalID']}


def get_nuage_domain_by_zoneid(restproxy_serv, zone_id):
    nuage_dom = get_nuage_zone_by_id(restproxy_serv, zone_id)
    req_params = {
        'domain_id': nuage_dom['nuage_parent_id']
    }
    nuage_l3domain = nuagelib.NuageL3Domain(create_params=req_params)
    l3domain = restproxy_serv.get(nuage_l3domain.get_resource(),
                                  required=True)[0]

    return {'nuage_domain_id': l3domain['ID'],
            'externalID': (strip_cms_id(l3domain['externalID'])
                           if l3domain['externalID'] else None)}


def get_net_partition_id_by_name(restproxy_serv, ent_name):
    req_params = {
        'name': ent_name
    }
    nuagenet_partition = nuagelib.NuageNetPartition(create_params=req_params)
    nuage_ent_extra_headers = nuagenet_partition.extra_headers_get()
    enterprise = restproxy_serv.get(nuagenet_partition.get_resource(),
                                    extra_headers=nuage_ent_extra_headers,
                                    required=True)[0]
    return enterprise['ID']


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
    nuage_zones = restproxy_serv.get(nuagezone.get_resource(),
                                     required=required)
    return nuage_zones[0]['parentID'] if nuage_zones else None


def delete_resource(restproxy_serv, resource, resource_id):
    delete_uri = '/%s/%s?responseChoice=1' % (resource, resource_id)
    restproxy_serv.delete(delete_uri)


def process_rollback(restproxy_serv, rollback_list):
    while rollback_list:
        entry = rollback_list.pop()
        resource = entry.get('resource')
        resource_id = entry.get('resource_id')
        delete_resource(restproxy_serv, resource, resource_id)


def get_in_adv_fwd_policy(restproxy_serv, parent_type, parent_id):
    template = None
    nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
    if parent_type == constants.L2DOMAIN:
        template = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l2(parent_id),
            required=True)
    elif parent_type == constants.DOMAIN:
        template = restproxy_serv.get(
            nuageadvfwdtmplt.get_resource_l3(parent_id),
            required=True)
    return template[0]['ID'] if template else None


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
    return restproxy_serv.get(nuage_np_net.get_resource_by_id(net_macro_id),
                              required=True)[0]


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
    return restproxy_serv.put(resource, update_params)


def set_external_id_with_openstack(restproxy_serv, resource, id):
    update_params = {"externalID": id + '@openstack'}
    return restproxy_serv.put(resource, update_params)


def get_nuage_fip(restproxy_serv, nuage_fip_id):
    req_params = {'fip_id': nuage_fip_id}
    nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
    return restproxy_serv.get(nuage_fip.get_fip_resource(),
                              required=True)[0]


def get_vport_assoc_with_fip(restproxy_serv, nuage_fip_id):
    req_params = {'fip_id': nuage_fip_id}
    nuage_vport = nuagelib.NuageVPort(create_params=req_params)
    return restproxy_serv.get(nuage_vport.get_vport_for_fip(),
                              required=True)[0]


def change_perm_of_subns(restproxy_serv, nuage_npid, nuage_subnetid,
                         shared, tenant_id, remove_everybody=False):
    if shared:
        params = {
            'net_partition_id': nuage_npid
        }
        nuagegroup = nuagelib.NuageGroup(create_params=params)
        group = restproxy_serv.get(
            nuagegroup.list_resource(),
            nuagegroup.extra_headers_get_for_everybody(),
            required=True)[0]
        nuage_groupid = group['ID']
    else:
        nuage_userid, nuage_groupid = create_usergroup(restproxy_serv,
                                                       tenant_id, nuage_npid)
        if remove_everybody:
            params = {
                'l2dom_id': nuage_subnetid
            }
            nuagepermission = nuagelib.NuagePermission(create_params=params)
            resource = nuagepermission.get_resource_by_l2dom_id()
            try:
                permissions = restproxy_serv.get(resource, required=True)
            except restproxy.ResourceNotFoundException:
                return
            except restproxy.RESTProxyError:
                raise

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
    restproxy_serv.post(nuage_permission.post_resource_by_parent_id(
                        'l2domains', nuage_subnetid),
                        post_data)


# function to be able to convert the value in to a VSD supported hex format
def convert_hex_for_vsd(value):
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


def get_subnet_update_data(ipv4_subnet, ipv6_subnet, params):
    # get the parameters to create single stack or update dualstack to single
    if ipv4_subnet and not ipv6_subnet:
        return {
            'description': get_subnet_description(ipv4_subnet),
            'IPv6Address': None,
            'IPType': constants.IPV4,
            'IPv6Gateway': None,
            'enableDHCPv6': False  # keep default value
        }
    elif ipv6_subnet and not ipv4_subnet:
        return {
            'description': get_subnet_description(ipv6_subnet),
            'address': None,
            'IPType': constants.IPV6,
            'gateway': None,
            'netmask': None,
            'enableDHCPv4': True  # keep default value
        }
    else:
        ipv4_network = netaddr.IPNetwork(ipv4_subnet['cidr'])
        ipv6_network = netaddr.IPNetwork(ipv6_subnet['cidr'])
        mapping = params.get('mapping')
        if mapping:
            # get the parameters to update single to dualstack
            if mapping['subnet_id'] == ipv4_subnet['id']:
                # update ipv4 subnet to dualstack, get ipv6 attributes
                dual_stack_data = {
                    'IPv6Address': str(ipv6_network.cidr),
                    'enableDHCPv6': ipv6_subnet['enable_dhcp']
                }
                if mapping['nuage_l2dom_tmplt_id']:
                    dual_stack_data['IPv6Gateway'] = params['dhcpv6_ip']
                else:
                    dual_stack_data['IPv6Gateway'] = ipv6_subnet['gateway_ip']
            else:
                # update ipv6 subnet to dualstack, get ipv4 attributes
                dual_stack_data = {
                    'address': str(ipv4_network.ip),
                    'netmask': str(ipv4_network.netmask),
                    'enableDHCPv4': ipv4_subnet['enable_dhcp']
                }
                if mapping['nuage_l2dom_tmplt_id']:
                    dual_stack_data['gateway'] = params['dhcp_ip']
                else:
                    dual_stack_data['gateway'] = ipv4_subnet['gateway_ip']
        else:
            # For creating domain subnet
            dual_stack_data = {
                'IPv6Address': str(ipv6_network.cidr),
                'IPv6Gateway': ipv6_subnet['gateway_ip'],
                'enableDHCPv6': ipv6_subnet['enable_dhcp']}
            # For creating l2domain when detaching router
            if 'dhcpv6_ip' in params:
                dual_stack_data['IPv6Gateway'] = params['dhcpv6_ip']
        dual_stack_data['IPType'] = constants.DUALSTACK
        dual_stack_data['description'] = get_subnet_description(
            ipv4_subnet, params['network_name'])
        return dual_stack_data


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


def get_subnet_name_for_pg(subnet):
    return subnet['nuage_l2bridge'] or subnet['id']


def get_subnet_name(subnet):
    return subnet['nuage_l2bridge'] or (subnet['network_id'] + '_'
                                        + subnet['id'])


def get_subnet_description(subnet, network_name=None):
    if subnet['nuage_l2bridge']:
        session = db_api.get_reader_session()
        return nuagedb.get_nuage_l2bridge(session,
                                          subnet['nuage_l2bridge'])['name']
    else:
        return network_name or subnet['name']


def _chunks(l, n):
    """Split a list l in chunks of length n """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def _chunked_extra_header_match_any_filter(field, values,
                                           max_predicates_per_request=80):
    """Creates X-Nuage-Filters to fetch objects that have 'field' in 'values'

    Selective fetching of objects from the VSD is possible using the
    X-Nuage-Filter header. This header is sent in a GET request for which
    the max header size is limited (currently 8K). In order to not exceed
    this value, it was decided to, for now, default it to the magic number 50,
    this works well for the (only) use case where we fetch FirewallRules
    by externalID, leaving still some room in the header protecting us
    against unexpected changes in the header size by future developments

    :param field: name of the field in VSD used for filtering
    :param values: list of values for that field
    :param max_predicates_per_request: max number of predicates per GET request
    :return: chunked headers
    """
    if not values:
        yield None
    else:
        for chunk in _chunks(values, max_predicates_per_request):
            yield {'X-Nuage-FilterType': 'predicate',
                   'X-Nuage-Filter': '{} IN {{"{}"}}'.format(
                       field, '","'.join(chunk))}


def get_by_field_values(restproxy_serv, resource, field_name, field_values,
                        **kwargs):
    """Get objects which have field_name IN(field_values)

    :param restproxy_serv: RESTProxy
    :param resource: The resource to get
    :param field_name: The name of the field used for filtering
    :param field_values: The values used for filtering
    :param kwargs: arguments for vsd_resource.get_url
    :return: objects in random order
    """
    chunked_headers = _chunked_extra_header_match_any_filter(field_name,
                                                             field_values)
    url = resource.get_url(**kwargs)
    iterators = (restproxy_serv.get(url, extra_headers=header, required=True)
                 for header in chunked_headers if header)
    return itertools.chain.from_iterable(iterators)
