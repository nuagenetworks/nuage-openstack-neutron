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

import datetime
import logging

import netaddr

from nuage_neutron.plugins.common import constants as plugin_constants
from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.common import pnet_helper
from nuage_neutron.vsdclient.resources import dhcpoptions
from nuage_neutron.vsdclient import restproxy

VSD_RESP_OBJ = constants.VSD_RESP_OBJ
TEMPLATE_ISOLATED_ZONE = constants.TEMPLATE_ISOLATED_ZONE
TEMPLATE_SHARED_ZONE = constants.TEMPLATE_SHARED_ZONE

LOG = logging.getLogger(__name__)


class NuageDomain(object):
    def __init__(self, restproxy_serv, policygroups):
        self.restproxy = restproxy_serv
        self.domainsubnet = NuageDomainSubnet(restproxy_serv,
                                              policygroups)

    def _create_nuage_def_l3domain_acl(self, id, neutron_router_id):
        nuageibacl_id = self._create_nuage_l3dom_ingress_tmplt(
            id,
            neutron_router_id)
        nuageobacl_id = self._create_nuage_l3dom_egress_tmplt(
            id,
            neutron_router_id)
        return nuageibacl_id, nuageobacl_id

    def _create_nuage_l3dom_ingress_tmplt(self, id, neutron_router_id):
        req_params = {
            'parent_id': id,
            'name': id,
            'externalID': get_vsd_external_id(neutron_router_id)
        }
        nuageibacl = nuagelib.NuageInboundACL(create_params=req_params)
        response = self.restproxy.rest_call('POST',
                                            nuageibacl.post_resource_l3(),
                                            nuageibacl.post_data_default_l3())
        if not nuageibacl.validate(response):
            raise nuageibacl.get_rest_proxy_error()
        return nuageibacl.get_iacl_id(response)

    def _create_nuage_l3dom_egress_tmplt(self, id, neutron_router_id):
        req_params = {
            'parent_id': id,
            'name': id,
            'externalID': get_vsd_external_id(neutron_router_id)
        }
        nuageobacl = nuagelib.NuageOutboundACL(create_params=req_params)
        response = self.restproxy.rest_call('POST',
                                            nuageobacl.post_resource_l3(),
                                            nuageobacl.post_data_default_l3())
        if not nuageobacl.validate(response):
            raise nuageobacl.get_rest_proxy_error()
        return nuageobacl.get_oacl_id(response)

    @staticmethod
    def _calculate_pat_and_underlay(router):
        underlay_routing = router.get(plugin_constants.NUAGE_UNDERLAY)
        if underlay_routing == plugin_constants.NUAGE_UNDERLAY_SNAT:
            nuage_pat = nuage_underlay = 'ENABLED'
        elif underlay_routing == plugin_constants.NUAGE_UNDERLAY_ROUTE:
            nuage_pat = 'DISABLED'
            nuage_underlay = 'ENABLED'
        else:
            nuage_pat = nuage_underlay = 'DISABLED'
        return nuage_pat, nuage_underlay

    def get_router_by_external(self, ext_id):
        params = {
            'externalID': get_vsd_external_id(ext_id)
        }

        nuagerouter = nuagelib.NuageL3Domain(create_params=params)
        response = self.restproxy.rest_call(
            'GET', nuagerouter.get_resource_with_ext_id(), '',
            extra_headers=nuagerouter.extra_headers_get())
        if not nuagerouter.validate(response):
            raise nuagerouter.get_rest_proxy_error()
        if response[3]:
            return nuagerouter.get_response_obj(response)
        else:
            return None

    def get_router_by_id(self, nuage_l3domain_id, required=False):
        params = {
            'domain_id': nuage_l3domain_id
        }
        nuage_router = nuagelib.NuageL3Domain(create_params=params)
        response = self.restproxy.get(nuage_router.get_resource(),
                                      required=required)
        return response[0] if response else None

    def _create_nuage_def_l3domain_adv_fwd_template(self, l3dom_id,
                                                    neutron_router_id):
        nuageadvfwdtmplt = nuagelib.NuageInAdvFwdTemplate()
        response = self.restproxy.rest_call(
            'POST',
            nuageadvfwdtmplt.post_resource_l3(l3dom_id),
            nuageadvfwdtmplt.post_data_default_l3(
                l3dom_id,
                get_vsd_external_id(neutron_router_id)))
        if not nuageadvfwdtmplt.validate(response):
            raise nuageadvfwdtmplt.get_rest_proxy_error()
        return nuageadvfwdtmplt.get_response_objid(response)

    def get_routers_by_netpart(self, netpart_id):
        nuagel3dom = nuagelib.NuageL3Domain({'net_partition_id': netpart_id})
        response = self.restproxy.rest_call(
            'GET', nuagel3dom.get_all_resources_in_ent(), '')
        if not nuagel3dom.validate(response):
            raise nuagel3dom.get_rest_proxy_error()
        res = []
        for l3dom in nuagel3dom.get_response_objlist(response):
            np_dict = dict()
            np_dict['domain_name'] = l3dom['name']
            np_dict['domain_id'] = l3dom['ID']
            res.append(np_dict)
        return res

    def get_fip_underlay_enabled_domain_by_netpart(self, netpart_id):
        nuagel3dom = nuagelib.NuageL3Domain({'net_partition_id': netpart_id})
        fip_enabled_domain = self.restproxy.get(
            nuagel3dom.get_all_resources_in_ent(),
            extra_headers=nuagel3dom.extra_headers_get_fipunderlay(True))
        if fip_enabled_domain:
            return fip_enabled_domain[0]['ID']
        else:
            return None

    def create_shared_l3domain(self, params):
        req_params = {
            'net_partition_id': params['netpart_id'],
            'templateID': params['templateID'],
            'externalID': None
        }
        if params['FIPUnderlay']:
            req_params['name'] = (plugin_constants.
                                  SHARED_FIP_UNDERLAY_ENABLED_DOMAIN_NAME)
        else:
            req_params['name'] = ('OpenStack' + '_' + datetime.datetime.now()
                                  .strftime('%Y-%m-%d_%H-%M-%S-%f'))

        extra_params = {'FIPUnderlay': params['FIPUnderlay']}

        nuagel3domain, _ = self._create_domain(req_params, extra_params)
        return nuagel3domain['ID']

    def create_l3domain(self, neutron_router, router, net_partition,
                        tenant_name):
        req_params = {
            'net_partition_id': net_partition['id'],
            'name': neutron_router['id'],
            'templateID': net_partition['l3dom_tmplt_id'],
            'externalID': get_vsd_external_id(neutron_router['id'])
        }
        if router.get('nuage_router_template'):
            req_params['templateID'] = router['nuage_router_template']

        extra_params = {
            'description': neutron_router['name']
        }
        if 'rd' in router and router['rd']:
            extra_params['routeDistinguisher'] = router['rd']
        if 'rt' in router and router['rt']:
            extra_params['routeTarget'] = router['rt']
        if router.get('tunnel_type'):
            neutron_tunnel_type = router['tunnel_type']
            vsd_types = constants.VSD_TUNNEL_TYPES
            extra_params['tunnelType'] = vsd_types[neutron_tunnel_type]
        if 'ecmp_count' in router:
            extra_params['ECMPCount'] = router.get('ecmp_count')
        if ('nuage_backhaul_vnid' in router and
                router['nuage_backhaul_vnid']):
            extra_params['backHaulVNID'] = router['nuage_backhaul_vnid']
        if ('nuage_backhaul_rd' in router and
                router['nuage_backhaul_rd']):
            extra_params['backHaulRouteDistinguisher'] = (
                router['nuage_backhaul_rd'])
        if ('nuage_backhaul_rt' in router and
                router['nuage_backhaul_rt']):
            extra_params['backHaulRouteTarget'] = router['nuage_backhaul_rt']

        # PATEnabled & UnderlayEnabled
        pat_enabled, underlay_enabled = self._calculate_pat_and_underlay(
            router)
        extra_params['PATEnabled'] = pat_enabled
        extra_params['underlayEnabled'] = underlay_enabled

        router_dict = {}
        nuagel3domain, zone_list = self._create_domain(req_params,
                                                       extra_params)
        nuage_domain_id = nuagel3domain['ID']
        external_id = nuagel3domain['externalID']
        parent_id = nuagel3domain['parentID']
        router_dict['nuage_external_id'] = strip_cms_id(external_id)
        router_dict['nuage_parent_id'] = parent_id
        router_dict['nuage_domain_id'] = nuage_domain_id
        router_dict['rt'] = nuagel3domain.get('routeTarget')
        router_dict['rd'] = nuagel3domain.get('routeDistinguisher')
        router_dict['ecmp_count'] = nuagel3domain.get('ECMPCount')
        router_dict['tunnel_type'] = nuagel3domain.get('tunnelType')
        router_dict['nuage_backhaul_vnid'] = nuagel3domain.get('backHaulVNID')
        router_dict['nuage_backhaul_rd'] = (
            nuagel3domain.get('backHaulRouteDistinguisher'))
        router_dict['nuage_backhaul_rt'] = (
            nuagel3domain.get('backHaulRouteTarget'))

        isolated_id = None
        shared_id = None

        if router.get('nuage_router_template'):
            for zone in zone_list:
                if (zone['name'] == TEMPLATE_ISOLATED_ZONE and
                        not zone['publicZone']):
                    isolated_id = zone['ID']
                elif (zone['name'] == TEMPLATE_SHARED_ZONE and
                      not zone['publicZone']):
                    shared_id = zone['ID']
                external_id_params = {
                    'zone_id': zone['ID']
                }
                external_id_zone = nuagelib.NuageZone(
                    create_params=external_id_params)
                helper.set_external_id_only(
                    self.restproxy,
                    resource=external_id_zone.get_resource(),
                    id=neutron_router['id'])
            if not isolated_id or not shared_id:
                msg = ("Mandatory zones %s or %s do not exist in VSD" % (
                    TEMPLATE_ISOLATED_ZONE, TEMPLATE_SHARED_ZONE))
                self.delete_l3domain(nuage_domain_id)
                raise restproxy.ResourceNotFoundException(msg)
            router_dict['nuage_def_zone_id'] = isolated_id
            router_dict['nuage_shared_zone_id'] = shared_id
            self._make_nuage_zone_shared(net_partition['id'], shared_id,
                                         neutron_router['tenant_id'])
        elif net_partition.get('isolated_zone', None):
            for zone in zone_list:
                if zone['name'] == net_partition['isolated_zone']:
                    isolated_id = zone['ID']
                if zone['name'] == net_partition['shared_zone']:
                    shared_id = zone['ID']
                external_id_params = {
                    'zone_id': zone['ID']
                }
                external_id_zone = nuagelib.NuageZone(
                    create_params=external_id_params)
                helper.set_external_id_only(
                    self.restproxy,
                    resource=external_id_zone.get_resource(),
                    id=neutron_router['id'])
            if not isolated_id or not shared_id:
                msg = "Default zones do not exist in VSD"
                self.delete_l3domain(nuage_domain_id)
                raise restproxy.ResourceNotFoundException(msg)

            router_dict['nuage_def_zone_id'] = isolated_id
            router_dict['nuage_shared_zone_id'] = shared_id
            # TODO(Ronak) - Handle exception here
            self._make_nuage_zone_shared(net_partition['id'], shared_id,
                                         neutron_router['tenant_id'])

        nuage_userid, nuage_groupid = \
            helper.create_usergroup(self.restproxy,
                                    neutron_router['tenant_id'],
                                    net_partition['id'],
                                    tenant_name)
        router_dict['nuage_userid'] = nuage_userid
        router_dict['nuage_groupid'] = nuage_groupid

        self._attach_nuage_group_to_zone(nuage_groupid,
                                         router_dict['nuage_def_zone_id'],
                                         neutron_router['tenant_id'])
        iacl_id, oacl_id = self._create_nuage_def_l3domain_acl(
            nuage_domain_id, neutron_router['id'])
        router_dict['iacl_id'] = iacl_id
        router_dict['oacl_id'] = oacl_id
        self._create_nuage_def_l3domain_adv_fwd_template(nuage_domain_id,
                                                         neutron_router['id'])
        return router_dict

    def _create_domain(self, req_params, extra_params):
        nuagel3domain = nuagelib.NuageL3Domain(create_params=req_params,
                                               extra_params=extra_params)
        created_domain = self.restproxy.post(nuagel3domain.post_resource(),
                                             nuagel3domain.post_data())[0]
        req_params = {
            'domain_id': created_domain['ID']
        }
        nuage_zone = nuagelib.NuageZone(req_params)
        zone_list = self.restproxy.get(nuage_zone.list_resource())
        if not zone_list:
            self.delete_l3domain(created_domain['ID'])
            msg = ("Cannot find zone under the created domain {} on VSD. "
                   "Delete the created domain".format(created_domain['ID']))
            raise restproxy.ResourceNotFoundException(msg)
        return created_domain, zone_list

    def update_router(self, nuage_domain_id, router, updates):
        tunnel_types = constants.VSD_TUNNEL_TYPES
        update_dict = {
            'name': router['id'],
            'description': router['name'],
            'routeDistinguisher': router.get('rd'),
            'routeTarget': router.get('rt'),
            'tunnelType': tunnel_types.get(router.get('tunnel_type'),
                                           router.get('tunnel_type')),
            'ECMPCount': router.get('ecmp_count'),
            'backHaulVNID': router.get('nuage_backhaul_vnid'),
            'backHaulRouteDistinguisher': router.get('nuage_backhaul_rd'),
            'backHaulRouteTarget': router.get('nuage_backhaul_rt')
        }

        underlay_routing = updates.get(plugin_constants.NUAGE_UNDERLAY)
        if underlay_routing is not None:
            pat_enabled, underlay_enabled = \
                self._calculate_pat_and_underlay(updates)
            update_dict['PATEnabled'] = pat_enabled
            update_dict['underlayEnabled'] = underlay_enabled

        nuagel3domain = nuagelib.NuageL3Domain()
        self.restproxy.put(nuagel3domain.put_resource(nuage_domain_id),
                           update_dict)

    def _make_nuage_zone_shared(self, nuage_netpartid, nuage_zoneid,
                                neutron_tenant_id):
        params = {
            'net_partition_id': nuage_netpartid
        }
        nuagegroup = nuagelib.NuageGroup(create_params=params)
        response = self.restproxy.rest_call(
            'GET',
            nuagegroup.list_resource(), '',
            nuagegroup.extra_headers_get_for_everybody())
        if not nuagegroup.validate(response):
            raise nuagegroup.get_rest_proxy_error()

        nuage_all_groupid = nuagegroup.get_groupid(response)
        self._attach_nuage_group_to_zone(nuage_all_groupid,
                                         nuage_zoneid,
                                         neutron_tenant_id)

    def delete_l3domain(self, domain_id):
        nuagel3domain = nuagelib.NuageL3Domain()
        self.restproxy.delete(nuagel3domain.delete_resource(domain_id))

    def validate_zone_create(self, l3dom_id,
                             l3isolated, l3shared):
        params = {
            'l3domain_id': l3dom_id
        }
        nuagezonetemplate = nuagelib.NuageZoneTemplate(create_params=params)
        response = self.restproxy.rest_call(
            'GET', nuagezonetemplate.list_resource(), '')
        if not nuagezonetemplate.validate(response):
            raise nuagezonetemplate.get_rest_proxy_error()
        isolated_match = False
        shared_match = False
        zone_tlist = nuagezonetemplate.zonetemplate_list(response)
        for zone in zone_tlist:
            if zone['name'] == l3isolated:
                isolated_match = True
            if zone['name'] == l3shared:
                shared_match = True
        return (shared_match, isolated_match)

    def delete_nuage_staticroute(self, params):
        static_route = self.get_nuage_static_route(params)
        if static_route:
            nuage_staticroute = nuagelib.NuageStaticRoute()
            self.restproxy.rest_call(
                'DELETE',
                nuage_staticroute.delete_resource(
                    static_route['nuage_static_route_id']), '')

    def get_nuage_static_route(self, params):
        cidr = netaddr.IPNetwork(params['address'])
        req_params = {
            'cidr': cidr,
            'nexthop': params['nexthop'],
            'domain_id': params['nuage_domain_id'],
            'ip_type': cidr.ip.version
        }

        static_route = nuagelib.NuageStaticRoute(create_params=req_params)
        static_route = self.restproxy.get(
            static_route.get_resources_of_domain(),
            extra_headers=static_route.extra_headers_get())
        return {
            'nuage_zone_id': static_route[0]['ID'],
            'nuage_static_route_id': static_route[0]['ID'],
            'rd': static_route[0]['routeDistinguisher']
        } if static_route else None

    def create_nuage_staticroute(self, params):
        ipv6_net = ipv4_net = None
        if netaddr.IPNetwork(params['net']).version == constants.IPV6_VERSION:
            ipv6_net = params['net']
            ip_type = constants.IPV6
        else:
            ipv4_net = params['net']
            ip_type = constants.IPV4

        req_params = {
            'domain_id': params['nuage_domain_id'],
            'router_id': params['neutron_rtr_id'],
            'net': ipv4_net,
            'ipv6_net': ipv6_net,
            'nexthop': params['nexthop'],
            'IPType': ip_type
        }

        nuage_staticroute = nuagelib.NuageStaticRoute(create_params=req_params)
        response = self.restproxy.rest_call(
            'POST', nuage_staticroute.post_resource(),
            nuage_staticroute.post_data())
        if not nuage_staticroute.validate(response):
            raise nuage_staticroute.get_rest_proxy_error()
        return nuage_staticroute.get_staticrouteid(response)

    def _attach_nuage_group_to_zone(self, nuage_groupid, nuage_zoneid,
                                    neutron_tenant_id):
        nuage_permission = nuagelib.NuagePermission()
        resp = self.restproxy.rest_call(
            'POST',
            nuage_permission.post_resource_by_parent_id('zones', nuage_zoneid),
            nuage_permission.perm_create_data(
                nuage_groupid,
                constants.NUAGE_PERMISSION_USE,
                neutron_tenant_id))
        if not nuage_permission.validate(resp):
            if (nuage_permission.get_error_code(resp) !=
                    constants.CONFLICT_ERR_CODE):
                raise nuage_permission.get_rest_proxy_error()

    def get_zone_by_domainid(self, domain_id):
        nuage_l3_domain = nuagelib.NuageL3Domain({'domain_id': domain_id})
        response = self.restproxy.rest_call(
            'GET', nuage_l3_domain.get_all_zones(), '')
        if not nuage_l3_domain.validate(response):
            raise nuage_l3_domain.get_rest_proxy_error()
        res = []
        for zone in nuage_l3_domain.get_response_objlist(response):
            np_dict = dict()
            np_dict['zone_name'] = zone['name']
            np_dict['zone_id'] = zone['ID']
            res.append(np_dict)
        return res

    def get_zone_by_routerid(self, neutron_router_id, shared=False):
        nuage_rtr_id = helper.get_l3domid_by_router_id(
            self.restproxy, neutron_router_id)
        l3dom_tmplt_id = helper.get_l3dom_template_id_by_dom_id(
            self.restproxy, nuage_rtr_id)

        req_params = {
            'domain_id': nuage_rtr_id
        }
        nuage_l3_domain = nuagelib.NuageL3Domain(create_params=req_params)

        if shared:
            zone_name = (plugin_constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' +
                         l3dom_tmplt_id)
        else:
            zone_name = (plugin_constants.DEF_NUAGE_ZONE_PREFIX + '-' +
                         l3dom_tmplt_id)

        nuage_extra_headers = nuage_l3_domain.extra_headers_get_name(zone_name)
        response = self.restproxy.rest_call(
            'GET', nuage_l3_domain.get_all_zones(), '',
            extra_headers=nuage_extra_headers)
        if not nuage_l3_domain.validate(response):
            raise nuage_l3_domain.get_rest_proxy_error()
        if shared:
            if response[constants.VSD_RESP_OBJ]:
                return response[3][0]
            else:
                # TODO(Divya): try seems to be not required here
                try:
                    nuage_extra_headers = (
                        nuage_l3_domain.extra_headers_get_name(
                            TEMPLATE_SHARED_ZONE))
                    shared_zone = self.restproxy.rest_call(
                        'GET', nuage_l3_domain.get_all_zones(), '',
                        extra_headers=nuage_extra_headers)
                    if not nuage_l3_domain.validate(shared_zone):
                        raise nuage_l3_domain.get_rest_proxy_error()
                    if shared_zone[VSD_RESP_OBJ]:
                        return shared_zone[VSD_RESP_OBJ][0]
                except Exception:
                    return None
        else:
            if response[constants.VSD_RESP_OBJ]:
                return response[3][0]
            else:
                # This is needed for add_router_interface to a router created
                # with nuage-router-template parameter
                # return None when called from router_delete
                # TODO(Divya): try seems to be not required here
                try:
                    nuage_extra_headers = (
                        nuage_l3_domain.extra_headers_get_name(
                            TEMPLATE_ISOLATED_ZONE))
                    isolated_zone = self.restproxy.rest_call(
                        'GET', nuage_l3_domain.get_all_zones(), '',
                        extra_headers=nuage_extra_headers)
                    if not nuage_l3_domain.validate(isolated_zone):
                        raise nuage_l3_domain.get_rest_proxy_error()
                    if isolated_zone[VSD_RESP_OBJ]:
                        return isolated_zone[VSD_RESP_OBJ][0]
                except Exception:
                    return None

        return None

    def _get_nuage_static_routes_by_router_id(self, neutron_router_id):
        domain_id = helper.get_l3domid_by_router_id(self.restproxy,
                                                    neutron_router_id)
        req_params = {
            'domain_id': domain_id
        }
        nuage_route = nuagelib.NuageStaticRoute(create_params=req_params)
        response = self.restproxy.rest_call(
            'GET', nuage_route.post_resource(), '', '')

        if not nuage_route.validate(response):
            raise nuage_route.get_rest_proxy_error()

        return response[3]

    def confirm_router_interface_not_in_use(self, neutron_router_id,
                                            neutron_subnet):
        nuage_routes = self._get_nuage_static_routes_by_router_id(
            neutron_router_id)
        for route in nuage_routes:
            if netaddr.all_matching_cidrs(route['nextHopIp'],
                                          [neutron_subnet['cidr']]):
                msg = ("router interface for subnet %s is required by one or"
                       " more routes") % neutron_subnet['name']
                raise restproxy.ResourceConflictException(msg)

    def create_nuage_floatingip(self, params):
        fip = self.create_nuage_floatingip_details(params)
        return fip['ID']

    def create_nuage_floatingip_details(self, params):
        req_params = {
            'domain_id': params['nuage_rtr_id'],
            'shared_netid': params['nuage_fippool_id'],
            'address': params['neutron_fip_ip'],
            'externalID': get_vsd_external_id(params['neutron_fip_id'])
        }
        nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
        response = self.restproxy.post(nuage_fip.post_resource(),
                                       nuage_fip.post_data())
        return response[0]

    def get_nuage_floatingip(self, id, required=False, **filters):
        floatingip = nuagelib.NuageFloatingIP()
        floatingips = self.restproxy.get(
            floatingip.get_resource_by_id(id),
            extra_headers=floatingip.extra_header_filter(**filters),
            required=required)
        if floatingips:
            return floatingips[0]

    def get_nuage_floatingips(self, required=False, **filters):
        floatingip = nuagelib.NuageFloatingIP()
        return self.restproxy.get(
            floatingip.get_resource(),
            extra_headers=floatingip.extra_header_filter(**filters),
            required=required)

    def get_child_floatingips(self, parent_resource, parent_id,
                              required=False, **filters):
        floatingip = nuagelib.NuageFloatingIP()
        return self.restproxy.get(
            floatingip.get_child_resource(parent_resource, parent_id),
            extra_headers=floatingip.extra_header_filter(**filters),
            required=required)

    def delete_nuage_floatingip(self, id):
        nuagefip = nuagelib.NuageFloatingIP()
        resp = self.restproxy.rest_call('DELETE', nuagefip.delete_resource(id),
                                        '')
        if not nuagefip.validate(resp):
            raise nuagefip.get_rest_proxy_error()

    def update_vport_floatingip(self, vport_id, floatingip_id):
        floatingip = nuagelib.NuageFloatingIP()
        self.restproxy.put(
            floatingip.get_child_resource(nuagelib.NuageVPort.resource,
                                          vport_id),
            floatingip_id)

    def validate_port_create_redirect_target(self, params):
        nuage_subnet_id = params.get('nuage_subnet_id')
        if params.get('parent_type') == constants.DOMAIN:
            nuage_domain_id = params.get('parent')
            nuagel3dom = nuagelib.NuageL3Domain()
            l3dom_subnets = self.restproxy.rest_call(
                'GET',
                nuagel3dom.get_domain_subnets(nuage_domain_id), '')
            if not nuagel3dom.validate(l3dom_subnets):
                raise nuagel3dom.get_rest_proxy_error()

            for subnet in l3dom_subnets[3]:
                if subnet['ID'] == nuage_subnet_id:
                    return True
        elif params.get('parent_type') == constants.L2DOMAIN:
            nuage_l2domain_id = params.get('parent')
            if nuage_l2domain_id == nuage_subnet_id:
                return True
        return False

    def create_nuage_fip_for_vpnaas(self, params):
        req_params = {
            'domain_id': params['nuage_rtr_id'],
            'shared_netid': params['nuage_fippool_id'],
            'externalID': params['vpn_id']
        }
        nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
        response = self.restproxy.rest_call('POST', nuage_fip.post_resource(),
                                            nuage_fip.post_fip_data())
        if not nuage_fip.validate(response):
            raise nuage_fip.get_rest_proxy_error()
        return response[3][0]


class NuageDomainSubnet(object):
    def __init__(self, restproxy_serv, policygroups):
        self.restproxy = restproxy_serv
        self.policygroups = policygroups

    def get_domain_subnet_by_id(self, nuage_id):
        nuagesubnet = nuagelib.NuageSubnet()
        return self.restproxy.get(nuagesubnet.get_resource(nuage_id),
                                  required=True)[0]

    def get_domain_subnet_by_ext_id_and_cidr(self, neutron_subnet):
        return helper.get_domain_subnet_by_ext_id_and_cidr(self.restproxy,
                                                           neutron_subnet)

    def get_domain_subnet_by_zone_id(self, zone_id):
        subnet = nuagelib.NuageSubnet({'zone': zone_id})
        return self.restproxy.get(subnet.get_all_resources_in_zone())

    def update_domain_subnet_to_dualstack(self, ipv4_subnet, ipv6_subnet,
                                          params):
        mapping = params['mapping']
        data = helper.get_subnet_update_data(ipv4_subnet, ipv6_subnet, params)
        self.update_domain_subnet_for_stack_exchange(
            mapping['nuage_subnet_id'], **data)
        nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
        if mapping['subnet_id'] == ipv4_subnet['id']:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv6_subnet,
                parent_id=mapping['nuage_subnet_id'],
                network_type=constants.NETWORK_TYPE_L3)
        if mapping['subnet_id'] == ipv6_subnet['id']:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv4_subnet,
                parent_id=mapping['nuage_subnet_id'],
                network_type=constants.NETWORK_TYPE_L3)

    def update_domain_subnet_to_single_stack(self, mapping, ipv4_subnet,
                                             ipv6_subnet):
        data = helper.get_subnet_update_data(ipv4_subnet, ipv6_subnet,
                                             params=None)
        self.update_domain_subnet_for_stack_exchange(
            mapping['nuage_subnet_id'], **data)

    def delete_l3domain_subnet(self, vsd_id):
        vsd_subnet = nuagelib.NuageSubnet()
        self.restproxy.delete(vsd_subnet.delete_resource(vsd_id))

    def update_domain_subnet_for_stack_exchange(self, domain_subnet_id,
                                                **data):
        vsd_subnet = nuagelib.NuageSubnet()
        self.restproxy.put(vsd_subnet.put_resource(domain_subnet_id), data)

    def create_shared_subnet(self, vsd_zone_id, subnet, params):
        req_params = {
            'name': helper.get_subnet_name(subnet),
            'zone': vsd_zone_id,
            'externalID': helper.get_subnet_external_id(subnet)
        }
        net = netaddr.IPNetwork(subnet['cidr'])
        extra_params = {
            'address': str(net.ip),
            'netmask': str(net.netmask),
            'gateway': subnet['gateway_ip'],
            'resourceType': params['resourceType'],
            'description': subnet['name'],
            'IPType': constants.IPV4
        }
        if params.get('underlay'):
            extra_params['underlay'] = params['underlay']

        nuage_subnet = self._create_subnet(req_params, extra_params)
        nuage_subnet['nuage_userid'] = None
        nuage_subnet['nuage_groupid'] = None
        return nuage_subnet

    def create_domain_subnet(self, vsd_zone, ipv4_subnet, ipv6_subnet,
                             pnet_binding, network_name):
        subnet = ipv4_subnet or ipv6_subnet
        net = netaddr.IPNetwork(subnet['cidr'])
        req_params = {
            'name': helper.get_subnet_name(subnet),
            'zone': vsd_zone['ID'],
            'externalID': helper.get_subnet_external_id(subnet)
        }
        description = helper.get_subnet_description(subnet)
        extra_params = {'description': description,
                        'entityState': 'UNDER_CONSTRUCTION',
                        'dynamicIpv4Address': False,
                        'dynamicIpv6Address': False}
        if ipv4_subnet:
            extra_params.update({
                'address': str(net.ip),
                'netmask': str(net.netmask),
                'gateway': ipv4_subnet['gateway_ip'],
                'enableDHCPv4': ipv4_subnet['enable_dhcp']
            })
        elif ipv6_subnet:
            extra_params.update({
                'IPv6Address': str(net.cidr),
                'IPv6Gateway': ipv6_subnet['gateway_ip'],
                'IPType': constants.IPV6,
                'enableDHCPv6': ipv6_subnet['enable_dhcp']
            })

        # attach dualstack subnet to a router
        if ipv4_subnet and ipv6_subnet:
            params = {'network_name': network_name,
                      'network_id': subnet['network_id']}
            data = helper.get_subnet_update_data(ipv4_subnet, ipv6_subnet,
                                                 params)
            req_params['name'] = data.pop('name')
            extra_params.update(data)

        vsd_subnet = self._create_subnet(req_params, extra_params)

        nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
        if ipv4_subnet:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv4_subnet,
                parent_id=vsd_subnet['ID'],
                network_type=constants.NETWORK_TYPE_L3)
        if ipv6_subnet:
            nuagedhcpoptions.create_nuage_dhcp(
                ipv6_subnet,
                parent_id=vsd_subnet['ID'],
                network_type=constants.NETWORK_TYPE_L3)

        if pnet_binding:
            # Get netpart id needed in process_provider_network to check the
            # gateway port enterprise permissions
            req_params = {'domain_id': vsd_zone['parentID']}
            nuage_l3domain = nuagelib.NuageL3Domain(create_params=req_params)
            domain = self.restproxy.get(nuage_l3domain.get_resource())[0]
            np_id = helper.get_l3domain_np_id(self.restproxy, domain['ID'])

            if ipv4_subnet:
                self._process_provider_network(pnet_binding, vsd_subnet['ID'],
                                               np_id, ipv4_subnet['id'])
            if ipv6_subnet:
                self._process_provider_network(pnet_binding, vsd_subnet['ID'],
                                               np_id, ipv6_subnet['id'])
        return vsd_subnet

    def _create_subnet(self, req_params, extra_params):
        nuagel3domsub = nuagelib.NuageSubnet(create_params=req_params,
                                             extra_params=extra_params)

        ignore_error_codes = [constants.RES_EXISTS_INTERNAL_ERR_CODE,
                              constants.SUBNET_NAME_DUPLICATE_ERROR]
        return self.restproxy.post(
            nuagel3domsub.post_resource(),
            nuagel3domsub.post_data(),
            on_res_exists=self.restproxy.retrieve_by_ext_id_and_cidr,
            ignore_err_codes=ignore_error_codes)[0]

    def _process_provider_network(
            self, pnet_binding, vsd_subnet_id, np_id, subnet):
        pnet_params = helper.get_pnet_params(
            pnet_binding, vsd_subnet_id, np_id, subnet)
        pnet_helper.process_provider_network(self.restproxy,
                                             self.policygroups,
                                             pnet_params)

    def update_domain_subnet(self, neutron_subnet, params):
        if params.get('dhcp_opts_changed'):
            nuagedhcpoptions = dhcpoptions.NuageDhcpOptions(self.restproxy)
            nuagedhcpoptions.update_nuage_dhcp(
                neutron_subnet, parent_id=params['parent_id'],
                network_type=constants.NETWORK_TYPE_L3)

        updates = {}
        if params.get('dhcp_enable_changed'):
            if params.get('ip_type') == constants.IPV4:
                updates['enableDHCPv4'] = neutron_subnet.get('enable_dhcp')
            else:
                updates['enableDHCPv6'] = neutron_subnet.get('enable_dhcp')

        new_name = helper.get_subnet_description(neutron_subnet,
                                                 params.get('network_name'))
        if new_name:
            # update the description on the VSD for this subnet if required
            # If a subnet is updated from horizon, we get the name of the
            # subnet as well in the subnet dict for update.
            nuagesubn = nuagelib.NuageSubnet()
            subn = self.restproxy.get(
                nuagesubn.get_resource(params['parent_id']),
                required=True)[0]
            if subn['description'] != new_name and not params.get('dualstack'):
                updates['description'] = new_name
        if neutron_subnet.get(plugin_constants.NUAGE_UNDERLAY):
            nuage_pat, nuage_underlay = self._calculate_pat_and_underlay(
                neutron_subnet)
            updates['PATEnabled'] = nuage_pat
            updates['underlayEnabled'] = nuage_underlay
        if updates:
            nuagel3domsub = nuagelib.NuageSubnet()
            self.restproxy.put(nuagel3domsub.put_resource(params['parent_id']),
                               updates)

    @staticmethod
    def _calculate_pat_and_underlay(subnet):
        underlay_routing = subnet.get(plugin_constants.NUAGE_UNDERLAY)
        if underlay_routing == plugin_constants.NUAGE_UNDERLAY_SNAT:
            nuage_pat = nuage_underlay = 'ENABLED'
        elif underlay_routing == plugin_constants.NUAGE_UNDERLAY_ROUTE:
            nuage_pat = 'DISABLED'
            nuage_underlay = 'ENABLED'
        elif underlay_routing == plugin_constants.NUAGE_UNDERLAY_OFF:
            nuage_pat = nuage_underlay = 'DISABLED'
        else:
            nuage_pat = nuage_underlay = 'INHERITED'
        return nuage_pat, nuage_underlay

    def update_nuage_subnet(self, nuage_id, params):
        req_params = {}
        if params.get('subnet_name'):
            req_params['description'] = params['subnet_name']
        if params.get('gateway_ip'):
            req_params['gateway'] = params.get('gateway_ip')
        if not req_params:
            return
        nuagel3domsub = nuagelib.NuageSubnet()
        self.restproxy.put(
            nuagel3domsub.put_resource(nuage_id),
            req_params)

    def delete_domain_subnet(self, nuage_subn_id, neutron_subn_id,
                             pnet_binding):
        nuagel3domsub = nuagelib.NuageSubnet()
        if pnet_binding:
            pnet_helper.delete_resources_created_for_domainsubnet_providernet(
                self.restproxy, self.policygroups, nuage_subn_id,
                neutron_subn_id)

        # Delete domain_subnet
        self.restproxy.rest_call('DELETE',
                                 nuagel3domsub.delete_resource(nuage_subn_id),
                                 '')

    def validate_create_domain_subnet(self, neutron_subn, nuage_subnet_id,
                                      nuage_rtr_id):
        net_cidr = netaddr.IPNetwork(neutron_subn['cidr'])

        nuagel3dom = nuagelib.NuageL3Domain()
        overlapping_subnet = self.restproxy.get(
            nuagel3dom.get_domain_subnets(nuage_rtr_id),
            extra_headers=nuagel3dom.extra_headers_get_address(
                cidr=net_cidr, ip_type=neutron_subn['ip_version']),
            required=True)

        if overlapping_subnet:
            msg = ("Cidr %s of subnet %s overlaps with another subnet in the "
                   "VSD" % (net_cidr, nuage_subnet_id))
            raise restproxy.ResourceConflictException(msg)
        return True

    def move_to_l2(self, subnet_id, l2domain_id):
        url = nuagelib.Job.post_url('subnets', subnet_id)
        try:
            self.restproxy.post(url, {
                'command': 'DETACH',
                'parameters': {'destinationL2DomainID': l2domain_id}
            })
        except restproxy.ResourceNotFoundException:
            pass
