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

from abc import ABCMeta
import uuid

from six.moves.urllib.parse import urlencode

from oslo_serialization import jsonutils as json
import six

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.restproxy import RESTProxyError

REST_SUCCESS_CODES = constants.REST_SUCCESS_CODES
REST_NOT_FOUND = constants.RES_NOT_FOUND
DEF_OPENSTACK_USER = constants.DEF_OPENSTACK_USER
DEF_OPENSTACK_USER_EMAIL = constants.DEF_OPENSTACK_USER_EMAIL
REST_SERV_UNAVAILABLE_CODE = constants.REST_SERV_UNAVAILABLE_CODE


class NuageResource(object):
    def __init__(self, create_params=None, extra_params=None):
        self.create_params = create_params
        self.extra_params = extra_params
        self.error_msg = None
        self.error_code = None
        self.vsd_error_code = None

    def validate(self, response):
        if response[0] == 0:
            return False
        if response[0] not in REST_SUCCESS_CODES:
            errors = json.loads(response[3])
            self.error_code = response[0]
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                self.error_msg = self.get_503_error_msg(errors)
            else:
                self.error_msg = self.get_error_msg(errors)
                if response[0] != REST_NOT_FOUND:  # 404s don't have an
                    #                                internalErrorCode
                    self.vsd_error_code = self.get_internal_error_code(errors)
            return False
        return True

    def get_503_error_msg(self, errors):
        return 'VSD temporarily unavailable, ' + str(errors['errors'])

    def get_error_msg(self, errors):
        return str(errors['errors'][0]['descriptions'][0]['description'])

    def get_internal_error_code(self, errors):
        return str(errors.get('internalErrorCode'))

    def get_response_objid(self, response):
        return str(response[3][0]['ID'])

    def get_response_objtype(self, response):
        if 'type' in response[3][0]:
            return str(response[3][0]['type'])

    def get_response_obj(self, response):
        return response[3][0]

    def get_response_objlist(self, response):
        return response[3]

    def get_response_parentid(self, response):
        return response[3][0]['parentID']

    def get_response_externalid(self, response):
        return strip_cms_id(response[3][0]['externalID'])

    def get_description(self, response):
        return response[3][0]['description']

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def check_response_exist(self, response):
        return len(response[3]) > 0

    def delete_validate(self, response):
        return (self.validate(response) or
                response[0] == constants.RES_NOT_FOUND)

    def get_error_code(self, response):
        return response[0]

    def resource_exists(self, response):
        error_code = self.get_error_code(response)
        if error_code == 0:
            return False
        errors = json.loads(response[3])
        int_error_code = self.get_internal_error_code(errors)
        # 2510 is the internal error code returned by VSD in case
        # template already exists
        if (error_code != constants.CONFLICT_ERR_CODE or
            (error_code == constants.CONFLICT_ERR_CODE and
             int_error_code != constants.RES_EXISTS_INTERNAL_ERR_CODE)):
            return False
        return True

    def extra_header_filter(self, **filters):
        filter = ''
        for field, value in six.iteritems(filters):
            if isinstance(value, six.string_types):
                value = "'%s'" % value
            if value is None:
                value = 'null'
            if filter:
                filter += " and "
            filter += "%s IS %s" % (field, value)
        return {'X-Nuage-Filter': filter} if filter else None

    def single_filter_header(self, **filters):
        assert len(filters) == 1
        filter = ''
        field = next(iter(filters))
        for value in filters[field]:
            if isinstance(value, six.string_types):
                value = "'%s'" % value
            if value is None:
                value = 'null'
            if filter:
                filter += " or "
            filter += "%s IS %s" % (field, value)
        return {'X-Nuage-Filter': filter} if filter else None

    def get_rest_proxy_error(self):
        return RESTProxyError(self.error_msg,
                              self.error_code,
                              self.vsd_error_code)


class NuageL3DomTemplate(NuageResource):
    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/domaintemplates?responseChoice=1' % ent_id

    def list_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/domaintemplates' % ent_id

    def post_data(self):
        data = {
            'name': self.create_params['name']
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def get_templateid(self, response):
        if response[3]:
            return self.get_response_objid(response)
        else:
            return None

    def delete_resource(self, id):
        return '/domaintemplates/%s?responseChoice=1' % id

    def put_resource(self, id):
        return '/domaintemplates/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers


class NuageL2DomTemplate(NuageResource):
    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/l2domaintemplates?responseChoice=1' % ent_id

    def list_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/l2domaintemplates' % ent_id

    def post_data(self):
        data = {
            "name": self.create_params['name']
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def get_resource(self, id):
        return '/l2domaintemplates/%s' % id

    def put_resource(self, id):
        return '/l2domaintemplates/%s?responseChoice=1' % id

    def get_templateid(self, response):
        if response[3]:
            return self.get_response_objid(response)
        else:
            return None

    def delete_resource(self, id):
        return '/l2domaintemplates/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers


class NuageZoneTemplate(NuageResource):
    def post_resource(self):
        l3dom_id = self.create_params['l3domain_id']
        return '/domaintemplates/%s/zonetemplates?responseChoice=1' % l3dom_id

    def list_resource(self):
        l3dom_id = self.create_params['l3domain_id']
        return '/domaintemplates/%s/zonetemplates' % l3dom_id

    def post_data(self):
        data = {
            "name": self.create_params['name']
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def get_templateid(self, response):
        return self.get_response_objid(response)

    def delete_resource(self, id):
        return '/zonetemplates/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers

    def zonetemplate_list(self, response):
        return response[3]


class NuageL2Domain(NuageResource):
    resource = 'l2domains'

    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/%s?responseChoice=1' % (ent_id, self.resource)

    def post_data(self):
        data = {
            'name': self.create_params['name'],
            'templateID': self.create_params['template'],
            'externalID': get_vsd_external_id(
                self.create_params['externalID'])
        }

        if self.extra_params:
            data.update(self.extra_params)
        return data

    def put_resource(self, id):
        return '/%s/%s?responseChoice=1' % (self.resource, id)

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def get_domainid(self, response):
        return self.get_response_objid(response)

    def get_template_id(self, response):
        return response[3][0]['templateID']

    def delete_resource(self, id):
        return '/%s/%s?responseChoice=1' % (self.resource, id)

    def get_resource(self, id):
        return '/%s/%s' % (self.resource, id)

    def get_all_resources_in_ent(self):
        return '/enterprises/%s/%s' % (
            self.create_params['net_partition_id'], self.resource)

    def get_all_resources(self):
        return '/%s' % self.resource

    def vm_get_resource(self, id):
        return '/%s/%s/vms' % (self.resource, id)

    def vport_get_resource(self, l2dom_id):
        return '/%s/%s/vports' % (self.resource, l2dom_id)

    def vm_exists(self, response):
        return self.validate(response) and len(response[3]) > 0

    def nuage_redirect_target_get_resource(self, id):
        return '/%s/%s/redirectiontargets' % (self.resource, id)

    def dhcp_get_resource(self, id):
        return '/%s/%s/dhcpoptions' % (self.resource, id)

    def get_gwIp_set_via_dhcp(self, dhcpoption):
        gw_ip_via_dhcp_option = dhcpoption['value']
        bytes = ["".join(x) for x in zip(*[iter(gw_ip_via_dhcp_option)] * 2)]
        bytes = [int(x, 16) for x in bytes]
        return ".".join(str(x) for x in bytes)

    def get_gw_info(self, response):
        gw_ip = response[3][0]['gateway']
        return gw_ip

    def get_all_vports(self, id):
        return '/%s/%s/vports' % (self.resource, id)

    def vport_post(self, id):
        return '/%s/%s/vports' % (self.resource, id)

    def vport_post_data(self, params):
        data = {
            'VLANID': params['vlan'],
            'type': params['type'],
            'name': params['name'],
            'externalID': get_vsd_external_id(params['externalID'])
        }

        if params.get('type') == constants.BRIDGE_VPORT_TYPE:
            data['addressSpoofing'] = constants.ENABLED
        else:
            data['addressSpoofing'] = constants.DISABLED
        return data

    def vm_vport_post_data(self, params):
        data = {
            'type': params['type'],
            'name': params['name'],
            'addressSpoofing': params['addressSpoofing'],
            'externalID': get_vsd_external_id(params['externalID'])
        }

        if params.get('description'):
            data['description'] = params.get('description')
        return data

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '{}'".format(
            get_vsd_external_id(self.create_params['externalID']))
        return headers

    def extra_headers_ext_id_and_cidr_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if self.create_params['ip_type'] == constants.IPV4_VERSION:
            headers['X-Nuage-Filter'] = (
                "externalID IS '{}' and address IS '{}'".format(
                    self.create_params['externalID'],
                    str(self.create_params['cidr'].ip)))
        else:
            headers['X-Nuage-Filter'] = (
                "externalID IS '{}' and IPv6Address IS '{}'".format(
                    self.create_params['externalID'],
                    str(self.create_params['cidr'])))
        return headers

    def extra_headers_vport_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "type IS BRIDGE"
        return headers

    def extra_headers_host_and_vm_vport_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "type IS VM or type is HOST"
        return headers


class NuageSubnet(NuageResource):
    resource = 'subnets'

    def post_resource(self):
        return ('/zones/%s/subnets?responseChoice=1'
                % self.create_params['zone'])

    def post_data(self):
        data = {
            'name': self.create_params['name'],
            'externalID': get_vsd_external_id(
                self.create_params['externalID'])
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def get_subnetid(self, response):
        return self.get_response_objid(response)

    def delete_resource(self, id):
        return '/subnets/%s?responseChoice=1' % id

    def get_resource(self, id):
        return '/subnets/%s' % id

    def put_resource(self, id):
        return '/subnets/%s?responseChoice=1' % id

    def get_all_resources_in_domain(self):
        return '/domains/%s/subnets' % self.create_params['nuage_domain_id']

    def get_all_resources_in_zone(self):
        return '/zones/%s/subnets' % self.create_params['zone']

    def get_all_resources(self):
        return '/subnets'

    def get_parentzone(self, response):
        return response[3][0]['parentID']

    def vm_get_resource(self, id):
        return '/subnets/%s/vms' % id

    def vport_get_resource(self, subnet_id):
        return '/subnets/%s/vports' % subnet_id

    def vm_exists(self, response):
        return self.validate(response) and len(response[3]) > 0

    def dhcp_get_resource(self, id):
        return '/subnets/%s/dhcpoptions' % id

    def get_gwIp_set_via_dhcp(self, dhcpoption):
        gw_ip_via_dhcp_option = dhcpoption['value']
        bytes = ["".join(x) for x in zip(*[iter(gw_ip_via_dhcp_option)] * 2)]
        bytes = [int(x, 16) for x in bytes]
        return ".".join(str(x) for x in bytes)

    def get_gw_info(self, response):
        gw_ip = response[3][0]['gateway']
        return gw_ip

    def vport_post(self, id):
        return '/subnets/%s/vports' % id

    def vport_post_data(self, params):
        data = {
            'VLANID': params['vlan'],
            'type': params['type'],
            'name': params['name'],
            'externalID': get_vsd_external_id(params['externalID'])
        }

        if params.get('type') == constants.BRIDGE_VPORT_TYPE:
            data['addressSpoofing'] = constants.ENABLED
        else:
            data['addressSpoofing'] = constants.DISABLED

        return data

    def vm_vport_post_data(self, params):
        data = {
            'type': params['type'],
            'name': params['name'],
            'addressSpoofing': params['addressSpoofing'],
            'externalID': get_vsd_external_id(params['externalID'])
        }

        if params.get('description'):
            data['description'] = params.get('description')
        return data

    def get_all_vports(self, id):
        return '/subnets/%s/vports' % id

    def extra_headers_vport_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "type IS BRIDGE"
        return headers

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '{}'".format(
            get_vsd_external_id(self.create_params['externalID']))
        return headers

    def extra_headers_ext_id_and_cidr_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if self.create_params['ip_type'] == constants.IPV4_VERSION:
            headers['X-Nuage-Filter'] = (
                "externalID IS '{}' and address IS '{}'".format(
                    self.create_params['externalID'],
                    str(self.create_params['cidr'].ip))
            )
        else:
            headers['X-Nuage-Filter'] = (
                "externalID IS '{}' and IPv6Address IS '{}'".format(
                    self.create_params['externalID'],
                    str(self.create_params['cidr'])))
        return headers

    def extra_headers_host_and_vm_vport_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "type IS VM or type is HOST"
        return headers


class NuageDhcpOptions(NuageResource):
    def __init__(self, ip_version, create_params=None, extra_params=None):
        super(NuageDhcpOptions, self).__init__(create_params, extra_params)
        self.resource = 'dhcpoptions' if ip_version == 4 else 'dhcpv6options'

    def resource_by_l2domainid(self, id):
        # This method is used for GET and POST for l2 case
        return '/l2domains/{}/{}'.format(id, self.resource)

    def resource_by_subnetid(self, id):
        # This method is used for GET and POST for l3 case
        return '/subnets/{}/{}'.format(id, self.resource)

    def resource_by_vportid(self, id):
        # This method is used for GET and POST for VPort case
        return '/vports/{}/{}'.format(id, self.resource)

    def dhcp_resource(self, id):
        # This method is used for DELETE and PUT with acceptance
        return '/{}/{}?responseChoice=1'.format(self.resource, id)

    @staticmethod
    def get_gwIp_set_via_dhcp(dhcp_option):
        gw_ip_via_dhcp_option = dhcp_option['value']
        bytes = ["".join(x) for x in zip(*[iter(gw_ip_via_dhcp_option)] * 2)]
        bytes = [int(x, 16) for x in bytes]
        return ".".join(str(x) for x in bytes)


class NuageL3Domain(NuageResource):
    resource = 'domains'

    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/%s' % (ent_id, self.resource)

    def get_resource(self):
        return '/%s/%s' % (self.resource, self.create_params['domain_id'])

    def post_data(self):
        data = {
            "name": self.create_params['name'],
            "templateID": self.create_params['templateID'],
            "externalID": get_vsd_external_id(self.create_params['externalID'])
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def get_domainid(self, response):
        return self.get_response_objid(response)

    def delete_resource(self, id):
        return '/%s/%s?responseChoice=1' % (self.resource, id)

    def put_resource(self, id):
        return '/%s/%s?responseChoice=1' % (self.resource, id)

    def get_all_resources(self):
        return '/%s' % self.resource

    def get_resource_with_ext_id(self):
        return '/%s' % self.resource

    def get_all_resources_in_ent(self):
        return '/enterprises/%s/%s' % (self.create_params[
            'net_partition_id'], self.resource)

    def get_all_zones(self):
        return '/%s/%s/zones' % (self.resource,
                                 self.create_params['domain_id'])

    def get_all_vports(self):
        return '/%s/%s/vports' % (self.resource,
                                  self.create_params['domain_id'])

    def get_domain_rt(self, response):
        return response[3][0].get('routeTarget')

    def get_domain_rd(self, response):
        return response[3][0].get('routeDistinguisher')

    def get_domain_ecmp_count(self, response):
        return response[3][0].get('ECMPCount')

    def get_domain_tunnel_type(self, response):
        return response[3][0].get('tunnelType')

    def get_domain_backhaul_vnid(self, response):
        return response[3][0].get('backHaulVNID')

    def get_domain_backhaul_rd(self, response):
        return response[3][0].get('backHaulRouteDistinguisher')

    def get_domain_backhaul_rt(self, response):
        return response[3][0].get('backHaulRouteTarget')

    def get_patenabled(self, response):
        return response[3][0].get('PATEnabled', None)

    def get_domain_subnets(self, id):
        return '/%s/%s/subnets' % (self.resource, id)

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" %  \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers

    def extra_headers_get_name(self, zone_name):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % zone_name
        return headers

    def extra_headers_get_address(self, cidr, ip_type):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if ip_type == constants.IPV4_VERSION:
            headers['X-Nuage-Filter'] = "address IS '{}'".format(str(cidr.ip))
        else:
            headers['X-Nuage-Filter'] = "IPv6Address IS '{}'".format(str(cidr))
        return headers

    def extra_headers_get_fipunderlay(self, fipunderlay):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "FIPUnderlay IS {}".format(fipunderlay)
        return headers


class NuageZone(NuageResource):
    def get_zoneid(self, response):
        return self.get_response_objid(response)

    def get_resource(self):
        return '/zones/%s' % self.create_params['zone_id']

    def post_resource(self):
        return '/domains/%s/zones' % self.create_params['domain_id']

    def list_resource(self):
        return '/domains/%s/zones' % self.create_params['domain_id']

    def get_all_resource(self):
        return '/zones'

    def post_data(self):
        data = {
            "name": self.create_params['name'],
            "externalID": get_vsd_external_id(self.create_params['externalID'])
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def zone_list(self, response):
        return response[3]

    def get_isolated_zone_id(self, zones):
        for zone in zones:
            if '-pub-' not in zone['name']:
                return zone['ID']

    def get_shared_zone_id(self, zones):
        for zone in zones:
            if '-pub-' in zone['name']:
                return zone['ID']

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" %  \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers


class NuageStaticRoute(NuageResource):
    def get_staticrouteid(self, response):
        return self.get_response_objid(response)

    def post_resource(self):
        return ("/domains/%s/staticroutes"
                "?responseChoice=1" % self.create_params['domain_id'])

    def get_resource(self):
        return '/staticroutes'

    def get_resources_of_domain(self):
        return '/domains/%s/staticroutes' % self.create_params['domain_id']

    def post_data(self):
        data = {
            'address': str(self.create_params['net'].ip
                           ) if self.create_params['net'] else None,
            'netmask': str(self.create_params['net'].netmask
                           ) if self.create_params['net'] else None,
            'IPv6Address': str(self.create_params['ipv6_net']
                               ) if self.create_params['ipv6_net'] else None,
            'nextHopIp': self.create_params['nexthop'],
            'IPType': str(self.create_params['IPType']),
            'externalID': get_vsd_external_id(self.create_params['router_id']),
            'type': "OVERLAY"
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def delete_resource(self, id):
        return '/staticroutes/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if self.create_params['ip_type'] == constants.IPV4_VERSION:
            headers['X-Nuage-Filter'] = (
                "address IS '{}' and nextHopIp IS '{}'".format(
                    str(self.create_params['cidr'].ip),
                    self.create_params['nexthop']))
        else:
            headers['X-Nuage-Filter'] = (
                "IPv6Address IS '{}' and nextHopIp IS '{}'".format(
                    str(self.create_params['cidr']),
                    self.create_params['nexthop']))
        return headers


class NuageGroup(NuageResource):
    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/groups' % ent_id

    def get_group_id(self, response):
        return self.get_response_objid(response)

    def list_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/groups' % ent_id

    def find_group_by_name(self, name, group_list):
        for group in group_list:
            if name == group['name']:
                return group['ID']
        return None

    def group_list(self, response):
        return response[3]

    def post_data(self):
        data = {}
        data['name'] = self.create_params['name']
        data['managementMode'] = constants.NUAGE_LDAP_MODE
        data['externalID'] = self.create_params['externalID']
        if self.create_params['description'] is not None:
            data['description'] = self.create_params['description']
        return data

    def get_groupid(self, response):
        return self.get_response_objid(response)

    def zone_attach_resource(self, zoneid):
        return '/zones/%s/groups' % zoneid

    def l2domain_groups(self, l2domid):
        return '/l2domains/%s/groups' % l2domid

    def l2dom_attach_groupid_list(self, groupid):
        return groupid

    def zone_attach_data(self, groupid):
        return [groupid]

    def zone_attach_groupid_list(self, groupid):
        return groupid

    def delete_resource(self, id):
        return '/groups/%s?responseChoice=1' % id

    def group_resource(self, id):
        return '/groups/%s' % id

    def update_data(self, key, value):
        data = {
            key: value
        }
        return data

    def extra_headers_get_for_everybody(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS 'Everybody'"
        return headers

    def extra_headers_get_by_name(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers


class NuageUser(NuageResource):
    def ent_post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/users' % ent_id

    def group_post_resource(self):
        return '/groups/%s/users' % self.create_params['group_id']

    def find_user_by_name(self, name, user_list):
        for user in user_list:
            if name == user['userName']:
                return user['ID']
        return None

    def user_list(self, response):
        return response[3]

    def set_group_id(self, groupid):
        self.create_params['group_id'] = groupid

    def post_data(self):
        data = {}
        data["firstName"] = DEF_OPENSTACK_USER
        data["lastName"] = DEF_OPENSTACK_USER
        data["userName"] = self.create_params['name']
        data["email"] = DEF_OPENSTACK_USER_EMAIL
        data["password"] = uuid.uuid4().hex
        data["managementMode"] = constants.NUAGE_LDAP_MODE
        data['externalID'] = self.create_params['externalID']
        return data

    def get_userid(self, response):
        return self.get_response_objid(response)

    def delete_resource(self, id):
        return '/users/%s?responseChoice=1' % id

    def user_resource(self, id):
        return '/users/%s' % id

    def update_data(self, key, value):
        data = {
            key: value
        }
        return data

    def extra_headers_get_by_username(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = (
            "userName IS '%s'" % self.extra_params['userName'])
        return headers


class NuageNetPartition(NuageResource):
    def post_resource(self):
        return '/enterprises'

    def get_resource(self):
        return '/enterprises'

    def get_resource_by_id(self):
        return '/enterprises/%s' % self.create_params['netpart_id']

    def default_post_data(self):
        data = {
            'allowedForwardingClasses': ['E', 'F', 'G', 'H']
        }
        return data

    def post_data(self):
        data = {
            'name': self.create_params['name'],
            'floatingIPsQuota': self.create_params['fp_quota'],
            'externalID': self.create_params['externalID']
        }
        data.update(self.default_post_data())
        return data

    def get_net_partition_id(self, response):
        return self.get_response_objid(response)

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def delete_resource(self, id):
        return '/enterprises/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers


class NuageEntProfile(NuageResource):
    def get_resource(self):
        return '/enterpriseprofiles'

    def get_resource_by_id(self, id):
        return '/enterpriseprofiles/%s' % id

    def post_fip_quota(self, fip_quota):
        data = {
            'floatingIPsQuota': fip_quota
        }
        return data

    def get_validate(self, response):
        return self.validate(response) and response[3]


class NuageVM(NuageResource):
    resource = 'vms'

    def post_resource(self):
        return '/vms'

    def get_resource(self):
        return '/vms'

    def delete_resource(self):
        return '/vms/%s?responseChoice=1' % self.create_params['id']

    def post_data(self):
        interface = {
            'MAC': self.create_params['mac'],
            'externalID': get_vsd_external_id(self.create_params['externalID'])
        }
        if self.create_params.get('attachedNetworkID'):
            interface['attachedNetworkID'] = (
                self.create_params['attachedNetworkID'])
        if self.create_params.get('vport_id'):
            interface['VPortID'] = self.create_params['vport_id']
        if self.create_params['ipv4'] is not None:
            interface['IPAddress'] = self.create_params['ipv4']
        if self.create_params['ipv6'] is not None:
            interface['IPv6Address'] = self.create_params['ipv6']

        data = {
            'name': 'vm-' + self.create_params['mac'].replace(':', ''),
            'interfaces': [interface],
            'UUID': self.create_params['id'],
            'externalID': get_vsd_external_id(self.create_params['id'])

        }
        return data

    def extra_headers_post(self):
        headers = {}
        ent_name = self.extra_params['net_partition_name']
        headers['X-Nuage-ProxyUser'] = "%s@%s" % (self.extra_params['tenant'],
                                                  ent_name)
        return headers

    def extra_headers_delete(self):
        return self.extra_headers_post()

    def extra_headers_get(self):
        headers = {}
        ent_name = self.extra_params['net_partition_name']
        headers['X-Nuage-ProxyUser'] = "%s@%s" % (self.extra_params['tenant'],
                                                  ent_name)
        headers['X-NUAGE-FilterType'] = "predicate"
        id = str(self.create_params['id'])
        headers['X-Nuage-Filter'] = "UUID IS '%s'" % id
        return headers

    def extra_headers_get_by_externalID(self):
        headers = {}
        headers['X-/vport-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def get_vmid(self, response):
        return self.get_response_objid(response)

    def get_num_interfaces(self, response):
        return len(response[3][0]['interfaces'])

    def get_new_vmif(self, response):
        vm_interfaces = response[0]['interfaces']
        for vm_if in vm_interfaces:
            if str(vm_if['MAC']) == self.create_params['mac']:
                return vm_if
        return None

    def get_vmif_ip(self, vm_if):
        return vm_if['IPAddress']

    def get_vmif_id(self, vm_if):
        return vm_if['ID']

    def get_vmif_vportid(self, vm_if):
        return vm_if['VPortID']

    def get_all_resources(self):
        return '/l2domains/%s/vms' % self.create_params['l2domain_id']


class NuageVMInterface(NuageResource):
    def get_all_resource(self):
        return '/vminterfaces'

    def get_interface_for_vport(self):
        return '/vports/%s/vminterfaces' % self.create_params['vport_id']

    def post_resource(self):
        return '/vms/%s/vminterfaces' % self.create_params['vm_id']

    def delete_resource(self):
        return '/vminterfaces/%s?responseChoice=1' % self.create_params['id']

    def create_resync_id(self):
        return '/vms/%s/resync' % self.create_params['vm_id']

    def post_data(self):
        data = {
            'MAC': self.create_params['mac'],
            'externalID': get_vsd_external_id(self.create_params['externalID'])
        }
        if self.create_params.get('attachedNetworkID'):
            data['attachedNetworkID'] = (
                self.create_params['attachedNetworkID'])
        if self.create_params.get('vport_id'):
            data['VPortID'] = self.create_params['vport_id']
        if self.create_params['ipv4'] is not None:
            data['IPAddress'] = self.create_params['ipv4']
        if self.create_params['ipv6'] is not None:
            data['IPv6Address'] = self.create_params['ipv6']
        return data

    def put_data(self):
        data = {
            'MAC': self.create_params['mac'],
            'IPAddress': self.create_params['ipv4'],
            'IPv6Address': self.create_params['ipv6']
        }
        return data

    def extra_headers(self):
        headers = {}
        ent_name = self.extra_params['net_partition_name']
        headers['X-Nuage-ProxyUser'] = "%s@%s" % (self.extra_params['tenant'],
                                                  ent_name)
        return headers

    def extra_headers_for_all_vmifs(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" %  \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers

    def get_vif_id(self, response):
        return response[0]['ID']

    def get_vport_id(self, response):
        return response[0]['VPortID']

    def get_vmif_ip(self, response):
        return response[0]['IPAddress']


class NuageInboundACL(NuageResource):

    def get_resource_l2(self):
        parent_id = self.create_params['parent_id']
        return '/l2domains/%s/ingressacltemplates' % parent_id

    def post_resource_l2(self):
        parent_id = self.create_params['parent_id']
        return '/l2domains/%s/ingressacltemplates' % parent_id

    def get_resource_l3(self):
        parent_id = self.create_params['parent_id']
        return '/domains/%s/ingressacltemplates' % parent_id

    def post_resource_l3(self):
        parent_id = self.create_params['parent_id']
        return '/domains/%s/ingressacltemplates' % parent_id

    def post_data_default_l2(self, allow_non_ip=False):
        data = {}
        data['name'] = (self.create_params['name'] +
                        constants.NUAGE_DEFAULT_L2_INGRESS_ACL)
        data['description'] = 'default ACL'
        data['active'] = True
        data['defaultAllowNonIP'] = allow_non_ip
        data['externalID'] = self.create_params['externalID']
        if self.create_params.get('priority'):
            data['priority'] = self.create_params.get('priority')
        return data

    def post_data_l2(self):
        return

    def post_data_default_l3(self, allow_non_ip=False):
        data = {}
        data['name'] = (self.create_params['name'] +
                        constants.NUAGE_DEFAULT_L3_INGRESS_ACL)
        data['description'] = 'default ACL'
        data['active'] = True
        data['defaultAllowNonIP'] = allow_non_ip
        data['externalID'] = self.create_params['externalID']
        if self.create_params.get('priority'):
            data['priority'] = self.create_params.get('priority')
        return data

    def post_data_default_l3rule(self):
        aclentry = {
            "locationType": "ANY",
            "networkType": "ENDPOINT_DOMAIN",
            "etherType": constants.IPV4_ETHERTYPE,
            "protocol": "ANY",
            "priority": 32768,
            "action": "FORWARD",
            "DSCP": '*',
        }
        return aclentry

    def post_data_default_l2rule(self):
        aclentry = {
            "locationType": "ANY",
            "networkType": "ANY",
            "etherType": constants.IPV4_ETHERTYPE,
            "protocol": "ANY",
            "priority": 32768,
            "action": "FORWARD",
            "DSCP": '*',
        }
        return aclentry

    def post_data_l3(self):
        return

    def get_iacl_id(self, response):
        return self.get_response_objid(response)

    def extra_headers_get_by_name(self, name):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % name
        return headers

    def extra_headers_get_by_externalID(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers


class NuageOutboundACL(NuageResource):

    def get_resource_l2(self):
        parent_id = self.create_params['parent_id']
        return '/l2domains/%s/egressacltemplates' % parent_id

    def post_resource_l2(self):
        parent_id = self.create_params['parent_id']
        return '/l2domains/%s/egressacltemplates' % parent_id

    def get_resource_l3(self):
        parent_id = self.create_params['parent_id']
        return '/domains/%s/egressacltemplates' % parent_id

    def post_resource_l3(self):
        parent_id = self.create_params['parent_id']
        return '/domains/%s/egressacltemplates' % parent_id

    def post_data_default_l2(self, allow_non_ip=False):
        data = {}
        data['name'] = (self.create_params['name'] +
                        constants.NUAGE_DEFAULT_L2_EGRESS_ACL)
        data['description'] = 'default ACL'
        data['active'] = True
        data['defaultAllowNonIP'] = allow_non_ip
        data['defaultInstallACLImplicitRules'] = False
        data['externalID'] = self.create_params['externalID']
        if self.create_params.get('priority'):
            data['priority'] = self.create_params.get('priority')
        return data

    def post_data_l2(self):
        return

    def post_data_default_l3(self, allow_non_ip=False):
        data = {}
        data['name'] = (self.create_params['name'] +
                        constants.NUAGE_DEFAULT_L3_EGRESS_ACL)
        data['description'] = 'default ACL'
        data['active'] = True
        data['defaultAllowNonIP'] = allow_non_ip
        data['defaultInstallACLImplicitRules'] = False
        data['externalID'] = self.create_params['externalID']
        if self.create_params.get('priority'):
            data['priority'] = self.create_params.get('priority')
        return data

    def post_data_default_l3rule(self):
        aclentry = {
            "locationType": "ANY",
            "networkType": "ENDPOINT_DOMAIN",
            "etherType": constants.IPV4_ETHERTYPE,
            "protocol": "ANY",
            "priority": 32768,
            "action": "FORWARD",
            "DSCP": '*',
        }
        return aclentry

    def post_data_default_l2rule(self):
        aclentry = {
            "locationType": "ANY",
            "networkType": "ANY",
            "etherType": constants.IPV4_ETHERTYPE,
            "protocol": "ANY",
            "priority": 32768,
            "action": "FORWARD",
            "DSCP": '*',
        }
        return aclentry

    def post_data_l3(self):
        return

    def get_oacl_id(self, response):
        return self.get_response_objid(response)

    def extra_headers_get_by_name(self, name):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % name
        return headers


class NuageFloatingIP(NuageResource):
    resource = 'floatingips'

    def get_fip_id(self, response):
        return self.get_response_objid(response)

    def post_resource(self):
        return '/domains/%s/%s' % (self.create_params['domain_id'],
                                   self.resource)

    def put_resource(self):
        return '/%s/%%s?responseChoice=1' % self.resource

    def get_resource(self):
        return '/%s' % self.resource

    def get_resource_by_id(self, id):
        return '/%s/%s' % (self.resource, id)

    def get_child_resource(self, parent_resource, parent_id):
        return '/%s/%s/%s' % (parent_resource, parent_id, self.resource)

    def post_data(self):
        data = {
            "associatedSharedNetworkResourceID":
                self.create_params['shared_netid'],
            "address": self.create_params['address'],
            "externalID": get_vsd_external_id(self.create_params['externalID'])
        }
        if self.extra_params:
            data.update(self.extra_params)
        return data

    def post_fip_data(self):
        data = {
            "associatedSharedNetworkResourceID":
                self.create_params['shared_netid'],
            "domain_id": self.create_params['domain_id'],
            "externalID": get_vsd_external_id(self.create_params['externalID'])
        }
        return data

    def delete_resource(self, id):
        return '/%s/%s?responseChoice=1' % (self.resource, id)

    def get_fip_resource(self):
        return '/%s/%s' % (self.resource, self.create_params['fip_id'])

    def extra_headers(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers


class NuageVPort(NuageResource):
    resource = 'vports'

    def get_url(self, parent, parent_id):
        return '/%s/%s/%s' % (parent, parent_id, self.resource)

    def get_vport_id(self, response):
        return self.get_response_objid(response)

    def get_mac_spoofing(self, response):
        if self.check_response_exist(response):
            return response[3][0]['addressSpoofing']

    def get_resource(self):
        return '/%s/%s' % (self.resource, self.create_params['vport_id'])

    def get_by_id(self, id):
        return '/%s/%s' % (self.resource, id)

    def delete_resource(self):
        return '/%s/%s?responseChoice=1' % (self.resource,
                                            self.create_params['vport_id'])

    def put_resource(self):
        return '/%s/%s?responseChoice=1' % (self.resource,
                                            self.create_params['vport_id'])

    def get_vports_for_policygroup(self):
        return '/policygroups/%s/%s' % (self.create_params['policygroup_id'],
                                        self.resource)

    def get_vports_for_subnet(self):
        return '/subnets/%s/%s' % (self.create_params['subnet_id'],
                                   self.resource)

    def get_vports_for_l2domain(self):
        return '/l2domains/%s/%s' % (self.create_params['l2domain_id'],
                                     self.resource)

    def get_vport_for_fip(self):
        return '/floatingips/%s/%s' % (self.create_params['fip_id'],
                                       self.resource)

    def get_vport_for_redirectiontargets(self):
        return ('/redirectiontargets/%s/%s'
                % (self.create_params['rtarget_id'], self.resource))

    def get_child_resource(self, parent_resource, parent_id):
        return '/%s/%s/%s' % (parent_resource, parent_id, self.resource)

    def post_vport_for_l2domain(self):
        return '/l2domains/%s/%s' % (self.create_params['l2domain_id'],
                                     self.resource)

    def post_vport_for_subnet(self):
        return '/subnets/%s/%s' % (self.create_params['subnet_id'],
                                   self.resource)

    def post_vport_data(self):
        data = {
            'VLANID': self.extra_params['vlan'],
            'type': self.extra_params['type'],
            'name': self.extra_params['name'],
            "externalID": self.extra_params['externalID']
        }

        if self.extra_params.get('type') == constants.BRIDGE_VPORT_TYPE:
            data['addressSpoofing'] = constants.ENABLED
        else:
            data['addressSpoofing'] = \
                (constants.DISABLED if
                 self.extra_params[constants.PORTSECURITY]
                 else constants.ENABLED)

        if self.extra_params.get('externalID'):
            data['externalID'] = get_vsd_external_id(
                self.extra_params['externalID'])
        return data

    def fip_update_data(self):
        data = {
            'associatedFloatingIPID': self.create_params['fip_id']
        }
        return data

    def mac_spoofing_update_data(self):
        data = {
            'addressSpoofing': self.extra_params['mac_spoofing']
        }
        return data

    def get_vport_policygroup_resource(self, id):
        return '/%s/%s/policygroups' % (self.resource, id)

    def get_vport_redirect_target_resource(self, vport_id):
        return '/%s/%s/redirectiontargets' % (self.resource, vport_id)

    def post_bridge_interface(self, id):
        return '/%s/%s/bridgeinterfaces' % (self.resource, id)

    def del_bridge_interface(self, id):
        return '/bridgeinterfaces/%s?responseChoice=1' % id

    def del_vport(self, vport_id):
        return '/%s/%s?responseChoice=1' % (self.resource, vport_id)

    def post_bridge_iface_data(self, net_type, name, neutron_id):
        data = {
            "attachedNetworkType": net_type,
            "name": name,
            "externalID": get_vsd_external_id(neutron_id)
        }
        return data

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" %\
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers

    def extra_headers_get_by_name(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" %\
                                    self.extra_params['vport_name']
        return headers

    def extra_headers_host_or_bridge(self):
        query = ("type IS '%(bridge)s' OR type IS '%(host)s'"
                 % {'bridge': constants.BRIDGE_VPORT_TYPE,
                    'host': constants.HOST_VPORT_TYPE})
        return {'X-Nuage-Filter': query}


class NuageNetPartitionNetwork(NuageResource):
    def get_resource_by_id(self, net_id):
        return '/enterprisenetworks/%s' % net_id

    def post_resource(self):
        ent_id = self.create_params['net_partition_id']
        return ('/enterprises/%s/enterprisenetworks'
                '?responseChoice=1' % ent_id)

    def post_data(self):
        data = {
            'name': self.create_params['name'],
            'address': str(self.create_params['net'].ip
                           ) if self.create_params['net'] else None,
            'netmask': str(self.create_params['net'].netmask
                           ) if self.create_params['net'] else None,
            'IPv6Address': str(self.create_params['ipv6_net']
                               ) if self.create_params['ipv6_net'] else None,
            'IPType': str(self.create_params['IPType']),
            'externalID': str(self.create_params['net_partition_id'] +
                              '@openstack')
        }
        return data

    def get_np_network_id(self, response):
        return self.get_response_objid(response)

    def delete_resource(self, id):
        return '/enterprisenetworks/%s?responseChoice=1' % id

    def put_resource(self, id):
        return '/enterprisenetworks/%s?responseChoice=1' % id

    def get_resource(self):
        ent_id = self.create_params['net_partition_id']
        return '/enterprises/%s/enterprisenetworks' % ent_id

    def get_np_net_list(self, response):
        return response[3]

    def get_np_net_by_name(self, response, name):
        for pubnet in self.get_np_net_list(response):
            if pubnet['name'] == name:
                return pubnet['ID']
        return None

    def extra_headers_get_name(self, name):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % name
        return headers

    def extra_headers_get_netadress(self, req_params):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if req_params.get('net'):
            cidr, netmask = req_params['net'].ip, req_params['net'].netmask
            headers['X-Nuage-Filter'] = ("address IS '%s' and netmask IS '%s'"
                                         % (cidr, netmask))
        else:
            headers['X-Nuage-Filter'] = ("IPv6Address IS '%s'" % (
                req_params['ipv6_net']))
        return headers


class NuageGatewayBase(NuageResource):
    # creation method
    def factory(create_params, extra_params, redundant=False):
        if redundant:
            return NuageRedundancyGroup(create_params=create_params,
                                        extra_params=extra_params)
        else:
            return NuageGateway(create_params=create_params,
                                extra_params=extra_params)
    factory = staticmethod(factory)

    def get_response_id(self, response):
        return self.get_response_objid(response)

    def ent_perm_update(self, np_id):
        data = {
            'permittedAction': 'EXTEND',
            'permittedID': np_id
        }
        return data

    def extra_headers_by_name(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.extra_params['name']
        return headers

    def extra_headers_by_system_id(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "systemID IS '%s'" %\
            self.extra_params['system_id']
        return headers


class NuageGateway(NuageGatewayBase):
    def get_resource(self):
        return '/gateways'

    def get_resource_for_netpart(self):
        return '/enterprises/%s/gateways' % \
            self.create_params['netpart_id']

    def get_resource_by_id(self):
        return '/gateways/%s' % self.create_params['gw_id']

    def get_ent_perm(self):
        return ('/gateways/%s/enterprisepermissions' %
                self.create_params['gw_id'])


class NuageRedundancyGroup(NuageGatewayBase):
    def get_resource(self):
        return '/redundancygroups'

    def get_resource_for_netpart(self):
        return ('/enterprises/%s/redundancygroups' %
                self.create_params['netpart_id'])

    def get_resource_by_id(self):
        return '/redundancygroups/%s' % self.create_params['gw_id']

    def get_ent_perm(self):
        return ('/redundancygroups/%s/enterprisepermissions' %
                self.create_params['gw_id'])


class NuageGatewayPortBase(NuageResource):
    # creation method
    def factory(create_params, extra_params, redundant=False):
        if redundant:
            return NuageGatewayRedundantPort(create_params=create_params,
                                             extra_params=extra_params)
        else:
            return NuageGatewayPort(create_params=create_params,
                                    extra_params=extra_params)
    factory = staticmethod(factory)

    def get_response_id(self, response):
        return self.get_response_objid(response)

    def get_gw(self, response):
        if response[3]:
            return response[3][0]['parentID']

    def post_vlan_data(self, vlanid):
        externalid = self.create_params['port_id'] + '.' + str(vlanid)
        data = {
            'value': vlanid,
            'externalID': get_vsd_external_id(externalid)
        }
        return data

    def delete_vlan(self, vlanid):
        return '/vlans/%s?responseChoice=1' % vlanid

    def ent_perm_update(self, np_id):
        data = {
            'permittedAction': "EXTEND",
            'permittedEntityID': np_id
        }
        return data

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = ("externalID IS '%s'" %
                                     get_vsd_external_id(
                                         self.create_params['externalID']))
        return headers

    def extra_headers_by_name(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = ("name IS '%s'" %
                                     self.extra_params['gw_port_name'])
        return headers

    def extra_headers_by_phys_name(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = ("physicalName IS '%s'" %
                                     self.extra_params['physical_name'])
        return headers


class NuageGatewayPort(NuageGatewayPortBase):
    def get_resource(self):
        return '/ports/%s' % self.create_params['port_id']

    def get_resource_by_gateway(self):
        return '/gateways/%s/ports' % self.create_params['gw_id']

    def post_vlan(self):
        return '/ports/%s/vlans' % self.create_params['port_id']

    def get_ent_perm(self):
        return '/ports/%s/enterprisepermissions' % \
            self.create_params['port_id']


class NuageGatewayRedundantPort(NuageGatewayPortBase):
    def get_resource(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/ports/%s' % self.create_params['port_id']
        else:
            return '/vsgredundantports/%s' % self.create_params['port_id']

    def get_resource_by_gateway(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/redundancygroups/%s/ports' % \
                self.create_params['gw_id']
        else:
            return '/redundancygroups/%s/vsgredundantports' % \
                self.create_params['gw_id']

    def post_vlan(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/ports/%s/vlans' % self.create_params['port_id']
        else:
            return '/vsgredundantports/%s/vlans' % \
                self.create_params['port_id']

    def get_ent_perm(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/ports/%s/enterprisepermissions' % \
                self.create_params['port_id']
        else:
            return '/vsgredundantports/%s/enterprisepermissions' % \
                self.create_params['port_id']


class NuageVlanBase(NuageResource):
    # create method
    def factory(create_params, extra_params, redundant=False):
        if redundant:
            return NuageRedundantVlan(create_params=create_params,
                                      extra_params=extra_params)
        else:
            return NuageVlan(create_params=create_params,
                             extra_params=extra_params)
    factory = staticmethod(factory)

    def get_resonse_id(self, response):
        return self.get_response_objid(response)

    def get_resource(self):
        return '/vlans/%s' % self.create_params['vlan_id']

    def get_ent_perm(self):
        return ('/vlans/%s/enterprisepermissions' % self.create_params[
            'vlan_id'])

    def post_vlan_data(self, vlanid):
        externalid = str(self.create_params['port_id']) + '.' + str(vlanid)
        data = {
            'value': vlanid,
            'externalID': get_vsd_external_id(externalid)
        }
        return data

    def ent_perm_update(self, np_id):
        data = {
            'permittedAction': "USE",
            'permittedEntityID': np_id
        }
        return data

    def extra_headers_by_value(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = ("value IS %s" %
                                     self.extra_params['vlan_value'])
        return headers


class NuageVlan(NuageVlanBase):
    def post_vlan(self):
        return '/ports/%s/vlans' % self.create_params['port_id']

    def get_resource_by_port(self):
        return '/ports/%s/vlans' % self.create_params['port_id']


class NuageRedundantVlan(NuageVlanBase):
    def post_vlan(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/ports/%s/vlans' % self.create_params['port_id']
        else:
            return '/vsgredundantports/%s/vlans' % \
                self.create_params['port_id']

    def get_resource_by_port(self):
        if self.create_params['personality'] in constants.SW_GW_TYPES:
            return '/ports/%s/vlans' % self.create_params['port_id']
        else:
            return '/vsgredundantports/%s/vlans' % \
                self.create_params['port_id']


@six.add_metaclass(ABCMeta)
class NuageQOS(NuageResource):
    def get_resource(self):
        return '/qos/%s' % self.create_params['qos_id']

    def post_data(self):
        data = {
            "name": self.create_params['name'],
        }

        if self.extra_params:
            data.update(self.extra_params)
        return data

    def put_resource(self):
        return '/qos/%s?responseChoice=1' % self.create_params['qos_id']

    def get_qosid(self, response):
        return self.get_response_objid(response)

    def delete_resource(self):
        return '/qos/%s?responseChoice=1' % self.create_params['qos_id']


class NuageVportQOS(NuageQOS):

    def get_all_resource(self):
        return '/vports/%s/qos' % self.create_params['vport_id']

    def post_resource(self):
        return '/vports/%s/qos' % self.create_params['vport_id']

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = (
            "externalID IS '%s'" % get_vsd_external_id(
                self.create_params['externalID']))
        return headers

    def extra_headers_by_value(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "value IS %s" %\
                                    self.extra_params['vlan_value']
        return headers


class NuageBasePermission(object):

    def get_permitted_entity_id(self, response):
        return response[3][0]['permittedEntityID']

    def get_permitted_entity_type(self, response):
        return response[3][0]['permittedEntityType']

    def perm_update(self, id):
        data = {
            'permittedAction': constants.NUAGE_PERMISSION_USE,
            'permittedEntityID': id
        }
        return data


class NuagePermission(NuageResource, NuageBasePermission):
    # def __init__(self, create_params=None, extra_params=None):
    #   super(NuagePermission, self).__init__(create_params, extra_params)

    def get_resource_by_id(self):
        return '/permissions/%s' % self.create_params['perm_id']

    def get_resource_by_vlan(self):
        return '/vlans/%s/permissions' % self.create_params['vlan_id']

    def get_resource_by_l2dom_id(self):
        return '/l2domains/%s/permissions' % self.create_params['l2dom_id']

    def get_resource_by_zone_id(self):
        return '/zones/%s/permissions' % self.create_params['zone_id']

    def delete_resource(self, perm_id):
        return '/permissions/%s?responseChoice=1' % perm_id

    def post_resource_by_parent_id(self, entity_type, parent_id):
        return '/%s/%s/permissions' % (entity_type, parent_id)

    def extra_headers_by_entity_id(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "permittedEntityID IS %s" %\
                                    self.extra_params['entity_id']
        return headers

    def perm_create_data(self, vsd_entity_id, permitted_action,
                         parent_neutron_id):
        data = {'permittedEntityID': vsd_entity_id,
                'permittedAction': permitted_action,
                'externalID': get_vsd_external_id(parent_neutron_id)
                }
        return data


class NuageEntPermission(NuageResource, NuageBasePermission):
    # def __init__(self, create_params=None, extra_params=None):
    #   super(NuageEntPermission, self).__init__(create_params, extra_params)

    def get_response_obj(self, response):
        if response[3]:
            return super(NuageEntPermission, self).get_response_obj(response)

    def get_resource_by_id(self):
        return '/enterprisepermissions/%s' % self.create_params['perm_id']

    def get_resource_by_vlan(self):
        return '/vlans/%s/enterprisepermissions' % self.create_params[
            'vlan_id']

    def get_resource_by_port(self, redundancy=False):
        if redundancy:
            return '/vsgredundantports/%s/enterprisepermissions' %\
                self.create_params['port_id']
        else:
            return '/ports/%s/enterprisepermissions' %\
                self.create_params['port_id']

    def get_resource_by_gw(self, redundancy=False):
        if redundancy:
            return '/redundancygroups/%s/enterprisepermissions' %\
                self.create_params['gw_id']
        else:
            return '/gateways/%s/enterprisepermissions' %\
                self.create_params['gw_id']


class NuageHostInterface(NuageResource):
    def get_all_resource(self):
        return '/vports/%s/hostinterfaces' % self.create_params['vport_id']

    def get_resource(self):
        return '/hostinterfaces/%s' % self.create_params['interface_id']

    def delete_resource(self):
        return '/hostinterfaces/%s?responseChoice=1' % self.create_params[
            'interface_id']

    def get_resource_by_vport(self):
        return '/vports/%s/hostinterfaces' % self.create_params['vport_id']

    def post_resource_by_vport(self):
        return self.get_resource_by_vport() + '?responseChoice=1'

    def post_iface_data(self):
        data = {
            "attachedNetworkType": self.extra_params['net_type'],
            "IPAddress": self.extra_params['ipaddress'],
            'IPv6Address': self.extra_params.get('ipaddress_v6'),
            "MAC": self.extra_params['mac'],
            'externalID': get_vsd_external_id(self.extra_params['externalID'])
        }
        return data

    def extra_headers_by_externalid(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers


class NuageBridgeInterface(NuageResource):
    def get_resource(self):
        return '/bridgeinterfaces/%s' % self.create_params['interface_id']

    def delete_resource(self):
        return '/bridgeinterfaces/%s?responseChoice=1' % self.create_params[
            'interface_id']

    def get_resource_by_vport(self):
        return '/vports/%s/bridgeinterfaces' % self.create_params['vport_id']

    def post_resource_by_vport(self):
        return self.get_resource_by_vport()

    def post_iface_data(self):
        data = {
            "attachedNetworkType": self.extra_params['net_type'],
            "name": self.extra_params['name'],
            "externalID": self.extra_params['externalID']
        }
        return data


class NuageRedirectTarget(NuageResource):
    resource = 'redirectiontargets'

    def post_resource_l2dom(self, l2dom_id):
        return '/l2domains/%s/%s' % (l2dom_id, self.resource)

    def post_resource_l3dom(self, l3dom_id):
        return '/domains/%s/%s' % (l3dom_id, self.resource)

    def post_virtual_ip(self, rtarget_id):
        return '/%s/%s/virtualips' % (self.resource, rtarget_id)

    def get_resource_l2dom(self, l2dom_id):
        return '/l2domains/%s/%s' % (l2dom_id, self.resource)

    def get_resource_subnet(self, subnet_id):
        return '/subnets/%s/%s' % (subnet_id, self.resource)

    def get_resource_l3dom(self, l3dom_id):
        return '/domains/%s/%s' % (l3dom_id, self.resource)

    def get_redirect_target(self, rtarget_id):
        return '/%s/%s' % (self.resource, rtarget_id)

    def get_child_resource(self, parent_resource, parent_id):
        return '/%s/%s/%s' % (parent_resource, parent_id, self.resource)

    def get_all_redirect_targets(self):
        return '/%s' % self.resource

    def get_virtual_ip(self, virtual_ip_id):
        return '/virtualips/%s' % virtual_ip_id

    def get_vport_redirect_target(self, vport_id):
        return '/vports/%s/%s' % (vport_id, self.resource)

    def delete_redirect_target(self, rtarget_id):
        return '/%s/%s?responseChoice=1' % (self.resource, rtarget_id)

    def delete_virtual_ip(self, virtual_ip_id):
        return '/virtualips/%s?responseChoice=1' % virtual_ip_id

    def post_rtarget_data(self, params):
        if params.get('description'):
            description = params.get('description')
        else:
            description = params.get('name')
        if params.get('redundancy_enabled', 'false').lower() == "true":
            redundancy = True
        else:
            redundancy = False
        data = {
            'name': params.get('name'),
            'description': description,
            'endPointType': params.get('insertion_mode'),
            'redundancyEnabled': redundancy,
            'externalID': params.get('externalID')
        }
        return data

    def post_virtualip_data(self, vip, vip_port_id):
        data = {
            'virtualIP': vip,
            'externalID': get_vsd_external_id(vip_port_id)
        }
        return data

    def put_vport_data(self, rtarget_id):
        if not rtarget_id:
            data = []
        else:
            data = [rtarget_id]
        return data

    def extra_headers_by_name(self, name):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % name
        return headers

    def extra_headers_by_id(self, rtarget_id):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "id IS '%s'" % rtarget_id
        return headers


class NuageInAdvFwdTemplate(NuageResource):

    def list_resource(self):
        return '/ingressadvfwdtemplates/'

    def get_resource(self, tmplt_id):
        return '/ingressadvfwdtemplates/%s' % tmplt_id

    def get_resource_l2(self, l2dom_id):
        return '/l2domains/%s/ingressadvfwdtemplates' % l2dom_id

    def get_resource_l3(self, l3dom_id):
        return '/domains/%s/ingressadvfwdtemplates' % l3dom_id

    def post_resource_l2(self, l2dom_id):
        return '/l2domains/%s/ingressadvfwdtemplates' % l2dom_id

    def post_resource_l3(self, l3dom_id):
        return '/domains/%s/ingressadvfwdtemplates' % l3dom_id

    def post_data_default_l2(self, name, neutron_subnet_id):
        data = {}
        data['name'] = name + '_def_ibadvfwdl2tmplt'
        data['description'] = 'default Policy'
        data['active'] = True
        data['externalID'] = neutron_subnet_id
        return data

    def post_data_default_l3(self, name, neutron_router_id):
        data = {}
        data['name'] = name + '_def_ibadvfwdl3tmplt'
        data['description'] = 'default Policy'
        data['active'] = True
        data['externalID'] = neutron_router_id
        return data


class NuageAdvFwdRule(NuageResource):
    def in_post_resource(self, policy_id):
        return ("/ingressadvfwdtemplates/%s/ingressadvfwdentrytemplates"
                "?responseChoice=1" % policy_id)

    def in_get_resource(self, rule_id):
        return '/ingressadvfwdentrytemplates/%s' % rule_id

    def in_get_all_resources(self):
        return '/ingressadvfwdentrytemplates/'

    def in_delete_resource(self, rule_id):
        return '/ingressadvfwdentrytemplates/%s?responseChoice=1' % rule_id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % \
                                    get_vsd_external_id(
                                        self.create_params['externalID'])
        return headers

    def extra_headers_get_locationID(self, policygroup_id):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "locationID IS '%s'" % policygroup_id
        return headers


class NuageCms(NuageResource):
    def post_resource(self):
        return '/cms'

    def post_data(self):
        return {"name": self.create_params['name']}

    def get_resource(self):
        return '/cms/%s' % self.create_params['cms_id']


class NuageVIP(NuageResource):
    resource = 'virtualips'

    def get_resource(self):
        return "/virtualips/%s" % self.create_params['vip_id']

    def put_resource(self):
        return "/virtualips/%s?responseChoice=1" % self.create_params['vip_id']

    def delete_resource(self):
        return self.get_resource() + '?responseChoice=1'

    def get_resource_for_vport(self):
        return "/vports/%s/virtualips" % self.create_params['vport_id']

    def get_resource_for_subnet(self):
        return "/subnets/%s/virtualips" % self.create_params['subnet_id']

    def get_child_resource(self, parent_resource, parent_id):
        return '/%s/%s/%s' % (parent_resource, parent_id, self.resource)

    def extra_headers_given_vip(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "virtualIP IS '%s'" % self.extra_params[
            'vip']
        return headers

    def post_vip_data(self):
        data = dict()
        if 'mac' in self.extra_params:
            data['MAC'] = self.extra_params['mac']

        if 'vip' in self.extra_params:
            data['virtualIP'] = self.extra_params['vip']

        if 'fip' in self.extra_params:
            if self.extra_params['fip']:
                data['associatedFloatingIPID'] = self.extra_params['fip']
            else:
                data['associatedFloatingIPID'] = None
        if 'IPType' in self.extra_params:
            data['IPType'] = self.extra_params['IPType']
        if 'externalID' in self.create_params:
            data['externalID'] = self.create_params['externalID']
        return data

    @staticmethod
    def get_ip_addr(vip):
        return vip['virtualIP']

    @staticmethod
    def get_mac_addr(vip):
        return vip['MAC']

    @staticmethod
    def get_vip_id(vip):
        return vip['ID']


@six.add_metaclass(ABCMeta)
class VsdResource(object):
    resource = None

    def get_url(self):
        return '/%s' % self.resource

    def show_url(self):
        return '/%s/%%s' % self.resource

    def post_url(self):
        return self.get_url() + '?responseChoice=1'

    def put_url(self):
        return self.show_url() + '?responseChoice=1'

    def delete_url(self):
        return self.show_url() + '?responseChoice=1'

    def bulk_url(self):
        return self.get_url() + '?responseChoice=1'

    @staticmethod
    def extra_header_filter(**filters):

        def vsd_stringify(filter_value):
            if isinstance(filter_value, six.string_types):
                filter_value = "'%s'" % filter_value
            if filter_value is None:
                filter_value = 'null'
            return filter_value

        values = []
        for field, value in six.iteritems(filters):
            if isinstance(value, list):
                value = ["%s IS %s" % (field,
                                       vsd_stringify(filter_value))
                         for filter_value in value]
                values.append(' OR '.join(value))
            else:
                values.append("%s IS %s" % (field, vsd_stringify(value)))
        filter_string = ' AND '.join(values)
        return {'X-Nuage-FilterType': 'predicate',
                'X-Nuage-Filter': filter_string} if filter_string else None


@six.add_metaclass(ABCMeta)
class VsdChildResource(VsdResource):

    def get_url(self, parent=None, parent_id=None):
        if parent and parent_id:
            return '/%s/%s/%s' % (parent, parent_id, self.resource)
        else:
            return super(VsdChildResource, self).get_url()

    def post_url(self, parent=None, parent_id=None):
        return self.get_url(parent=parent,
                            parent_id=parent_id) + '?responseChoice=1'


class FirewallRule(VsdChildResource):
    resource = 'firewallrules'


class FirewallAcl(VsdChildResource):
    resource = 'firewallacls'

    @classmethod
    def insert_url(cls):
        return cls.show_url() + '/insert?responseChoice=1'

    @classmethod
    def remove_url(cls):
        return cls.show_url() + '/remove?responseChoice=1'

    @classmethod
    def domains_url(cls):
        return cls.show_url() + '/domains?responseChoice=1'


class NuageRateLimiter(VsdResource):
    resource = 'ratelimiters'


class Job(VsdChildResource):
    resource = 'jobs'


class Policygroup(VsdChildResource):
    resource = 'policygroups'


class Trunk(VsdChildResource):
    resource = 'trunks'


class TrunkPort(VsdChildResource):
    resource = 'vports'


class TrunkInterface(VsdChildResource):
    resource = 'vminterfaces'


class Resync(VsdChildResource):
    resource = 'resync'


class VmIpReservation(VsdChildResource):
    resource = 'vmipreservations'

    def delete_url(self, parent=None, parent_id=None, url_parameters=None):
        base = self.get_url(parent=parent,
                            parent_id=parent_id) + '?responseChoice=1'
        if url_parameters:
            return base + '&' + urlencode(url_parameters)
        else:
            return base


class EnterpriseNetwork(VsdChildResource):
    resource = 'enterprisenetworks'


class ACLTemplate(VsdChildResource):

    def __init__(self, direction):
        self.resource = "%sacltemplates" % direction

    @staticmethod
    def post_data(name, external_id, allow_non_ip, priority):
        return {
            'name': name,
            'description': 'default ACL',
            'active': True,
            'defaultAllowNonIp': allow_non_ip,
            'defaultInstallACLImplicitRules': False,
            'externalID': external_id,
            'priority': priority
        }


class ACLEntryTemplate(VsdChildResource):

    def __init__(self, direction):
        self.resource = '%saclentrytemplates' % direction
