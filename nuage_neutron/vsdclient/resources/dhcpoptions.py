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

from nuage_neutron.vsdclient.common import cms_id_helper
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

DHCP_OPTIONS = constants.DHCP_OPTIONS
LOG = logging.getLogger(__name__)


class NuageDhcpOptions(object):
    def __init__(self, restproxy_server):
        self.restproxy = restproxy_server

    @staticmethod
    def _get_dhcp_template(_value, _length, _type):
        return {
            "value": _value,
            "length": _length,
            "type": DHCP_OPTIONS[_type],
        }

    @staticmethod
    def _get_extra_dhcp_template(_value, _type, _external_id):
        return {
            "actualValues": _value,
            "actualType": _type,
            "externalID": _external_id
        }

    def create_nuage_dhcp(self, subnet, parent_id=None, network_type=None):
        """Function:  create_nuage_dhcp

        Creates the nuage DHCP options on a l2 only domain and domain/subnet

        subnet         : neutron subnet on which to create the dhcpoptions
        parent_id      : Nuage l2 only domain or dom/subnet ID
        network_type   : l2 only domain or domain/subnet
        """
        LOG.debug('create_nuage_dhcp() for resource %s '
                  'network type %s', parent_id, network_type)

        opts_todo = []
        if subnet.get('dns_nameservers'):
            opts_todo.append(DHCP_OPTIONS['dns_nameservers'])
        if subnet.get('host_routes'):
            opts_todo.append(DHCP_OPTIONS['classless-static-route'])
            opts_todo.append(DHCP_OPTIONS['microsoft-classless-static-route'])
        if (subnet.get('gateway_ip') and
                network_type == constants.NETWORK_TYPE_L2):
            opts_todo.append(DHCP_OPTIONS['gateway_ip'])
        for opt in opts_todo:
            self._create_nuage_dhcp_options(subnet,
                                            parent_id,
                                            network_type,
                                            opt)

    def update_nuage_dhcp(self, subnet, parent_id=None, network_type=None):
        """Function:  update_nuage_dhcp

        Update the nuage DHCP options on a l2 only domain and domain/subnet

        subnet         : neutron subnet on which to updates the dhcpoptions
        parent_id      : Nuage l2 only domain or dom/subnet ID
        network_type   : l2 only domain or domain/subnet
        """
        LOG.debug('update_nuage_dhcp() for resource %s '
                  'network type %s', parent_id, network_type)
        """
        In case of update, we need to delete the objects
        only if the subnet has them as empty list otherwise
        let create method take care of rest.
        """
        opts_todo = []
        if ('dns_nameservers' in subnet and
                not subnet['dns_nameservers']):
            opts_todo.append(DHCP_OPTIONS['dns_nameservers'])
        if ('host_routes' in subnet and
                not subnet['host_routes']):
            opts_todo.append(DHCP_OPTIONS['classless-static-route'])
            opts_todo.append(DHCP_OPTIONS['microsoft-classless-static-route'])
        if ('gateway_ip' in subnet and
                not subnet['gateway_ip'] and
                network_type == constants.NETWORK_TYPE_L2):
            opts_todo.append(DHCP_OPTIONS['gateway_ip'])
        for opt in opts_todo:
            self._delete_nuage_dhcp_option(parent_id,
                                           network_type,
                                           opt)
        self.create_nuage_dhcp(subnet, parent_id, network_type)

    def nuage_extra_dhcp_option(self, extra_dhcp_opt, parent_id, external_id):
        """Function:  nuage_extra_dhcp_option

        Creates/Updates the nuage DHCP options for the Vports

        extra_dhcp_opt : extra DHCP options details to be configured.
        external_id    : neutron portID on which we create the DHCP options.
        parent_id      : Vport on which to create the DHCP options.
        resp           : Contains response from VSD for the DHCP options.
        """
        LOG.debug('Create/Update nuage dhcp option for resource %s '
                  '', parent_id)
        nuage_dhcpoptions = nuagelib.NuageDhcpOptions()
        external_id = cms_id_helper.get_vsd_external_id(external_id)
        option_number = extra_dhcp_opt['opt_name']
        option_value = extra_dhcp_opt['opt_value']
        length = 0
        opt_value = ""
        dhcp_id = self._check_dhcpoption_exists(parent_id,
                                                constants.VPORT,
                                                helper.
                                                convert_to_hex(hex(
                                                    option_number)))
        if option_number in constants.PRCS_DHCP_OPT_AS_RAW_HEX:
            try:
                for value in option_value:
                    val = helper.convert_to_hex(value)
                    opt_value = opt_value + val
                    length = len(val) + length
            except Exception as e:
                raise e
        if length:
            length = helper.convert_to_hex(hex(length / 2))
            data = {"length": length}
            type = helper.convert_to_hex(hex(option_number))
            data['type'] = type
            data["value"] = opt_value
            data["externalID"] = external_id
        else:
            data = self._get_extra_dhcp_template(option_value,
                                                 option_number, external_id)
        resp = self._set_nuage_dhcp_options(parent_id, data,
                                            dhcp_id, constants.VPORT)
        if not nuage_dhcpoptions.validate(resp):
            if (nuage_dhcpoptions.vsd_error_code !=
                    constants.VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE):
                raise restproxy.RESTProxyError(nuage_dhcpoptions.error_msg)
            return data
        return resp

    def delete_nuage_extra_dhcp_option(self, dhcp_id, on_rollback):
        nuage_dhcpoptions = nuagelib.NuageDhcpOptions()
        resp = self.restproxy.rest_call('DELETE',
                                        nuage_dhcpoptions.
                                        dhcp_resource(dhcp_id), '')
        if not nuage_dhcpoptions.validate(resp):
            if on_rollback:
                raise restproxy.RESTProxyError("Rollback also failed due to "
                                               "the exception: " +
                                               nuage_dhcpoptions.error_msg)
            else:
                raise restproxy.RESTProxyError(nuage_dhcpoptions.error_msg)

    def _create_nuage_dhcp_options(self, subnet, _resource_id, type,
                                   _dhcp_option):
        """Function:  create_nuage_dhcp_options

        Creates the nuage DHCP options on a l2 only doamain and domain/subnet

        restproxy_serv: restproxy server instance
        _resource_id  : Nuage l2 only domian or dom/subnetID
        type          : l2 only domain or domain/subnet
        _dhcp_option  : Type of the DHCP option
        """
        LOG.debug('_create_nuage_dhcp_options() for resource %s', _resource_id)
        dhcp_id = self._check_dhcpoption_exists(_resource_id, type,
                                                _dhcp_option)

        if _dhcp_option == DHCP_OPTIONS['dns_nameservers']\
                and subnet['dns_nameservers']:
            _data = self._get_dns_tmpl(subnet['dns_nameservers'])
        elif _dhcp_option == DHCP_OPTIONS['microsoft-classless-static-route']\
                and subnet['host_routes']:
            _data = self._get_static_rte_tmpl(
                subnet['host_routes'],
                'microsoft-classless-static-route')
        elif _dhcp_option == DHCP_OPTIONS['classless-static-route']\
                and subnet['host_routes']:
            _data = self._get_static_rte_tmpl(subnet['host_routes'],
                                              'classless-static-route')
        elif _dhcp_option == DHCP_OPTIONS['gateway_ip']\
                and subnet['gateway_ip']:
            _data = self._get_gateway_ip_tmpl(subnet['gateway_ip'])
        else:
            raise Exception("Unknown DHCP option")
        _data['externalID'] = cms_id_helper.get_vsd_external_id(subnet['id'])
        resp = self._set_nuage_dhcp_options(_resource_id, _data,
                                            dhcp_id, type)

        if resp[0] not in (self.restproxy.success_codes + [409]):
            raise restproxy.RESTProxyError(str(resp[2]))

    def _set_nuage_dhcp_options(self, resource_id,
                                data, dhcp_id=False, resource_type=None):
        """Function:  set_nuage_dhcpoptions

        Sets the nuage DHCP options on a l2 only domain and subnet/port.

        restproxy_serv: restproxy server instance
        resource_id   : Nuage l2 only domian or dom/subnetID or VportID
        data          : data the user is going to apply as dhcpoption
        dhcp_id       : Nuage DHCP option ID
        l2_dom        : l2 only domain or domain/subnet
        """
        LOG.debug('_set_nuage_dhcpoptions() for resource %s', resource_id)
        nuage_dhcpoptions = nuagelib.NuageDhcpOptions()
        if data:
            if dhcp_id:
                # dhcpoptions already set for this l2domain. We do a PUT
                # operation with the new data
                del data["externalID"]
                return self.restproxy.rest_call(
                    'PUT', nuage_dhcpoptions.dhcp_resource(dhcp_id), data)
            else:
                if resource_type == constants.VPORT:
                    # POST the dhcpoptions for the Vport
                    return self.restproxy.rest_call(
                        'POST', nuage_dhcpoptions.resource_by_vportid(
                            resource_id), data)
                elif resource_type == constants.NETWORK_TYPE_L2:
                    # POST the dhcpoptions for the l2only domain
                    return self.restproxy.rest_call(
                        'POST', nuage_dhcpoptions.resource_by_l2domainid(
                            resource_id),
                        data)
                else:
                    # POST the dhcpoptions for the domain/subnet
                    return self.restproxy.rest_call(
                        'POST', nuage_dhcpoptions.resource_by_subnetid(
                            resource_id),
                        data)
        elif resource_type != constants.VPORT:
            return self.restproxy.rest_call(
                'DELETE', nuage_dhcpoptions.dhcp_resource(dhcp_id), '')

    def _delete_nuage_dhcp_option(self, subnet_id, isl2dom, dhcp_type):
        """Function:  _delete_nuage_dhcp_option

        Deletes the nuage DHCP options on a l2 only doamain and domain/subnet

        restproxy_serv: restproxy server instance
        subnet_id     : Nuage l2 only domian or dom/subnet ID
        isl2dom       : l2 only domain or domain/subnet
        dhcp_type     : Type of the DHCP option
        """
        LOG.debug('_delete_nuage_dhcp_option() called for subnet %s '
                  'dhcp_type %s', subnet_id, dhcp_type)
        # Check if the dhcpoptions exists of type dhcp_type on this l2/l3
        # subnet
        dhcp_id = self._check_dhcpoption_exists(subnet_id, isl2dom,
                                                dhcp_type)
        if dhcp_id:
            nuage_dhcpoptions = nuagelib.NuageDhcpOptions()
            resp = self.restproxy.rest_call(
                'DELETE', nuage_dhcpoptions.dhcp_resource(dhcp_id), '')
            if not nuage_dhcpoptions.validate(resp):
                raise restproxy.RESTProxyError(nuage_dhcpoptions.error_msg)

    def _check_dhcpoption_exists(self, resource_id, resource_type, dhcp_type):
        """Function:  _check_dhcpoption_exists

        Check if the dhcpoption exists

        restproxy_serv: restproxy server instance
        resource_id: vsd-id of the resource
        resource_type  : If the resource is a l2/l3/vport
        dhcp_type     : Type of the DHCP option
        """
        LOG.debug('_check_dhcpoption_exists() for resource %s', resource_id)
        nuage_dhcpoptions = nuagelib.NuageDhcpOptions()
        if resource_type == constants.VPORT:
            resp = self.restproxy.rest_call(
                'GET', nuage_dhcpoptions.resource_by_vportid(
                    resource_id), '')
            return NuageDhcpOptions._is_option_already_present(resp, dhcp_type)
        elif resource_type == constants.NETWORK_TYPE_L2:
            resp = self.restproxy.rest_call(
                'GET', nuage_dhcpoptions.resource_by_l2domainid(
                    resource_id), '')
            return NuageDhcpOptions._is_option_already_present(resp, dhcp_type)
        else:
            resp = self.restproxy.rest_call(
                'GET', nuage_dhcpoptions.resource_by_subnetid(
                    resource_id), '')
            return NuageDhcpOptions._is_option_already_present(resp, dhcp_type)

    @staticmethod
    def _is_option_already_present(resp, dhcp_type):
        if resp[3]:
            # we need to verify that there is a same option already present.
            for dhcp_item in resp[3]:
                if dhcp_item['type'] == dhcp_type:
                    return dhcp_item['ID']

    def _get_dns_tmpl(self, dns_list):
        _dns_length = format(4 * len(dns_list), '02x')
        _dns = ""
        for dns_item in dns_list:
            _dns = _dns + self.get_ip_hex_value(netaddr.IPNetwork(dns_item).ip)
        return NuageDhcpOptions._get_dhcp_template(_dns, _dns_length,
                                                   'dns_nameservers')

    # TODO(team): Will move this util function to common utils
    def get_ip_hex_value(self, ip):
        return str(hex(ip)[2:]).zfill(8)

    def _get_static_rte_tmpl(self, static_routes, static_route_type):
        # minimum is 5, multiplied by the number of routes
        _length_d = len(static_routes) * 5
        _data = ""
        for static_route in static_routes:
            _ip = netaddr.IPNetwork(static_route['destination'])
            # length of the subnet
            _netmask_length = \
                sum([1 for a in str(_ip.netmask).split('.') if int(a) > 0])
            _length_d = _length_d + _netmask_length
            cidr_prefix = format(_ip.prefixlen, '02x')
            # need to do that to get the correction padding for length
            cidr_ip = self.get_ip_hex_value(_ip.ip)[:_netmask_length * 2]
            _ip = netaddr.IPAddress(static_route['nexthop'])
            nexthop_ip = self.get_ip_hex_value(_ip)
            _data += "%s%s%s" % (cidr_prefix, cidr_ip, nexthop_ip)
        _length = format(_length_d, '02x')
        return NuageDhcpOptions._get_dhcp_template(_data, _length,
                                                   static_route_type)

    def _get_gateway_ip_tmpl(self, gateway_ip):
        _length = format(4, '02x')
        _ip = netaddr.IPAddress(gateway_ip)
        _data = self.get_ip_hex_value(_ip)
        return NuageDhcpOptions._get_dhcp_template(_data, _length,
                                                   'gateway_ip')
