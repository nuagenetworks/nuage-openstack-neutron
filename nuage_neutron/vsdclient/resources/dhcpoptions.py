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
    def _get_dhcp_template(ip_version, _value, _length, _type):
        return {
            "value": _value,
            "length": _length,
            "type": DHCP_OPTIONS[ip_version][_type]
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
        ip_version = subnet['ip_version']
        dhcp_options = DHCP_OPTIONS[ip_version]
        # ipv4 and ipv6
        if subnet.get('dns_nameservers'):
            opts_todo.append(dhcp_options['dns_nameservers'])
        # ipv4 only
        if ip_version == 4:
            if subnet.get('host_routes'):
                opts_todo.append(
                    dhcp_options['classless-static-route'])
                opts_todo.append(
                    dhcp_options['microsoft-classless-static-route'])
            if (subnet.get('gateway_ip') and
                    network_type == constants.NETWORK_TYPE_L2):
                opts_todo.append(
                    dhcp_options['gateway_ip'])
        for opt in opts_todo:
            self._create_nuage_dhcp_options(subnet,
                                            parent_id,
                                            network_type,
                                            opt)

    def clear_nuage_dhcp_for_ip_version(self, ip_version, parent_id,
                                        network_type):
        """Function: clear_nuage_dhcp_for_ip_version

        Clears the dhcp options for the specified ip_version on the l2domain
        or l3 subnet.

        :param ip_version: 4 or 6
        :param parent_id: l2domain_id or domainsubnet_id
        :param network_type: NETWORK_TYPE_L2 or NETWORK_TYPE_L3
        :return: None
        """
        nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
        if network_type == constants.NETWORK_TYPE_L2:
            resource = nuage_dhcp_options.resource_by_l2domainid(parent_id)
        else:
            resource = nuage_dhcp_options.resource_by_subnetid(parent_id)
        dhcptions = self.restproxy.get(resource)
        for option in dhcptions:
            self.restproxy.delete(
                nuage_dhcp_options.dhcp_resource(option['ID']))

    def update_nuage_dhcp(self, subnet, parent_id=None,
                          network_type=None):
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
        ip_version = subnet['ip_version']
        dhcp_options = DHCP_OPTIONS[ip_version]
        # ipv4 and ipv6
        if ('dns_nameservers' in subnet and
                not subnet['dns_nameservers']):
            opts_todo.append(dhcp_options['dns_nameservers'])
        # ipv4 only
        if ip_version == 4:
            if ('host_routes' in subnet and
                    not subnet['host_routes']):
                opts_todo.append(
                    dhcp_options['classless-static-route'])
                opts_todo.append(
                    dhcp_options['microsoft-classless-static-route'])
            if ('gateway_ip' in subnet and
                    not subnet['gateway_ip'] and
                    network_type == constants.NETWORK_TYPE_L2):
                opts_todo.append(dhcp_options['gateway_ip'])
        for opt in opts_todo:
            self._delete_nuage_dhcp_option(
                parent_id, network_type, ip_version, opt)
        self.create_nuage_dhcp(subnet, parent_id, network_type)

    def delete_vport_nuage_dhcp(self, dhcp_opt, vport_id):
        """Function:  delete_nuage_extra_dhcp_option

        Delete the nuage DHCP options for the Vports

        dhcp_opt       : DHCP opt to delete from VSD.
        vport_id       : Vport on which to delete the DHCP option.
        """
        LOG.debug('delete nuage dhcp option for resource {}'.format(vport_id))
        ip_version = dhcp_opt['ip_version']
        nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
        dhcp_id = self._check_dhcp_option_exists(
            vport_id, constants.VPORT, ip_version,
            helper.convert_hex_for_vsd(hex(dhcp_opt['opt_name'])))
        resp = self.restproxy.delete(nuage_dhcp_options.dhcp_resource(dhcp_id))
        return resp

    def create_update_extra_dhcp_option_on_vport(self, extra_dhcp_opt,
                                                 parent_id, external_id):
        """Function:  create_update_extra_dhcp_option_on_vport

        Creates/Updates nuage DHCP options on Vport

        extra_dhcp_opt : extra DHCP options details to be configured.
        parent_id      : Vport on which to create the DHCP options.
        external_id    : neutron portID on which we create the DHCP options.
        """
        LOG.debug('Create/Update nuage dhcp option for '
                  'resource {}'.format(parent_id))
        ip_version = extra_dhcp_opt['ip_version']
        option_number = extra_dhcp_opt['opt_name']
        option_value = extra_dhcp_opt['opt_value']

        external_id = cms_id_helper.get_vsd_external_id(external_id)
        length = 0
        opt_value = ""
        dhcp_id = self._check_dhcp_option_exists(
            parent_id, constants.VPORT, ip_version,
            helper.convert_hex_for_vsd(hex(option_number)))
        if option_number in constants.PRCS_DHCP_OPT_AS_RAW_HEX[ip_version]:
            try:
                for value in option_value:
                    val = helper.convert_hex_for_vsd(value)
                    opt_value = opt_value + val
                    length = len(val) + length
            except Exception as e:
                raise e
        if length:
            length = helper.convert_hex_for_vsd(hex(length // 2))
            data = {"length": length}
            opt_type = helper.convert_hex_for_vsd(hex(option_number))
            data['type'] = opt_type
            data["value"] = opt_value
            data["externalID"] = external_id
        else:
            data = self._get_extra_dhcp_template(option_value,
                                                 option_number, external_id)
        return self._set_nuage_dhcp_options(parent_id, ip_version, data,
                                            dhcp_id, constants.VPORT)

    def delete_nuage_extra_dhcp_option(self, dhcp_id, ip_version, on_rollback):
        nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
        try:
            self.restproxy.delete(nuage_dhcp_options.dhcp_resource(dhcp_id))
        except restproxy.RESTProxyError as e:
            if on_rollback:
                e.message = ("Rollback also failed due to the exception: " +
                             e.message)
            raise

    def _create_nuage_dhcp_options(self, subnet, resource_id,
                                   resource_type, dhcp_option):
        """Function:  create_nuage_dhcp_options

        Creates the nuage DHCP options on a l2 only domain and domain/subnet

        subnet        : openstack subnet
        resource_id   : Nuage l2 only domain or dom/subnetID
        resource_type : l2 domain or domain/subnet
        dhcp_option   : Type of the DHCP option
        """
        LOG.debug('_create_nuage_dhcp_options() for resource %s', resource_id)
        ip_version = subnet['ip_version']
        dhcp_options = DHCP_OPTIONS[ip_version]
        dhcp_id = self._check_dhcp_option_exists(resource_id, resource_type,
                                                 ip_version, dhcp_option)

        if dhcp_option == dhcp_options['dns_nameservers']\
                and subnet['dns_nameservers']:
            data = self._get_dns_tmpl(ip_version, subnet['dns_nameservers'])
        elif ip_version == 4:
            if (dhcp_option == dhcp_options[
                    'microsoft-classless-static-route'] and
                    subnet['host_routes']):
                data = self._get_static_rte_tmpl(
                    ip_version,
                    subnet['host_routes'], 'microsoft-classless-static-route')
            elif (dhcp_option == dhcp_options['classless-static-route'] and
                  subnet['host_routes']):
                data = self._get_static_rte_tmpl(
                    ip_version,
                    subnet['host_routes'], 'classless-static-route')
            elif (dhcp_option == dhcp_options['gateway_ip'] and
                  subnet['gateway_ip']):
                data = self._get_gateway_ip_tmpl(
                    ip_version, subnet['gateway_ip'])
            else:
                raise Exception("Unknown DHCPv4 option")
        else:
            raise Exception("Unknown DHCP option")

        data['externalID'] = helper.get_external_id_based_on_subnet_id(subnet)
        self._set_nuage_dhcp_options(resource_id, ip_version, data,
                                     dhcp_id, resource_type)

    def _set_nuage_dhcp_options(self, resource_id, ip_version,
                                data, dhcp_id=False, resource_type=None):
        """Function:  set_nuage_dhcp_options

        Sets the nuage DHCP options on a l2 only domain and subnet/port.

        resource_id   : Nuage l2 only domian or dom/subnetID or VportID
        ip_version    : IP version of the option
        data          : data the user is going to apply as dhcp_option
        dhcp_id       : Nuage DHCP option ID
        l2_dom        : l2 only domain or domain/subnet
        """
        LOG.debug('_set_nuage_dhcp_options() for resource %s', resource_id)
        nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
        if data:
            if dhcp_id:
                # dhcp option already set for this l2domain. We do a PUT
                # operation with the new data
                del data["externalID"]
                return self.restproxy.put(
                    nuage_dhcp_options.dhcp_resource(dhcp_id),
                    data)
            else:
                if resource_type == constants.VPORT:
                    # POST the dhcp options for the Vport
                    return self.restproxy.post(
                        nuage_dhcp_options.resource_by_vportid(resource_id),
                        data)
                elif resource_type == constants.NETWORK_TYPE_L2:
                    # POST the dhcp options for the l2only domain
                    return self.restproxy.post(
                        nuage_dhcp_options.resource_by_l2domainid(resource_id),
                        data)
                else:
                    # POST the dhcp options for the domain/subnet
                    return self.restproxy.post(
                        nuage_dhcp_options.resource_by_subnetid(resource_id),
                        data)
        elif resource_type != constants.VPORT:
            return self.restproxy.delete(
                nuage_dhcp_options.dhcp_resource(dhcp_id))

    def _delete_nuage_dhcp_option(self, subnet_id, isl2dom, ip_version,
                                  dhcp_type):
        """Function:  _delete_nuage_dhcp_option

        Deletes the nuage DHCP options on a l2 only doamain and domain/subnet

        subnet_id     : Nuage l2 only domian or dom/subnet ID
        isl2dom       : l2 only domain or domain/subnet
        ip_version    : IP version of the option
        dhcp_type     : Type of the DHCP option
        """
        LOG.debug('_delete_nuage_dhcp_option() called for subnet %s '
                  'dhcp_type %s', subnet_id, dhcp_type)
        # Check if the dhcp options exists of type dhcp_type on this l2/l3
        # subnet
        dhcp_id = self._check_dhcp_option_exists(subnet_id, isl2dom,
                                                 ip_version, dhcp_type)
        if dhcp_id:
            nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
            self.restproxy.delete(nuage_dhcp_options.dhcp_resource(dhcp_id))

    def _check_dhcp_option_exists(self, resource_id, resource_type,
                                  ip_version, dhcp_type):
        """Function:  _check_dhcp_option_exists

        Check if the dhcp option exists

        resource_id: vsd-id of the resource
        resource_type  : If the resource is a l2/l3/vport
        ip_version     : IP version of the option
        dhcp_type     : Type of the DHCP option
        """
        LOG.debug('_check_dhcp_option_exists() for resource %s', resource_id)
        nuage_dhcp_options = nuagelib.NuageDhcpOptions(ip_version)
        if resource_type == constants.VPORT:
            dhcp_options = self.restproxy.get(
                nuage_dhcp_options.resource_by_vportid(resource_id))
        elif resource_type == constants.NETWORK_TYPE_L2:
            dhcp_options = self.restproxy.get(
                nuage_dhcp_options.resource_by_l2domainid(resource_id))
        else:
            dhcp_options = self.restproxy.get(
                nuage_dhcp_options.resource_by_subnetid(resource_id))
        return NuageDhcpOptions._is_option_already_present(dhcp_options,
                                                           dhcp_type)

    @staticmethod
    def _is_option_already_present(dhcpoptions, dhcp_type):
        # we need to verify that there is a same option already present.
        for dhcp_item in dhcpoptions:
            if dhcp_item['type'] == dhcp_type:
                return dhcp_item['ID']
        return None

    def _get_dns_tmpl(self, ip_version, dns_list):
        _dns_length = format(4 * len(dns_list), '02x')
        _dns = ""
        for dns_item in dns_list:
            _dns = _dns + self.get_ip_hex_value(netaddr.IPNetwork(dns_item).ip)
        return NuageDhcpOptions._get_dhcp_template(
            ip_version, _dns, _dns_length, 'dns_nameservers')

    # TODO(team): Will move this util function to common utils
    @staticmethod
    def get_ip_hex_value(ip):
        return str(hex(ip)[2:]).zfill(8)

    def _get_static_rte_tmpl(self, ip_version,
                             static_routes, static_route_type):
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
        return NuageDhcpOptions._get_dhcp_template(
            ip_version, _data, _length, static_route_type)

    def _get_gateway_ip_tmpl(self, ip_version, gateway_ip):
        _length = format(4, '02x')
        _ip = netaddr.IPAddress(gateway_ip)
        _data = self.get_ip_hex_value(_ip)
        return NuageDhcpOptions._get_dhcp_template(
            ip_version, _data, _length, 'gateway_ip')
