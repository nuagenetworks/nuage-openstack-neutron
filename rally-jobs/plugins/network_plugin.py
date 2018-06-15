# Copyright 2014: Intel Inc.
# All Rights Reserved.
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
#

from rally.task import atomic
from rally.task import validation
from rally_openstack import consts
from rally_openstack import scenario
from rally_openstack.scenarios.neutron import utils
from rally_openstack.wrappers import network as network_wrapper


@validation.add("required_services", services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_networks")
class CreateNetwork(utils.NeutronScenario):
    """Benchmark scenarios for Neutron."""

    def run(self, network_create_args=None):
        """Create a network.

        Measure the "neutron net-create" command performance.

        If you have only 1 user in your context, you will
        add 1 network on every iteration.

        :param network_create_args: dict, POST /v2.0/networks request options
        """
        self._create_network(network_create_args or {})


@validation.add("number", param_name="subnets_per_network",
                minval=1, integer_only=True)
@validation.add("required_services", services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_subnets")
class CreateSubnets(utils.NeutronScenario):
    def run(self,
            network_create_args=None,
            subnet_create_args=None,
            subnet_cidr_start=None,
            subnets_per_network=None):
        """Create a given number of subnets.

        The scenario creates a network and a given number of subnets.

        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        """
        network = self._get_or_create_network(network_create_args)
        self._create_subnets(network, subnet_create_args, subnet_cidr_start,
                             subnets_per_network)


@validation.add("number", param_name="subnets_per_network",
                minval=1, integer_only=True)
@validation.add("required_services", services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_subnets_routers_interfaces")
class CreateSubnetsRoutersInterfaces(utils.NeutronScenario):
    def run(self,
            network_create_args=None,
            subnet_create_args=None,
            subnet_cidr_start=None,
            subnets_per_network=None,
            router_create_args=None):
        """Create a network, a given number of subnets and routers.

        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated.
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        :param router_create_args: dict, POST /v2.0/routers request options
        """
        self._create_network_structure(network_create_args, subnet_create_args,
                                       subnet_cidr_start, subnets_per_network,
                                       router_create_args)


@validation.add("number", param_name="routers_per_subnet",
                minval=1, integer_only=True)
@validation.add("required_services", services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_routers")
class CreateRouters(utils.NeutronScenario):
    def run(self,
            network_create_args=None,
            routers_per_subnet=None,
            router_create_args=None,
            port_create_args=None):
        """Create a given number of ports and routers.

        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated.
        :param routers_per_subnet: int, number of routers for one subnet
        :param router_create_args: dict, POST /v2.0/routers request options
        :param port_create_args: dict, POST /v2.0/ports request options
        """

        network = self._get_or_create_network(network_create_args)
        for i in range(routers_per_subnet):
            router = self._create_router(router_create_args or {})
            port = self._create_port(network, port_create_args or {})
            self._add_interface_router_port(router, port)

    @atomic.action_timer("neutron.add_interface_router_port")
    def _add_interface_router_port(self, router, port):
        self.clients("neutron").add_interface_router(
            router["router"]["id"], {"port_id": port["port"]["id"]})


@validation.add("number", param_name="ports_per_network",
                minval=1, integer_only=True)
@validation.add("required_services", services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_ports")
class CreatePorts(utils.NeutronScenario):
    def run(self,
            network_create_args=None,
            port_create_args=None,
            ports_per_network=None):
        """Create a given number of ports.

        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated.
        :param port_create_args: dict, POST /v2.0/ports request options
        :param ports_per_network: int, number of ports for one network
        """
        network = self._get_or_create_network(network_create_args)
        for i in range(ports_per_network):
            self._create_port(network, port_create_args or {})


@validation.add("required_services",
                services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_and_list_dualstack_subnets",
                    platform="openstack")
class CreateAndListDualStackSubnets(utils.NeutronScenario):

    SUBNET_IP_VERSION = 4
    SUBNET_IP_VERSION_v4 = 4
    SUBNET_IP_VERSION_v6 = 6

    @atomic.action_timer("neutron.create_subnet")
    def _create_subnet(self, network, subnet_create_args, start_cidr=None,
                       ip_version=4):
        """Create neutron subnet.

        :param network: neutron network dict
        :param subnet_create_args: POST /v2.0/subnets request options
        :returns: neutron subnet dict
        """
        network_id = network["network"]["id"]

        if not subnet_create_args.get("cidr"):
            if ip_version == 4:
                start_cidr = start_cidr or "10.2.0.0/24"
                subnet_create_args["cidr"] = (
                    network_wrapper.generate_cidr(start_cidr=start_cidr))
                subnet_create_args.setdefault("ip_version",
                                              self.SUBNET_IP_VERSION_v4)
            elif ip_version == 6:
                start_cidr = (start_cidr or
                              "1504:40db:0000:0000:0000:0000:0000:0001/64")
                subnet_create_args["cidr"] = (
                    network_wrapper.generate_cidr(start_cidr=start_cidr))
                subnet_create_args.setdefault("ip_version",
                                              self.SUBNET_IP_VERSION_v6)
        subnet_create_args["network_id"] = network_id
        subnet_create_args["name"] = self.generate_random_name()
        return self.clients("neutron").create_subnet(
            {"subnet": subnet_create_args})

    def _create_subnets(self, network,
                        subnet_create_args=None,
                        subnet_cidr_start=None,
                        subnets_per_network=1,
                        ip_version=4):
        """Create <count> new subnets in the given network.

        :param network: network to create subnets in
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        :returns: List of subnet dicts
        """
        return [self._create_subnet(network, subnet_create_args or {},
                                    subnet_cidr_start, ip_version)
                for i in range(subnets_per_network)]

    def run(self, network_create_args=None, subnet_create_args=None,
            subnetv4_cidr_start=None, subnetv6_cidr_start=None,
            subnets_per_network=1):
        """Create and a given number of subnets and list all subnets.

        The scenario creates a network, a given number of subnets and then
        lists subnets.
        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        """
        network = self._create_network(network_create_args or {})
        ip_version = 6
        self._create_subnets(network, subnet_create_args, subnetv6_cidr_start,
                             subnets_per_network, ip_version)
        ip_version = 4
        self._create_subnets(network, subnet_create_args, subnetv4_cidr_start,
                             subnets_per_network, ip_version)
        self._list_subnets()


@validation.add("required_services",
                services=[consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NetworkPlugin.create_and_delete_dualstack_subnets",
                    platform="openstack")
class CreateAndDeleteDualStackSubnets(utils.NeutronScenario):

    SUBNET_IP_VERSION = 4
    SUBNET_IP_VERSION_v4 = 4
    SUBNET_IP_VERSION_v6 = 6

    @atomic.action_timer("neutron.create_subnet")
    def _create_subnet(self, network, subnet_create_args, start_cidr=None,
                       ip_version=4):
        """Create neutron subnet.

        :param network: neutron network dict
        :param subnet_create_args: POST /v2.0/subnets request options
        :returns: neutron subnet dict
        """
        network_id = network["network"]["id"]

        if not subnet_create_args.get("cidr"):
            if ip_version == 4:
                start_cidr = start_cidr or "10.2.0.0/24"
                subnet_create_args["cidr"] = (
                    network_wrapper.generate_cidr(start_cidr=start_cidr))
                subnet_create_args.setdefault("ip_version",
                                              self.SUBNET_IP_VERSION_v4)
            elif ip_version == 6:
                start_cidr = (start_cidr or
                              "1504:40db:0000:0000:0000:0000:0000:0001/64")
                subnet_create_args["cidr"] = (
                    network_wrapper.generate_cidr(start_cidr=start_cidr))
                subnet_create_args.setdefault("ip_version",
                                              self.SUBNET_IP_VERSION_v6)
        subnet_create_args["network_id"] = network_id
        subnet_create_args["name"] = self.generate_random_name()
        return self.clients("neutron").create_subnet(
            {"subnet": subnet_create_args})

    def _create_subnets(self, network,
                        subnet_create_args=None,
                        subnet_cidr_start=None,
                        subnets_per_network=1,
                        ip_version=4):
        """Create <count> new subnets in the given network.

        :param network: network to create subnets in
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        :returns: List of subnet dicts
        """
        return [self._create_subnet(network, subnet_create_args or {},
                                    subnet_cidr_start, ip_version)
                for i in range(subnets_per_network)]

    def run(self, network_create_args=None, subnet_create_args=None,
            subnetv4_cidr_start=None, subnetv6_cidr_start=None,
            subnets_per_network=1):
        """Create and a given number of subnets and list all subnets.

        The scenario creates a network, a given number of subnets and then
        lists subnets.
        :param network_create_args: dict, POST /v2.0/networks request
                                    options. Deprecated
        :param subnet_create_args: dict, POST /v2.0/subnets request options
        :param subnet_cidr_start: str, start value for subnets CIDR
        :param subnets_per_network: int, number of subnets for one network
        """
        network = self._create_network(network_create_args or {})
        ip_version = 6
        subnetsv4 = self._create_subnets(network, subnet_create_args,
                                         subnetv6_cidr_start,
                                         subnets_per_network,
                                         ip_version)
        ip_version = 4
        subnetsv6 = self._create_subnets(network, subnet_create_args,
                                         subnetv4_cidr_start,
                                         subnets_per_network,
                                         ip_version)
        for subnet in subnetsv4:
            self._delete_subnet(subnet)

        for subnet in subnetsv6:
            self._delete_subnet(subnet)
