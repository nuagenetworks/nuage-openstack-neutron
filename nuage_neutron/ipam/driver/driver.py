# Copyright 2018 NOKIA
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

from neutron.ipam.drivers.neutrondb_ipam.driver import NeutronDbPool
from neutron.ipam.requests import AddressRequestFactory
from neutron.ipam.requests import PreferNextAddressRequest

from nuage_neutron.plugins.common import constants


class NuageAddressRequestFactory(AddressRequestFactory):

    @classmethod
    def get_request(cls, context, port, ip_dict):
        """Builds request using ip info

        :param context: context (not used here, but can be used in sub-classes)
        :param port: port dict (not used here, but can be used in sub-classes)
        :param ip_dict: dict that can contain 'ip_address', 'mac' and
            'subnet_cidr' keys. Request to generate is selected depending on
             this ip_dict keys.
        :return: returns prepared AddressRequest (specific or any)
        """

        if (port['device_owner'] == constants.DEVICE_OWNER_DHCP_NUAGE and
                not ip_dict.get('ip_address')):  # OPENSTACK-2593
            return PreferNextAddressRequest()
        else:
            return super(NuageAddressRequestFactory, cls).get_request(
                context, port, ip_dict)


class NuageNeutronDbPool(NeutronDbPool):
    """Subnet pools backed by Neutron Database.

    As this driver does not implement yet the subnet pool concept, most
    operations are either trivial or no-ops.
    """

    def get_address_request_factory(self):
        """Returns default NuageAddressRequestFactory

        """
        return NuageAddressRequestFactory
