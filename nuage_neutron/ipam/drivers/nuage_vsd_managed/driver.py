# Copyright 2019 NOKIA
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
import netaddr
from sqlalchemy import event

from neutron.db.db_base_plugin_v2 import NeutronDbPluginV2
from neutron.ipam.drivers.neutrondb_ipam import driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron_lib import constants as n_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_log import log

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils
from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient import restproxy

LOG = log.getLogger(__name__)


class NuageIpamSubnet(driver.NeutronDbSubnet):

    def allocate(self, address_request):
        # NOTE(pbondar): Ipam driver is always called in context of already
        # running transaction, which is started on create_port or upper level.
        # To be able to do rollback/retry actions correctly ipam driver
        # should not create new nested transaction blocks.
        if isinstance(address_request, TransparentSpecificAddressrequest):
            return super(NuageIpamSubnet, self).allocate(
                ipam_req.SpecificAddressRequest(address_request.address))
        if isinstance(address_request, TransparentPreferNextAddressRequest):
            return super(NuageIpamSubnet, self).allocate(
                ipam_req.PreferNextAddressRequest())

        subnet_mapping = self._get_subnet_mapping()
        if not subnet_mapping:
            raise n_exc.BadRequest(resource='ipam',
                                   msg='Unable to find vsd subnet '
                                       'for requested ip allocation')
        is_l2 = utils.SubnetUtilsBase._is_l2(subnet_mapping)
        nuage_parent_id = subnet_mapping['nuage_subnet_id']
        vsdclient = self._get_vsdclient()
        ip_address = None
        max_retries = 5
        nr_retries = 0
        while not ip_address and nr_retries < max_retries:
            try:
                ip_address = self.create_vmipreservation(address_request,
                                                         vsdclient, is_l2,
                                                         nuage_parent_id)
                if not ip_address:
                    reason = "Unable to reserve IP on VSD"
                    raise ipam_exc.InvalidAddressRequest(reason=reason)
                break
            except restproxy.ResourceNotFoundException:
                # l2domain or l3domain not found, due to router attach may have
                # moved.
                nr_retries += 1
                if nr_retries < max_retries:
                    LOG.debug('Could not find VSD Domain/Subnet. '
                              'Retrying {}/{}.'.format(nr_retries,
                                                       max_retries))
                    # Find on VSD parent based on reverse of is_l2, as we
                    # assume router-attach/detach scenario
                    is_l2 = not is_l2
                    try:
                        nuage_parent_id = self._get_nuage_id_from_vsd(
                            vsdclient, is_l2)
                    except restproxy.ResourceNotFoundException:
                        pass
                else:
                    LOG.debug('Could not find VSD Domain/Subnet after '
                              'retrying {}/{} times.'.format(nr_retries,
                                                             max_retries))
                    raise

        # Create IP allocation request object
        # The only defined status at this stage is 'ALLOCATED'.
        # More states will be available in the future - e.g.: RECYCLABLE
        try:
            with self._context.session.begin(subtransactions=True):
                # NOTE(kevinbenton): we use a subtransaction to force
                # a flush here so we can capture DBReferenceErrors due
                # to concurrent subnet deletions. (galera would deadlock
                # later on final commit)
                self.subnet_manager.create_allocation(self._context,
                                                      ip_address)
        except db_exc.DBReferenceError:
            raise n_exc.SubnetNotFound(
                subnet_id=self.subnet_manager.neutron_id)
        return ip_address

    def create_vmipreservation(self, address_request, vsdclient,
                               is_l2, nuage_id):
        ip_type = self._get_ip_type()
        try:
            ipv4_address = ipv6_address = None
            if isinstance(address_request, ipam_req.SpecificAddressRequest):
                # This handles both specific and automatic address requests
                # Check availability of requested IP
                ip_address = str(address_request.address)
                self._verify_ip(self._context, ip_address)
                if ip_type == 'IPV4':
                    ipv4_address = ip_address
                else:
                    ipv6_address = ip_address

                vsdclient.create_vm_ip_reservation(
                    is_l2, nuage_id, ip_type=ip_type,
                    ipv4_address=ipv4_address, ipv6_address=ipv6_address)

            else:
                # Calculate allocation pools
                allocation_pools = self.subnet_manager.list_pools(
                    self._context)
                ipreservation = vsdclient.create_vm_ip_reservation(
                    is_l2, nuage_id, ip_type=ip_type,
                    allocation_pools=allocation_pools)
                if ip_type == 'IPV4':
                    ipv4_address = ip_address = ipreservation['ipv4_address']
                else:
                    ipv4_address = ip_address = ipreservation['ipv6_address']
        except restproxy.RESTProxyError as e:
            if e.vsd_code == vsd_constants.VSD_DUPLICATE_VMIPRESERVATION:
                reason = ('The requested ip address is already reserved '
                          'on VSD by another entity.')
                raise ipam_exc.InvalidAddressRequest(reason=reason)
            if e.vsd_code == vsd_constants.VSD_SUBNET_FULL:
                raise ipam_exc.IpAddressGenerationFailure(
                    subnet_id=self._subnet_id)
            elif e.vsd_code == vsd_constants.VSD_IP_IN_USE_ERR_CODE:
                raise ipam_exc.InvalidAddressRequest(reason=str(e))
            raise

        def rollback(db_api_conn):
            vsdclient.delete_vm_ip_reservation(
                is_l2, nuage_id,
                ipv4_address, ipv6_address)

        event.listen(self._context.session, "after_rollback", rollback)
        return ip_address

    def deallocate(self, address):
        super(NuageIpamSubnet, self).deallocate(address)

        subnet_mapping = self._get_subnet_mapping()
        if not subnet_mapping:
            # No VSD subnet connected
            return

        vsdclient = self._get_vsdclient()

        is_l2 = utils.SubnetUtilsBase._is_l2(subnet_mapping)

        ip_type = self._get_ip_type()
        ipv4_address = ipv6_address = None
        if ip_type == 'IPV4':
            ipv4_address = address
        else:
            ipv6_address = address

        vsdclient.delete_vm_ip_reservation(
            is_l2, subnet_mapping['nuage_subnet_id'],
            ipv4_address, ipv6_address)

        def rollback(db_api_conn):
            try:
                existing_reservation = vsdclient.get_vm_ip_reservation(
                    is_l2, subnet_mapping['nuage_subnet_id'],
                    ipv4_address, ipv6_address
                )
                if existing_reservation:
                    vsdclient.update_vm_ip_reservation_state(
                        existing_reservation['ID'], target_state='ASSIGNED')
                else:
                    vsdclient.create_vm_ip_reservation(
                        is_l2, subnet_mapping['nuage_subnet_id'],
                        ip_type, ipv4_address, ipv6_address)
            except restproxy.ResourceNotFoundException:
                # Retry during router attach/detach to find l2domain/subnet
                nuage_parent_id = self._get_nuage_id_from_vsd(
                    vsdclient, not is_l2)
                existing_reservation = vsdclient.get_vm_ip_reservation(
                    not is_l2, nuage_parent_id,
                    ipv4_address, ipv6_address
                )
                if existing_reservation:
                    vsdclient.update_vm_ip_reservation_state(
                        existing_reservation['ID'], target_state='ASSIGNED')
                else:
                    vsdclient.create_vm_ip_reservation(
                        is_l2, subnet_mapping['nuage_subnet_id'],
                        ip_type, ipv4_address, ipv6_address)

        event.listen(self._context.session, "after_rollback", rollback)

    @staticmethod
    def _get_vsdclient():
        nuage_mech_drivers = [
            x for x in
            directory.get_plugin().mechanism_manager.ordered_mech_drivers
            if x.name == constants.NUAGE_ML2_DRIVER_NAME]
        if not nuage_mech_drivers:
            raise n_exc.BadRequest(
                resource='ipam',
                msg='Unable to load {} '
                    'mechanism driver'.format(constants.NUAGE_ML2_DRIVER_NAME))
        vsdclient = nuage_mech_drivers[0].obj.vsdclient
        return vsdclient

    def _get_nuage_id_from_vsd(self, vsdclient, is_l2):
        neutron_subnet = NeutronDbPluginV2().get_subnet(self._context,
                                                        self._subnet_id)
        l2bridge = nuagedb.get_nuage_l2bridge_id_for_subnet(
            self._context.session, self._subnet_id)
        neutron_subnet['nuage_l2bridge'] = l2bridge
        if is_l2:
            return vsdclient.get_l2domain_by_ext_id_and_cidr(
                neutron_subnet)
        else:
            return vsdclient.get_domain_subnet_by_ext_id_and_cidr(
                neutron_subnet)

    def _get_subnet_mapping(self):
        return nuagedb.get_subnet_l2dom_by_id(self._context.session,
                                              self._subnet_id)

    def _get_ip_type(self):
        return 'IPV4' if netaddr.IPNetwork(self._cidr).version == 4 else 'IPV6'


class TransparentPreferNextAddressRequest(ipam_req.PreferNextAddressRequest):
    """Used to request next available IP address from the pool."""


class TransparentSpecificAddressrequest(ipam_req.SpecificAddressRequest):
    """For requesting a specified address from IPAM"""


class NuageVSDManagedAddressRequestFactory(ipam_req.AddressRequestFactory):

    # Ports with these device owners are only validated locally, not on VSD
    transparent_device_owners = [constants.DEVICE_OWNER_DHCP_NUAGE,
                                 n_constants.DEVICE_OWNER_ROUTER_GW
                                 ] + list(n_constants.ROUTER_INTERFACE_OWNERS)

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
        if port['device_owner'] in cls.transparent_device_owners:
            if ip_dict.get('ip_address'):
                return TransparentSpecificAddressrequest(ip_dict['ip_address'])
            else:
                return TransparentPreferNextAddressRequest()
        else:
            return super(NuageVSDManagedAddressRequestFactory,
                         cls).get_request(context, port, ip_dict)


class NuageVSDManagedDbPool(driver.NeutronDbPool):
    """Subnet pools backed by Neutron Database.

    As this driver does not implement yet the subnet pool concept, most
    operations are either trivial or no-ops.
    """
    # This driver requires for allowed address pair ips to be reserved
    # before usage with a dummy/vip port.
    requires_ipam_for_aap = True

    def get_address_request_factory(self):
        """Returns default NuageAddressRequestFactory

        """
        return NuageVSDManagedAddressRequestFactory

    def get_subnet(self, subnet_id):
        return NuageIpamSubnet.load(subnet_id, self._context)

    def needs_rollback(self):
        return False
