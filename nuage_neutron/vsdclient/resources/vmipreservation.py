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

import logging

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import nuagelib

LOG = logging.getLogger(__name__)


class NuageVMIpReservation(object):
    def __init__(self, restproxy_serv):
        self.restproxy = restproxy_serv

    def create_vm_ip_reservation(self, is_l2, parent_id, ip_type,
                                 ipv4_address=None,
                                 ipv6_address=None,
                                 allocation_pools=None):
        if is_l2:
            parent_type = nuagelib.NuageL2Domain.resource
        else:
            parent_type = nuagelib.NuageSubnet.resource
        post_data = {'IPType': ip_type,
                     'externalID': get_vsd_external_id('openstack')}
        if ipv4_address:
            post_data['IPV4Address'] = ipv4_address
        if ipv6_address:
            post_data['IPV6Address'] = ipv6_address
        if allocation_pools:
            if ip_type == 'IPV4':
                post_data['allocationPools'] = [
                    {'minAddress': pool.first_ip, 'maxAddress': pool.last_ip}
                    for pool in allocation_pools]
            else:
                post_data['IPV6AllocationPools'] = [
                    {'minAddress': pool.first_ip, 'maxAddress': pool.last_ip}
                    for pool in allocation_pools]

        ipreservation = nuagelib.VmIpReservation()
        reservation = self.restproxy.post(
            ipreservation.post_url(parent_type, parent_id),
            post_data)[0]

        return {
            'ipv4_address': reservation.get('IPV4Address'),
            'ipv6_address': reservation.get('IPV6Address')
        }

    def update_vm_ip_reservation_state(self, vmipreservation_id,
                                       target_state=''):
        ipreservation = nuagelib.VmIpReservation()
        self.restproxy.put(ipreservation.put_url() % vmipreservation_id,
                           {'state': target_state})

    def delete_vm_ip_reservation(self, is_l2, parent_id,
                                 ipv4_address=None,
                                 ipv6_address=None):
        if is_l2:
            parent_type = nuagelib.NuageL2Domain.resource
        else:
            parent_type = nuagelib.NuageSubnet.resource
        url_params = {}
        if ipv4_address:
            url_params['IPV4Address'] = ipv4_address
        if ipv6_address:
            url_params['IPV6Address'] = ipv6_address
        ipreservation = nuagelib.VmIpReservation()
        self.restproxy.delete(
            ipreservation.delete_url(parent_type, parent_id, url_params))

    def get_vm_ip_reservation(self, is_l2, parent_id, ipv4_address=None,
                              ipv6_address=None):
        if is_l2:
            parent_type = nuagelib.NuageL2Domain.resource
        else:
            parent_type = nuagelib.NuageSubnet.resource

        ipreservation = nuagelib.VmIpReservation()
        if ipv4_address:
            filters = {'IPV4Address': ipv4_address}
        if ipv6_address:
            filters = {'IPV6Address': ipv6_address}
        extra_header = ipreservation.extra_header_filter(**filters)
        ipreservations = self.restproxy.get(ipreservation.get_url(parent_type,
                                                                  parent_id),
                                            extra_headers=extra_header,
                                            required=True)
        if ipreservations:
            return ipreservations[0]
        else:
            return None
