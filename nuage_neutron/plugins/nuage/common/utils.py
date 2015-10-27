# Copyright 2015 Alcatel-Lucent USA Inc.
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

import sys

from neutron.common import exceptions as n_exc
from nuage_neutron.plugins.nuage.common import constants
from nuage_neutron.plugins.nuage.common import exceptions as nuage_exc


def handle_nuage_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as ex:
            if isinstance(ex, n_exc.NeutronException):
                raise
            et, ei, tb = sys.exc_info()
            raise nuage_exc.NuageAPIException, \
                nuage_exc.NuageAPIException(msg=ex), tb
    return wrapped


def convert_to_cidr(address, mask):
    ipaddr = address.split('.')
    netmask = mask.split('.')
    # calculate network start
    net_start = [str(int(ipaddr[x]) & int(netmask[x]))
                 for x in range(0, 4)]

    def get_net_size(netmask):
        binary_str = ''
        for octet in netmask:
            binary_str += bin(int(octet))[2:].zfill(8)
        return str(len(binary_str.rstrip('0')))

    return '.'.join(net_start) + '/' + get_net_size(netmask)


def check_vport_creation(device_owner, prefix_list):
    if (device_owner in constants.AUTO_CREATE_PORT_OWNERS or
            device_owner.startswith(tuple(prefix_list))):
        return False
    return True
