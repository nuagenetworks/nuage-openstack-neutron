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
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuagenetlib.restproxy import RESTProxyError

from oslo_log import log as logging


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


def context_log(fn):
    def wrapped(*args, **kwargs):
        instance = args[0]
        class_name = instance.__class__.__name__
        method_name = fn.__name__
        context = args[1]
        LOG = logging.getLogger(fn.__module__)
        LOG.debug('%s method %s is getting called with context.current %s, '
                  'context.original %s' % (class_name, method_name,
                                           context.current,
                                           context.original))
        return fn(*args, **kwargs)
    return wrapped


class Ignored(object):
    """Class that will evaluate to False in if-statement and contains error.

    This is returned when exceptions are silently ignored from nuageclient.
    It will return false when doing if x:
    But it's still possible to raise the original exception by doing
    raise x.exception
    """
    def __init__(self, exception):
        self.exception = exception

    def __nonzero__(self):
        return False


def handle_nuage_api_errorcode(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            raise nuage_exc.NuageBadRequest(msg=ERROR_DICT.get(
                str(e.code), e.message))
    return wrapped


def ignore_no_update(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # See ERROR_DICT below. This should never go to the user. Neutron
            # does not complain when updating to the same values.
            if str(e.code) == '2039':
                return Ignored(e)
            raise e
    return wrapped


def ignore_not_found(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # We probably want to ignore 404 errors when we're deleting anyway.
            if str(e.code) == '404':
                return Ignored(e)
            raise e
    return wrapped


ERROR_DICT = {
    '2039': _("There are no attribute changes to modify the entity."),
    '2050': _("Netpartition does not match the network."),
    '7022': _("Redirection target belongs to a different subnet."),
    '7027': _("Redirection target already has a port assigned. Can't assign"
              " more with redundancy disabled.")
}
