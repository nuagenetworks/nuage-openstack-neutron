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

from __future__ import print_function

import contextlib
import functools
import netaddr
import six
import socket
import struct
import sys

from neutron._i18n import _
from neutron_lib import constants as neutron_constants
from oslo_config import cfg

from nuage_neutron.plugins.common import constants as nuage_constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.vsdclient.restproxy import RESTProxyError


def get_logger(name=None, fn=None):
    try:
        from oslo_log import log as logging
        return logging.getLogger(fn.__module__ if fn else name)

    except ImportError:
        # cygwin does not support oslo logging
        class SimpleLogger(object):
            def __init__(self, mod_name=None):
                self.name = mod_name if mod_name else ''
                self.debug('Caution: SimpleLogger activated.')

            def debug(self, debug_str, *args):
                print('[%s] [DEBUG] %s' % (self.name, debug_str), *args)

            def info(self, info_str, *args):
                print('[%s] [INFO] %s' % (self.name, info_str), *args)

            def warn(self, warn_str, *args):
                print('[%s] [WARN] %s' % (self.name, warn_str), *args)

            def error(self, error_str, *args):
                print('[%s] [ERROR] %s' % (self.name, error_str), *args)

        return SimpleLogger(fn.__module__ if fn else name)


def handle_nuage_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as ex:
            _, _, tb = sys.exc_info()
            six.reraise(nuage_exc.NuageAPIException,
                        nuage_exc.NuageAPIException(msg=ex.message),
                        tb)
    return wrapped


def compare_ip(ip1, ip2):
    return ((ip1 is None and ip2 is None) or
            (ip1 is not None and ip2 is not None and
             netaddr.IPAddress(ip1) == netaddr.IPAddress(ip2)))


def compare_cidr(cidr1, cidr2):
    return ((cidr1 is None and cidr2 is None) or
            (cidr1 is not None and cidr2 is not None and
             normalize_cidr(cidr1) == normalize_cidr(cidr2)))


def normalize_cidr(value):
    try:
        ip = netaddr.IPNetwork(value).cidr
        return six.text_type(ip)
    except netaddr.core.AddrFormatError:
        pass
    return value


def context_log(fn):
    def wrapped(*args, **kwargs):
        instance = args[0]
        class_name = instance.__class__.__name__
        method_name = fn.__name__
        context = args[1]
        LOG = get_logger(fn=fn)
        LOG.debug('%s method %s is getting called with context.current %s, '
                  'context.original %s',
                  class_name, method_name, context.current, context.original)
        return fn(*args, **kwargs)
    return wrapped


class Ignored(object):
    """Class that will evaluate to False in if-statement and contains error.

    This is returned when exceptions are silently ignored from vsdclient.
    It will return false when doing if x:
    But it's still possible to raise the original exception by doing
    raise x.exception
    """

    def __init__(self, exception):
        self.exception = exception

    def __nonzero__(self):
        return False


def retry_on_vsdclient_error(fn, nr_retries=3, vsd_error_codes=None):
    """Retry function on vsdclient error

    :param fn: function to (re)try
    :param nr_retries
    :param vsd_error_codes: vsd_error_codes to retry [(http_code, vsd_code)]
        [(409,'7010')]
    """
    def wrapped(*args, **kwargs):
        tries = 1
        while tries <= nr_retries:
            try:
                return fn(*args, **kwargs)
            except RESTProxyError as e:
                LOG = get_logger(fn=fn)
                if tries == nr_retries:
                    LOG.debug('Failed to execute {} {} times.'.format(
                        fn.func_name, nr_retries)
                    )
                    raise
                if (e.code, e.vsd_code) in vsd_error_codes:
                    LOG.debug('Attempt {} of {} to execute {} failed.'.format(
                        tries, nr_retries, fn.func_name)
                    )
                    tries += 1
                else:
                    LOG.debug('Non retry-able error '
                              'encountered on {}.'.format(fn.func_name))
                    raise
    return wrapped


def handle_nuage_api_errorcode(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            _, _, tb = sys.exc_info()
            six.reraise(nuage_exc.NuageBadRequest,
                        nuage_exc.NuageBadRequest(
                            msg=ERROR_DICT.get(str(e.vsd_code), e.message)),
                        tb)

    return wrapped


def ignore_no_update(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # See ERROR_DICT below. This should never go to the user. Neutron
            # does not complain when updating to the same values.
            if str(e.vsd_code) == '2039':
                return Ignored(e)
            raise
    return wrapped


def ignore_not_found(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # We probably want to ignore 404 errors when we're deleting anyway.
            if str(e.vsd_code) == '404':
                return Ignored(e)
            raise
    return wrapped


ERROR_DICT = {
    '2039': _("There are no attribute changes to modify the entity."),
    '2050': _("Netpartition does not match the network."),
    '7022': _("Redirection target belongs to a different subnet."),
    '7027': _("Redirection target already has a port assigned. Can't assign"
              " more with redundancy disabled."),
    '7036': _("The port is in an L2Domain, it can't have floating ips"),
    '7038': _("Nuage floatingip is not available for this port"),
    '7309': _("Nuage policy group is not available for this port"),
}


def filters_to_vsd_filters(filterables, filters, os_to_vsd):
    """Translates openstack filters to vsd filters.

    :param filterables: The attributes which are filterable on VSD.
    :param filters: the neutron filters list from a list request.
    :param os_to_vsd: a dict where the key is the neutron name, and the key is
     the vsd attribute name. For example {'rd': 'routeDistinguisher', ...}
     the key can also be a method which will be called with this method's
     return dict and the 'filters' parameter.
    :return: A dict with vsd-friendly keys and values taken from the filters
     parameter
    """

    if not filters or not filterables or not os_to_vsd:
        return {}
    vsd_filters = {}
    for filter in filterables:
        if filter in filters:
            vsd_key = os_to_vsd[filter]
            if hasattr(vsd_key, '__call__'):
                vsd_key(vsd_filters, filters)
            else:
                vsd_filters[vsd_key] = filters[filter][0]
    return vsd_filters


def add_rollback(rollbacks, method, *args, **kwargs):
    rollbacks.append(functools.partial(method, *args, **kwargs))


@contextlib.contextmanager
def rollback():
    rollbacks = []
    log = get_logger()
    try:
        yield functools.partial(add_rollback, rollbacks)
    except Exception:
        for action in reversed(rollbacks):
            try:
                action()
            except Exception:
                log.exception("Rollback failed.")
        raise


def get_auto_create_port_owners():
    return [neutron_constants.DEVICE_OWNER_ROUTER_INTF,
            neutron_constants.DEVICE_OWNER_ROUTER_GW,
            neutron_constants.DEVICE_OWNER_FLOATINGIP,
            nuage_constants.DEVICE_OWNER_VIP_NUAGE,
            nuage_constants.DEVICE_OWNER_IRONIC,
            nuage_constants.DEVICE_OWNER_OCTAVIA
            ]


def needs_vport_for_fip_association(device_owner):
    return (device_owner not in
            get_device_owners_vip() + [nuage_constants.DEVICE_OWNER_IRONIC])


def needs_vport_creation(device_owner):
    if (device_owner in get_auto_create_port_owners() or
            device_owner.startswith(tuple(
                cfg.CONF.PLUGIN.device_owner_prefix))):
        return False
    return True


def get_device_owners_vip():
    return ([nuage_constants.DEVICE_OWNER_VIP_NUAGE,
             nuage_constants.DEVICE_OWNER_OCTAVIA] +
            cfg.CONF.PLUGIN.device_owner_prefix)


def count_fixed_ips_per_version(fixed_ips):
    ipv4s = 0
    ipv6s = 0
    for fixed_ip in fixed_ips:
        if netaddr.valid_ipv4(fixed_ip['ip_address']):
            ipv4s += 1
        if netaddr.valid_ipv6(fixed_ip['ip_address']):
            ipv6s += 1
    return ipv4s, ipv6s


def _convert_ipv6(ip):
    hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, ip))
    return (hi << 64) | lo


def sort_ips(ips):
    # (gridinv): attempt first ipv4 conversion
    # on socket.error assume ipv6
    try:
        return sorted(ips,
                      key=lambda ip: struct.unpack(
                          '!I', socket.inet_pton(socket.AF_INET, ip))[0])
    except socket.error:
        return sorted(ips,
                      key=lambda ip: _convert_ipv6(ip))
