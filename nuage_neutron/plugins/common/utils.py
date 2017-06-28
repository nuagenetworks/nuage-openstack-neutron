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

import contextlib
import functools
import netaddr
import six
import sys

from neutron._i18n import _
from neutron_lib import constants as neutron_constants
from oslo_config import cfg
from oslo_log import log as logging

from nuage_neutron.plugins.common import constants as nuage_constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.vsdclient.restproxy import RESTProxyError


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


def compare_cidr(cidr1, cidr2):
    return cidr1 is not None and cidr2 is not None and \
        normalize_cidr(cidr1) == normalize_cidr(cidr2)


def normalize_cidr(value):
    try:
        ip = netaddr.IPNetwork(value).cidr
        return six.text_type(ip)
    except netaddr.core.AddrFormatError:
        pass
    return value


def check_vport_creation(device_owner, prefix_list):
    if (device_owner in get_auto_create_port_owners() or
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

    This is returned when exceptions are silently ignored from vsdclient.
    It will return false when doing if x:
    But it's still possible to raise the original exception by doing
    raise x.exception
    """

    def __init__(self, exception):
        self.exception = exception

    def __nonzero__(self):
        return False


def handle_nuage_api_errorcode(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # raise nuage_exc.NuageBadRequest(msg=ERROR_DICT.get(
            #     str(e.vsd_code), e.message)), None, sys.exc_info()[2]
            e = nuage_exc.NuageBadRequest(msg=ERROR_DICT.get(
                str(e.vsd_code), e.message))
            e.__traceback__ = sys.exc_info()[2]
            raise e

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
            raise e
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
    log = logging.getLogger()
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
    return [neutron_constants.DEVICE_OWNER_DHCP,
            neutron_constants.DEVICE_OWNER_ROUTER_INTF,
            neutron_constants.DEVICE_OWNER_ROUTER_GW,
            neutron_constants.DEVICE_OWNER_FLOATINGIP,
            nuage_constants.DEVICE_OWNER_VIP_NUAGE,
            nuage_constants.DEVICE_OWNER_IRONIC
            ] + cfg.CONF.PLUGIN.device_owner_prefix


def get_device_owners_vip():
    return ([nuage_constants.DEVICE_OWNER_VIP_NUAGE] +
            cfg.CONF.PLUGIN.device_owner_prefix)
