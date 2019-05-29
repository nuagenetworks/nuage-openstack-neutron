# Copyright NOKIA 2017
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
"""routing_mechanisms handles PAT to underlay and route to underlay
functionality.

"""
from oslo_config import cfg

from neutron._i18n import _
from neutron_lib import constants as os_constants

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import nuagedb


from nuage_neutron.plugins.common.exceptions import NuageBadRequest


def is_not_available():
    return (cfg.CONF.RESTPROXY.nuage_underlay_default ==
            constants.NUAGE_UNDERLAY_NOT_AVAILABLE)


def update_routing_values(router, old_router={}):
    """Update routing values as per (updated) router

    Defaults are applied as per nuage_underlay_default and
     enable_snat_by_default
    """

    # Current values
    ext_gw_info = router.get('external_gateway_info')
    ext_enable_snat = (router['external_gateway_info'].get('enable_snat')
                       if ext_gw_info else None)

    nuage_underlay = router.get(constants.NUAGE_UNDERLAY)

    if nuage_underlay is None and ext_gw_info is None and old_router:
        # No update needed
        return

    if ((nuage_underlay is None or
            nuage_underlay == old_router.get(constants.NUAGE_UNDERLAY)) and
            ext_gw_info is None and old_router):
        # No update needed as updated values are same as previous.
        return

    if nuage_underlay is None and not old_router:
        # set default value
        nuage_underlay = cfg.CONF.RESTPROXY.nuage_underlay_default
    elif nuage_underlay is None:
        # Copy old value
        nuage_underlay = old_router.get(constants.NUAGE_UNDERLAY)

    if ext_gw_info and ext_enable_snat is None:
        ext_gw_info['enable_snat'] = cfg.CONF.enable_snat_by_default
        ext_enable_snat = cfg.CONF.enable_snat_by_default
    elif ext_gw_info is None and old_router.get('external_gateway_info'):
        ext_gw_info = old_router.get('external_gateway_info')
        ext_enable_snat = old_router.get('external_gateway_info').get(
            'enable_snat')

    exception_msg = ("Unable to configure router given parameters "
                     "external_gateway_info.enable_snat={} and"
                     " {}={}.").format(ext_enable_snat,
                                       constants.NUAGE_UNDERLAY,
                                       nuage_underlay)
    validate_updated_routing_values(
        nuage_underlay,
        ext_enable_snat if ext_gw_info else None,
        msg=exception_msg)

    # Update
    if ext_gw_info:
        router['external_gateway_info'] = ext_gw_info
    router[constants.NUAGE_UNDERLAY] = nuage_underlay


def validate_updated_routing_values(nuage_underlay, enable_snat, msg):
    if ((nuage_underlay != constants.NUAGE_UNDERLAY_NOT_AVAILABLE and
         nuage_underlay != constants.NUAGE_UNDERLAY_OFF) and
            is_not_available()):
        msg += ("\n"
                "nuage_underlay is not available. Contact your "
                "operator to explore options.")
        raise NuageBadRequest(resource='router', msg=msg)
    if (enable_snat is True and
            nuage_underlay != constants.NUAGE_UNDERLAY_OFF):
        msg += ("\n"
                "enable_snat cannot be enabled when "
                " nuage_underlay is set.")
        raise NuageBadRequest(resource='router', msg=msg)
    if enable_snat is True:
        msg += ("\n"
                "SNAT to overlay currently not supported."
                " Set enable_snat = False.")
        raise NuageBadRequest(resource='router', msg=msg)


def update_nuage_router_parameters(router, context, router_id):
    """Update router parameters in db

    """
    if is_not_available():
        return
    nuage_underlay = router.get(constants.NUAGE_UNDERLAY)
    if nuage_underlay is None:
        # no update
        return
    if nuage_underlay != constants.NUAGE_UNDERLAY_OFF:
        nuagedb.add_router_parameter(context.session, router_id,
                                     constants.NUAGE_UNDERLAY,
                                     nuage_underlay)
    else:
        router_parameter = nuagedb.get_router_parameter(
            context.session,
            router_id,
            constants.NUAGE_UNDERLAY)
        if router_parameter:
            nuagedb.delete_router_parameter(context.session, router_parameter)


def add_nuage_router_attributes(session, router):
    # Add nuage_underlay to router attributes
    nuage_underlay = nuagedb.get_router_parameter(
        session,
        router['id'],
        constants.NUAGE_UNDERLAY)
    if nuage_underlay is None:
        nuage_underlay = constants.NUAGE_UNDERLAY_OFF
    else:
        nuage_underlay = nuage_underlay['parameter_value']
    router[constants.NUAGE_UNDERLAY] = nuage_underlay


def validate_update_subnet(network_external, subnet_mapping, updated_subnet):
    """Validate nuage_underlay for updated subnet

    """
    if (is_not_available() and (
            updated_subnet.get(constants.NUAGE_UNDERLAY) in
            [constants.NUAGE_UNDERLAY_SNAT,
             constants.NUAGE_UNDERLAY_ROUTE])):
        msg = _("It is not allowed to configure {}"
                " on a subnet when nuage_underlay is not available. "
                "Contact your "
                "operator to explore options").format(constants.NUAGE_UNDERLAY)
        raise NuageBadRequest(resource='subnet', msg=msg)

    if network_external and updated_subnet.get(constants.NUAGE_UNDERLAY):
        msg = _("It is not allowed to configure {}"
                " on an external subnet").format(constants.NUAGE_UNDERLAY)
        raise NuageBadRequest(resource='subnet', msg=msg)

    if (updated_subnet['ip_version'] == os_constants.IP_VERSION_6 and
            updated_subnet.get(constants.NUAGE_UNDERLAY)):
        msg = _("It is not allowed to configure {}"
                " on an ipv6 subnet. ").format(constants.NUAGE_UNDERLAY)
        raise NuageBadRequest(resource='subnet', msg=msg)

    if (subnet_mapping and subnet_mapping['nuage_l2dom_tmplt_id'] and
            updated_subnet.get(constants.NUAGE_UNDERLAY)):
        msg = _("It is not allowed to configure {} "
                "on a subnet that is not attached to a router."
                "").format(constants.NUAGE_UNDERLAY)
        raise NuageBadRequest(resource='subnet', msg=msg)


def update_nuage_subnet_parameters(context, subnet):
    nuage_underlay = subnet.get(constants.NUAGE_UNDERLAY)
    if nuage_underlay is None:
        # no update
        return
    if nuage_underlay != constants.NUAGE_UNDERLAY_INHERITED:
        nuagedb.add_subnet_parameter(context.session, subnet['id'],
                                     constants.NUAGE_UNDERLAY,
                                     nuage_underlay)
    else:
        subnet_parameter = nuagedb.get_subnet_parameter(
            context.session,
            subnet['id'],
            constants.NUAGE_UNDERLAY)
        if subnet_parameter:
            nuagedb.delete_subnet_parameter(context.session, subnet_parameter)


def delete_nuage_subnet_parameters(context, subnet_id):
    subnet_parameter = nuagedb.get_subnet_parameter(
        context.session,
        subnet_id,
        constants.NUAGE_UNDERLAY)
    if subnet_parameter:
        nuagedb.delete_subnet_parameter(context.session, subnet_parameter)
