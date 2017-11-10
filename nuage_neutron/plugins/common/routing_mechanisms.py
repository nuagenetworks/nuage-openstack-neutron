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

import constants
import nuagedb


from nuage_neutron.plugins.common.exceptions import NuageBadRequest


def check_routing_mechanisms_config():
    """Validate nuage.ini configuration

    :raise Raises ConfigFileValueError when configuration is not correct
    """
    if (cfg.CONF.RESTPROXY.nuage_underlay_default
        != constants.NUAGE_UNDERLAY_OFF and
            cfg.CONF.RESTPROXY.nuage_pat !=
            constants.NUAGE_PAT_LEGACY_DISABLED):
        msg = ("It is not possible to configure both {} "
               "and {}. Set {} to "
               "{}.".format('nuage_pat',
                            constants.NUAGE_UNDERLAY_INI,
                            'nuage_pat',
                            constants.NUAGE_PAT_LEGACY_DISABLED))
        raise cfg.ConfigFileValueError(msg=msg)
    elif (cfg.CONF.RESTPROXY.nuage_underlay_default is None and
          cfg.CONF.RESTPROXY.nuage_pat == constants.NUAGE_PAT_LEGACY_DISABLED):
        msg = ("It is compulsory to configure {} when "
               "setting {} to {}.".format(constants.NUAGE_UNDERLAY_INI,
                                          'nuage_pat',
                                          constants.NUAGE_PAT_LEGACY_DISABLED))
        raise cfg.ConfigFileValueError(msg=msg)


def is_legacy():
    return cfg.CONF.RESTPROXY.nuage_pat != constants.NUAGE_PAT_LEGACY_DISABLED


def is_not_available():
    return (cfg.CONF.RESTPROXY.nuage_underlay_default
            == constants.NUAGE_UNDERLAY_NOT_AVAILABLE)


def create_legacy_routing_values(router):
    validate_legacy_router(router)
    enable_snat = router['external_gateway_info'].get('enable_snat')

    if enable_snat is None:
        config = cfg.CONF.RESTPROXY.nuage_pat
        if config == constants.NUAGE_PAT_DEF_ENABLED:
            router[constants.NUAGE_UNDERLAY] = constants.NUAGE_UNDERLAY_SNAT
        else:
            # default disabled or not_available
            router[constants.NUAGE_UNDERLAY] = constants.NUAGE_UNDERLAY_OFF
    elif enable_snat is True:
        router[constants.NUAGE_UNDERLAY] = constants.NUAGE_UNDERLAY_SNAT
    else:
        router[constants.NUAGE_UNDERLAY] = constants.NUAGE_UNDERLAY_OFF

    # Set enable_snat=False, since this signifies pat to overlay in non-legacy
    router['external_gateway_info']['enable_snat'] = False


def validate_legacy_router(router):
    enable_snat = (router['external_gateway_info'].get('enable_snat')
                   if router.get('external_gateway_info') else None)
    nuage_pat = cfg.CONF.RESTPROXY.nuage_pat
    if (nuage_pat == constants.NUAGE_PAT_NOT_AVAILABLE
            and enable_snat is True):
        msg = _("nuage_pat config is set to 'not_available'. "
                "Can't enable 'enable_snat'.")
        raise NuageBadRequest(resource='router', msg=msg)


def update_routing_values(router, old_router={}):
    """Update routing values as per (updated) router

    Defaults are applied as per nuage_pat (legacy behavior), nuage_underlay
    and enable_snat_by_default
    """
    if is_legacy():
        if router.get(constants.NUAGE_UNDERLAY) is not None:
            msg = _("To configure {} disable "
                    "'nuage_pat' and configure "
                    "{}.").format(constants.NUAGE_UNDERLAY,
                                  constants.NUAGE_UNDERLAY_INI)
            raise NuageBadRequest(resource='subnet', msg=msg)
        if router.get('external_gateway_info') == {}:
            # router-gateway-clear
            router[constants.NUAGE_UNDERLAY] = constants.NUAGE_UNDERLAY_OFF
            return
        elif router.get('external_gateway_info'):
            create_legacy_routing_values(router)
            return

    # Current values
    ext_gw_info = router.get('external_gateway_info')
    ext_enable_snat = (router['external_gateway_info'].get('enable_snat')
                       if ext_gw_info else None)

    nuage_underlay = router.get(constants.NUAGE_UNDERLAY)

    if nuage_underlay is None and ext_gw_info is None and old_router:
        # No update needed
        return

    if ((nuage_underlay is None
            or nuage_underlay == old_router.get(constants.NUAGE_UNDERLAY))
            and ext_gw_info is None and old_router):
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
    if ((nuage_underlay != constants.NUAGE_UNDERLAY_NOT_AVAILABLE
         and nuage_underlay != constants.NUAGE_UNDERLAY_OFF)
            and is_not_available()):
        msg += ("\n"
                "nuage_underlay is not available. Contact your "
                "operator to explore options.")
        raise NuageBadRequest(resource='router', msg=msg)
    if (enable_snat is True
            and nuage_underlay != constants.NUAGE_UNDERLAY_OFF):
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

    if is_legacy() and router.get('external_gateway_info'):
        router['external_gateway_info']['enable_snat'] = (
            nuage_underlay == constants.NUAGE_UNDERLAY_SNAT)


def validate_update_subnet(network_external, subnet_mapping, updated_subnet):
    """Validate nuage_underlay for updated subnet

    """
    if (is_not_available() and
            updated_subnet.get(constants.NUAGE_UNDERLAY) !=
            constants.NUAGE_UNDERLAY_OFF):
        msg = _("It is not allowed to configure {}"
                " on a subnet when nuage_underlay is not available. "
                "Contact your "
                "operator to explore options").format(constants.NUAGE_UNDERLAY)
        raise NuageBadRequest(resource='subnet', msg=msg)

    if is_legacy() and updated_subnet.get(constants.NUAGE_UNDERLAY):
        msg = _("It is not allowed to configure {}"
                " on a subnet when 'nuage_pat' "
                "is set.").format(constants.NUAGE_UNDERLAY)
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
    if is_legacy() or is_not_available():
        return
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
