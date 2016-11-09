# Copyright 2016 Alcatel-Lucent USA Inc.
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

import copy
import itertools
from nuage_neutron.plugins.common.exceptions import SubnetMappingNotFound

from oslo_log import log as logging

from neutron.callbacks import resources
from neutron.common import constants as os_constants
from neutron.common import exceptions as n_exc
from neutron_lib.api import validators as lib_validators
from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb

LOG = logging.getLogger(__name__)


class PortDHCPOptionsNuage(BaseNuagePlugin):

    def __init__(self):
        super(PortDHCPOptionsNuage, self).__init__()
        self.nuage_callbacks.subscribe(self._validate_port_dhcp_opts,
                                       resources.PORT, constants.BEFORE_CREATE)
        self.nuage_callbacks.subscribe(self._validate_port_dhcp_opts,
                                       resources.PORT, constants.BEFORE_UPDATE)
        self.nuage_callbacks.subscribe(self._create_port_dhcp_opts,
                                       resources.PORT, constants.AFTER_CREATE)
        self.nuage_callbacks.subscribe(self._update_port_dhcp_opts,
                                       resources.PORT, constants.AFTER_UPDATE)

    def _create_update_extra_dhcp_options(self, dhcp_options, vport,
                                          port_id, on_opts_update=False):
        response = []
        for dhcp_option in dhcp_options:
            try:
                resp = self.nuageclient.crt_or_updt_vport_dhcp_option(
                    dhcp_option, vport['ID'], port_id)
            except Exception as e:
                e = self._build_dhcp_option_error_message(
                    dhcp_option['opt_name'], e)
                if on_opts_update:
                    response.append(e)
                    response.append("error")
                    return response
                for del_resp in response:
                    if del_resp[1] == 'Created':
                        self.nuageclient.delete_vport_dhcp_option(
                            del_resp[3][0]['ID'], True)
                raise e
            response.append(resp)
        return response

    def _validate_extra_dhcp_option_ip_version(self, dhcp_option):
        if dhcp_option.get('ip_version') == os_constants.IP_VERSION_6:
            msg = _("DHCP options for IPV6 are not yet supported")
            raise nuage_exc.NuageBadRequest(msg=msg)

    def _validate_extra_dhcp_opt_for_neutron(self, new_dhcp_opts):
        # validating for neutron internal error, checking for the
        #  neutron failure case
        for key, group in itertools.groupby(
                sorted(new_dhcp_opts, key=lambda opt: opt['opt_name']),
                lambda opt: opt['opt_name']):
            options = list(group)
            if len(options) > 1:
                e = n_exc.InvalidInput()
                raise self._build_dhcp_option_error_message(
                    options[0]['opt_name'], e)

    def _build_dhcp_option_error_message(self, dhcpoption, e):
        for name, number in constants.DHCP_OPTION_NAME_TO_NUMBER.iteritems():
            if number == dhcpoption:
                if isinstance(e, n_exc.InvalidInput):
                    error = ("Neutron Error: DHCP Option %s that is being set"
                             " for the first time cannot be mentioned more"
                             " than once") % name
                    e.message = error
                    e.msg = error
                    return e
                elif hasattr(e, 'msg'):
                    error = "For DHCP option " + name + ", " + e.msg
                    return nuage_exc.NuageBadRequest(msg=error)
                else:
                    error = ("Error encountered while processing option value"
                             " of " + name + " due to: " + e.message)
                    return nuage_exc.NuageBadRequest(msg=error)

    def _translate_dhcp_option(self, dhcp_option):
        if dhcp_option['opt_name'] in constants.DHCP_OPTION_NAME_TO_NUMBER:
            dhcp_option['opt_name'] = (constants.DHCP_OPTION_NAME_TO_NUMBER
                                       [dhcp_option['opt_name']])
            dhcp_option['opt_value'] = dhcp_option['opt_value'].split(";")
        else:
            msg = _("There is no DHCP option available with the "
                    "opt_ name: %s ") % dhcp_option['opt_name']
            raise nuage_exc.NuageBadRequest(msg=msg)

    def _categorise_dhcp_options_for_update(self, old_dhcp_opts,
                                            new_dhcp_opts):
        add_dhcp_opts = []
        update_dhcp_opts = []
        existing_opts = set()
        for old_dhcp_opt in old_dhcp_opts:
            existing_opts.add(old_dhcp_opt['opt_name'])
        for new_dhcp_opt in new_dhcp_opts:
            if new_dhcp_opt['opt_name'] in existing_opts:
                update_dhcp_opts.append(new_dhcp_opt)
            else:
                add_dhcp_opts.append(new_dhcp_opt)
        return {'new': add_dhcp_opts, 'update': update_dhcp_opts}

    def _update_extra_dhcp_options(self, categorised_dhcp_opts, subnet_mapping,
                                   port_id, current_owner, old_dhcp_opts,
                                   vport):
        if not subnet_mapping:
            # For preventing updating of a port on External Network
            msg = ("Cannot Update a port that does not have corresponding"
                   " Vport on Nuage")
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not vport:
            if (subnet_mapping['nuage_l2dom_tmplt_id'] and
                    current_owner == constants.DEVICE_OWNER_DHCP_NUAGE):
                msg = ("Cannot set DHCP options for a port owned by Nuage, "
                       "which was created for internal use only.")
                raise nuage_exc.NuageBadRequest(msg=msg)
            else:
                msg = ("Could not find corresponding Vport for the specified"
                       " Neutron Port-ID: " + port_id)
                raise nuage_exc.NuageBadRequest(msg=msg)
        try:
            created_rollback_opts = self._create_update_extra_dhcp_options(
                categorised_dhcp_opts['new'], vport, port_id, False)
        except Exception as e:
            LOG.error(_("Port Update failed due to: %s") % e.msg)
            raise e
        try:
            update_rollback = self._create_update_extra_dhcp_options(
                categorised_dhcp_opts['update'], vport, port_id, True)
            if "error" in update_rollback:
                update_rollback.remove("error")
                e = update_rollback.pop(-1)
                include_rollback_opt = [categorised_dhcp_opts['update'][i]
                                        ['opt_name'] for i in
                                        range(len(update_rollback))]
                for dhcp_opt in old_dhcp_opts:
                    if dhcp_opt['opt_name'] not in include_rollback_opt:
                        old_dhcp_opts.remove(dhcp_opt)
                raise e
        except Exception as e:
            for rollback_opt in created_rollback_opts:
                self.nuageclient.delete_vport_dhcp_option(
                    rollback_opt[3][0]['ID'], True)
            self._create_update_extra_dhcp_options(old_dhcp_opts, vport,
                                                   port_id, True)
            LOG.error(_("Port Update failed due to: %s") % e.message)
            raise e

    def _validate_port_dhcp_opts(self, resource, event, trigger, **kwargs):
        request_port = kwargs.get('request_port')
        if not request_port or \
                not lib_validators.is_attr_set(
                    request_port.get('extra_dhcp_opts')):
            return
        dhcp_options = copy.deepcopy(request_port['extra_dhcp_opts'])
        for dhcp_option in dhcp_options:
            self._translate_dhcp_option(dhcp_option)
            self._validate_extra_dhcp_option_ip_version(dhcp_option)
        self._validate_extra_dhcp_opt_for_neutron(dhcp_options)

    def _create_port_dhcp_opts(self, resource, event, trigger, **kwargs):
        request_port = kwargs.get('request_port')
        port = kwargs.get('port')
        vport = kwargs.get('vport')
        context = kwargs.get('context')
        if not request_port or \
                not lib_validators.is_attr_set(
                    request_port.get('extra_dhcp_opts')):
            return
        try:
            nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                port['id'])
        except SubnetMappingNotFound:
            msg = ("Cannot create a port with DHCP options on a subnet that "
                   "does not have mapping to a L2Domain (OR) "
                   "a L3 Subnet on Nuage.")
            raise nuage_exc.NuageBadRequest(msg=msg)
        dhcp_options = copy.deepcopy(request_port['extra_dhcp_opts'])
        for dhcp_opt in dhcp_options:
            self._translate_dhcp_option(dhcp_opt)
        self._create_update_extra_dhcp_options(
            dhcp_options, vport, port['id'])

    def _update_port_dhcp_opts(self, resource, event, trigger, **kwargs):
        request_port = kwargs.get('request_port')
        original_port = kwargs.get('original_port')
        updated_port = kwargs.get('updated_port')
        vport = kwargs.get('vport')
        context = kwargs.get('context')

        if not request_port or not original_port or \
                'extra_dhcp_opts' not in request_port:
            return

        subnet_id = updated_port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        old_dhcp_options = original_port.get('extra_dhcp_opts', [])
        request_dhcp_options = copy.deepcopy(
            request_port.get('extra_dhcp_opts', []))
        for dhcp_opt in request_dhcp_options:
            self._translate_dhcp_option(dhcp_opt)
        categorised_dhcp_opts = self._categorise_dhcp_options_for_update(
            copy.deepcopy(old_dhcp_options),
            request_dhcp_options)
        self._update_extra_dhcp_options(categorised_dhcp_opts,
                                        subnet_mapping,
                                        original_port.get('id'),
                                        original_port['device_owner'],
                                        old_dhcp_options, vport)
