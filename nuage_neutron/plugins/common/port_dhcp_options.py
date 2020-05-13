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

from oslo_log import log as logging
import six

from neutron._i18n import _
from neutron.objects import ports as port_obj
from neutron_lib.api import validators as lib_validators
from neutron_lib.callbacks import resources
from neutron_lib import constants as os_constants

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc

LOG = logging.getLogger(__name__)


class PortDHCPOptionsNuage(base_plugin.BaseNuagePlugin):

    DHCP_OPTION_NUMBER_TO_NAME = {
        4: {
            v: k for k, v in six.iteritems(
                constants.DHCP_OPTION_NAME_TO_NUMBER[4])},
        6: {
            v: k for k, v in six.iteritems(
                constants.DHCP_OPTION_NAME_TO_NUMBER[6])}
    }

    def subscribe(self):
        self.nuage_callbacks.subscribe(self._validate_port_dhcp_opts,
                                       resources.PORT, constants.BEFORE_CREATE)
        self.nuage_callbacks.subscribe(self._validate_port_dhcp_opts,
                                       resources.PORT, constants.BEFORE_UPDATE)
        self.nuage_callbacks.subscribe(self.post_port_create_dhcp_opts,
                                       resources.PORT, constants.AFTER_CREATE)
        self.nuage_callbacks.subscribe(self.post_port_update_dhcp_opts,
                                       resources.PORT, constants.AFTER_UPDATE)

    def _create_update_extra_dhcp_options(self, dhcp_options, vport,
                                          port_id, on_opts_update=False):
        response = []
        for dhcp_option in dhcp_options:
            ip_type = dhcp_option['ip_version']
            try:
                resp = self.vsdclient.crt_or_updt_vport_dhcp_option(
                    dhcp_option, vport['ID'], port_id)
            except Exception as e:
                e = self._build_dhcp_option_error_message(
                    dhcp_option['opt_name'], ip_type, e)
                if on_opts_update:
                    response.append(e)
                    response.append("error")
                    return response
                for del_resp in response:
                    if del_resp[1] == 'Created':
                        self.vsdclient.delete_vport_dhcp_option(
                            del_resp[3][0]['ID'], ip_type, True)
                raise e
            response.append(resp)
        return response

    def _delete_extra_dhcp_options(self, dhcp_options, vport, port_id):
        response = []
        for dhcp_option in dhcp_options:
            try:
                resp = self.vsdclient.delete_vport_nuage_dhcp(dhcp_option,
                                                              vport['ID'])
                response.append(resp)
            except Exception as e:
                e = self._build_dhcp_option_error_message(
                    dhcp_option['opt_name'], e)
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
        self._validate_extra_dhcp_opt_for_duplicate_numerical(dhcp_options)

    @staticmethod
    def _is_ipv4_option(dhcp_option):
        return dhcp_option['ip_version'] == os_constants.IP_VERSION_4

    @staticmethod
    def _is_ipv6_option(dhcp_option):
        return dhcp_option['ip_version'] == os_constants.IP_VERSION_6

    def _validate_extra_dhcp_opt_for_duplicate_numerical(self, new_dhcp_opts):
        dhcp_v4_options = [opt for opt in new_dhcp_opts
                           if self._is_ipv4_option(opt)]
        dhcp_v6_options = [opt for opt in new_dhcp_opts
                           if self._is_ipv6_option(opt)]
        self._validate_extra_dhcp_opt_for_duplicate_numerical_within_ip_type(
            os_constants.IP_VERSION_4, dhcp_v4_options)
        self._validate_extra_dhcp_opt_for_duplicate_numerical_within_ip_type(
            os_constants.IP_VERSION_6, dhcp_v6_options)

    def _validate_extra_dhcp_opt_for_duplicate_numerical_within_ip_type(
            self, ip_type, new_dhcp_opts):
        # Check for duplicate extra dhcp options that are mixed between
        # numerical and string based option names.
        for key, group in itertools.groupby(
                sorted(new_dhcp_opts, key=lambda opt: opt['opt_name']),
                lambda opt: opt['opt_name']):
            options = list(group)
            if len(options) > 1:
                opt_number = options[0]['opt_name']
                msg = _("It is not allowed to mix numerical extra "
                        "dhcp options and named extra dhcp options for "
                        "the same extra dhcp option: {}/{}.").format(
                    opt_number,
                    self.DHCP_OPTION_NUMBER_TO_NAME[ip_type][opt_number])
                raise nuage_exc.NuageBadRequest(msg=msg)

    @staticmethod
    def _build_dhcp_option_error_message(dhcp_option, ip_version, e):
        for name, number in six.iteritems(
                constants.DHCP_OPTION_NAME_TO_NUMBER[ip_version]):
            if number == dhcp_option:
                if hasattr(e, 'msg'):
                    error = "For DHCP option " + name + ", " + str(e)
                    return nuage_exc.NuageBadRequest(msg=error)
                else:
                    error = ("Error encountered while processing option value"
                             " of {} due to: {}".format(name, e))
                    return nuage_exc.NuageBadRequest(msg=error)

    @staticmethod
    def _translate_dhcp_option(dhcp_option):
        ip_version = dhcp_option['ip_version']
        opt_name_to_number = constants.DHCP_OPTION_NAME_TO_NUMBER[ip_version]

        def check_option_name(opt_name, opt_names):
            if opt_name not in opt_names:
                msg = _("There is no DHCPv{} option {} available").format(
                    ip_version, opt_name)
                raise nuage_exc.NuageBadRequest(msg=msg)
        try:
            # Numerical DHCP option name
            option_number = int(dhcp_option['opt_name'])
            check_option_name(option_number, opt_name_to_number.values())
            dhcp_option['opt_name'] = option_number

        except ValueError:
            # Non-numerical DHCP option name
            check_option_name(dhcp_option['opt_name'], opt_name_to_number)
            dhcp_option['opt_name'] = opt_name_to_number[
                dhcp_option['opt_name']]

        dhcp_option['opt_value'] = (dhcp_option['opt_value'].split(";")
                                    if dhcp_option['opt_value'] else None)

    @staticmethod
    def _categorise_dhcp_options_for_update(old_dhcp_opts, new_dhcp_opts):
        add_dhcp_opts = []
        update_dhcp_opts = []
        delete_dhcp_opts = []
        existing_opts = set()
        for old_dhcp_opt in old_dhcp_opts:
            existing_opts.add(old_dhcp_opt['opt_name'])
        for new_dhcp_opt in new_dhcp_opts:
            if new_dhcp_opt['opt_name'] in existing_opts:
                if new_dhcp_opt['opt_value'] is not None:
                    update_dhcp_opts.append(new_dhcp_opt)
                else:
                    delete_dhcp_opts.append(new_dhcp_opt)
                existing_opts.remove(new_dhcp_opt['opt_name'])
            else:
                add_dhcp_opts.append(new_dhcp_opt)
        # Add remaining existing dhcp options to deleted.
        for dhcp_opt in existing_opts:
            delete_dhcp_opts.extend(
                [opt for opt in old_dhcp_opts if opt['opt_name'] == dhcp_opt])
        return {'new': add_dhcp_opts, 'update': update_dhcp_opts,
                'delete': delete_dhcp_opts}

    def _update_extra_dhcp_options(self, categorised_dhcp_opts, ip_version,
                                   subnet_mapping,
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
            LOG.error(_("Port Update failed due to: {}").format(e))
            raise
        try:
            # Delete
            delete_rollback = self._delete_extra_dhcp_options(
                categorised_dhcp_opts['delete'], vport, port_id)
            # Update
            update_rollback = self._create_update_extra_dhcp_options(
                categorised_dhcp_opts['update'], vport, port_id, True)
            if "error" in update_rollback:
                update_rollback.remove("error")
                e = update_rollback.pop(-1)
                include_rollback_opt = ([categorised_dhcp_opts['update'][i]
                                        ['opt_name'] for i in
                                        range(len(update_rollback))] +
                                        [categorised_dhcp_opts['delete'][i]
                                        ['opt_name'] for i in
                                        range(len(delete_rollback))])
                for dhcp_opt in old_dhcp_opts:
                    if dhcp_opt['opt_name'] not in include_rollback_opt:
                        old_dhcp_opts.remove(dhcp_opt)
                raise e
        except Exception as e:
            # Roll back create
            for rollback_opt in created_rollback_opts:
                self.vsdclient.delete_vport_dhcp_option(
                    rollback_opt[3][0]['ID'], ip_version, True)
            # Roll back update & delete
            self._create_update_extra_dhcp_options(old_dhcp_opts, vport,
                                                   port_id, True)
            LOG.error(_("Port Update failed due to: {}").format(e))
            raise e

    def _get_nuage_vport(self, port, subnet_mapping, required=True):
        port_params = {'neutron_port_id': port['id']}
        if self._is_l2(subnet_mapping):
            port_params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            port_params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        return self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params, required=required)

    def post_port_create_dhcp_opts(self, resource, event, trigger, port,
                                   vport, **kwargs):
        context = kwargs.get('context')
        port_db = port_obj.Port.get_object(context, id=port['id']).to_dict()
        port['extra_dhcp_opts'] = port_db.get('dhcp_options')

        if (not lib_validators.is_attr_set(port.get('extra_dhcp_opts')) or
                len(port.get('extra_dhcp_opts')) == 0):
            return

        dhcp_options = copy.deepcopy(port['extra_dhcp_opts'])
        for dhcp_opt in dhcp_options:
            self._translate_dhcp_option(dhcp_opt)
        self._create_update_extra_dhcp_options(
            dhcp_options, vport, port['id'])

    def post_port_update_dhcp_opts(self, resource, event, trigger,
                                   port, original_port, vport, subnet_mapping,
                                   **kwargs):
        if port['extra_dhcp_opts'] == original_port['extra_dhcp_opts']:
            return

        old_dhcp_options = (copy.deepcopy(original_port['extra_dhcp_opts'])
                            if original_port['extra_dhcp_opts'] else [])
        request_dhcp_options = (copy.deepcopy(port['extra_dhcp_opts'])
                                if port['extra_dhcp_opts'] else [])

        for ip_version in [4, 6]:
            self._post_port_update_dhcp_opts(original_port, vport,
                                             subnet_mapping,
                                             ip_version,
                                             request_dhcp_options,
                                             old_dhcp_options)

    def _post_port_update_dhcp_opts(self, port, vport, subnet_mapping,
                                    ip_version, request_dhcp_options,
                                    old_dhcp_options,):
        old_dhcp_options = [opt for opt in old_dhcp_options
                            if opt['ip_version'] == ip_version]
        request_dhcp_options = [opt for opt in request_dhcp_options
                                if opt['ip_version'] == ip_version]
        for dhcp_opt in request_dhcp_options:
            self._translate_dhcp_option(dhcp_opt)
        for dhcp_opt in old_dhcp_options:
            self._translate_dhcp_option(dhcp_opt)
        categorised_dhcp_opts = self._categorise_dhcp_options_for_update(
            old_dhcp_options, request_dhcp_options)
        self._update_extra_dhcp_options(categorised_dhcp_opts,
                                        ip_version,
                                        subnet_mapping,
                                        port['id'],
                                        port['device_owner'],
                                        old_dhcp_options, vport)
