# Copyright 2015 Intel Corporation.
# All Rights Reserved.
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

from oslo_log import log as logging

from neutron.plugins.ml2 import driver_api as api

from nuage_neutron.plugins.common import addresspair
from nuage_neutron.plugins.common import port_dhcp_options

LOG = logging.getLogger(__name__)


class NuagePortExtensionDriver(addresspair.NuageAddressPair,
                               port_dhcp_options.PortDHCPOptionsNuage,
                               api.ExtensionDriver):
    _supported_extension_alias = 'nuage-redirect-target'

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_port(self, plugin_context, data, result):
        # We can't process port nuage extensions here because this is called
        # inside a transaction and we must talk with a VSD multiple times.
        # So the request data is copied over into the result so the mechanism
        # driver can deal with it outside of a transaction.
        if 'request_port' not in result:
            result['request_port'] = data

    def process_update_port(self, plugin_context, data, result):
        # We can't process port nuage extensions here because this is called
        # inside a transaction and we must talk with a VSD multiple times.
        # So the request data is copied over into the result so the mechanism
        # driver can deal with it outside of a transaction.
        if 'request_port' not in result:
            result['request_port'] = data
