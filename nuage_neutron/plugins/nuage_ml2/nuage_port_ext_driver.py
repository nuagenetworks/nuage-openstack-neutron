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

from neutron_lib import constants
from neutron_lib.plugins.ml2 import api

from nuage_neutron.plugins.common import addresspair
from nuage_neutron.plugins.common.extensions import nuage_redirect_target
from nuage_neutron.plugins.common.extensions import nuagefloatingip
from nuage_neutron.plugins.common.extensions import nuagepolicygroup
from nuage_neutron.plugins.common import port_dhcp_options

LOG = logging.getLogger(__name__)


class NuagePortExtensionDriver(addresspair.NuageAddressPair,
                               port_dhcp_options.PortDHCPOptionsNuage,
                               api.ExtensionDriver):

    def initialize(self):
        port_dhcp_options.PortDHCPOptionsNuage.subscribe(self)

    def process_create_port(self, plugin_context, data, result):
        self._copy_nuage_attributes(data, result)

    def process_update_port(self, plugin_context, data, result):
        self._copy_nuage_attributes(data, result)

    def _copy_nuage_attributes(self, data, result):
        nuage_attributes = (nuage_redirect_target.REDIRECTTARGETS,
                            nuagepolicygroup.NUAGE_POLICY_GROUPS,
                            nuagefloatingip.NUAGE_FLOATINGIP)
        for attribute in nuage_attributes:
            if (attribute in data and
                    data[attribute] != constants.ATTR_NOT_SPECIFIED):
                result[attribute] = data[attribute]
