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

from neutron.common import utils
from neutron.plugins.ml2 import driver_api as api

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import nuagedb


LOG = logging.getLogger(__name__)


class NuageNetworkExtensionDriver(api.ExtensionDriver,
                                  base_plugin.RootNuagePlugin):
    _supported_extension_alias = 'nuage-network'

    def initialize(self):
        super(NuageNetworkExtensionDriver, self).__init__()
        self.init_vsd_client()

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    @utils.exception_logger()
    def extend_network_dict(self, session, db_data, result):
        result['nuage_l2bridge'] = nuagedb.get_nuage_l2bridge_id_for_network(
            session, result['id'])
        return result
