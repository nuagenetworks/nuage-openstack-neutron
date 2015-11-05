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

from neutron.api.v2.attributes import is_attr_set
from neutron.plugins.ml2 import driver_api as api

LOG = logging.getLogger(__name__)


class NuagePortExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'nuage-redirect-target'

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_port(self, plugin_context, data, result):
        if is_attr_set(data.get('nuage_redirect_targets')):
            result['nuage_redirect_targets'] = data['nuage_redirect_targets']
        else:
            result['nuage_redirect_targets'] = None

    def process_update_port(self, plugin_context, data, result):
        if is_attr_set(data.get('nuage_redirect_targets')):
            result['nuage_redirect_targets'] = data['nuage_redirect_targets']

    def extend_port_dict(self, session, base_model, result):
        return result
