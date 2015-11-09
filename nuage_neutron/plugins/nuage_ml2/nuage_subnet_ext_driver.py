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


class NuageSubnetExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'nuage-subnet'

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_subnet(self, plugin_context, data, result):
        result['net_partition'] = data['net_partition']
        result['nuagenet'] = data['nuagenet']
        result['custom_pools'] = is_attr_set(data['allocation_pools'])
        result['custom_gateway'] = is_attr_set(data['gateway_ip'])

    def extend_subnet_dict(self, session, db_data, result):
        return result
