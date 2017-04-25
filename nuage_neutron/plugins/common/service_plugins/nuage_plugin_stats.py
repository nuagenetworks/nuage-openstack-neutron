# Copyright 2017 NOKIA
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

from neutron.services import service_base
from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants


class NuagePluginStats(service_base.ServicePluginBase,
                       BaseNuagePlugin):

    supported_extension_aliases = ['nuage-plugin-stats']

    def get_plugin_type(self):
        return constants.NUAGE_PLUGIN_STATS

    def get_plugin_description(self):
        return ("Nuage Plugin Statistics")

    def get_nuage_plugin_stats(self, context, filters=None, fields=None):
        return [self.vsdclient.get_nuage_plugin_stats()]
