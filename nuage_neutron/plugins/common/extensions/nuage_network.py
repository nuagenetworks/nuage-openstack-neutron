# Copyright 2018 NOKIA
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

from neutron.api import extensions


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'nuage_l2bridge': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True,
            'enforce_policy': True
        }
    }
}


class Nuage_network(extensions.ExtensionDescriptor):
    """Extension class supporting Nuage network."""

    @classmethod
    def get_name(cls):
        return "Nuage network"

    @classmethod
    def get_alias(cls):
        return "nuage-network"

    @classmethod
    def get_description(cls):
        return "Nuage network"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/networks/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2018-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
