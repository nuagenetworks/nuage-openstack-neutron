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

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions


EXTENDED_ATTRIBUTES_2_0 = {
    'security_groups': {
        'stateful': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': True,
            'convert_to': converters.convert_to_boolean,
        },
    },
}


class Nuage_securitygroup(api_extensions.ExtensionDescriptor):
    """Extension class supporting nuage router."""

    @classmethod
    def get_name(cls):
        return "Nuage security group"

    @classmethod
    def get_alias(cls):
        return "nuage-security-group"

    @classmethod
    def get_description(cls):
        return "Nuage Security group"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/security_groups/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2018-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
