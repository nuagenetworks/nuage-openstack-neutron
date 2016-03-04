# Copyright 2014 Alcatel-Lucent USA Inc.
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

from oslo_config import cfg

from neutron.api.v2 import attributes as attr


def convert_default_to_default_value(data):
    if data in ['default', 'DEFAULT']:
        return cfg.CONF.FIPRATE.default_fip_rate
    return data


def send_fip_rate_limit_info():
    msg = (_("'nuage_fip_rate' should be a number higher than 0, -1 for "
             "unlimited or 'default' for the configured default value."))
    return msg


def fip_rate_limit_validation(data, valid_values=None):
    if data is None:
        msg = _("Missing value for nuage_fip_rate")
        return msg

    if isinstance(data, bool):
        return send_fip_rate_limit_info()

    try:
        data = float(data)
    except (ValueError, TypeError):
        return send_fip_rate_limit_info()

    if data < -1:
        return send_fip_rate_limit_info()

attr.validators['type:fip_rate_valid'] = fip_rate_limit_validation


EXTENDED_ATTRIBUTES_2_0 = {
    'floatingips': {
        'nuage_fip_rate': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': attr.ATTR_NOT_SPECIFIED,
            'validate': {'type:fip_rate_valid': None},
            'convert_to': convert_default_to_default_value,
            'enforce_policy': True
        }
    }
}


class Nuage_floatingip(object):
    """Extension class supporting nuage floatingip."""

    @classmethod
    def get_name(cls):
        return "Nuage floatingip"

    @classmethod
    def get_alias(cls):
        return "nuage-floatingip"

    @classmethod
    def get_description(cls):
        return "Nuage Floatingip"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/floatingips/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
