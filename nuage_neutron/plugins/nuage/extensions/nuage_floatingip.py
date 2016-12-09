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

from neutron._i18n import _
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators as lib_validators
from neutron_lib import constants as lib_constants
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc


def convert_default_to_default_value(data):
    if data in ['default', 'DEFAULT']:
        return cfg.CONF.FIPRATE.default_fip_rate
    return data


def convert_egress_default_to_default_value(data):
    if data in ['default', 'DEFAULT']:
        return cfg.CONF.FIPRATE.default_egress_fip_rate_kbps
    return data


def convert_ingress_default_to_default_value(data):
    if data in ['default', 'DEFAULT']:
        return cfg.CONF.FIPRATE.default_ingress_fip_rate_kbps
    return data


def send_fip_rate_limit_info(attribute):
    msg = (_("'%s' should be a number higher than 0, -1 for "
             "unlimited or 'default' for the configured default value.")
           % attribute)
    raise nuage_exc.NuageBadRequest(msg=msg)


def fip_value_validator(fip_value, attribute, units='mbps'):
    if fip_value is None:
        msg = (_("Missing value for %s") % attribute)
        raise nuage_exc.NuageBadRequest(msg=msg)
    if isinstance(fip_value, bool):
        return send_fip_rate_limit_info(attribute)
    try:
        fip_value = float(fip_value)
        if units == 'kbps' and int(fip_value) != fip_value:
            msg = (_('%s value cannot be in fraction') % attribute)
            raise nuage_exc.NuageBadRequest(msg=msg)
        else:
            fip_value = int(fip_value)
    except (ValueError, TypeError):
        return send_fip_rate_limit_info(attribute)

    if fip_value < -1:
        return send_fip_rate_limit_info(attribute)

    if fip_value > constants.MAX_VSD_INTEGER:
        msg = (_("%(attr)s cannot be > %(max)s") %
               {'attr': attribute,
                'max': constants.MAX_VSD_INTEGER})
        raise nuage_exc.NuageBadRequest(msg=msg)


def fip_rate_limit_validation(data, valid_values=None):
    fip_value_validator(data, "nuage_fip_rate")


def egress_limit_validation_kbps(data, valid_values=None):
    fip_value_validator(data, "nuage_egress_fip_rate_kbps", units='kbps')


def ingress_limit_validation_kbps(data, valid_values=None):
    fip_value_validator(data, "nuage_ingress_fip_rate_kbps", units='kbps')

lib_validators.add_validator('type:fip_rate_valid', fip_rate_limit_validation)
lib_validators.add_validator('type:egress_rate_valid_kbps',
                             egress_limit_validation_kbps)
lib_validators.add_validator('type:ingress_rate_valid_kbps',
                             ingress_limit_validation_kbps)


EXTENDED_ATTRIBUTES_2_0 = {
    'floatingips': {
        'nuage_fip_rate': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'validate': {'type:fip_rate_valid': None},
            'convert_to': convert_default_to_default_value,
            'enforce_policy': True
        },
        'nuage_ingress_fip_rate_kbps': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'validate': {'type:ingress_rate_valid_kbps': None},
            'convert_to': convert_ingress_default_to_default_value,
            'enforce_policy': True
        },
        'nuage_egress_fip_rate_kbps': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': lib_constants.ATTR_NOT_SPECIFIED,
            'validate': {'type:egress_rate_valid_kbps': None},
            'convert_to': convert_egress_default_to_default_value,
            'enforce_policy': True
        }
    }
}


class Nuage_floatingip(api_extensions.ExtensionDescriptor):
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
