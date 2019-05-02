# Copyright 2016 NOKIA
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

import abc

from neutron._i18n import _
from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib import exceptions as n_exc
import six

from nuage_neutron.plugins.common import constants


class SwitchportNotFound(n_exc.NotFound):
    message = _("Switchport %(id)s does not exist")


class SwitchportParamDuplicate(n_exc.InUse):
    message = _("Request failed - "
                "%(param_name)s %(param_value)s %(reason)s")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = "is already used"
        super(SwitchportParamDuplicate, self).__init__(**kwargs)


class SwitchportInUse(n_exc.InUse):
    message = _("Switchport %(id)s %(reason)s")

    def __init__(self, **kwargs):
        if 'reason' not in kwargs:
            kwargs['reason'] = "is in use"
        super(SwitchportInUse, self).__init__(**kwargs)


class SwitchportBindingNotFound(n_exc.NotFound):
    message = _("Switchport binding %(id)s does not exist")


class SwitchTypeNotSupported(n_exc.Conflict):
    message = _("Switch personality %(p)s is not supported")


NET_TOPOLOGY_PREFIX = '/net-topology'

SWITCHPORT_MAPPING = 'switchport_mapping'
SWITCHPORT_MAPPINGS = '%ss' % SWITCHPORT_MAPPING
SWITCHPORT_BINDING = 'switchport_binding'
SWITCHPORT_BINDINGS = '%ss' % SWITCHPORT_BINDING

RESOURCE_ATTRIBUTE_MAP = {
    SWITCHPORT_MAPPINGS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'switch_info': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'required': False,
                        'default': '',
                        'is_visible': True},
        'switch_id': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'port_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'port_uuid': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'host_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'pci_slot': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': False},
    },
    SWITCHPORT_BINDINGS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'neutron_port_id': {'allow_post': False, 'allow_put': False,
                            'validate': {'type:string': None},
                            'is_visible': True},
        'switch_id': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'port_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'port_uuid': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'nuage_vport_id': {'allow_post': False, 'allow_put': False,
                           'validate': {'type:string': None},
                           'is_visible': True},
        'segmentation_id': {'allow_post': False, 'allow_put': False,
                            'validate': {'type:string': None},
                            'is_visible': True},
    }
}


class Net_topology(extensions.ExtensionDescriptor):
    """Extension class supporting net-topology."""
    @classmethod
    def get_name(cls):
        return "net-topology"

    @classmethod
    def get_alias(cls):
        return "net-topology"

    @classmethod
    def get_description(cls):
        return "Nuage Net Topology extension"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/net_topology/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2016-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.NUAGE_NET_TOPOLOGY_SERVICE_PLUGIN,
            register_quota=True,
            allow_bulk=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class NuageNetTopologyPluginBase(object):

    path_prefix = NET_TOPOLOGY_PREFIX

    @abc.abstractmethod
    def create_switchport_mapping(self, context, gateway_mapping):
        pass

    @abc.abstractmethod
    def delete_switchport_mapping(self, context, id):
        pass

    @abc.abstractmethod
    def update_switchport_mapping(self, context, id, gateway_mapping):
        pass

    @abc.abstractmethod
    def get_switchport_mappings(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        pass

    @abc.abstractmethod
    def get_switchport_mapping(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_switchport_bindings(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        pass

    @abc.abstractmethod
    def get_switchport_binding(self, context, id, fields=None):
        pass
