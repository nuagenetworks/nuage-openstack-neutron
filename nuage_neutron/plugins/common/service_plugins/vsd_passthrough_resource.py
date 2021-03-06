# Copyright 2016 Alcatel-Lucent USA Inc.
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

import six

from neutron._i18n import _

from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import utils as nuage_utils


class VsdPassthroughResource(BaseNuagePlugin):
    vsd_to_os = {}
    os_to_vsd = {}
    vsd_filterables = []
    extra_filters = []
    filters_to_ignore = ['tenant_id']

    def osfilters_to_vsdfilters(self, filters):
        for f in self.filters_to_ignore:
            filters.pop(f, None)
        if not all(x in self.vsd_filterables for x in filters or []):
            msg = (_("Only %s are filterable fields")
                   % (self.vsd_filterables + self.extra_filters))
            raise exceptions.NuageBadRequest(msg=msg)
        return nuage_utils.filters_to_vsd_filters(self.vsd_filterables,
                                                  filters,
                                                  self.os_to_vsd)

    def map_vsd_to_os(self, resource, fields=None):
        return self._translate_dict(resource, self.vsd_to_os, fields=fields)

    def map_os_to_vsd(self, resource, fields=None):
        return self._translate_dict(resource, self.os_to_vsd, fields=fields)

    def _translate_dict(self, resource, translation_mapping, fields=None):
        dict = {}
        for key, value in six.iteritems(translation_mapping):
            if hasattr(value, '__call__'):
                value(resource, dict)
            elif key in resource:
                dict[value] = resource[key]
        return self._fields(dict, fields)
