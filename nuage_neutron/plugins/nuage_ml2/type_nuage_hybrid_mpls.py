# Copyright 2020 Nokia.
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

from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_log import log


from neutron.plugins.ml2.drivers import helpers

from nuage_neutron.plugins.common import constants


LOG = log.getLogger(__name__)


class NuageHybridMplsTypeDriver(helpers.BaseTypeDriver):
    """Manage state for Nuage Hybrid_MPLS networks

    The NuageHybridMplsTypeDriver implements networks for
    the Segment Routing Native Integration
    """

    def __init__(self):
        super(NuageHybridMplsTypeDriver, self).__init__()

    def get_type(self):
        return constants.NUAGE_HYBRID_MPLS_NET_TYPE

    def initialize(self):
        LOG.info('ML2 NuageHybridMplsTypeDriver initialization complete')

    def initialize_network_segment_range_support(self):
        pass

    def update_network_segment_range_allocations(self):
        pass

    def get_network_segment_ranges(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        for key, value in segment.items():
            if value and key != api.NETWORK_TYPE:
                msg = ('{} prohibited for nuage_hybrid_mpls provider '
                       'network').format(key)
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment, filters=None):
        # No resources to reserve
        return segment

    def allocate_tenant_segment(self, context, filters=None):
        # No resources to allocate
        return

    def release_segment(self, context, segment):
        # No resources to release
        return segment

    def get_mtu(self, physical_network=None):
        seg_mtu = super(NuageHybridMplsTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0
