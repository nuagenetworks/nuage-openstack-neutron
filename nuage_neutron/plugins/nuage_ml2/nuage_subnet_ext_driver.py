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

from neutron.db.models import external_net
from neutron.plugins.ml2 import driver_api as api
from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import nuagedb
from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


class NuageSubnetExtensionDriver(api.ExtensionDriver,
                                 base_plugin.RootNuagePlugin):
    _supported_extension_alias = 'nuage-subnet'

    def initialize(self):
        super(NuageSubnetExtensionDriver, self).__init__()
        self.init_vsd_client()

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def _is_network_external(self, session, net_id):
        try:
            session.query(
                external_net.ExternalNetwork).filter_by(
                    network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def process_create_subnet(self, plugin_context, data, result):
        result['net_partition'] = data['net_partition']
        result['nuagenet'] = data['nuagenet']
        result['underlay'] = data['underlay']
        result['nuage_uplink'] = data['nuage_uplink']

    def extend_subnet_dict(self, session, db_data, result):
        if self._is_network_external(session, db_data['network_id']):
            try:
                nuage_subnet = self.get_vsd_shared_subnet_attributes(
                    result['id'])
            except Exception as e:
                LOG.exception(e)
                raise
            if nuage_subnet:
                result['underlay'] = nuage_subnet['underlay']
                result['nuage_uplink'] = nuage_subnet['sharedResourceParentID']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session, result['id'])
        if subnet_mapping:
            result['vsd_managed'] = subnet_mapping['nuage_managed_subnet']
        else:
            result['vsd_managed'] = False
        return result
