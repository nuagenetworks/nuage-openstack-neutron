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

from neutron.common import utils
from neutron.db.models import external_net
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants as nuage_constants
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.time_tracker import TimeTracker

from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


class NuageSubnetExtensionDriver(api.ExtensionDriver,
                                 base_plugin.RootNuagePlugin):
    _supported_extension_alias = 'nuage-subnet'

    def initialize(self):
        super(NuageSubnetExtensionDriver, self).__init__()
        self.init_vsd_client()
        # keep track of values
        self.val_by_id = {}

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def _is_network_external(self, session, net_id):
        try:
            session.query(external_net.ExternalNetwork)\
                .filter_by(network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _store_change(self, result, data, field):
        # Due to ml2 plugin result does not get passed to our plugin
        if field in data and data[field] != constants.ATTR_NOT_SPECIFIED:
            if field == nuage_constants.NUAGE_UNDERLAY:
                self.val_by_id[(result['id'], field)] = data[field]
            result[field] = data[field]

    def process_create_subnet(self, plugin_context, data, result):
        self._copy_nuage_attributes(data, result)
        # Make sure nuage_underlay is not processed as part of create
        result.pop(nuage_constants.NUAGE_UNDERLAY, None)

    def process_update_subnet(self, plugin_context, data, result):
        self._copy_nuage_attributes(data, result)

    def _copy_nuage_attributes(self, data, result):
        nuage_attributes = ('net_partition', 'nuagenet', 'underlay',
                            'nuage_uplink', nuage_constants.NUAGE_UNDERLAY)
        for attribute in nuage_attributes:
                self._store_change(result, data, attribute)

    @utils.exception_logger()
    @TimeTracker.tracked
    def extend_subnet_dict(self, session, db_data, result):
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session, result['id'])
        if subnet_mapping:
            result['vsd_managed'] = subnet_mapping['nuage_managed_subnet']
        else:
            result['vsd_managed'] = False

        if self._is_network_external(session, db_data['network_id']):
            nuage_subnet = self.get_vsd_shared_subnet_attributes(
                result['id'])
            if nuage_subnet:
                result['underlay'] = nuage_subnet['underlay']
                result['nuage_uplink'] = nuage_subnet['sharedResourceParentID']
        else:
            # Add nuage_underlay parameter
            update = self.val_by_id.pop(
                (result['id'], nuage_constants.NUAGE_UNDERLAY),
                constants.ATTR_NOT_SPECIFIED)
            nuage_underlay_db = nuagedb.get_subnet_parameter(
                session, result['id'], nuage_constants.NUAGE_UNDERLAY)

            if (update is constants.ATTR_NOT_SPECIFIED
                    and not result['vsd_managed']
                    and not result['ip_version'] == constants.IP_VERSION_6
                    and subnet_mapping
                    and not subnet_mapping['nuage_l2dom_tmplt_id']):
                # No update, db value
                result['nuage_underlay'] = (
                    nuage_underlay_db['parameter_value']
                    if nuage_underlay_db else
                    nuage_constants.NUAGE_UNDERLAY_INHERITED)
            elif (update is not constants.ATTR_NOT_SPECIFIED
                  and update != nuage_underlay_db):
                # update + change
                result['nuage_underlay'] = update
        return result
