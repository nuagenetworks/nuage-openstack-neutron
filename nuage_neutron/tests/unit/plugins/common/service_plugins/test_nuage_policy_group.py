# Copyright 2020 NOKIA
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
import mock
from mock import MagicMock
import testtools

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_policy_group


@mock.patch.object(RootNuagePlugin, 'init_vsd_client')
class TestNuagePolicygroupPlugin(testtools.TestCase):

    def test_process_port_nuage_policy_group_rollback(self, *_):
        """_process_port_nuage_policy_group

        _process_port_nuage_policy_group uses the rollback mechanism of
        the nuage_callbacks.
        Simulate association of a nuage policy group and check that rollback
        is executed correctly.
        """
        driver = nuage_policy_group.NuagePolicyGroup()
        driver.vsdclient = MagicMock()
        driver.vsdclient.get_nuage_policy_group.return_value = {
            'ID': 'new_pg', 'externalID': ''}
        driver.vsdclient.get_nuage_vport_policy_groups.return_value = [
            {'ID': 'old_pg'}
        ]
        event = constants.AFTER_UPDATE
        rollbacks = []
        new_port = {'id': 'port_id', 'nuage_policy_groups': ['new_pg']}
        vport = {'ID': 'vport_id', 'associatedFloatingIPID': 'old_fip_id'}
        driver._process_port_nuage_policy_group(event, new_port,
                                                rollbacks,
                                                vport)

        # Normal flow: assert vsdclient called with correct association
        driver.vsdclient.update_vport_policygroups.assert_called_with(
            'vport_id', ['new_pg'])

        # Execute rollback
        for f, args, kwargs in rollbacks:
            f(*args, **kwargs)
        # Assert vsdclient called with original association
        driver.vsdclient.update_vport_policygroups.assert_called_with(
            'vport_id', ['old_pg'])
