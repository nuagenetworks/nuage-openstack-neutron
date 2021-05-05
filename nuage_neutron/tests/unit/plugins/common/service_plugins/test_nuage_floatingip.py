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

from unittest import mock
from unittest.mock import MagicMock

import testtools

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_floatingip


@mock.patch.object(RootNuagePlugin, 'init_vsd_client')
class TestNuageFloatingIP(testtools.TestCase):

    def test_process_port_nuage_floatingip_rollback(self, *_):
        """_process_port_nuage_floatingip

        process_port_nuage_floatingip uses the rollback mechanism of
        the nuage_callbacks.
        Simulate creation of a nuage floating ip and check that rollback
        is executed correctly.

        """
        driver = nuage_floatingip.NuageFloatingip()
        driver.vsdclient = MagicMock()
        driver.vsdclient.get_nuage_floatingip.return_value = {
            'ID': 'new_fip_id', 'externalID': ''}
        event = constants.AFTER_UPDATE
        rollbacks = []
        request_port = {'nuage_floatingip': {'id': 'new_fip_id'}}
        vport = {'ID': 'vport_id', 'associatedFloatingIPID': 'old_fip_id'}
        driver._process_port_nuage_floatingip(event, request_port, rollbacks,
                                              vport)

        # Normal flow: assert vsdclient called with correct association
        driver.vsdclient.update_vport.assert_called_with(
            'vport_id', {'associatedFloatingIPID': 'new_fip_id'})

        # Execute rollback
        for f, args, kwargs in rollbacks:
            f(*args, **kwargs)

        # Assert vsdclient called with original association
        driver.vsdclient.update_vport.assert_called_with(
            'vport_id', {'associatedFloatingIPID': 'old_fip_id'})
