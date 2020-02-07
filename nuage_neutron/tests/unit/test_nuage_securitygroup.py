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
import testtools

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.nuage_ml2 import securitygroup
from nuage_neutron.vsdclient import restproxy


class TestNuageSecurityGroup(testtools.TestCase):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(securitygroup.NuageSecurityGroup, 'core_plugin')
    def test_create_policygroup(self, *_):
        driver = securitygroup.NuageSecurityGroup()
        fake_sg = {
            'security_group_rules': []
        }
        driver.core_plugin.get_security_group = mock.MagicMock(
            return_value=fake_sg)
        vsd_mock = mock.MagicMock()
        driver.vsdclient = vsd_mock
        vsd_mock.create_security_group.side_effect = (
            restproxy.RESTProxyError(
                'fake_error', vsd_code=restproxy.REST_PG_EXISTS_ERR_CODE))
        driver._create_policygroup(mock.MagicMock(), mock.MagicMock(),
                                   mock.MagicMock())
        vsd_mock.create_security_group_rules.assert_not_called()
