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
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_redirect_target
from nuage_neutron.vsdclient import restproxy


class TestNuageRedirectTarget(testtools.TestCase):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(nuage_redirect_target.NuageRedirectTarget,
                       'core_plugin')
    def test_create_pg_for_rt(self, *_):
        driver = nuage_redirect_target.NuageRedirectTarget()
        fake_sg = {
            'security_group_rules': []
        }
        driver.core_plugin.get_security_group = mock.MagicMock(
            return_value=fake_sg)
        vsdclient_mock = mock.MagicMock()
        driver.vsdclient = vsdclient_mock
        vsdclient_mock.create_security_group_using_parent.side_effect = (
            restproxy.RESTProxyError(
                vsd_code=restproxy.REST_PG_EXISTS_ERR_CODE))
        rt = {'parentID': '1', 'parentType': 'l2domain'}
        pg = driver._create_pg_for_rt(mock.MagicMock(), mock.MagicMock(),
                                      rt, mock.MagicMock())
        self.assertIsNotNone(pg)
        vsdclient_mock.create_security_group_rules.assert_not_called()
        vsdclient_mock.get_nuage_l2domain_policy_groups.assert_called()
