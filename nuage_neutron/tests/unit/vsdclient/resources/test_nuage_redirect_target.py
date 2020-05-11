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
from mock import Mock
import testtools

from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.resources.policygroups import NuageRedirectTargets
from nuage_neutron.vsdclient.restproxy import RESTProxyServer


class TestNuageRedirectTarget(testtools.TestCase):

    @mock.patch.object(RESTProxyServer, 'rest_call')
    @mock.patch.object(RESTProxyServer, 'retrieve_by_ext_id_and_priority',
                       return_value=['fake_return_object'])
    @mock.patch.object(helper, 'get_in_adv_fwd_policy',
                       return_value='fake_pg_id')
    @mock.patch.object(helper, 'get_l3domain_np_id',
                       return_value='fake_np_id')
    @mock.patch.object(NuageRedirectTargets,
                       '_map_nuage_redirect_target_rule',
                       return_value={'externalID': '123'})
    @mock.patch.object(NuageRedirectTargets,
                       '_process_redirect_target_rule',
                       return_value='fake_fwd_rule')
    def test_redirect_target_rule_exists(self, *_):
        server = RESTProxyServer(Mock(), Mock(), Mock(), Mock(),
                                 Mock(), Mock(), Mock())
        redirect_target = NuageRedirectTargets(server)
        fake_rt_rule = {'parentType': 'domain', 'parentID': '1',
                        'externalID': '123'}
        server.retrieve_by_ext_id_and_priority.__name__ = (
            'retrieve_by_ext_id_and_priority')
        server.rest_call.return_value = [
            409, None, None, '{"internalErrorCode": 2591}']
        redirect_target.create_nuage_redirect_target_rule(
            mock.MagicMock(), fake_rt_rule)
        server.retrieve_by_ext_id_and_priority.assert_called()
        redirect_target._process_redirect_target_rule.assert_called_with(
            'fake_return_object')
