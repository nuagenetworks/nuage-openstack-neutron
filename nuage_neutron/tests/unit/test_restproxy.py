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
from unittest.mock import Mock

import testtools

from nuage_neutron.vsdclient import restproxy
from nuage_neutron.vsdclient.restproxy import RESTProxyServer


class TestNuageRestproxy(testtools.TestCase):

    @mock.patch.object(RESTProxyServer, 'rest_call')
    @mock.patch('nuage_neutron.vsdclient.restproxy.LOG')
    def test_post_on_res_exists(self, log_mock, rest_call_mock):
        """test_post_on_res_exists

        Test that when there is a conflict, the on_res_exist method is called
        upon. When successful the correct log message is executed.
        """
        rest_call_mock.return_value = [409, None, None,
                                       '{"internalErrorCode": 2510}']
        server = RESTProxyServer(Mock(), Mock(), Mock(), Mock(), Mock(),
                                 Mock(), Mock())
        on_res_exists = MagicMock(return_value='fake_return_object')
        on_res_exists.__name__ = 'on_res_exists'
        returned_value = server.post(Mock(), Mock(),
                                     on_res_exists=on_res_exists)
        on_res_exists.assert_called()
        self.assertEqual('fake_return_object', returned_value)
        # assert LOG is getting called correctly
        log_mock.debug.assert_any_call('Received %s from VSD with '
                                       'internalErrorCode %s. Trying '
                                       '%s to recover.', 409, 2510,
                                       "on_res_exists")
        log_mock.debug.assert_called_with('Recovery from %s successful.', 409)

    @mock.patch.object(RESTProxyServer, 'rest_call')
    @mock.patch('nuage_neutron.vsdclient.restproxy.LOG')
    def test_post_on_res_exists_neg(self, log_mock, rest_call_mock):
        """test_post_on_res_exists_neg

        Test that when there is a conflict, the on_res_exist method is called
        upon. When this method fails, the correct Exception and log calls are
        executed.
        """
        rest_call_mock.return_value = [
            409, None, None, '{"internalErrorCode": 2510, '
                             '"errors": [{"descriptions": '
                             '[{"description": "fake_msg"}]}]}']
        server = RESTProxyServer(Mock(), Mock(), Mock(), Mock(), Mock(),
                                 Mock(), Mock())
        on_res_exists = MagicMock(return_value=None)
        on_res_exists.__name__ = 'on_res_exists'
        self.assertRaisesRegex(restproxy.RESTProxyError,
                               'Error in REST call to VSD: fake_msg',
                               server.post, Mock(), Mock(),
                               on_res_exists=on_res_exists)
        on_res_exists.assert_called()
        # assert LOG is getting called correctly
        log_mock.debug.assert_any_call('Received %s from VSD with '
                                       'internalErrorCode %s. Trying '
                                       '%s to recover.', 409, 2510,
                                       "on_res_exists")
        log_mock.debug.assert_called_with('Recovery from %s unsuccessful.',
                                          409)
