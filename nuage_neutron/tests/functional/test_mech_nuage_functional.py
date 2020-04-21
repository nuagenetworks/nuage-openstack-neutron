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

import contextlib
import re

import mock
from mock import MagicMock
from oslo_config import cfg

from neutron.tests.unit.plugins.ml2.test_plugin import Ml2PluginV2TestCase

from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.nuage_ml2.mech_nuage import NuageMechanismDriver
from nuage_neutron.vsdclient.common import helper


@mock.patch.object(nuagedb, 'get_subnet_l2dom_by_id', return_value=None)
@mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
@mock.patch.object(NuageMechanismDriver, '_validate_mech_nuage_configuration')
@mock.patch('nuage_neutron.vsdclient.impl.vsdclientimpl.restproxy')
class NuageMechanismDriverTest(Ml2PluginV2TestCase):

    @staticmethod
    def _get_mech_driver():
        mech_driver = NuageMechanismDriver()
        mech_driver.initialize()
        mech_driver.core_plugin._create_port_db = MagicMock()
        mech_driver.vsdclient.set_auth_key_renewal(False)
        return mech_driver

    @staticmethod
    def _get_context(network, subnet):
        context = MagicMock()
        context.network.current = network
        context.current = subnet
        return context

    def assertInAndFalse(self, needle, haystack):
        self.assertFalse(haystack.get(needle),
                         "{} does not have '{}' set False".format(
                             haystack, needle))

    def assertInAndTrue(self, needle, haystack):
        self.assertTrue(haystack.get(needle),
                        "{} does not have '{}' set True".format(
                            haystack, needle))

    def setUp(self):
        super(NuageMechanismDriverTest, self).setUp()
        cfg.CONF.set_override("cms_id", '1', "RESTPROXY")

    def tearDown(self):
        super(NuageMechanismDriverTest, self).tearDown()
        helper.cache = {}  # clear the memoize cache

    @contextlib.contextmanager
    def network(self, name='net1',
                admin_state_up=True,
                fmt=None,
                **kwargs):
        network = self._make_network(fmt or self.fmt, name,
                                     admin_state_up, **kwargs)
        network['network']['provider:network_type'] = 'vxlan'
        network['network']['shared'] = False
        yield network['network']

    @contextlib.contextmanager
    def subnet(self, **kwargs):
        with super(NuageMechanismDriverTest, self).subnet(**kwargs) as subnet:
            subnet['subnet']['nuage_l2bridge'] = None
            yield subnet['subnet']

    def _create_subnet_and_get_post_args(self, req_matcher='.'):
        mech_driver = self._get_mech_driver()
        with self.network() as network, \
                self.subnet(network={'network': network}) as subnet:
            # Mock plugin context
            context = NuageMechanismDriverTest._get_context(network, subnet)
            mech_driver.core_plugin.get_network = mock.Mock(
                return_value=network)
            mech_driver.create_subnet_precommit(context)
            rest_proxy = mech_driver.vsdclient.restproxy
            return [{'resource': call[0][0], 'data': call[0][1]}
                    for call in rest_proxy.post.call_args_list
                    if re.compile(req_matcher).match(call[0][0])]

    def test_create_subnet_post_resources(self, *_):
        """test_create_subnet_post_reqs

        Test the post requests made on create subnet
        """
        post_args = self._create_subnet_and_get_post_args()
        expected_post_resources = [
            '/enterprises/.*/l2domaintemplates',
            '/enterprises/.*/l2domains',
            '/l2domains/.*/dhcpoptions',
            '/l2domains/.*/permissions',
            '/l2domains/.*/ingressacltemplates',
            '/l2domains/.*/egressacltemplates',
            '/l2domains/.*/ingressadvfwdtemplates'
        ]
        self.assertEqual(len(expected_post_resources), len(post_args))
        for i in range(len(expected_post_resources)):
            self.assertTrue(re.compile(expected_post_resources[i]).match(
                str(post_args[i]['resource'])),
                '{} does not match {}'.format(post_args[i]['resource'],
                                              expected_post_resources[i]))

    def test_create_subnet_allow_non_ip_disabled_by_default(self, *_):
        """test_create_subnet_allow_non_ip_disabled_by_default

        Test that by default l2domain is created with allow_now_ip
        set to False
        """
        post_args = self._create_subnet_and_get_post_args(
            '/l2domains/.*/.*acltemplates')
        # check ingress and egress
        self.assertEqual(2, len(post_args))
        for arg in post_args:
            self.assertInAndFalse('defaultAllowNonIP', arg['data'])

    def test_create_subnet_allow_non_ip_enabled(self, *_):
        """test_create_subnet_allow_non_ip_enabled

        Test that when default_allow_non_ip is enabled, the l2domain
        is created with allow_non_ip set to True
        """
        cfg.CONF.set_override('default_allow_non_ip', 'True', 'PLUGIN')
        post_args = self._create_subnet_and_get_post_args(
            '/l2domains/.*/.*acltemplates')
        # check ingress and egress
        self.assertEqual(2, len(post_args))
        for arg in post_args:
            self.assertInAndTrue('defaultAllowNonIP', arg['data'])

    def test_create_subnet_ingress_replication_disabled_by_default(self, *_):
        """test_create_subnet_ingress_replication_disabled_by_default

        Test that by default l2domain is created with ingressReplicationEnabled
        set to False
        """
        post_args = self._create_subnet_and_get_post_args(
            '/enterprises/.*/l2domains')
        self.assertEqual(1, len(post_args))
        self.assertInAndFalse('ingressReplicationEnabled',
                              post_args[0]['data'])

    def test_create_subnet_ingress_replication_enabled(self, *_):
        """test_create_subnet_ingress_replication_enabled

        Test that when enable_ingress_replication is enabled, the l2domain
        is created with ingressReplicationEnabled set to True
        """
        cfg.CONF.set_override('enable_ingress_replication', 'True', 'PLUGIN')
        post_args = self._create_subnet_and_get_post_args(
            '/enterprises/.*/l2domains')
        self.assertEqual(1, len(post_args))
        self.assertInAndTrue('ingressReplicationEnabled',
                             post_args[0]['data'])
