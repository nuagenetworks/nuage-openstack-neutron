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
from nuage_neutron.vsdclient.impl.vsdclientimpl import VsdClientImpl


@mock.patch.object(nuagedb, 'get_subnet_l2dom_by_id', return_value=None)
@mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
@mock.patch.object(NuageMechanismDriver, '_validate_mech_nuage_configuration')
@mock.patch('nuage_neutron.vsdclient.impl.vsdclientimpl.restproxy')
class NuageMechanismDriverTest(Ml2PluginV2TestCase):

    @classmethod
    def setUpClass(cls):
        super(NuageMechanismDriverTest, cls).setUpClass()
        cfg.CONF.set_override("cms_id", 'Dummy', "RESTPROXY")
        VsdClientImpl.set_auth_key_renewal(False)

    def _get_mech_driver(self):
        mech_driver = NuageMechanismDriver()
        mech_driver.initialize()
        mech_driver.core_plugin._create_port_db = MagicMock()
        return mech_driver

    def _get_context(self, network, subnet):
        context = MagicMock()
        context.network.current = network
        context.current = subnet
        return context

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

    def test_create_subnet_ingress_replication(self, *_):
        """test_create_subnet_ingress_replication

        Test that when enable_ingress_replication is enabled, the l2domain
        is created with ingressReplicationEnabled set to True
        """
        cfg.CONF.set_override("enable_ingress_replication", 'True', "PLUGIN")
        mech_driver = self._get_mech_driver()
        with self.network() as network, \
                self.subnet(network={'network': network}) as subnet:
            # Mock plugin context
            context = self._get_context(network, subnet)
            mech_driver.core_plugin.get_network = mock.Mock(
                return_value=network)
            mech_driver.create_subnet_precommit(context)
            # Verification
            # Verify that call to /enterprise/.*/l2domains was successful
            # with correct ingress replication
            restproxy = mech_driver.vsdclient.restproxy
            post_args = [
                call[0][1] for call in restproxy.post.call_args_list if
                re.compile("/enterprises/.*/l2domains").match(call[0][0])][0]
            self.assertTrue(post_args.get('ingressReplicationEnabled'))
