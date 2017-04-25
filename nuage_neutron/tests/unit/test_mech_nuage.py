# Copyright 2016 NOKIA
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

# run me using :
# python -m testtools.run nuage_neutron/tests/unit/test_mech_nuage.py

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.nuage_ml2.mech_nuage import NuageMechanismDriver
from oslo_context import context

import mock
import testtools
import traceback

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture


class TestNuageMechanismDriverNative(testtools.TestCase):

    def test_init_nmd_invalid_server(self):
        nmd = NuageMechanismDriver()
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='RESTPROXY', server='localhost:9876')
        conf.config(group='RESTPROXY', server_timeout=1)
        conf.config(group='RESTPROXY', server_max_retries=1)
        conf.config(group='RESTPROXY', cms_id='1')
        try:
            nmd.initialize()
            self.fail()  # should not get here
        except Exception as e:
            if str(e) != 'Could not establish conn with REST server. Abort':
                traceback.print_exc()
                raise e


class TestNuageMechanismDriverMocked(testtools.TestCase):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_create_subnet_precommit_no_nuage(self, mock):
        nmd = NuageMechanismDriver()
        nmd.initialize()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_create_subnet_precommit_nuage(self, mock):
        nmd = NuageMechanismDriver()
        nmd.initialize()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'partyland'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch('nuage_neutron.plugins.nuage_ml2.mech_nuage.LOG')
    def test_experimental_feature(self, logger, root_plugin):
        config.nuage_register_cfg_opts()
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

        conf.config(group='PLUGIN', experimental_features='experimental_test')
        NuageMechanismDriver().initialize()
        logger.info.assert_called_once_with('Have a nice day.')

        logger.info.reset_mock()
        conf.config(group='PLUGIN', experimental_features='')
        NuageMechanismDriver().initialize()
        logger.info.assert_not_called()


class Context(context.RequestContext):
    def __init__(self, network, subnet):
        super(Context, self).__init__()

        self.current = subnet
        self.original = subnet
        self.db_context = context.RequestContext()
        self._plugin_context = context.RequestContext()

        class CorePlugin(object):
            def __init__(self, _network):
                self.network = _network

            def get_network(self, _context, _subnet):
                return self.network

        self._plugin = CorePlugin(network)
