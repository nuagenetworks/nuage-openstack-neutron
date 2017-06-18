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

from neutron.conf import common as core_config
from neutron.plugins.ml2 import config as ml2_config
from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.nuage_ml2.mech_nuage import NuageMechanismDriver
from nuage_neutron.vsdclient.impl.vsdclientimpl import VsdClientImpl
from nuage_neutron.vsdclient.restproxy import RESTProxyServer

import mock
import testtools

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture


class TestNuageMechanismDriverNative(testtools.TestCase):

    def set_config_fixture_connc(self):
        cfg.CONF.register_opts(core_config.core_opts)
        cfg.CONF.register_opts(ml2_config.ml2_opts, "ml2")
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='RESTPROXY', server='localhost:9976')
        conf.config(group='RESTPROXY', server_timeout=1)
        conf.config(group='RESTPROXY', server_max_retries=1)
        conf.config(group='RESTPROXY', cms_id='1')
        conf.config(group='PLUGIN', enable_debug='api_stats')

        if config_type == ConfigTypes.MISSING_SERVICE_PLUGIN:
            conf.config(service_plugins=['NuagePortAttributes',
                                         'NuageL3'])
        else:
            conf.config(service_plugins=['NuagePortAttributes',
                                         'NuageL3', 'NuageAPI'])

        if config_type == ConfigTypes.MISSING_ML2_EXTENSION:
            conf.config(group='ml2',
                        extension_drivers=['nuage_subnet',
                                           'nuage_port'])
        else:
            conf.config(group='ml2',
                        extension_drivers=['nuage_subnet',
                                           'nuage_port',
                                           'port_security'])

    # get me a Nuage mechanism driver
    def get_me_a_nmd(self):
        nmd = NuageMechanismDriver()
        nmd._l2_plugin = nmd
        self.set_config_fixture()
        nmd.initialize()
        return nmd

    # NETWORK DRIVER INITIALIZATION CHECKS

    def test_init_native_nmd_missing_service_plugin(self):
        nmd = NuageMechanismDriver()
        self.set_config_fixture(ConfigTypes.MISSING_SERVICE_PLUGIN)
        try:
            nmd.initialize()
            self.fail()

        except Exception as e:
            self.assertEqual('Could not establish a connection with the VSD. '
                             'Please check VSD URI path in plugin config '
                             'and verify IP connectivity.', str(e))

    def test_init_nmd_invalid_server(self):
        nmd = NuageMechanismDriver()
        self.set_config_fixture_connc()
        self.initialize(nmd)


class TestNuageMechanismDriverMocked(testtools.TestCase):

    def set_config_fixture(self):
        cfg.CONF.register_opts(core_config.core_opts)
        cfg.CONF.register_opts(ml2_config.ml2_opts, "ml2")
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(service_plugins=['NuagePortAttributes',
                                     'NuageL3', 'NuageAPI'])
        conf.config(group='ml2',
                    extension_drivers=['nuage_subnet',
                                       'nuage_port',
                                       'port_security'])

    def set_invalid_config_fixture(self):
        cfg.CONF.register_opts(core_config.core_opts)
        cfg.CONF.register_opts(ml2_config.ml2_opts, "ML2")
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='RESTPROXY', server='localhost:9876')
        conf.config(group='RESTPROXY', server_timeout=1)
        conf.config(group='RESTPROXY', server_max_retries=1)
        conf.config(group='RESTPROXY', cms_id='1')
        conf.config(group='PLUGIN', enable_debug='api_stats')
        conf.config(service_plugins=['NuagePortAttributes',
                                     'NuageL3', 'NuageAPI'])
        conf.config(group='ml2',
                    extension_drivers=['nuage_subnet',
                                       'nuage_port',
                                       'port_security'])

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'get_cms')
    def test_multi_init_nmd_invalid_server(self, raise_rest, get_cms):

        # init nmd 3 times, mock out the failures
        nmd1 = NuageMechanismDriver()
        nmd2 = NuageMechanismDriver()
        nmd3 = NuageMechanismDriver()

        self.set_invalid_config_fixture()

        nmd1.initialize()
        nmd2.initialize()
        nmd3.initialize()

        # validate there is actually only 1 vsdclient (memoize)
        self.assertEqual(nmd2.vsdclient, nmd1.vsdclient)
        self.assertEqual(nmd3.vsdclient, nmd1.vsdclient)

        # validate only 1 api call is made
        self.assertEqual(1, nmd1.vsdclient.restproxy.api_count)

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, '_network_is_external',
                       return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_subnet_precommit_in_flat_network(self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 4}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_nuage_id_and_ipversion',
                       return_value=[])
    def test_create_subnet_precommit_in_flat_net_with_nuagenet(
            self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'ip_version': 4}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('Subnet precommit should not have succeeded')
        except NuageBadRequest as e:
            self.assertEqual('Bad request: Parameter net-partition required '
                             'when passing nuagenet', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_nuage_id_and_ipversion',
                       return_value=[])
    def test_create_vsd_mgd_subnet_precommit_in_flat_net(
            self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 4}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('Create subnet precommit should not have succeeded')
        except NuageBadRequest as e:
            self.assertEqual('Bad request: Network should have \'provider:'
                             'network_type\' vxlan or have such a segment',
                             str(e))

    # VXLAN NETWORKS

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_nuage_id_and_ipversion',
                       return_value=[])
    def test_create_subnet_precommit_with_nuagenet(self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'ip_version': 4}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('Subnet precommit should not have succeeded')
        except NuageBadRequest as e:
            self.assertEqual('Bad request: Parameter net-partition required '
                             'when passing nuagenet', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_nuage_id_and_ipversion',
                       return_value=[])
    def test_create_vsd_mgd_subnet_precommit(self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 4}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    def test_create_v6_subnet_precommit(self, m1, m2):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('Subnet precommit should not have succeeded')
        except NuageBadRequest as e:
            self.assertEqual('Bad request: Subnet with ip_version 6 is '
                             'currently not supported for OpenStack managed '
                             'subnets.', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    @mock.patch.object(nuagedb,
                       'get_subnet_l2dom_by_nuage_id_and_ipversion',
                       return_value=[])
    def test_create_vsd_mgd_v6_subnet_precommit(
            self, m1, m2, m3, m4, m5):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 6}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, '_network_is_external',
                       return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_subnet_precommit_default(self, m1, m2, m3, m4):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 4,
                  'cidr': '10.10.1.0/24',
                  'gateway_ip': '10.10.1.1'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'default_np_id',
                       return_value=1)
    @mock.patch.object(NuageMechanismDriver, '_network_is_external',
                       return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_net_partition_by_id',
                       return_value={'id': 1})
    @mock.patch.object(NuageMechanismDriver, '_create_nuage_subnet')
    def test_create_subnet_precommit_and_postcommit_default(
            self, m1, m2, m3, m4, m5, m6, m7):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 4,
                  'cidr': '10.10.1.0/24',
                  'gateway_ip': '10.10.1.1'}

        context = Context(network, subnet)
        nmd.create_subnet_precommit(context)
        nmd.create_subnet_postcommit(context)

    # EXPERIMENTAL FEATURES

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch('nuage_neutron.plugins.nuage_ml2.mech_nuage.LOG')
    def test_experimental_feature(self, logger, root_plugin):
        self.set_config_fixture()
        config.nuage_register_cfg_opts()
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

        conf.config(group='PLUGIN', experimental_features='experimental_test')
        NuageMechanismDriver().initialize()
        logger.info.assert_called_once_with('Have a nice day.')

        logger.info.reset_mock()
        conf.config(group='PLUGIN', experimental_features='')
        NuageMechanismDriver().initialize()
        logger.info.assert_not_called()


class Context(object):
    def __init__(self, network, subnet):
        self.current = subnet
        self.original = subnet
        self.db_context = self
        self._plugin_context = self

        class Session(object):
            @staticmethod
            def is_active():
                return True

        self.session = Session()

        class Network(object):
            def __init__(self, curr_network):
                self.current = curr_network

        class CorePlugin(object):
            def __init__(self, _network):
                self.network = _network

            def get_network(self, _context, _subnet):
                return self.network

        self._plugin = CorePlugin(network)
        self.network = Network(network)
