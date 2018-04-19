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

import mock
import testtools

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from neutron.conf import common as core_config
from neutron.plugins.ml2 import config as ml2_config

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.time_tracker import TimeTracker

from nuage_neutron.plugins.nuage_ml2.mech_nuage import NuageMechanismDriver
from nuage_neutron.vsdclient.impl.vsdclientimpl import VsdClientImpl
from nuage_neutron.vsdclient.restproxy import RESTProxyServer


class ConfigTypes(object):
    MINIMAL_CONFIG = 1
    MISSING_SERVICE_PLUGIN = 2
    MISSING_ML2_EXTENSION = 3
    NUAGE_UNDERLAY_CONFIG_ONLY = 4
    NUAGE_PAT_WITH_NUAGE_UNDERLAY_CONFIG = 5


class TestNuageMechanismDriver(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestNuageMechanismDriver, cls).setUpClass()

        # make sure we have the configs
        if core_config.core_opts is None or ml2_config.ml2_opts is None:
            cls.fail('Fix your setup.')

        # disable the auth key renewal in VsdClient
        VsdClientImpl.set_auth_key_renewal(False)

    def set_config_fixture(self, config_type=ConfigTypes.MINIMAL_CONFIG):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

        conf.config(group='RESTPROXY', server='localhost:9876')
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
        if config_type == ConfigTypes.NUAGE_UNDERLAY_CONFIG_ONLY:
            conf.config(group='RESTPROXY', nuage_underlay_default='snat')

        if config_type == ConfigTypes.NUAGE_PAT_WITH_NUAGE_UNDERLAY_CONFIG:
            conf.config(group='RESTPROXY', nuage_pat='not_available')
            conf.config(group='RESTPROXY',
                        nuage_underlay_default='not_available')
        return conf

    # get me a Nuage mechanism driver
    def get_me_a_nmd(self):
        self.set_config_fixture()
        nmd = NuageMechanismDriver()
        nmd._l2_plugin = nmd
        nmd.initialize()
        return nmd

    # get me a Restproxy client
    def get_me_rest_proxy(self):
        vsd_client = RESTProxyServer(server='localhost:9876',
                                     base_uri='/nuage/api/v5_0',
                                     serverssl=True,
                                     verify_cert='False',
                                     serverauth='1:1',
                                     auth_resource='/me',
                                     organization='org')
        return vsd_client

    # NETWORK DRIVER INITIALIZATION CHECKS

    def test_init_with_nuage_underlay_only(self):
        self.set_config_fixture(
            ConfigTypes.NUAGE_UNDERLAY_CONFIG_ONLY)
        try:
            NuageMechanismDriver().initialize()
            self.fail('nmd should not have successfully initialized.')

        except Exception as e:
            self.assertEqual('It is not possible to configure both'
                             ' nuage_pat and nuage_underlay_default.'
                             ' Set nuage_pat to legacy_disabled.', str(e))

    def test_init_with_nuage_pat_and_nuage_underlay(self):
        self.set_config_fixture(
            ConfigTypes.NUAGE_PAT_WITH_NUAGE_UNDERLAY_CONFIG)
        try:
            NuageMechanismDriver().initialize()
            self.fail('nmd should not have successfully initialized.')

        except Exception as e:
            self.assertEqual('It is not possible to configure both'
                             ' nuage_pat and nuage_underlay_default.'
                             ' Set nuage_pat to legacy_disabled.', str(e))

    def test_init_native_nmd_missing_service_plugin(self):
        self.set_config_fixture(ConfigTypes.MISSING_SERVICE_PLUGIN)
        try:
            NuageMechanismDriver().initialize()
            self.fail('nmd should not have successfully initialized.')

        except Exception as e:
            self.assertEqual('Missing required service_plugin(s) '
                             '[\'NuageAPI\'] '
                             'for mechanism driver nuage', str(e))

    def test_init_native_nmd_missing_ml2_extension(self):
        self.set_config_fixture(ConfigTypes.MISSING_ML2_EXTENSION)
        try:
            NuageMechanismDriver().initialize()
            self.fail('nmd should not have successfully initialized.')

        except Exception as e:
            self.assertEqual('Missing required extension(s) '
                             '[\'port_security\'] '
                             'for mechanism driver nuage', str(e))

    def test_init_native_nmd_invalid_server(self):
        self.set_config_fixture()
        try:
            NuageMechanismDriver().initialize()
            self.fail('nmd should not have successfully initialized.')

        except Exception as e:
            self.assertEqual('Could not establish a connection with the VSD. '
                             'Please check VSD URI path in plugin config '
                             'and verify IP connectivity.', str(e))

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_multi_init_nmd_invalid_server(self, raise_rest, verify_cms):
        # init nmd 3 times
        nmd1 = self.get_me_a_nmd()
        nmd2 = self.get_me_a_nmd()
        nmd3 = self.get_me_a_nmd()

        # validate there is actually only 1 vsdclient (memoize)
        self.assertEqual(nmd2.vsdclient, nmd1.vsdclient)
        self.assertEqual(nmd3.vsdclient, nmd1.vsdclient)

        # validate no api call is made - we don't count authentication calls!
        self.assertEqual(0, nmd1.vsdclient.restproxy.api_count)

        # validate no time is tracked
        self.assertFalse(TimeTracker.is_tracking_enabled())
        self.assertEqual(0, TimeTracker.get_time_tracked(),
                         'time tracked')
        self.assertEqual(0, TimeTracker.get_time_not_tracked(),
                         'time not tracked')

    # FLAT NETWORKS

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'is_external',
                       return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_subnet_precommit_in_flat_network(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 4,
                  'cidr': '10.0.0.0/24'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_subnet_precommit_in_flat_net_with_nuagenet(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'ip_version': 4,
                  'cidr': '10.0.0.0/24'}
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
    def test_create_vsd_mgd_subnet_precommit_in_flat_net(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'flat',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 4,
                  'cidr': '10.0.0.0/24'}
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
    def test_create_subnet_precommit_with_nuagenet(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'ip_version': 4,
                  'cidr': '10.0.0.0/24'}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('Subnet precommit should not have succeeded')
        except NuageBadRequest as e:
            self.assertEqual('Bad request: Parameter net-partition required '
                             'when passing nuagenet', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver, '_create_vsd_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_vsd_mgd_subnet_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 4,
                  'gateway_ip': None,
                  'cidr': '10.0.0.0/24'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets')
    @mock.patch.object(NuageMechanismDriver, '_create_vsd_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    @mock.patch.object(nuagedb, 'get_net_partition_by_id',
                       return_value={'id': 1})
    def test_create_vsd_mgd_v6_subnet_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'net_partition': 'lalaland',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'default_np_id',
                       return_value=1)
    @mock.patch.object(NuageMechanismDriver, 'is_external',
                       return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_net_partition_by_id',
                       return_value={'id': 1})
    @mock.patch.object(NuageMechanismDriver, '_create_nuage_subnet')
    def test_create_subnet_precommit_default(self, *mocks):
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
    @mock.patch.object(NuageMechanismDriver, 'get_subnets')
    @mock.patch.object(NuageMechanismDriver, 'is_external')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v6_subnet_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 6},
                                     {'id': 'subnet2', 'ip_version': 6}])
    @mock.patch.object(NuageMechanismDriver, 'is_external')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_two_v6_subnets_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('This is a negative test and was not meant to pass.')

        except NuageBadRequest as e:
            self.assertEqual('Bad request: A network with an ipv6 subnet '
                             'may only have maximum 1 ipv4 and 1 ipv6 '
                             'subnet', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 4}])
    @mock.patch.object(NuageMechanismDriver, 'is_external')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v4_v6_subnet_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 4},
                                     {'id': 'subnet2', 'ip_version': 4},
                                     {'id': 'subnet2', 'ip_version': 6}])
    @mock.patch.object(NuageMechanismDriver, 'is_external')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_two_v4_v6_subnets_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('This is a negative test and was not meant to pass.')

        except NuageBadRequest as e:
            self.assertEqual('Bad request: A network with an ipv6 subnet '
                             'may only have maximum 1 ipv4 and 1 ipv6 '
                             'subnet', str(e))

    @mock.patch.object(RESTProxyServer, 'generate_nuage_auth')
    @mock.patch.object(RESTProxyServer, '_rest_call',
                       return_value=(401, 'Unauthorized', None, None, None,
                                     None))
    def test_rest_call_infinite_recursion(self, *mock):
        rest_proxy = self.get_me_rest_proxy()
        try:
            rest_proxy.rest_call('get', '', '')
        except Exception as e:
            self.assertEqual(True, 'Unauthorized' in e.message,
                             "Got an exception other than Unauthorized")

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 4},
                                     {'id': 'subnet2', 'ip_version': 6},
                                     {'id': 'subnet2', 'ip_version': 4}])
    @mock.patch.object(NuageMechanismDriver, 'is_external')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v4_v6_v4_subnets_precommit(self, *mocks):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fee::/64'}
        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('This is a negative test and was not meant to pass.')

        except NuageBadRequest as e:
            self.assertEqual('Bad request: A network with an ipv6 subnet '
                             'may only have maximum 1 ipv4 and 1 ipv6 '
                             'subnet', str(e))

    # NON DEFAULT IP CHECKS

    def test_default_allow_non_ip_not_set(self):
        self.assertFalse(config.default_allow_non_ip())

    def test_default_allow_non_ip_set_empty_string(self):
        cfg = self.set_config_fixture()
        cfg.config(group='PLUGIN', default_allow_non_ip='')

        self.assertFalse(config.default_allow_non_ip())

    def test_default_allow_non_ip_set_to_rubbish(self):
        cfg = self.set_config_fixture()
        cfg.config(group='PLUGIN', default_allow_non_ip='rubbish')

        self.assertFalse(config.default_allow_non_ip())

    def test_default_allow_non_ip_set(self):
        cfg = self.set_config_fixture()
        cfg.config(group='PLUGIN', default_allow_non_ip=True)

        self.assertTrue(config.default_allow_non_ip())


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
