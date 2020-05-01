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

import mock
import oslo_config
import testtools

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from neutron.conf import common as core_config
from neutron.conf.plugins.ml2 import config as ml2_config

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common import config
from nuage_neutron.plugins.common.exceptions import NuageBadRequest
from nuage_neutron.plugins.common import nuagedb

from nuage_neutron.plugins.nuage_ml2.mech_nuage import NuageMechanismDriver
from nuage_neutron.vsdclient.impl.vsdclientimpl import VsdClientImpl
from nuage_neutron.vsdclient.restproxy import RESTProxyError
from nuage_neutron.vsdclient.restproxy import RESTProxyServer


class ConfigTypes(object):
    MINIMAL_CONFIG = 1
    MISSING_SERVICE_PLUGIN = 2
    MISSING_ML2_EXTENSION = 3
    NUAGE_PAT_WITH_NUAGE_UNDERLAY_CONFIG = 4
    NUAGE_L2BRIDGE_WITHOUT_NUAGE_NETWORK = 5


class TestNuageMechanismDriver(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestNuageMechanismDriver, cls).setUpClass()

        # make sure we have the configs
        if core_config.core_opts is None or ml2_config.ml2_opts is None:
            cls.fail('Fix your setup.')

    def set_config_fixture(self, config_type=ConfigTypes.MINIMAL_CONFIG):
        ml2_config.register_ml2_plugin_opts()
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
                                           'nuage_port',
                                           'port_security'])
        else:
            conf.config(group='ml2',
                        extension_drivers=['nuage_network',
                                           'nuage_subnet',
                                           'nuage_port',
                                           'port_security'])

        if config_type == ConfigTypes.NUAGE_L2BRIDGE_WITHOUT_NUAGE_NETWORK:
            conf.config(service_plugins=['NuagePortAttributes',
                                         'NuageL3', 'NuageAPI',
                                         'NuageL2Bridge'])
        return conf

    # get me a Nuage mechanism driver
    def get_me_a_nmd(self):
        self.set_config_fixture()
        nmd = NuageMechanismDriver()
        nmd._l2_plugin = nmd
        nmd.initialize()
        return nmd

    @staticmethod
    def get_me_a_rest_proxy():
        vsd_client = RESTProxyServer(server='localhost:9876',
                                     base_uri='/nuage/api/v6',
                                     serverssl=True,
                                     verify_cert='False',
                                     serverauth='1:1',
                                     auth_resource='/me',
                                     organization='org')
        return vsd_client

    # NETWORK DRIVER INITIALIZATION CHECKS

    def test_init_native_nmd_missing_service_plugin(self):
        self.set_config_fixture(ConfigTypes.MISSING_SERVICE_PLUGIN)
        self.assertRaisesRegex(
            oslo_config.cfg.ConfigFileValueError,
            r'Missing required service_plugin\(s\) '
            r'\[\'NuageAPI\'\] for mechanism driver nuage',
            NuageMechanismDriver().initialize)

    def test_init_native_nmd_missing_ml2_extension(self):
        self.set_config_fixture(ConfigTypes.MISSING_ML2_EXTENSION)
        self.assertRaisesRegex(
            oslo_config.cfg.ConfigFileValueError,
            r'Missing required extension\(s\) '
            r'\[\'nuage_network\'\] for mechanism driver nuage',
            NuageMechanismDriver().initialize)

    def test_init_native_nmd_invalid_server(self):
        self.set_config_fixture()
        self.assertRaisesRegex(
            RESTProxyError,
            'Error in REST call to VSD: '
            'Could not establish a connection with the VSD. '
            'Please check VSD URI path in plugin config '
            'and verify IP connectivity.',
            NuageMechanismDriver().initialize)

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_multi_init_nmd_invalid_server(self, *_):
        # init nmd 3 times
        nmd1 = self.get_me_a_nmd()
        nmd2 = self.get_me_a_nmd()
        nmd3 = self.get_me_a_nmd()

        # validate there is actually only 1 vsdclient (memoize)
        self.assertEqual(nmd2.vsdclient, nmd1.vsdclient)
        self.assertEqual(nmd3.vsdclient, nmd1.vsdclient)

        # validate no api call is made - we don't count authentication calls!
        self.assertEqual(0, nmd1.vsdclient.restproxy.api_count)

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
    def test_create_subnet_precommit_in_flat_network(self, *_):
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
    def test_create_subnet_precommit_in_flat_net_with_nuagenet(self, *_):
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
            self.assertEqual("Bad request: Network should have 'provider:"
                             "network_type' vxlan or nuage_hybrid_mpls, or "
                             "have such a segment", str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_vsd_mgd_subnet_precommit_in_flat_net(self, *_):
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
            self.assertEqual("Bad request: Network should have 'provider:"
                             "network_type' vxlan or nuage_hybrid_mpls, or "
                             "have such a segment", str(e))

    # VXLAN NETWORKS

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver, '_create_vsd_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_subnet_precommit_with_nuagenet(self, *_):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'nuagenet': '0x100',
                  'ip_version': 4,
                  'cidr': '10.0.0.0/24'}
        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver, '_create_vsd_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids',
                       return_value=[])
    def test_create_vsd_mgd_subnet_precommit(self, *_):
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
    def test_create_vsd_mgd_v6_subnet_precommit(self, *_):
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
    def test_create_subnet_precommit_default(self, *_):
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
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v6_subnet_precommit(self, *_):
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
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'check_dhcp_agent_alive',
                       return_value=False)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_two_v6_subnets_precommit(self, *_):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'fef::/64'}

        nmd.create_subnet_precommit(Context(network, subnet))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 6},
                                     {'id': 'subnet2', 'ip_version': 6}])
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(NuageMechanismDriver, 'check_dhcp_agent_alive',
                       return_value=True)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_two_v6_subnets_with_dhcp_agent_precommit(self, *_):
        nmd = self.get_me_a_nmd()

        network = {'id': '1',
                   'provider:network_type': 'vxlan',
                   'router:external': False}
        subnet = {'id': '10',
                  'network_id': '1',
                  'ip_version': 6,
                  'cidr': 'eef::/64'}

        try:
            nmd.create_subnet_precommit(Context(network, subnet))
            self.fail('This is a negative test and was not meant to pass.')

        except NuageBadRequest as e:
            self.assertEqual('Bad request: A network with multiple ipv4 or '
                             'ipv6 subnets is not allowed when '
                             'neutron-dhcp-agent is enabled', str(e))

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 4}])
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(NuageMechanismDriver,
                       '_create_openstack_managed_subnet')
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v4_v6_subnet_precommit(self, *_):
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
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_two_v4_v6_subnets_precommit(self, *_):
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
            self.assertEqual('Bad request: A network can only have maximum 1 '
                             'ipv4 and 1 ipv6 subnet existing together', str(e)
                             )

    @mock.patch.object(RESTProxyServer, 'generate_nuage_auth')
    @mock.patch.object(RESTProxyServer, '_rest_call',
                       return_value=(401, 'Unauthorized', None, None, None,
                                     None))
    def test_rest_call_infinite_recursion(self, *_):
        rest_proxy = self.get_me_a_rest_proxy()
        try:
            rest_proxy.rest_call('get', '', '')
        except Exception as e:
            self.assertEqual(True, 'Unauthorized' in str(e),
                             "Got an exception other than Unauthorized")

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageMechanismDriver, 'get_subnets',
                       return_value=[{'id': 'subnet1', 'ip_version': 4},
                                     {'id': 'subnet2', 'ip_version': 6},
                                     {'id': 'subnet2', 'ip_version': 4}])
    @mock.patch.object(NuageMechanismDriver, 'is_external', return_value=False)
    @mock.patch.object(nuagedb, 'get_subnet_l2dom_by_network_id',
                       return_value=[])
    @mock.patch.object(nuagedb, 'get_subnet_l2doms_by_subnet_ids')
    def test_create_v4_v6_v4_subnets_precommit(self, *_):
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
            self.assertEqual('Bad request: A network can only have maximum 1 '
                             'ipv4 and 1 ipv6 subnet existing together', str(e)
                             )

    # DEFAULT ALLOW NON IP CHECKS

    def test_default_allow_non_ip_not_set(self):
        self.assertFalse(config.default_allow_non_ip())

    def test_default_allow_non_ip_set_empty_string(self):
        try:
            conf = self.set_config_fixture()
            conf.config(group='PLUGIN', default_allow_non_ip='')

            self.fail('From Ocata onwards oslo is correctly checking its '
                      'config value parsing; '
                      'hence this line shd not be reached.')

        except ValueError as e:
            self.assertEqual('Unexpected boolean value \'\'', str(e))

    def test_default_allow_non_ip_set(self):
        conf = self.set_config_fixture()
        conf.config(group='PLUGIN', default_allow_non_ip=True)

        self.assertTrue(config.default_allow_non_ip())

    # ip utility checks

    def test_ip_comparison(self):
        self.assertTrue(NuageMechanismDriver.compare_ip(
            'cafe:babe::1', 'cafe:babe:0::1'))

        self.assertFalse(NuageMechanismDriver.compare_cidr(
            'cafe:babe::1', 'cafe:babe:1::1'))

    def test_cidr_comparison(self):
        self.assertTrue(NuageMechanismDriver.compare_cidr(
            'cafe:babe::1/64', 'cafe:babe:0::1/64'))

        self.assertFalse(NuageMechanismDriver.compare_cidr(
            'cafe:babe::1/64', 'cafe:babe::1/63'))

    def test_needs_vport_creation_basic(self):
        self.assertFalse(NuageMechanismDriver.needs_vport_creation(
            'nuage:vip'))

    def test_needs_vport_creation_using_prefix(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='PLUGIN', device_owner_prefix='no_vport')

        # test match
        self.assertFalse(NuageMechanismDriver.needs_vport_creation(
            'no_vport:something'))

        # test no match
        self.assertTrue(NuageMechanismDriver.needs_vport_creation(
            'something:no_vport'))

    def test_count_fixed_ips_per_version(self):
        self.assertEqual(
            (1, 2), NuageMechanismDriver.count_fixed_ips_per_version(
                [{'ip_address': 'cafe:babe::1'},
                 {'ip_address': '69.69.69.69'},
                 {'ip_address': 'dead:beef::1'}]))

    def test_sort_ips(self):
        self.assertEqual([], NuageMechanismDriver.sort_ips([]))
        self.assertEqual(['cafe:babe:1::1', 'cafe:babe:12::1'],
                         NuageMechanismDriver.sort_ips(
                             ['cafe:babe:12::1', 'cafe:babe:1::1']))


class Context(object):
    def __init__(self, network, subnet):
        self.current = subnet
        self.original = subnet
        self.db_context = self
        self._plugin_context = self

        class Transaction(object):
            def __init__(self):
                pass

            def __enter__(self):
                pass

            def __exit__(self, type, value, traceback):
                pass

            def __del__(self):
                pass

        class Session(object):
            @staticmethod
            def is_active():
                return True

            def begin(self, **_):
                return Transaction()

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
