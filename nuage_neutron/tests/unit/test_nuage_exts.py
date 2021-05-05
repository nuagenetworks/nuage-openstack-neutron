# Copyright 2018 NOKIA
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

import testtools

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.nuage_ml2.nuage_network_ext_driver import \
    NuageNetworkExtensionDriver
from nuage_neutron.plugins.nuage_ml2.nuage_port_ext_driver import \
    NuagePortExtensionDriver
from nuage_neutron.plugins.nuage_ml2.nuage_subnet_ext_driver import \
    NuageSubnetExtensionDriver
from nuage_neutron.plugins.nuage_ml2.securitygroup import \
    NuageSecurityGroup
from nuage_neutron.plugins.nuage_ml2.trunk_driver import NuageTrunkDriver
from nuage_neutron.vsdclient.impl.vsdclientimpl import VsdClientImpl
from nuage_neutron.vsdclient.restproxy import RESTProxyServer


class TestNuageExtensions(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestNuageExtensions, cls).setUpClass()

    def set_config_fixture(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

        conf.config(group='RESTPROXY', server='localhost:9876')
        conf.config(group='RESTPROXY', server_timeout=1)
        conf.config(group='RESTPROXY', server_max_retries=1)
        conf.config(group='RESTPROXY', cms_id='1')


class TestNuagePortExtensionDriver(TestNuageExtensions):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_init_nuage_port_extension_driver(self, *_):
        NuagePortExtensionDriver().initialize()

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_init_nuage_port_extension_driver2(self, *_):
        self.set_config_fixture()
        NuagePortExtensionDriver().initialize()


class TestNuageSubnetExtensionDriver(TestNuageExtensions):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_init_nuage_subnet_extension_driver(self, *_):
        NuageSubnetExtensionDriver().initialize()

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_init_nuage_subnet_extension_driver2(self, *_):
        self.set_config_fixture()
        NuageSubnetExtensionDriver().initialize()


class TestNuageNetworkExtensionDriver(TestNuageExtensions):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_init_nuage_network_extension_driver(self, *_):
        NuageNetworkExtensionDriver().initialize()

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_init_nuage_network_extension_driver2(self, *_):
        self.set_config_fixture()
        NuageNetworkExtensionDriver().initialize()


class TestNuageSecurityGroupExtensionDriver(TestNuageExtensions):

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_init_nuage_sg_extension_driver(self, *_):
        NuageSecurityGroup()

    @mock.patch.object(RESTProxyServer, 'raise_rest_error')
    @mock.patch.object(VsdClientImpl, 'verify_cms')
    def test_init_nuage_sg_extension_driver2(self, *_):
        self.set_config_fixture()
        NuageSecurityGroup()


class TestNuageTrunkDriver(TestNuageExtensions):

    def test_init_nuage_trunk_driver(self):
        NuageTrunkDriver('test', ['normal'], ['vxlan'])
