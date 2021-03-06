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

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common.service_plugins.nuage_apis import NuageApi


class TestNuageApis(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestNuageApis, cls).setUpClass()

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    @mock.patch.object(NuageApi, '_prepare_netpartitions')
    def test_nuage_apis_init(self, *_):
        NuageApi()
