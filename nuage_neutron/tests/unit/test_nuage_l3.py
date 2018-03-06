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

# run me using :
# python -m testtools.run nuage_neutron/tests/unit/test_nuage_l3.py

import mock
import testtools

from nuage_neutron.plugins.common.base_plugin import RootNuagePlugin
from nuage_neutron.plugins.common.service_plugins.l3 import NuageL3Plugin


class TestNuageL3Plugin(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestNuageL3Plugin, cls).setUpClass()

    @mock.patch.object(RootNuagePlugin, 'init_vsd_client')
    def test_l3_init(self, *mocks):
        NuageL3Plugin()
