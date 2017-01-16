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
# python -m testtools.run nuage_neutron/tests/unit/test_plugin.py

from nuage_neutron.plugins.nuage.plugin import NuagePlugin

import testtools
import traceback

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture


class TestNuagePlugin(testtools.TestCase):

    def setUp(self):
        super(TestNuagePlugin, self).setUp()

        # do a first attempt of nuage init,
        # which will fail as oslo configs are not set, but then
        # as side effect, the groups are registered by the plugin
        # so can be set through fixture
        try:
            NuagePlugin()
        except cfg.ConfigFileValueError:
            pass

    def test_init_nuage_plugin_invalid_server(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='RESTPROXY', server='localhost:9876')
        conf.config(group='RESTPROXY', server_timeout=1)
        conf.config(group='RESTPROXY', server_max_retries=1)
        conf.config(group='RESTPROXY', cms_id='1')

        try:
            NuagePlugin()
        except Exception as e:
            if str(e) != 'Could not establish conn with REST server. Abort':
                traceback.print_exc()
                raise e
