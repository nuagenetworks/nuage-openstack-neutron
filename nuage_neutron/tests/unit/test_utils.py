# Copyright 2018 Nokia
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
# python -m testtools.run nuage_neutron/tests/unit/test_utils.py

import testtools

import nuage_neutron.plugins.common.utils as common_utils

LOG = common_utils.get_logger(__name__)


class UtilsTest(testtools.TestCase):

    @staticmethod
    def test_say_hi():
        LOG.debug('(Say) Hi!')

    def test_needs_vport_creation_basic(self):
        self.assertFalse(common_utils.needs_vport_creation(
            'nuage:vip'))

    def test_needs_vport_creation_using_prefix(self):
        from oslo_config import cfg
        from oslo_config import fixture as oslo_fixture

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='PLUGIN', device_owner_prefix='no_vport')

        # test match
        self.assertFalse(common_utils.needs_vport_creation(
            'no_vport:something'))

        # test no match
        self.assertTrue(common_utils.needs_vport_creation(
            'something:no_vport'))

    def test_ip_comparison(self):
        self.assertTrue(common_utils.compare_ip(
            'cafe:babe::1', 'cafe:babe:0::1'))

        self.assertFalse(common_utils.compare_cidr(
            'cafe:babe::1', 'cafe:babe:1::1'))

    def test_cidr_comparison(self):
        self.assertTrue(common_utils.compare_cidr(
            'cafe:babe::1/64', 'cafe:babe:0::1/64'))

        self.assertFalse(common_utils.compare_cidr(
            'cafe:babe::1/64', 'cafe:babe::1/63'))

    def test_count_fixed_ips_per_version(self):
        self.assertEqual((1, 2), common_utils.count_fixed_ips_per_version(
            [{'ip_address': 'cafe:babe::1'},
             {'ip_address': '69.69.69.69'},
             {'ip_address': 'dead:beef::1'}]))

    def test_sort_ips(self):
        self.assertEqual([], common_utils.sort_ips([]))
        self.assertEqual(['cafe:babe:1::1', 'cafe:babe:12::1'],
                         common_utils.sort_ips(
                             ['cafe:babe:12::1', 'cafe:babe:1::1']))
