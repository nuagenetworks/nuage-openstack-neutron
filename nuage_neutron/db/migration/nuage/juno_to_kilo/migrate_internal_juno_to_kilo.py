# Copyright 2015 OpenStack Foundation
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
#

import argparse
import neutron
import os
import subprocess
import sys


NEUTRON_DB_MIGRATE_NUAGE_PATH = (os.path.join(os.path.dirname(__file__)) + '/'
                                 if os.path.join(os.path.dirname(__file__))
                                 else os.path.join(os.path.dirname(__file__)))
NEUTRON_DB_MIGRATE_ALEM_VER_PATH = \
    (os.path.join(os.path.dirname(neutron.__file__),
                  'db/migration/alembic_migrations/versions/'))

NUAGE_UNIQUE_CONSTRAINT_VSD_ID_SCRIPT = \
    '36f580568441_nuage_unique_constraint_vsd_id.py'
NUAGE_ADD_RT_RD_TO_RTR_MAPPING_SCRIPT = \
    '826ff855615_add_rt_rd_to_router_mapping.py'
ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES = \
    '44621190bc02_add_uniqueconstraint_ipavailability_ranges.py'
ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES_TMP = \
    '44621190bc02_add_uniqueconstraint_ipavailability_ranges.py.tmp'


def cleanup():
    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + NUAGE_UNIQUE_CONSTRAINT_VSD_ID_SCRIPT),
                     (NEUTRON_DB_MIGRATE_NUAGE_PATH
                      + NUAGE_UNIQUE_CONSTRAINT_VSD_ID_SCRIPT)])

    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + NUAGE_ADD_RT_RD_TO_RTR_MAPPING_SCRIPT),
                     (NEUTRON_DB_MIGRATE_NUAGE_PATH
                      + NUAGE_ADD_RT_RD_TO_RTR_MAPPING_SCRIPT)])

    subprocess.call(['rm',
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES)])

    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES_TMP),
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES)])


def upgrade_till_head(conf_list):
    command = ['neutron-db-manage']
    command.extend(conf_list)
    command.extend(['upgrade', 'head'])
    subprocess.call(command)


def stamp_to_cascade_fip_floating_port_deletion(conf_list):
    command = ['neutron-db-manage']
    command.extend(conf_list)
    command.extend(['stamp', '57dd745253a6'])
    subprocess.call(command)


def upgrade_till_before_nuage_kilo_migrate(conf_list):
    command = ['neutron-db-manage']
    command.extend(conf_list)
    command.extend(['upgrade', '2d2a8a565438'])
    subprocess.call(command)


def copy_required_files():
    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES),
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES_TMP)])

    subprocess.call(['cp',
                     (NEUTRON_DB_MIGRATE_NUAGE_PATH
                      + ADD_UNIQUECONSTRAINT_IPAVAILABILITY_RANGES),
                     NEUTRON_DB_MIGRATE_ALEM_VER_PATH])

    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_NUAGE_PATH
                      + NUAGE_UNIQUE_CONSTRAINT_VSD_ID_SCRIPT),
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + NUAGE_UNIQUE_CONSTRAINT_VSD_ID_SCRIPT)])

    subprocess.call(['mv',
                     (NEUTRON_DB_MIGRATE_NUAGE_PATH
                      + NUAGE_ADD_RT_RD_TO_RTR_MAPPING_SCRIPT),
                     (NEUTRON_DB_MIGRATE_ALEM_VER_PATH
                      + NUAGE_ADD_RT_RD_TO_RTR_MAPPING_SCRIPT)])


def main():
    parser = argparse.ArgumentParser()
    requiredNamed = parser.add_argument_group('mandatory arguments')
    requiredNamed.add_argument("--config-file",
                               nargs='+',
                               help='List of config files separated by space')
    args = parser.parse_args()

    if sys.argv[1:].count('--config-file') != 1:
        parser.print_help()
        return

    conffiles = args.config_file
    if conffiles is None:
        parser.print_help()
        return

    conf_list = []
    for conffile in conffiles:
        conf_list.append('--config-file')
        conf_list.append(conffile)

    copy_required_files()
    upgrade_till_before_nuage_kilo_migrate(conf_list)
    stamp_to_cascade_fip_floating_port_deletion(conf_list)
    upgrade_till_head(conf_list)
    cleanup()

if __name__ == '__main__':
    main()
