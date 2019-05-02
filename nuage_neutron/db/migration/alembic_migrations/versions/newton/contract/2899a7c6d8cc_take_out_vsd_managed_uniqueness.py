# Copyright 2018  Alcatel-Lucent USA Inc.
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

"""Take_out_vsd_managed_uniqueness_constraint

Revision ID: 2899a7c6d8cc
Revises: 3b9b57c10ad9
Create Date: 2018-01-16 10:15:42.103015

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = '2899a7c6d8cc'
down_revision = '3b9b57c10ad9'


def upgrade():
    op.execute("ALTER TABLE nuage_subnet_l2dom_mapping DROP INDEX "
               "uniq_nuage_subnet_l2dom_mapping0nuage_subnet_id0ip_version")
