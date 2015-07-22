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

"""nuage_unique_constraint_vsd_id

Revision ID: 36f580568441
Revises: 826ff855615
Create Date: 2015-02-19 11:44:47.285463

"""

# revision identifiers, used by Alembic.
revision = '36f580568441'
down_revision = '826ff855615'

from alembic import op


def upgrade():
    op.create_unique_constraint(
        None, 'nuage_net_partition_router_mapping',
        ['nuage_router_id'])
    op.create_unique_constraint(
        None, 'nuage_subnet_l2dom_mapping',
        ['nuage_subnet_id'])

