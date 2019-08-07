# Copyright 2019 NOKIA
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
from alembic import op
import sqlalchemy as sa

"""add nuage_project_net_partition_mapping table


Revision ID: 80a19bb49f41
Revises: 5106156f8300
Create Date: 2019-08-05 17:21:41.123782

"""

# revision identifiers, used by Alembic.
revision = '80a19bb49f41'
down_revision = '5106156f8300'


def upgrade():

    op.create_table(
        'nuage_project_net_partition_mapping',
        sa.Column('project', sa.String(64), nullable=False,
                  primary_key=True),
        sa.Column('net_partition_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['net_partition_id'],
                                ['nuage_net_partitions.id'],
                                name='fk_nuage_net_partition',
                                ondelete='CASCADE')
    )
