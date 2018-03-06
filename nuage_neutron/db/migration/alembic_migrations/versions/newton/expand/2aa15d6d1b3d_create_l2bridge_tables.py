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
#

"""Create l2bridge tables

Revision ID: 2aa15d6d1b3d
Revises: c5a28aa0e583
Create Date: 2018-03-05 14:50:56.612857

"""

# revision identifiers, used by Alembic.
revision = '2aa15d6d1b3d'
down_revision = 'c5a28aa0e583'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'nuage_l2bridge',
        sa.Column('project_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('nuage_subnet_id', sa.String(length=36), nullable=True)
    )

    op.create_table(
        'nuage_l2bridge_physnet_mapping',
        sa.Column('l2bridge_id', sa.String(length=36)),
        sa.Column('physnet', sa.String(length=255)),
        sa.Column('segmentation_id', sa.Integer()),
        sa.Column('segmentation_type', sa.String(length=32)),
        sa.PrimaryKeyConstraint('l2bridge_id', 'physnet', 'segmentation_id',
                                'segmentation_type'),
        sa.ForeignKeyConstraint(['l2bridge_id'], ['nuage_l2bridge.id'],
                                name='fk_nuage_l2bridge',
                                ondelete='CASCADE'),
    )
