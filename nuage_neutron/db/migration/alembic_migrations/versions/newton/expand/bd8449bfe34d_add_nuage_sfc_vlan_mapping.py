# Copyright 2017 Nokia.
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

"""add nuage sfc vlan mapping

Revision ID: bd8449bfe34d
Revises: c4fb5a76b195
Create Date: 2017-06-01 12:08:07.203656

"""

# revision identifiers, used by Alembic.
revision = 'bd8449bfe34d'
down_revision = 'c4fb5a76b195'

from alembic import op
import sqlalchemy as sa


def upgrade():
    if op.get_bind().engine.name == 'postgresql':
        op.create_table('nuage_sfc_vlan_subnet_mapping',
                        sa.Column('subnet_id', sa.String(36), nullable=False),
                        sa.Column('vlan_bit_map',
                                  sa.dialects.postgresql.BYTEA(),
                                  nullable=False),
                        sa.PrimaryKeyConstraint('subnet_id'),
                        sa.ForeignKeyConstraint(['subnet_id'],
                                                ['subnets.id'],
                                                ondelete='CASCADE')
                        )
    else:
        op.create_table('nuage_sfc_vlan_subnet_mapping',
                        sa.Column('subnet_id', sa.String(36), nullable=False),
                        sa.Column('vlan_bit_map', sa.VARBINARY(512),
                                  nullable=False),
                        sa.PrimaryKeyConstraint('subnet_id'),
                        sa.ForeignKeyConstraint(['subnet_id'],
                                                ['subnets.id'],
                                                ondelete='CASCADE')
                        )
