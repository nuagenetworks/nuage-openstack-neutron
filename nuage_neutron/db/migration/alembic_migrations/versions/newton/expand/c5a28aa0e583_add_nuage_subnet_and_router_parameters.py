# Copyright 2017 NOKIA
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

"""add_nuage_subnet_and_router_parameters

Revision ID: c5a28aa0e583
Revises: dde3c65f57d8
Create Date: 2017-07-07 12:25:41.025388

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c5a28aa0e583'
down_revision = 'dde3c65f57d8'


def upgrade():

    op.create_table(
        'nuage_subnet_parameter',
        sa.Column('name', sa.String(255), primary_key=True)
    )

    op.create_table(
        'nuage_router_parameter',
        sa.Column('name', sa.String(255), primary_key=True)
    )

    op.create_table(
        'nuage_subnet',
        sa.Column('subnet_id', sa.String(36), nullable=False),
        sa.Column('subnet_parameter', sa.String(255), nullable=False),
        sa.Column('parameter_value', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('subnet_id', 'subnet_parameter'),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                name='fk_nuage_subnet_subnet_id',
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subnet_parameter'],
                                ['nuage_subnet_parameter.name'],
                                name='fk_nuage_subnet_subnet_parameter',
                                ondelete='CASCADE')
    )

    op.create_table(
        'nuage_router',
        sa.Column('router_id', sa.String(36), nullable=False),
        sa.Column('router_parameter', sa.String(255), nullable=False),
        sa.Column('parameter_value', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('router_id', 'router_parameter'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                name='fk_nuage_router_router_id',
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_parameter'],
                                ['nuage_router_parameter.name'],
                                name='fk_nuage_router_router_parameter',
                                ondelete='CASCADE')

    )

    insert_table = sa.sql.table(
        'nuage_router_parameter',
        sa.sql.column('name', sa.String)
    )

    op.bulk_insert(
        insert_table,
        [
            {'name': 'nuage_underlay'},
        ]
    )

    insert_table = sa.sql.table(
        'nuage_subnet_parameter',
        sa.sql.column('name', sa.String)
    )

    op.bulk_insert(
        insert_table,
        [
            {'name': 'nuage_underlay'},
        ]
    )
