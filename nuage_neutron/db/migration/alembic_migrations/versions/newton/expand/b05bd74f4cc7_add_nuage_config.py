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

"""add nuage config and nuage_config_param

Revision ID: b05bd74f4cc7
Revises: c5a28aa0e583
Create Date: 2017-08-01 16:35:25.246027

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b05bd74f4cc7'
down_revision = 'bd8449bfe34d'


def upgrade():

    op.create_table(
        'nuage_config_parameter',
        sa.Column('name', sa.String(255), primary_key=True)
    )

    op.create_table(
        'nuage_config',
        sa.Column('organization', sa.String(255), nullable=False),
        sa.Column('username', sa.String(255), nullable=False),
        sa.Column('config_parameter', sa.String(255), nullable=False),
        sa.Column('config_value', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('organization', 'username',
                                'config_parameter'),
        sa.ForeignKeyConstraint(['config_parameter'],
                                ['nuage_config_parameter.name'],
                                name='fk_nuage_config_config_parameter',
                                ondelete='CASCADE')
    )

    nuage_config_param = sa.Table('nuage_config_parameter', sa.MetaData(),
                                  sa.Column('name', sa.String(255),
                                            primary_key=True)
                                  )

    op.bulk_insert(nuage_config_param,
                   [
                       {'name': 'auth_token'}
                   ])
