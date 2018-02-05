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

from alembic import op
import sqlalchemy as sa

"""add_nuage_securitygroup_parameter

Revision ID: dde3c65f57d8
Revises: b05bd74f4cc7
Create Date: 2018-01-05 16:00:58.787771

"""

# revision identifiers, used by Alembic.
revision = 'dde3c65f57d8'
down_revision = 'c842e8cac9a0'


def upgrade():
    op.create_table(
        'nuage_security_group_parameter',
        sa.Column('name', sa.String(255), primary_key=True)
    )

    op.create_table(
        'nuage_security_group',
        sa.Column('security_group_id', sa.String(255), nullable=False),
        sa.Column('parameter_name', sa.String(255), nullable=False),
        sa.Column('parameter_value', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('security_group_id', 'parameter_name'),
        sa.ForeignKeyConstraint(['parameter_name'],
                                ['nuage_security_group_parameter.name'],
                                name='fk_nuage_security_group_parameter',
                                ondelete='CASCADE')
    )

    nuage_sg_parameter = sa.Table('nuage_security_group_parameter',
                                  sa.MetaData(),
                                  sa.Column('name', sa.String(255),
                                            primary_key=True)
                                  )
    op.bulk_insert(nuage_sg_parameter, [{'name': 'STATEFUL'}])
