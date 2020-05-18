# Copyright 2016 Nokia.
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

"""add gateway port mapping

Revision ID: c4fb5a76b195
Revises: 13cf8b5dfd05
Create Date: 2016-04-12 11:35:51.542465

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4fb5a76b195'
down_revision = '13cf8b5dfd05'


def upgrade():
    op.create_table('nuage_switchport_mapping',
                    sa.Column('id', sa.String(36), nullable=False),
                    sa.Column('switch_info', sa.String(255), nullable=False),
                    sa.Column('switch_id', sa.String(36), nullable=False),
                    sa.Column('redundant', sa.Boolean(), nullable=False),
                    # sa.Column('port_id', sa.String(255), nullable=False),
                    sa.Column('port_uuid', sa.String(36), nullable=False),
                    sa.Column('physnet', sa.String(255), nullable=False),
                    sa.Column('host_id', sa.String(255), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('physnet', 'host_id'))

    op.create_table('nuage_switchport_binding',
                    sa.Column('id', sa.String(36), nullable=False),
                    sa.Column('neutron_port_id',
                              sa.String(36),
                              nullable=False),
                    sa.Column('nuage_vport_id', sa.String(36), nullable=False),
                    sa.Column('switchport_uuid',
                              sa.String(36),
                              nullable=False),
                    sa.Column('segmentation_id', sa.Integer, nullable=False),
                    sa.ForeignKeyConstraint(
                        ['neutron_port_id'],
                        ['ports.id'],
                        ondelete='CASCADE'))
