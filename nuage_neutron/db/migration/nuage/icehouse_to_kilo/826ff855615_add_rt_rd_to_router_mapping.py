# Copyright 2014 OpenStack Foundation
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

"""add_rt_rd_to_router_mapping

Revision ID: 826ff855615
Revises: juno
Create Date: 2014-11-12 15:32:10.629562

"""

# revision identifiers, used by Alembic.
revision = '826ff855615'
down_revision = 'juno'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('nuage_net_partition_router_mapping',
                  sa.Column('nuage_rtr_rd',
                            sa.String(length=36), nullable=True))
    op.add_column('nuage_net_partition_router_mapping',
                  sa.Column('nuage_rtr_rt',
                            sa.String(length=36), nullable=True))

