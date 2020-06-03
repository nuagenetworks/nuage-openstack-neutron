# Copyright 2019 OpenStack Foundation
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


"""add nuage_aggregate_flows key to nuage_router_parameter

Revision ID: ea1edcbfd1c9
Revises: 80a19bb49f41
Create Date: 2019-12-05 16:48:16.783223

"""

# revision identifiers, used by Alembic.
revision = 'ea1edcbfd1c9'
down_revision = '80a19bb49f41'


def upgrade():
    insert_table = sa.sql.table(
        'nuage_router_parameter',
        sa.sql.column('name', sa.String)
    )

    op.bulk_insert(
        insert_table,
        [
            {'name': 'nuage_aggregate_flows'},
        ]
    )
