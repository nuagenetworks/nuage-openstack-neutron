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

"""extend unique constraint on nuage_subnet_l2dom_mapping for ipv6
Revision ID: 4fdefabb76a8
Revises: 13129a71ae66
Create Date: 2015-11-16 13:54:29.874191
"""

# revision identifiers, used by Alembic.

revision = '4fdefabb76a8'
down_revision = '13129a71ae66'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.inspection import inspect


def upgrade():
    inspector = inspect(op.get_bind())
    constraints = inspector.get_unique_constraints(
        'nuage_subnet_l2dom_mapping')
    for constraint in constraints:
        if (len(constraint['column_names']) == 1 and
                constraint['column_names'][0] == 'nuage_subnet_id'):
            op.drop_constraint(constraint['name'],
                               'nuage_subnet_l2dom_mapping',
                               type_='unique')
    op.add_column('nuage_subnet_l2dom_mapping',
                  sa.Column('ip_version', sa.Integer, nullable=False))
    op.create_unique_constraint(
        'uniq_nuage_subnet_l2dom_mapping0nuage_subnet_id0ip_version',
        'nuage_subnet_l2dom_mapping',
        ['nuage_subnet_id', 'ip_version'])
    op.execute("UPDATE nuage_subnet_l2dom_mapping SET ip_version = "
               "(SELECT ip_version from subnets WHERE "
               "nuage_subnet_l2dom_mapping.subnet_id = subnets.id)")
