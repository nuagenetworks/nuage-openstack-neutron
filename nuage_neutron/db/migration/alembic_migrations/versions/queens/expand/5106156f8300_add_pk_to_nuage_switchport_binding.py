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

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection


"""add pk to nuage_switchport_binding

Revision ID: 5106156f8300
Revises: 2aa15d6d1b3d
Create Date: 2019-03-19 10:05:26.396754

"""

# revision identifiers, used by Alembic.
revision = '5106156f8300'
down_revision = '2aa15d6d1b3d'


def upgrade():
    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk = inspector.get_pk_constraint('nuage_switchport_binding')
    if not pk['constrained_columns']:
        op.create_primary_key(op.f('pk_nuage_switchport_binding'),
                              'nuage_switchport_binding', ['id'])
