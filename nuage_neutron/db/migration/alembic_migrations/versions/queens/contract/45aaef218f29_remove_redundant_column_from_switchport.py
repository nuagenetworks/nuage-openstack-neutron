# Copyright 2020 NOKIA
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


"""remove redundant column from nuage_switchport_mapping

Revision ID: 45aaef218f29
Revises: 3526ce5c02ce
Create Date: 2020-05-01 08:09:16.834607

"""

# revision identifiers, used by Alembic.
revision = '45aaef218f29'
down_revision = '3526ce5c02ce'


def upgrade():
    op.drop_column('nuage_switchport_mapping', 'redundant')
