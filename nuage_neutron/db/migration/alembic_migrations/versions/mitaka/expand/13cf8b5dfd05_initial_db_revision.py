# Copyright 2015 OpenStack Foundation
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

"""Initial Mitaka no-op contract revision.

Revision ID: 13cf8b5dfd05
Revises: liberty
Create Date: 2015-11-13 13:18:58.627075

"""

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '13cf8b5dfd05'
down_revision = 'liberty'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass
