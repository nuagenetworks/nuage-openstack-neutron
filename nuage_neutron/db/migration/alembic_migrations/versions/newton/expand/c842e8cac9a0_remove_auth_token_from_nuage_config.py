# Copyright 2017  Alcatel-Lucent USA Inc.
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

"""remove auth_token from nuage config

Revision ID: c842e8cac9a0
Revises: b05bd74f4cc7
Create Date: 2017-12-19 16:01:36.644126

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = 'c842e8cac9a0'
down_revision = 'b05bd74f4cc7'


def upgrade():
    op.execute("DELETE FROM nuage_config_parameter WHERE name='auth_token'")
