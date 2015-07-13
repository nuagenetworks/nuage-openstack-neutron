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

"""internal_icehouse_to_internal_juno

Revision ID: 4201f5479350
Revises: 36f580568441
Create Date: 2014-11-17 14:38:55.585488

"""

# revision identifiers, used by Alembic.
revision = '4201f5479350'
down_revision = '36f580568441'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_table('secgroup_vporttag_mapping')
    op.drop_table('secgrouprule_acl_mapping')
    op.drop_table('vport_vporttag_mapping')
    op.drop_table('router_acl_mapping')
    op.drop_table('floatingip_pool_mapping')
    op.drop_table('floatingip_mapping')

