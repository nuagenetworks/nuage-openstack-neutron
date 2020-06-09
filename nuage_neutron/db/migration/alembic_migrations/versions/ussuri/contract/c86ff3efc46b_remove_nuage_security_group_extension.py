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
import sqlalchemy as sa


"""Remove nuage security group extension

Revision ID: c86ff3efc46b
Revises: 45aaef218f29
Create Date: 2020-08-24 20:13:51.288485

"""

# revision identifiers, used by Alembic.
revision = 'c86ff3efc46b'
down_revision = '45aaef218f29'
depends_on = ('dde3c65f57d8')


def upgrade():
    nuage_security_group = sa.Table(
        'nuage_security_group',
        sa.MetaData(),
        sa.Column('security_group_id', sa.String(255), nullable=False),
        sa.Column('parameter_name', sa.String(255), nullable=False),
        sa.Column('parameter_value', sa.String(255), nullable=False)
    )
    neutron_security_group = sa.Table(
        'securitygroups',
        sa.MetaData(),
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('stateful', sa.Boolean())
    )

    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        # we only need to transfer the stateless ones since by default
        # security groups are stateful.
        stateless_sgs = (session.query(nuage_security_group)
                         .filter_by(parameter_name='STATEFUL',
                                    parameter_value='0')
                         .all())
        session.execute(
            neutron_security_group.update().values(stateful=False).where(
                neutron_security_group.c.id.in_(
                    [i[0] for i in stateless_sgs])))

        op.drop_table('nuage_security_group')
        op.drop_table('nuage_security_group_parameter')

    session.commit()
