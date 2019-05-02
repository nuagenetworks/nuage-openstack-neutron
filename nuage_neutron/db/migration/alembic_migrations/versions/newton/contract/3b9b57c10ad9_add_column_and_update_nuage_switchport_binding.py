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

"""add switchport_mapping_id column to nuage_switchport_binding

Revision ID: 3b9b57c10ad9
Revises: 4fdefabb76a8
Create Date: 2017-09-01 11:39:38.492960

"""

import json

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3b9b57c10ad9'
down_revision = '4fdefabb76a8'
depends_on = ('c4fb5a76b195')


def upgrade():
    op.add_column('nuage_switchport_binding',
                  sa.Column('switchport_mapping_id', sa.String(36),
                            nullable=False))

    ml2_port_bindings = sa.Table('ml2_port_bindings',
                                 sa.MetaData(),
                                 sa.Column('port_id', sa.String(length=36),
                                           nullable=False),
                                 sa.Column('host', sa.String(length=255),
                                           nullable=False,
                                           server_default=''),
                                 sa.Column('vif_type', sa.String(length=64),
                                           nullable=False),
                                 sa.Column('vnic_type', sa.String(length=64),
                                           nullable=False,
                                           server_default='normal'),
                                 sa.Column('profile', sa.String(length=4095),
                                           nullable=False,
                                           server_default=''),
                                 sa.Column('vif_details',
                                           sa.String(length=4095),
                                           nullable=False,
                                           server_default='')
                                 )

    nuage_switchport_mapping = sa.Table('nuage_switchport_mapping',
                                        sa.MetaData(),
                                        sa.Column('id', sa.String(36),
                                                  nullable=False),
                                        sa.Column('switch_info',
                                                  sa.String(255),
                                                  nullable=False),
                                        sa.Column('switch_id',
                                                  sa.String(36),
                                                  nullable=False),
                                        sa.Column('redundant',
                                                  sa.Boolean(),
                                                  nullable=False),
                                        sa.Column('port_id',
                                                  sa.String(255),
                                                  nullable=False),
                                        sa.Column('port_uuid',
                                                  sa.String(36),
                                                  nullable=False),
                                        sa.Column('pci_slot', sa.String(36),
                                                  nullable=False),
                                        sa.Column('host_id', sa.String(255),
                                                  nullable=False)
                                        )

    nuage_switchport_bindings = sa.Table('nuage_switchport_binding',
                                         sa.MetaData(),
                                         sa.Column('id',
                                                   sa.String(36),
                                                   nullable=False),
                                         sa.Column('neutron_port_id',
                                                   sa.String(36),
                                                   nullable=False),
                                         sa.Column('nuage_vport_id',
                                                   sa.String(36),
                                                   nullable=False),
                                         sa.Column('switchport_uuid',
                                                   sa.String(36),
                                                   nullable=False),
                                         sa.Column('segmentation_id',
                                                   sa.Integer,
                                                   nullable=False),
                                         sa.Column('switchport_mapping_id',
                                                   sa.String(36),
                                                   nullable=False))

    session = sa.orm.Session(bind=op.get_bind())

    with session.begin(subtransactions=True):
        for nuage_switchport_binding in session.query(nuage_switchport_bindings
                                                      ).all():
            port_binding = session.query(ml2_port_bindings).filter(
                ml2_port_bindings.c.port_id ==
                nuage_switchport_binding.neutron_port_id).first()

            switch_port_mapping = session.query(
                nuage_switchport_mapping).filter(
                nuage_switchport_mapping.c.port_uuid ==
                nuage_switchport_binding.switchport_uuid,
                nuage_switchport_mapping.c.pci_slot ==
                json.loads(port_binding.profile)["pci_slot"],
                nuage_switchport_mapping.c.host_id ==
                port_binding.host).first()

            session.execute(nuage_switchport_bindings.update().values(
                switchport_mapping_id=switch_port_mapping.id).where(
                nuage_switchport_bindings.c.id ==
                nuage_switchport_binding.id))
    session.commit()

    op.create_foreign_key(constraint_name=None,
                          source_table='nuage_switchport_binding',
                          referent_table='nuage_switchport_mapping',
                          local_cols=['switchport_mapping_id'],
                          remote_cols=['id'],
                          ondelete='RESTRICT')
