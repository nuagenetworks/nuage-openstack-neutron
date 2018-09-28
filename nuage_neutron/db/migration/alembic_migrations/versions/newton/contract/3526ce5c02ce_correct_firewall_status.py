# Copyright 2018 NOKIA
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

try:
    from neutron_fwaas.db.firewall.firewall_db import Firewall
    from neutron_fwaas.db.firewall.firewall_router_insertion_db import \
        FirewallRouterAssociation
except ImportError:
    Firewall = None
    firewallRouterAssociation = None
"""Correct Firewall status

Revision ID: 3526ce5c02ce
Revises: ab576f499aeb
Create Date: 2018-10-11 10:22:43.824464

"""

# revision identifiers, used by Alembic.
revision = '3526ce5c02ce'
down_revision = 'ab576f499aeb'


def upgrade():
    if Firewall:
        session = sa.orm.Session(bind=op.get_bind())
        with session.begin(subtransactions=True):
            # Make firewalls without a router association inactive
            session.query(Firewall).filter(
                Firewall.id.notin_(session.query(
                    FirewallRouterAssociation.fw_id))).update(
                        {Firewall.status: 'INACTIVE'},
                        synchronize_session='fetch')
            # Make firewalls with routers and admin_state_up false DOWN
            session.query(Firewall).filter(
                Firewall.admin_state_up == 0,
                Firewall.id.in_(session.query(
                    FirewallRouterAssociation.fw_id))
            ).update(
                {Firewall.status: 'DOWN'},
                synchronize_session='fetch')
        session.commit()
