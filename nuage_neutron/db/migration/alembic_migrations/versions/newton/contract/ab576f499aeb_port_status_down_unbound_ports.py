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

from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.plugins.ml2 import models as ml2_models
from neutron_lib import constants

from nuage_neutron.plugins.common import constants as nuage_constants

import sqlalchemy as sa

"""Set port status of all unbound, normal, ports to DOWN

Revision ID: ab576f499aeb
Revises: 2899a7c6d8cc
Create Date: 2018-09-05 09:58:52.027982

"""

# revision identifiers, used by Alembic.
revision = 'ab576f499aeb'
down_revision = '2899a7c6d8cc'


def upgrade():
    session = sa.orm.Session(bind=op.get_bind())

    with session.begin(subtransactions=True):

        query = (session.query(models_v2.Port)
                 .join(ml2_models.PortBinding)
                 .filter(ml2_models.PortBinding.port_id == models_v2.Port.id))

        ports = (query.filter(
            sa.and_(ml2_models.PortBinding.vnic_type ==
                    portbindings.VNIC_NORMAL,
                    models_v2.Port.device_owner !=
                    constants.DEVICE_OWNER_ROUTER_INTF,
                    models_v2.Port.device_owner !=
                    constants.DEVICE_OWNER_ROUTER_GW,
                    models_v2.Port.device_owner !=
                    nuage_constants.DEVICE_OWNER_DHCP_NUAGE,
                    ml2_models.PortBinding.vif_type == 'unbound'))
                 .all())

        for port in ports:
            port.status = 'DOWN'

        # Make sure nuage:dhcp ports are set to ACTIVE
        ports = query.filter(
            models_v2.Port.device_owner ==
            nuage_constants.DEVICE_OWNER_DHCP_NUAGE)
        for port in ports:
            port.status = 'ACTIVE'

    session.commit()
