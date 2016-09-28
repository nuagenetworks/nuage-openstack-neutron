# Copyright 2014 Alcatel-Lucent USA Inc.
# All Rights Reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import portbindings

BINDING_PROFILE_LEN = 4095


class PortBinding(model_base.BASEV2):
    """Represent binding-related state of a port.

    A port binding stores the port attributes required for the
    portbindings extension, as well as internal ml2 state such as
    which MechanismDriver and which segment are used by the port
    binding.
    """

    __tablename__ = 'ml2_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False, default='',
                     server_default='')
    vnic_type = sa.Column(sa.String(64), nullable=False,
                          default=portbindings.VNIC_NORMAL,
                          server_default=portbindings.VNIC_NORMAL)
    profile = sa.Column(sa.String(BINDING_PROFILE_LEN), nullable=False,
                        default='', server_default='')
    vif_type = sa.Column(sa.String(64), nullable=False)
    vif_details = sa.Column(sa.String(4095), nullable=False, default='',
                            server_default='')

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load port bindings
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("port_binding",
                            lazy='joined', uselist=False,
                            cascade='delete'))
