# Copyright 2017 Nokia
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

from neutron.db import models_v2
from neutron.db import segments_db
from neutron.services.trunk import constants as t_consts
from neutron.services.trunk import models

from sqlalchemy.orm import aliased
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import noload


def get_vlan_subports_of_trunk_physnet(session, trunk_id):
    cur_trunk = aliased(models.Trunk, name='cur_trunk')
    cur_parent_port = aliased(models_v2.Port, name='cur_parent_port')
    cur_parent_network = aliased(models_v2.Network, name='cur_parent_network')
    cur_parent_network_segment = aliased(segments_db.NetworkSegment,
                                         name='cur_parent_network_segment')
    other_parent_port = aliased(models_v2.Port, name='other_parent_port')

    return (
        session.query(models_v2.Port)
        .options(
            noload('*'),
            joinedload(models_v2.Port.sub_port),
            joinedload(models_v2.Port.fixed_ips))
        .join(
            (models.SubPort, models.SubPort.port_id == models_v2.Port.id),
            (models.Trunk, models.SubPort.trunk_id == models.Trunk.id),
            (other_parent_port, other_parent_port.id == models.Trunk.port_id),
            (models_v2.Network,
             models_v2.Network.id == other_parent_port.network_id),
            (segments_db.NetworkSegment,
             segments_db.NetworkSegment.network_id == models_v2.Network.id),
            (cur_parent_network_segment,
             cur_parent_network_segment.physical_network ==
             segments_db.NetworkSegment.physical_network),
            (cur_parent_network,
             cur_parent_network.id == cur_parent_network_segment.network_id),
            (cur_parent_port, cur_parent_port.network_id ==
             cur_parent_network.id),
            (cur_trunk, cur_parent_port.id == cur_trunk.port_id),
        )
        .filter(
            cur_trunk.id == trunk_id,
            models.SubPort.segmentation_type == t_consts.VLAN)
    ).all()


def get_vlan_subports_of_trunk(session, trunk_id):
    return (
        session.query(models_v2.Port)
        .options(
            noload('*'),
            joinedload(models_v2.Port.sub_port),
            joinedload(models_v2.Port.fixed_ips))
        .join(
            (models.SubPort, models.SubPort.port_id == models_v2.Port.id),
            (models.Trunk, models.SubPort.trunk_id == models.Trunk.id)
        )
        .filter(
            models.Trunk.id == trunk_id,
            models.SubPort.segmentation_type == t_consts.VLAN)
    ).all()
