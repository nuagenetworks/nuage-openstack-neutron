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

from neutron.db.models import segment as segments_db
from neutron.db import models_v2
from neutron.services.trunk import models
from neutron_lib import constants as os_constants

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
            models.SubPort.segmentation_type == os_constants.TYPE_VLAN)
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
            models.SubPort.segmentation_type == os_constants.TYPE_VLAN)
    ).all()


def get_segment_allocation_of_subports(session, subports):
    port_ids = [subport['port_id'] for subport in subports]
    segmentation_ids = [subport['segmentation_id'] for subport in subports]

    # Subquery selecting the Networksegment of a subport's trunk parent
    # port's network
    physnet_subquery = (
        session.query(segments_db.NetworkSegment)
        .join(
            (models_v2.Network,
             segments_db.NetworkSegment.network_id == models_v2.Network.id),
            (models_v2.Port,
             models_v2.Port.network_id == models_v2.Network.id),
            (models.Trunk,
             models.Trunk.port_id == models_v2.Port.id),
            (models.SubPort,
             models.SubPort.trunk_id == models.Trunk.id),
        )
        .filter(
            models.SubPort.port_id.in_(port_ids)
        )
    ).subquery()

    return (
        session.query(segments_db.NetworkSegment)
        .filter(
            (segments_db.NetworkSegment.physical_network ==
             physnet_subquery.c.physical_network),
            segments_db.NetworkSegment.segmentation_id.in_(segmentation_ids)
        )
    ).all()


def vlan_in_use_by_subport(session, segment):
    query = (
        session.query(models.SubPort)
        .join(
            (models.Trunk,
             models.SubPort.trunk_id == models.Trunk.id),
            (models_v2.Port,
             models.Trunk.port_id == models_v2.Port.id),
            (models_v2.Network,
             models_v2.Port.network_id == models_v2.Network.id),
            (segments_db.NetworkSegment,
             segments_db.NetworkSegment.network_id == models_v2.Network.id)
        )
        .filter(
            segments_db.NetworkSegment.network_type.in_(
                [os_constants.TYPE_VLAN,
                 os_constants.TYPE_FLAT]),
            (segments_db.NetworkSegment.physical_network ==
             segment['provider:physical_network']),
            (models.SubPort.segmentation_id ==
             segment['provider:segmentation_id']),
        )
    )
    return query.all()


def get_subports_in_conflict_with_net(session, subports):
    port_ids = [subport['port_id'] for subport in subports]
    query = (
        session.query(models.SubPort)
        .join(
            (models_v2.Port,
             models.SubPort.port_id == models_v2.Port.id),
            (models_v2.Network,
             models_v2.Port.network_id == models_v2.Network.id),
            (segments_db.NetworkSegment,
             segments_db.NetworkSegment.network_id == models_v2.Network.id)
        )
        .filter(
            models.SubPort.port_id.in_(port_ids),
            segments_db.NetworkSegment.network_type == os_constants.TYPE_VLAN,
            (models.SubPort.segmentation_id !=
             segments_db.NetworkSegment.segmentation_id)
        )
    )
    return query.all()
