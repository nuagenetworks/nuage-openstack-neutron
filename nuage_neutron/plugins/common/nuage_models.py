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

import sqlalchemy as sa

from neutron_lib.db import model_base


class NetPartition(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'nuage_net_partitions'
    name = sa.Column(sa.String(64))
    l3dom_tmplt_id = sa.Column(sa.String(36))
    l2dom_tmplt_id = sa.Column(sa.String(36))
    isolated_zone = sa.Column(sa.String(64))
    shared_zone = sa.Column(sa.String(64))


class NetPartitionRouter(model_base.BASEV2):
    __tablename__ = "nuage_net_partition_router_mapping"
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                 ondelete="CASCADE"),
                                 primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    nuage_router_id = sa.Column(sa.String(36), unique=True)
    nuage_rtr_rt = sa.Column(sa.String(36))
    nuage_rtr_rd = sa.Column(sa.String(36))


class NetPartitionProject(model_base.BASEV2):
    __tablename__ = "nuage_project_net_partition_mapping"
    project = sa.Column(sa.String(64), primary_key=True)
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                 ondelete="CASCADE"))


class SubnetL2Domain(model_base.BASEV2):
    __tablename__ = 'nuage_subnet_l2dom_mapping'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                 ondelete="CASCADE"))
    nuage_subnet_id = sa.Column(sa.String(36))
    nuage_l2dom_tmplt_id = sa.Column(sa.String(36))
    nuage_user_id = sa.Column(sa.String(36))
    nuage_group_id = sa.Column(sa.String(36))
    nuage_managed_subnet = sa.Column(sa.Boolean())
    ip_version = sa.Column(sa.Integer(), nullable=False)


class NuageSwitchportMapping(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'nuage_switchport_mapping'
    switch_info = sa.Column(sa.String(255), nullable=False)
    switch_id = sa.Column(sa.String(36), nullable=False)
    redundant = sa.Column(sa.Boolean())
    # port_id = sa.Column(sa.String(255), nullable=False)
    port_uuid = sa.Column(sa.String(36), nullable=False)
    # pci_slot = sa.Column(sa.String(36), nullable=False)
    host_id = sa.Column(sa.String(255), nullable=False)
    physnet = sa.Column(sa.String(255), nullable=False)
    __table_args__ = (sa.PrimaryKeyConstraint('id'),
                      # Not unique when PCI slot mapping is used
                      # sa.UniqueConstraint('port_uuid'),
                      sa.UniqueConstraint('host_id', 'physnet'))


class NuageSwitchportBinding(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'nuage_switchport_binding'
    neutron_port_id = sa.Column(sa.String(36), nullable=False)
    nuage_vport_id = sa.Column(sa.String(36), nullable=False)
    switchport_uuid = sa.Column(sa.String(36), nullable=False)
    segmentation_id = sa.Column(sa.Integer, nullable=False)
    switchport_mapping_id = sa.Column(sa.String(36), nullable=False)
    sa.ForeignKeyConstraint(['neutron_port_id'],
                            ['ports.id'], ondelete="CASCADE")
    sa.ForeignKeyConstraint(['switchport_mapping_id'],
                            ['nuage_switchport_mapping.id'],
                            ondelete="RESTRICT")


class NuageSfcVlanSubnetMapping(model_base.BASEV2):
    __tablename__ = 'nuage_sfc_vlan_subnet_mapping'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete='CASCADE'),
                          primary_key=True)
    vlan_bit_map = sa.Column('vlan_bit_map', sa.VARBINARY(512), nullable=False)


class NuageSubnet(model_base.BASEV2):
    __tablename__ = 'nuage_subnet'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True,
                          nullable=False)
    subnet_parameter = sa.Column(sa.String(255),
                                 sa.ForeignKey('nuage_subnet_parameter.name',
                                               ondelete="CASCADE"),
                                 primary_key=True,
                                 nullable=False)
    parameter_value = sa.Column(sa.String(255),
                                nullable=False)


class NuageRouter(model_base.BASEV2):
    __tablename__ = 'nuage_router'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True,
                          nullable=False)
    router_parameter = sa.Column(sa.String(255),
                                 sa.ForeignKey('nuage_router_parameter.name',
                                               ondelete="CASCADE"),
                                 primary_key=True,
                                 nullable=False)
    parameter_value = sa.Column(sa.String(255),
                                nullable=False)


class NuageSubnetParameter(model_base.BASEV2):
    __tablename__ = 'nuage_subnet_parameter'
    name = sa.Column(sa.String(255), primary_key=True, nullable=False)


class NuageRouterParameter(model_base.BASEV2):
    __tablename__ = 'nuage_router_parameter'
    name = sa.Column(sa.String(255), primary_key=True, nullable=False)


class NuageConfig(model_base.BASEV2):
    __tablename__ = 'nuage_config'
    __table_args__ = (
        sa.PrimaryKeyConstraint('organization', 'username',
                                'config_parameter'),
    )
    organization = sa.Column('organization', sa.String(255), nullable=False)
    username = sa.Column('username', sa.String(255), nullable=False)
    config_parameter = sa.Column(sa.String(255),
                                 sa.ForeignKey('nuage_config_parameter.name',
                                 ondelete="CASCADE"),
                                 nullable=False)
    config_value = sa.Column(sa.String(255), nullable=False)


class NuageConfigParameter(model_base.BASEV2):
    __tablename__ = 'nuage_config_parameter'
    name = sa.Column(sa.String(255), primary_key=True, nullable=False)


class NuageSecurityGroup(model_base.BASEV2):
    __tablename__ = 'nuage_security_group'
    __table_args__ = (
        sa.PrimaryKeyConstraint('security_group_id', 'parameter_name'),
    )
    security_group_id = sa.Column('security_group_id', sa.String(255),
                                  nullable=False)
    parameter_name = sa.Column(sa.String(255),
                               sa.ForeignKey(
                                   'nuage_security_group_parameter.name',
                                   ondelete='CASCADE'),
                               nullable=False)
    parameter_value = sa.Column(sa.String(255), nullable=False)


class NuageSecurityGroupParameter(model_base.BASEV2):
    __tablename__ = 'nuage_security_group_parameter'
    name = sa.Column(sa.String(255), primary_key=True, nullable=False)


class NuageL2bridge(model_base.BASEV2, model_base.HasId,
                    model_base.HasProject):
    __tablename__ = 'nuage_l2bridge'
    name = sa.Column(sa.String(255), nullable=True)
    nuage_subnet_id = sa.Column(sa.String(36), nullable=True)


class NuageL2bridgePhysnetMapping(model_base.BASEV2):
    __tablename__ = 'nuage_l2bridge_physnet_mapping'
    l2bridge_id = sa.Column(sa.String(36), sa.ForeignKey('nuage_l2bridge.id',
                                                         ondelete='CASCADE'),
                            primary_key=True, nullable=False)
    physnet = sa.Column(sa.String(64), nullable=False, primary_key=True)
    segmentation_id = sa.Column(sa.Integer, nullable=False, primary_key=True)
    segmentation_type = sa.Column(sa.String(32), nullable=False,
                                  default='vlan')
    __table_args__ = (
        sa.UniqueConstraint(
            physnet, segmentation_id,
            name='uniq_physnet_segmentationid'),
        model_base.BASEV2.__table_args__
    )
