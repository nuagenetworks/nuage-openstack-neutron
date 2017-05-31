# Copyright 2014 Alcatel-Lucent USA Inc.
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
from sqlalchemy import func
from sqlalchemy.orm import aliased
from sqlalchemy.orm import exc as sql_exc

from neutron.db import common_db_mixin
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db.models import allowed_address_pair as addr_pair_models
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.plugins.ml2 import models as ml2_models
from neutron_lib import constants as os_constants

from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import nuage_models
from nuage_neutron.plugins.common import utils


def add_net_partition(session, netpart_id,
                      l3dom_id, l2dom_id,
                      ent_name, l3isolated,
                      l3shared):
    net_partitioninst = nuage_models.NetPartition(id=netpart_id,
                                                  name=ent_name,
                                                  l3dom_tmplt_id=l3dom_id,
                                                  l2dom_tmplt_id=l2dom_id,
                                                  isolated_zone=l3isolated,
                                                  shared_zone=l3shared)
    session.add(net_partitioninst)
    return net_partitioninst


def delete_net_partition(session, net_partition):
    session.delete(net_partition)


def delete_net_partition_by_id(session, netpart_id):
    query = session.query(nuage_models.NetPartition)
    query.filter_by(id=netpart_id).delete()


def get_net_partition_by_name(session, name):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(name=name).first()


def get_net_partition_by_id(session, id):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(id=id).first()


def get_net_partitions(session, filters=None, fields=None):
    query = session.query(nuage_models.NetPartition)
    common_db = common_db_mixin.CommonDbMixin()
    query = common_db._apply_filters_to_query(query,
                                              nuage_models.NetPartition,
                                              filters)
    return query


def get_net_partition_ids(session):
    query = session.query(nuage_models.NetPartition.id)
    return [netpart[0] for netpart in query]


def get_net_partition_with_lock(session, netpart_id):
    query = session.query(nuage_models.NetPartition)
    netpart_db = query.filter_by(id=netpart_id).with_lockmode('update').one()
    return netpart_db


def get_subnet_with_lock(session, sub_id):
    query = session.query(models_v2.Subnet)
    subnet_db = query.filter_by(id=sub_id).with_lockmode('update').one()
    return subnet_db


def get_router_with_lock(session, router_id):
    query = session.query(l3_db.Router)
    router_db = query.filter_by(id=router_id).with_lockmode('update').one()
    return router_db


def get_secgrp_with_lock(session, secgrp_id):
    query = session.query(securitygroups_db.SecurityGroup)
    secgrp_db = query.filter_by(id=secgrp_id).with_lockmode('update').one()
    return secgrp_db


def get_secgrprule_ids(session):
    query = session.query(securitygroups_db.SecurityGroupRule.id)
    return [secgrprule[0] for secgrprule in query]


def get_secgrprule_with_lock(session, secgrprule_id):
    query = session.query(securitygroups_db.SecurityGroupRule)
    secgrprule_db = (query.filter_by(id=secgrprule_id).with_lockmode(
        'update').one())
    return secgrprule_db


def get_port_with_lock(session, port_id):
    query = session.query(models_v2.Port)
    port_db = query.filter_by(id=port_id).with_lockmode('update').one()
    return port_db


def get_dhcp_port_with_lock(session, net_id):
    query = session.query(models_v2.Port)
    port_db = query.filter_by(network_id=net_id).filter_by(
        device_owner=os_constants.DEVICE_OWNER_DHCP).with_lockmode(
        'update').first()
    return port_db


def get_fip_with_lock(session, fip_id):
    query = session.query(l3_db.FloatingIP)
    fip_db = query.filter_by(id=fip_id).with_lockmode('update').one()
    return fip_db


def get_fip_by_floating_port_id(session, fixed_port_id):
    query = session.query(l3_db.FloatingIP)
    return query.filter_by(fixed_port_id=fixed_port_id).first()


def add_entrouter_mapping(session, np_id,
                          router_id,
                          n_l3id, rt, rd):
    ent_rtr_mapping = nuage_models.NetPartitionRouter(net_partition_id=np_id,
                                                      router_id=router_id,
                                                      nuage_router_id=n_l3id,
                                                      nuage_rtr_rt=rt,
                                                      nuage_rtr_rd=rd)
    session.add(ent_rtr_mapping)


def update_entrouter_mapping(ent_rtr_mapping, new_dict):
    ent_rtr_mapping.update(new_dict)


def add_subnetl2dom_mapping(session, neutron_subnet_id,
                            nuage_sub_id,
                            np_id,
                            ip_version,
                            l2dom_id=None,
                            nuage_user_id=None,
                            nuage_group_id=None,
                            managed=False):
    subnet_l2dom = nuage_models.SubnetL2Domain(subnet_id=neutron_subnet_id,
                                               nuage_subnet_id=nuage_sub_id,
                                               net_partition_id=np_id,
                                               nuage_l2dom_tmplt_id=l2dom_id,
                                               nuage_user_id=nuage_user_id,
                                               nuage_group_id=nuage_group_id,
                                               nuage_managed_subnet=managed,
                                               ip_version=ip_version)
    session.add(subnet_l2dom)
    return subnet_l2dom


def update_netpartition(net_partition_db, new_values):
    net_partition_db.update(new_values)


def update_subnetl2dom_mapping(subnet_l2dom,
                               new_dict):
    subnet_l2dom.update(new_dict)


def get_update_subnetl2dom_mapping(session, new_dict):
    subnet_l2dom = get_subnet_l2dom_with_lock(session, new_dict['subnet_id'])
    subnet_l2dom.update(new_dict)


def update_entrtr_mapping(ent_rtr, new_dict):
    ent_rtr.update(new_dict)


def get_update_entrtr_mapping(session, new_dict):
    ent_rtr = get_ent_rtr_mapping_with_lock(session, new_dict['router_id'])
    ent_rtr.update(new_dict)


def delete_subnetl2dom_mapping(session, subnet_l2dom):
    session.delete(subnet_l2dom)


def get_subnet_l2dom_by_id(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(subnet_id=id).first()


def get_subnet_l2doms_by_subnet_ids(session, subnet_ids):
    return (
        session.query(nuage_models.SubnetL2Domain)
        .filter(
            nuage_models.SubnetL2Domain.subnet_id.in_(subnet_ids)
        )).all()


def get_subnet_l2dom_by_port_id(session, port_id):
    query = (session.query(nuage_models.SubnetL2Domain)
             .join(models_v2.Subnet)
             .join(models_v2.IPAllocation)
             .filter(models_v2.IPAllocation.port_id == port_id))
    try:
        return query.one()
    except sql_exc.NoResultFound:
        raise exceptions.SubnetMappingNotFound(resource='port', id=port_id)
    except sql_exc.MultipleResultsFound:
        return query.first()


def get_subnet_l2dom_by_network_id(session, network_id):
    return (
        session.query(nuage_models.SubnetL2Domain)
        .join(models_v2.Subnet)
        .filter(
            models_v2.Subnet.network_id == network_id)
    ).all()


def get_nuage_subnet_info(session, subnet, fields):
    if not fields or not \
            any(x in fields for x in
                ['vsd_managed', 'vsd_id', 'nuage_net_partition_id']):
        return subnet
    result = (
        session.query(nuage_models.SubnetL2Domain)
        .filter(nuage_models.SubnetL2Domain.subnet_id == subnet['id']).first())
    subnet['vsd_managed'] = result.nuage_managed_subnet if result else False
    subnet['vsd_id'] = result.nuage_subnet_id if result else None
    subnet['nuage_net_partition_id'] = (result.net_partition_id
                                        if result else None)
    return subnet


def get_nuage_subnets_info(session, subnets, fields, filters):
    ids = [subnet['id'] for subnet in subnets]
    query = session \
        .query(nuage_models.SubnetL2Domain) \
        .filter(nuage_models.SubnetL2Domain.subnet_id.in_(ids))

    result = query.all()
    subnet_id_mapping = dict([(mapping.subnet_id, mapping)
                              for mapping in result])

    filtered = []
    for subnet in subnets:
        mapping = subnet_id_mapping.get(subnet['id'])
        subnet['vsd_managed'] = (mapping.nuage_managed_subnet
                                 if mapping else False)
        subnet['vsd_id'] = mapping.nuage_subnet_id if mapping else None
        subnet['nuage_net_partition_id'] = (mapping.net_partition_id
                                            if mapping else None)
        add = True
        if filters:
            if 'vsd_managed' in filters.keys():
                add = (str(subnet['vsd_managed']).lower() ==
                       str(filters['vsd_managed'][0]).lower())
            if 'vsd_id' in filters.keys():
                add = str(subnet['vsd_id']) == str(filters['vsd_id'][0])
            if 'nuage_net_partition_id' in filters.keys():
                add = (str(subnet['nuage_net_partition_id']) ==
                       str(filters['nuage_net_partition_id'][0]))
        if add:
            filtered.append(subnet)
    for subnet in filtered:
        for field in ['vsd_managed', 'vsd_id', 'nuage_net_partition_id']:
            if fields and field not in fields:
                del subnet[field]
    return filtered


def get_floatingip_per_vip_in_network(session, network_id):
    result = (
        session.query(l3_db.FloatingIP, models_v2.Port)
        .join(
            (models_v2.Port,
             l3_db.FloatingIP.fixed_port_id == models_v2.Port.id))
        .filter(
            models_v2.Port.network_id == network_id,
            models_v2.Port.device_owner.in_(utils.get_device_owners_vip())
        )
    ).all()
    fips_per_vip = {}
    for row in result:
        fip = row[0]
        vip_port = row[1]
        for fixed_ip in vip_port.fixed_ips:
            fips_per_vip[fixed_ip.ip_address] = fip
    return fips_per_vip


def get_routerport_by_port_id(session, port_id):
    query = session.query(l3_db.RouterPort)
    return query.filter_by(port_id=port_id).first()


def get_subnet_l2dom_by_nuage_id(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(nuage_subnet_id=str(id)).first()


def get_subnet_l2dom_by_nuage_id_and_ipversion(session, id, ipversion):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(nuage_subnet_id=str(id)).filter_by(
        ip_version=str(ipversion)).first()


def get_subnet_l2dom_with_lock(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    subl2dom = query.filter_by(subnet_id=id).with_lockmode('update').one()
    return subl2dom


def get_ent_rtr_mapping_by_entid(session, entid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(net_partition_id=entid).all()


def get_ent_l2dom_mapping_by_entid(session, entid):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(net_partition_id=entid).all()


def get_ent_rtr_mapping_by_rtrid(session, rtrid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(router_id=rtrid).first()


def get_ent_rtr_mapping_by_rtrids(session, rtrids):
    if not rtrids:
        return []
    return (
        session.query(nuage_models.NetPartitionRouter)
        .filter(
            nuage_models.NetPartitionRouter.router_id.in_(rtrids)
        )
    ).all()


def add_network_binding(session, network_id, network_type, physical_network,
                        vlan_id):
    binding = nuage_models.ProviderNetBinding(
        network_id=network_id, network_type=network_type,
        physical_network=physical_network, vlan_id=vlan_id)
    session.add(binding)
    return binding


def get_network_binding(session, network_id):
    return (session.query(nuage_models.ProviderNetBinding).
            filter_by(network_id=network_id).
            first())


def get_network_binding_with_lock(session, network_id):
    return (session.query(nuage_models.ProviderNetBinding).
            filter_by(network_id=network_id).with_lockmode('update').first())


def get_ent_rtr_mapping_with_lock(session, rtrid):
    query = session.query(nuage_models.NetPartitionRouter)
    entrtr = query.filter_by(router_id=rtrid).with_lockmode('update').one()
    return entrtr


def get_ipalloc_for_fip(session, network_id, ip, lock=False):
    query = session.query(models_v2.IPAllocation)
    if lock:
        # Lock is required when the resource is synced
        ipalloc_db = (query.filter_by(network_id=network_id).filter_by(
            ip_address=ip).with_lockmode('update').one())
    else:
        ipalloc_db = (query.filter_by(network_id=network_id).filter_by(
            ip_address=ip).one())
    return make_ipalloc_dict(ipalloc_db)


def get_all_net_partitions(session):
    net_partitions = get_net_partitions(session)
    return make_net_partition_list(net_partitions)


def get_default_net_partition(context, def_net_part):
    net_partition = get_net_partition_by_name(context.session,
                                              def_net_part)
    return net_partition


def get_all_routes(session):
    routes = session.query(extraroute_db.RouterRoute)
    return make_route_list(routes)


def get_ext_network_ids(session):
    query = session.query(external_net_db.ExternalNetwork.network_id)
    return [net[0] for net in query]


def get_route_with_lock(session, dest, nhop):
    query = session.query(extraroute_db.RouterRoute)
    route_db = (query.filter_by(destination=dest).filter_by(nexthop=nhop)
                .with_lockmode('update').one())
    return make_route_dict(route_db)


def get_all_provider_nets(session):
    provider_nets = session.query(nuage_models.ProviderNetBinding)
    return make_provider_net_list(provider_nets)


def make_provider_net_list(provider_nets):
    return [make_provider_net_dict(pnet) for pnet in provider_nets]


def make_provider_net_dict(provider_net):
    return {'network_id': provider_net['network_id'],
            'network_type': provider_net['network_type'],
            'physical_network': provider_net['physical_network'],
            'vlan_id': provider_net['vlan_id']}


def make_ipalloc_dict(subnet_db):
    return {'port_id': subnet_db['port_id'],
            'subnet_id': subnet_db['subnet_id'],
            'network_id': subnet_db['network_id'],
            'ip_address': subnet_db['ip_address']}


def make_net_partition_dict(net_partition):
    return {'id': net_partition['id'],
            'name': net_partition['name'],
            'l3dom_tmplt_id': net_partition['l3dom_tmplt_id'],
            'l2dom_tmplt_id': net_partition['l2dom_tmplt_id']}


def make_net_partition_list(net_partitions):
    return [make_net_partition_dict(net_partition) for net_partition in
            net_partitions]


def make_route_dict(route):
    return {'destination': route['destination'],
            'nexthop': route['nexthop'],
            'router_id': route['router_id']}


def make_route_list(routes):
    return [make_route_dict(route) for route in routes]


def make_subnl2dom_dict(subl2dom):
    return {'subnet_id': subl2dom['subnet_id'],
            'net_partition_id': subl2dom['net_partition_id'],
            'nuage_subnet_id': subl2dom['nuage_subnet_id'],
            'nuage_l2dom_tmplt_id': subl2dom['nuage_l2dom_tmplt_id'],
            'nuage_user_id': subl2dom['nuage_user_id'],
            'nuage_group_id': subl2dom['nuage_group_id']}


def make_entrtr_dict(entrtr):
    return {'net_partition_id': entrtr['net_partition_id'],
            'router_id': entrtr['router_id'],
            'nuage_router_id': entrtr['nuage_router_id']}


def count_allowedaddresspairs_for_subnet(session, subnet_id):
    return (
        session.query(addr_pair_models.AllowedAddressPair)
        .join(models_v2.Port)
        .join(models_v2.Network)
        .join(models_v2.Subnet)
        .filter(
            models_v2.Subnet.id == subnet_id
        )).count()


def get_port_bindings(session, port_ids):
    return (
        session.query(ml2_models.PortBinding)
        .filter(ml2_models.PortBinding.port_id.in_(port_ids))
    ).all()


def get_port_bindings_for_sg(session, sg_ids, vnic_types, bound_only=False):
    query = (
        session.query(ml2_models.PortBinding)
        .join(models_v2.Port)
        .join(securitygroups_db.SecurityGroupPortBinding)
        .filter(
            securitygroups_db.SecurityGroupPortBinding.security_group_id.in_(
                sg_ids),
            ml2_models.PortBinding.vnic_type.in_(vnic_types)
        ))
    if bound_only:
        query = query.filter(ml2_models.PortBinding.host.notin_(['']))
    return query.all()


def check_ports_to_router_mapping(context, port_ids):
    device_owner_router_itf_port = aliased(models_v2.Port)
    session = context.session
    result = (
        session.query(l3_db.Router)
        .join(l3_db.RouterPort)
        .join(device_owner_router_itf_port)
        .join(models_v2.Network)
        .join((models_v2.Port,
               models_v2.Port.network_id == models_v2.Network.id))
        .filter(
            models_v2.Port.id.in_(port_ids),
        )
        .group_by(l3_db.Router)
        .having(func.count(models_v2.Port.id) == len(port_ids))
    ).all()
    return result
