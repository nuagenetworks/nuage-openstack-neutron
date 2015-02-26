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
#

import argparse

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_utils import importutils
import sqlalchemy.orm.exc as db_exc

from neutron import context as ncontext
from neutron.common import config
from neutron.common import exceptions as n_exc
from neutron.extensions import l3
from neutron.extensions import securitygroup as ext_sg
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db
from neutron.openstack.common import log
from neutron.openstack.common.gettextutils import _LE, _LI, _LW
from nuage_neutron.plugins.nuage import nuagedb
from nuage_neutron.plugins.nuage.common import config as nuage_config

LOG = log.getLogger(__name__)


class SyncManager(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  securitygroups_db.SecurityGroupDbMixin):
    """
    This class provides functionality to sync data between OpenStack and VSD.
    """

    def __init__(self, nuageclient):
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient

    @lockutils.synchronized('synchronize', 'nuage-sync', external=True)
    def synchronize(self, fipquota, enable_sync):
        LOG.info(_LI("Starting the sync between Neutron and VSD"))
        try:
            # Get all data to determine the resources to sync
            data = self._get_all_data()
            data['enablesync'] = enable_sync
            resources = self.nuageclient.get_resources_to_sync(data)

            # Sync all resources
            if enable_sync:
                self._sync(resources, fipquota)
        except Exception as e:
            LOG.error(_LE("Cannot complete the sync between Neutron and VSD "
                          "because of error:%s"), e.message)
            return

        self.nuageclient.sync_complete()
        LOG.info(_LI("Sync between Neutron and VSD completed"))

    def _get_all_data(self):
        # Get all net-partitions
        net_partition_list = nuagedb.get_all_net_partitions(
            self.context.session)

        # Get all subnets
        subnet_list = self.get_subnets(self.context)

        # Get all external net ids
        ext_net_id_list = nuagedb.get_ext_network_ids(self.context.session)

        # Get all routers
        router_list = self.get_routers(self.context)

        # Get all ports
        port_list = self.get_ports(self.context)

        # Get all routes
        route_list = nuagedb.get_all_routes(self.context.session)

        # Get all floatingips
        fip_list = self.get_floatingips(self.context)

        # Get all securitygrp ids
        secgrp_list = self.get_security_groups(self.context)

        # Get all port bindings
        portbinding_list = self._get_port_security_group_bindings(self.context)

         # Get all provider-net bindings
        providernet_list = nuagedb.get_all_provider_nets(self.context.session)

        data = {
            'netpartition': net_partition_list,
            'subnet': subnet_list,
            'extnetwork': ext_net_id_list,
            'router': router_list,
            'port': port_list,
            'route': route_list,
            'fip': fip_list,
            'secgroup': secgrp_list,
            'portbinding': portbinding_list,
            'providernet': providernet_list
        }
        return data

    def _sync(self, resources, fip_quota):
        self.disassoc_security_groups(resources)
        self.delete_vm_interfaces(resources)
        self.delete_vms(resources)
        self.delete_security_group_rules(resources)
        self.delete_security_groups(resources)
        self.delete_fips(resources)
        self.delete_routes(resources)
        self.delete_domainsubnets(resources)
        self.delete_domains(resources)
        self.delete_l2domains(resources)

        # Sync net-partitions
        net_partition_id_dict = self.sync_net_partitions(fip_quota, resources)

        # Sync sharednetworks
        self.sync_sharednetworks(resources)

        # Sync l2domains
        self.sync_l2domains(net_partition_id_dict, resources)

        # Sync domains
        self.sync_domains(net_partition_id_dict, resources)

        # Sync domainsubnets
        self.sync_domainsubnets(resources)

        # Sync routes
        self.sync_routes(resources)

        # Sync vms
        self.sync_vms(resources)

        # Sync secgrps
        self.sync_secgrps(resources)

        # Sync secgrprules
        self.sync_secgrp_rules(resources)

        # Sync fips
        self._sync_fips(resources)

        # Delete the old net-partitions
        for net_id in net_partition_id_dict:
            nuagedb.delete_net_partition_by_id(self.context.session,
                                               net_id)

    def disassoc_security_groups(self, resources):
        secgrp_dict = resources['security']['secgroup']
        for secgrp_id, port_ids in secgrp_dict['disassociate'].iteritems():
            with self.context.session.begin(subtransactions=True):
                # This is just to lock the particular row in secgrp table
                self._get_sec_grp_data(secgrp_id)

                # Get port binding data
                port_id_list = []
                for port_id in port_ids:
                    sg_port_binding = self._get_sg_port_data(secgrp_id,
                                                             port_id)
                    if not sg_port_binding:
                        port_id_list.append(port_id)
                self.nuageclient.disassoc_security_groups(secgrp_id,
                                                          port_id_list)

    def delete_vm_interfaces(self, resources):
        for vm_id, intf_list in resources['vm']['interface'].iteritems():
            with self.context.session.begin(subtransactions=True):
                curr_intf_list = []
                for intf in intf_list:
                    vm_port = self._get_vm_port_data(intf['externalID'])
                    if not vm_port:
                        curr_intf_list.append(intf)

                if curr_intf_list:
                    netpart = self._get_netpart_data(
                        curr_intf_list[0]['netpart_id'])
                    if netpart:
                        LOG.info(_LI("VM interfaces %s not found in neutron, "
                                     "so will be deleted"), curr_intf_list)
                        self.nuageclient.delete_vm_interfaces(vm_id,
                                                              curr_intf_list,
                                                              netpart)

    def delete_vms(self, resources):
        for vm_id, data in resources['vm']['delete'].iteritems():
            with self.context.session.begin(subtransactions=True):
                vm_port = self._get_vm_port_data(vm_id)

                # Delete the vm only if there is no port associated with it
                if not vm_port:
                    netpart = self._get_netpart_data(data['netpart_id'])
                    if netpart:
                        LOG.info(_LI("VM %s not found in neutron, so will "
                                     "be deleted"), vm_id)
                        self.nuageclient.delete_vm(vm_id,
                                                   data['tenant_id'],
                                                   netpart)

    def delete_security_group_rules(self, resources):
        for secrule_id, secrules in resources['security']['secgrouprule'][
            'delete'].iteritems():
            try:
                self._get_security_group_rule(self.context, secrule_id)
                LOG.info(_LI("Secrule %s found in neutron, so will not be "
                             "deleted"), secrule_id)
            except ext_sg.SecurityGroupRuleNotFound:
                LOG.info(_LI("Secrule %s not found in neutron, so will be "
                             "deleted"), secrule_id)
                self.nuageclient.delete_security_group_rule(secrules)

    def delete_security_groups(self, resources):
        for secgrp_id in resources['security']['secgroup']['delete']:
            try:
                self._get_security_group(self.context, secgrp_id)
                LOG.info(_LI("Secgrp %s found in neutron, so will not be "
                             "deleted"), secgrp_id)
            except ext_sg.SecurityGroupNotFound:
                LOG.info(_LI("Secgrp %s not found in neutron, so will be "
                             "deleted"), secgrp_id)
                self.nuageclient.delete_security_group(secgrp_id)

    def delete_fips(self, resources):
        for fip_id in resources['fip']['delete']:
            try:
                self.get_floatingip(self.context, fip_id)
                LOG.info(_LI("FloatingIP %s found in neutron, so will not be "
                             "deleted"), fip_id)
            except l3.FloatingIPNotFound:
                LOG.info(_LI("FloatingIP %s not found in neutron, so will "
                             "be deleted"), fip_id)
                self.nuageclient.delete_fip(fip_id)

    def delete_routes(self, resources):
        for rt in resources['route']['delete']:
            try:
                nuagedb.get_route(self.context.session,
                                  rt['destination'],
                                  rt['nexthop'])
                LOG.info(_LI("Route with destination %(dest)s and nexthop %("
                             "hop)s found in neutron, so will not be deleted"),
                         {'dest': rt['destination'],
                          'hop': rt['nexthop']})
            except db_exc.NoResultFound:
                LOG.info(_LI("Route with destination %(dest)s and nexthop "
                             "%(hop)s not found in neutron, so will be "
                             "deleted"),
                         {'dest': rt['destination'],
                          'hop': rt['nexthop']})
                self.nuageclient.delete_route(rt)

    def delete_domainsubnets(self, resources):
        for domsubn_id in resources['domainsubnet']['add']:
            try:
                self.get_subnet(self.context, domsubn_id)
                LOG.info(_LI("Domain-Subnet %s found in neutron, so will not "
                             "be deleted"), domsubn_id)
            except n_exc.SubnetNotFound:
                LOG.info(_LI("Domain-Subnet %s not found in neutron, so "
                             "will be deleted"), domsubn_id)
                self.nuageclient.delete_domainsubnet(domsubn_id)

    def delete_domains(self, resources):
        for domain_id in resources['domain']['delete']:
            try:
                self.get_router(self.context, domain_id)
                LOG.info(_LI("Domain %s found in neutron, so will not be "
                             "deleted"), domain_id)
            except l3.RouterNotFound:
                LOG.info(_LI("Domain %s not found in neutron, so will be "
                             "deleted"), domain_id)
                self.nuageclient.delete_domain(domain_id)

    def delete_l2domains(self, resources):
        for l2dom_id in resources['l2domain']['delete']:
            try:
                self.get_subnet(self.context, l2dom_id)
                LOG.info(_LI("L2Domain %s found in neutron, so will not "
                             "be deleted"), l2dom_id)
            except n_exc.SubnetNotFound:
                LOG.info(_LI("L2Domain %s not found in neutron, so "
                             "will be deleted"), l2dom_id)
                self.nuageclient.delete_l2domain(l2dom_id)

    def sync_net_partitions(self, fip_quota, resources):
        net_partition_id_dict = {}
        for netpart_id in resources['netpartition']['add']:
            with self.context.session.begin(subtransactions=True):
                netpart = self._get_netpart_data(netpart_id)
                if netpart:
                    result = self.nuageclient.create_netpart(netpart,
                                                             fip_quota)
                    netpart = result.get(netpart_id)
                    if netpart:
                        net_partition_id_dict[netpart_id] = netpart['id']
                        nuagedb.add_net_partition(
                            self.context.session,
                            netpart['id'],
                            netpart['l3dom_tmplt_id'],
                            netpart['l2dom_tmplt_id'],
                            netpart['name'])

        for netpart in resources['netpartition']['update']:
            with self.context.session.begin(subtransactions=True):
                old_netpart = self._get_netpart_data(netpart['id'])
                if old_netpart:
                    nuagedb.get_update_netpartition(self.context.session,
                                                    netpart)

        return net_partition_id_dict

    def sync_sharednetworks(self, resources):
        for sharednet_id in resources['sharednetwork']['add']:
            with self.context.session.begin(subtransactions=True):
                subnet, subl2dom, dhcp_port = self._get_subnet_data(
                    sharednet_id,
                    get_mapping=False)
                if subnet:
                    self.nuageclient.create_sharednetwork(subnet)

    def sync_l2domains(self, net_partition_id_dict, resources):
        for l2dom_id in resources['l2domain']['add']:
            with self.context.session.begin(subtransactions=True):
                subnet, subl2dom, dhcp_port = self._get_subnet_data(l2dom_id)
                if subnet:
                    # if subnet exists, subl2dom will exist
                    netpart_id = subl2dom['net_partition_id']
                    if netpart_id in net_partition_id_dict.keys():
                        # Use the id of the newly created net_partition
                        netpart_id = net_partition_id_dict[netpart_id]

                    result = self.nuageclient.create_l2domain(netpart_id,
                                                              subnet,
                                                              dhcp_port)
                    if result:
                        nuagedb.get_update_subnetl2dom_mapping(
                            self.context.session,
                            result)

    def sync_domains(self, net_partition_id_dict, resources):
        for domain_id in resources['domain']['add']:
            with self.context.session.begin(subtransactions=True):
                router, entrtr = self._get_router_data(domain_id)
                if router:
                    # if router exists, entrtr will exist
                    netpart_id = entrtr['net_partition_id']
                    if netpart_id in net_partition_id_dict.keys():
                        # Use the id of the newly created net_partition
                        netpart_id = net_partition_id_dict[netpart_id]

                    netpart = nuagedb.get_net_partition_by_id(
                        self.context.session,
                        netpart_id)

                    router['rt'] = entrtr['rt']
                    router['rd'] = entrtr['rd']
                    result = self.nuageclient.create_domain(netpart, router)
                    if result:
                        nuagedb.get_update_entrtr_mapping(self.context.session,
                                                          result)

    def sync_domainsubnets(self, resources):
        for domsubn_id in resources['domainsubnet']['add']:
            # This is a dict of subn_id and the router interface port
            subn_rtr_intf_port_dict = (
                resources['port']['sub_rtr_intf_port_dict'])
            port_id = subn_rtr_intf_port_dict[domsubn_id]
            port = self._get_port_data(port_id)
            if port:
                with self.context.session.begin(subtransactions=True):
                    subnet, subl2dom, dhcp_port = self._get_subnet_data(
                        domsubn_id)
                    if subnet:
                        result = self.nuageclient.create_domainsubnet(subnet,
                                                                      port)
                        if result:
                            nuagedb.get_update_subnetl2dom_mapping(
                                self.context.session,
                                result)

    def sync_routes(self, resources):
        for rt in resources['route']['add']:
            with self.context.session.begin(subtransactions=True):
                route = self._get_route_data_with_lock(rt)
                if route:
                    self.nuageclient.create_route(route)

    def sync_vms(self, resources):
        for port_id in resources['port']['vm']:
            port = self._get_port_data(port_id)
            if port:
                self.nuageclient.create_vm(port)

    def sync_secgrps(self, resources):
        secgrp_dict = resources['security']['secgroup']
        for secgrp_id, port_ids in secgrp_dict['l2domain']['add'].iteritems():
            with self.context.session.begin(subtransactions=True):
                secgrp = self._get_sec_grp_data(secgrp_id)
                if secgrp:
                    for port_id in port_ids:
                        with self.context.session.begin(subtransactions=True):
                            port = self._get_port_data(port_id)
                            if port:
                                self.nuageclient.create_security_group(secgrp,
                                                                       port)

        for secgrp_id, port_ids in secgrp_dict['domain']['add'].iteritems():
            with self.context.session.begin(subtransactions=True):
                secgrp = self._get_sec_grp_data(secgrp_id)
                if secgrp:
                    for port_id in port_ids:
                        with self.context.session.begin(subtransactions=True):
                            port = self._get_port_data(port_id)
                            if port:
                                self.nuageclient.create_security_group(secgrp,
                                                                       port)

    def sync_secgrp_rules(self, resources):
        secrule_list = resources['security']['secgrouprule']
        for secrule_id in secrule_list['l2domain']['add']:
            with self.context.session.begin(subtransactions=True):
                secgrprule = self._get_sec_grp_rule_data(secrule_id)
                if secgrprule:
                    self.nuageclient.create_security_group_rule(secgrprule)

        for secrule_id in secrule_list['domain']['add']:
            with self.context.session.begin(subtransactions=True):
                secgrprule = self._get_sec_grp_rule_data(secrule_id)
                if secgrprule:
                    self.nuageclient.create_security_group_rule(secgrprule)

    def _sync_fips(self, resources):
        for fip_id in resources['fip']['add']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    ipalloc = self._get_ipalloc_for_fip(fip)
                    self.nuageclient.create_fip(fip, ipalloc)

        for fip_id in resources['fip']['disassociate']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    self.nuageclient.disassociate_fip(fip)

        for fip_id in resources['fip']['associate']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    self.nuageclient.associate_fip(fip)

    def _get_subnet_data(self, subnet_id, get_mapping=True):
        subnet = None
        subl2dom = None
        port = None
        try:
            if get_mapping:
                subl2dom_db = nuagedb.get_subnet_l2dom_with_lock(
                    self.context.session,
                    subnet_id)
                subl2dom = nuagedb.make_subnl2dom_dict(subl2dom_db)

            subnet_db = nuagedb.get_subnet_with_lock(self.context.session,
                                                     subnet_id)
            port_db = nuagedb.get_dhcp_port_with_lock(self.context.session,
                                                      subnet_db['network_id'])
            if port_db:
                port = self._make_port_dict(port_db)
            subnet = self._make_subnet_dict(subnet_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Subnet %s not found in neutron for sync"),
                        subnet_id)

        return subnet, subl2dom, port

    def _get_router_data(self, router_id):
        router = None
        entrtr = None
        try:
            entrtr_db = nuagedb.get_ent_rtr_mapping_with_lock(
                self.context.session,
                router_id)
            entrtr = nuagedb.make_entrtr_dict(entrtr_db)

            router_db = nuagedb.get_router_with_lock(self.context.session,
                                                     router_id)
            router = self._make_router_dict(router_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Router %s not found in neutron for sync"),
                        router_id)

        return router, entrtr

    def _get_route_data_with_lock(self, rt):
        route = None
        try:
            route = nuagedb.get_route_with_lock(self.context.session,
                                                rt['destination'],
                                                rt['nexthop'])
        except db_exc.NoResultFound:
            LOG.warning(_LW("Route with destination %(dest)s and nexthop "
                            "%(hop)s not found in neutron for sync"),
                        {'dest': rt['destination'],
                         'hop': rt['nexthop']})

        return route

    def _get_sec_grp_data(self, secgrp_id):
        secgrp = None
        try:
            secgrp_db = nuagedb.get_secgrp_with_lock(self.context.session,
                                                     secgrp_id)
            secgrp = self._make_security_group_dict(secgrp_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Security group %s not found in neutron for sync"),
                        secgrp_id)
        return secgrp

    def _get_sec_grp_rule_data(self, secgrprule_id):
        secgrprule = None
        try:
            secrule_db = nuagedb.get_secgrprule_with_lock(self.context.session,
                                                          secgrprule_id)
            secgrprule = self._make_security_group_rule_dict(secrule_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Security group rule %s not found in neutron for "
                            "sync"), secgrprule_id)
        return secgrprule

    def _get_fip_data(self, fip_id):
        fip = None
        try:
            fip_db = nuagedb.get_fip_with_lock(self.context.session, fip_id)
            fip = self._make_floatingip_dict(fip_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Floating ip %s not found in neutron for sync"),
                        fip_id)
        return fip

    def _get_ipalloc_for_fip(self, fip):
        ipalloc = None
        try:
            ipalloc = nuagedb.get_ipalloc_for_fip(self.context.session,
                                                  fip['floating_network_id'],
                                                  fip['floating_ip_address'],
                                                  lock=True)
        except db_exc.NoResultFound:
            LOG.warning(_LW("IP allocation for floating ip %s not found in "
                            "neutron for sync"), fip['id'])
        return ipalloc

    def _get_netpart_data(self, netpart_id):
        netpart = None
        try:
            netpart_db = nuagedb.get_net_partition_with_lock(
                self.context.session,
                netpart_id)
            netpart = nuagedb.make_net_partition_dict(netpart_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Net-partition %s not found in neutron for sync"),
                        netpart_id)
        return netpart

    def _get_port_data(self, port_id):
        port = None
        try:
            port_db = nuagedb.get_port_with_lock(self.context.session,
                                                 port_id)
            port = self._make_port_dict(port_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("VM port %s not found in neutron for sync"),
                        port_id)
        return port

    def _get_sg_port_data(self, secgrp_id, port_id):
        filters = {
            'security_group_id': [secgrp_id],
            'port_id': [port_id]
        }

        sg_port_binding = self._get_port_security_group_bindings(self.context,
                                                                 filters)

        if not sg_port_binding:
            LOG.warning(_LW("VM port %(port)s and secgrp %(sec)s has no "
                            "security-group binding in neutron"),
                        {'port': port_id,
                         'sec': secgrp_id})

        return sg_port_binding

    def _get_vm_port_data(self, device_id):
        filters = {'device_id': [device_id]}
        port = self.get_ports(self.context, filters)
        if not port:
            LOG.warning(_LW("VM  %s not found in neutron for sync"), device_id)
        return port


def main():
    try:
        logging = importutils.import_module('logging')
        logging.basicConfig(level=logging.DEBUG)
        parser = argparse.ArgumentParser()
        parser.add_argument("--config-file", nargs='+',
                            help='List of config files separated by space')
        args = parser.parse_args()

        conffiles = args.config_file
        if conffiles is None:
            parser.print_help()
            return

        arg_list = []
        for conffile in conffiles:
            arg_list.append('--config-file')
            arg_list.append(conffile)

        config.init(arg_list)
        nuage_config.nuage_register_cfg_opts()

        server = cfg.CONF.RESTPROXY.server
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        base_uri = cfg.CONF.RESTPROXY.base_uri
        auth_resource = cfg.CONF.RESTPROXY.auth_resource
        organization = cfg.CONF.RESTPROXY.organization
        fipquota = str(cfg.CONF.RESTPROXY.default_floatingip_quota)

        nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
        nuageclient = nuageclientinst.NuageClient(server, base_uri,
                                                  serverssl, serverauth,
                                                  auth_resource,
                                                  organization)
    except Exception as e:
        LOG.error("Error in Syncmanager:%s", str(e))
        return

    LOG.info('Sync/Audit is disabled')

if __name__ == '__main__':
    main()
