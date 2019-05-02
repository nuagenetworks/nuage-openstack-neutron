# Copyright 2016 Nuage Netowrks USA Inc.
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

import abc
import copy
import os

import oslo_messaging
import six

from neutron.agent.linux import ip_lib
from neutron.common import rpc as n_rpc
from neutron import context
from neutron_lib import constants
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import device_drivers
from neutron_vpnaas.services.vpn.device_drivers import fedora_strongswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from nuage_neutron.vpnaas.common import topics
from nuage_neutron.vpnaas.nuage_interface import NuageInterfaceDriver
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall


LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(os.path.abspath(__file__))
IPSEC_CONNS = 'ipsec_site_connections'


class NuageIPsecVpnDriverApi(object):
    """IPSecVpnDriver RPC api."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices.

            The vpnservices including related ipsec_site_connection,
            ikepolicy and ipsecpolicy on this host
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vpn_services_on_host', host=host)

    def update_status(self, context, status):
        """Update local status.

            This method call updates status attribute of
            VPNServices.
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_status', status=status)


@six.add_metaclass(abc.ABCMeta)
class NuageIPsecDriver(device_drivers.DeviceDriver):

    def __init__(self, vpn_service, host):
        self.conf = vpn_service.conf
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        self.topic = topics.NUAGE_IPSEC_AGENT_TOPIC
        self.processes = {}
        self.routers = {}
        self.process_status_cache = {}
        self.endpoints = [self]
        self.conn.create_consumer(self.topic, self.endpoints)
        self.conn.consume_in_threads()
        self.agent_rpc = NuageIPsecVpnDriverApi(
            topics.NUAGE_IPSEC_DRIVER_TOPIC)
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=20)
        self.nuage_if_driver = NuageInterfaceDriver(cfg.CONF)

    def _get_l3_plugin(self):
        return directory.get_plugin(constants.L3)

    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
        """
        return 'vpn-' + router_id

    def vpnservice_updated(self, context, **kwargs):
        """Vpnservice updated rpc handler

        VPN Service Driver will call this method
        when vpnservices updated.
        Then this method start sync with server.
        """
        router = kwargs.get('router', None)
        self.sync(context, [router] if router else [])

    def tracking(self, context, **kwargs):
        """Handling create router event.

        Agent calls this method, when the process namespace is ready.
        Note: process_id == router_id == vpnservice_id
        """
        router = kwargs.get('router', None)
        process_id = router['id']
        self.routers[process_id] = process_id
        if process_id in self.processes:
            # In case of vpnservice is created
            # before vpn service namespace
            process = self.processes[process_id]
            process.enable()

    def non_tracking(self, context, **kwargs):
        router = kwargs.get('router', None)
        process_id = router['id']
        self.destroy_process(process_id)
        if process_id in self.routers:
            del self.routers[process_id]

    def ensure_process(self, process_id, vpnservice=None):
        """Ensuring process.

        If the process doesn't exist, it will create process
        and store it in self.processs
        """
        process = self.processes.get(process_id)
        if not process or not process.namespace:
            namespace = self.get_namespace(process_id)
            process = self.create_process(
                process_id,
                vpnservice,
                namespace)
            self.processes[process_id] = process
        elif vpnservice:
            process.update_vpnservice(vpnservice)
        return process

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers):
        """Sync status with server side.

        :param context: context object for RPC call
        :param routers: Router objects which is created in this sync event

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle, these failure cases,
        the driver needs to take sync strategies.

        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)
        router_ids = [vpnservice['router_id'] for vpnservice in vpnservices]
        sync_router_ids = [router['id'] for router in routers]
        self._sync_vpn_processes(vpnservices, sync_router_ids)
        self._delete_vpn_processes(sync_router_ids, router_ids)
        self._cleanup_stale_vpn_processes(router_ids)
        self.report_status(context)

    def get_process_status_cache(self, process):
        if not self.process_status_cache.get(process.id):
            self.process_status_cache[process.id] = {
                'status': None,
                'id': process.vpnservice['id'],
                'updated_pending_status': False,
                'ipsec_site_connections': {}}
        return self.process_status_cache[process.id]

    def report_status(self, context):
        status_changed_vpn_services = []
        for process in self.processes.values():
            previous_status = self.get_process_status_cache(process)
            if self.is_status_updated(process, previous_status):
                new_status = self.copy_process_status(process)
                self.update_downed_connections(process.id, new_status)
                status_changed_vpn_services.append(new_status)
                self.process_status_cache[process.id] = (
                    self.copy_process_status(process))
                # We need unset updated_pending status after it
                # is reported to the server side
                self.unset_updated_pending_status(process)

        if status_changed_vpn_services:
            self.agent_rpc.update_status(context,
                                         status_changed_vpn_services)

    def _sync_vpn_processes(self, vpnservices, sync_router_ids):
        for vpnservice in vpnservices:
            if vpnservice['router_id'] not in self.processes or (
                    vpnservice['router_id'] in sync_router_ids):
                process = self.ensure_process(vpnservice['router_id'],
                                              vpnservice=vpnservice)
                router = self.routers.get(vpnservice['router_id'])
                if not router:
                    continue
                process.update()

    def _delete_vpn_processes(self, sync_router_ids, vpn_router_ids):
        for process_id in sync_router_ids:
            if process_id not in vpn_router_ids:
                self.destroy_process(process_id)

    def _cleanup_stale_vpn_processes(self, vpn_router_ids):
        process_ids = [pid for pid in self.processes
                       if pid not in vpn_router_ids]
        for process_id in process_ids:
            self.destroy_process(process_id)

    def is_status_updated(self, process, previous_status):
        if process.updated_pending_status:
            return True
        if process.status != previous_status['status']:
            return True
        if (process.connection_status !=
                previous_status['ipsec_site_connections']):
            return True

    def unset_updated_pending_status(self, process):
        process.updated_pending_status = False
        for connection_status in process.connection_status.values():
            connection_status['updated_pending_status'] = False

    def copy_process_status(self, process):
        return {
            'id': process.vpnservice['id'],
            'status': process.status,
            'updated_pending_status': process.updated_pending_status,
            'ipsec_site_connections': copy.deepcopy(process.connection_status)
        }

    def update_downed_connections(self, process_id, new_status):
        """Update info to be reported, if connections just went down.

            If there is no longer any information for a connection, because it
            has been removed (e.g. due to an admin down of VPN service or IPSec
            connection), but there was previous status information for the
            connection, mark the connection as down for reporting purposes.
        """
        if process_id in self.process_status_cache:
            for conn in self.process_status_cache[process_id][IPSEC_CONNS]:
                if conn not in new_status[IPSEC_CONNS]:
                    new_status[IPSEC_CONNS][conn] = {
                        'status': constants.DOWN,
                        'updated_pending_status': True
                    }

    def create_router(self, router):
        """Handling create router event."""
        pass

    def destroy_router(self, process_id):
        pass

    def destroy_process(self, process_id):
        """Destroy process.

        Disable the process and remove the process
        manager for the processes that no longer are running vpn service.
        """
        if process_id in self.processes:
            process = self.processes[process_id]
            process.disable()
            if process_id in self.processes:
                del self.processes[process_id]

    def plug_to_ovs(self, context, **kwargs):
        self.nuage_if_driver.plug(kwargs['network_id'], kwargs['port_id'],
                                  kwargs['device_name'], kwargs['mac'],
                                  'alubr0', kwargs['ns_name'])

        self.nuage_if_driver.init_l3(kwargs['device_name'], kwargs['cidr'],
                                     kwargs['ns_name'])
        device = ip_lib.IPDevice(kwargs['device_name'],
                                 namespace=kwargs['ns_name'])
        for gateway_ip in kwargs['gw_ip']:
            device.route.add_gateway(gateway_ip)

    def unplug_from_ovs(self, context, **kwargs):
        self.nuage_if_driver.unplug(kwargs['device_name'], 'alubr0',
                                    kwargs['ns_name'])
        ip = ip_lib.IPWrapper(kwargs['ns_name'])
        ip.garbage_collect_namespace()
        # On Redhat deployments an additional directory is created named
        # 'ip_vti0' in the namespace which prevents the cleanup
        # of namespace by the neutron agent in 'ip_lib.py' which we clean.
        if kwargs['ns_name'] in ip.get_namespaces():
            ip.netns.delete(kwargs['ns_name'])


class NuageOpenSwanDriver(NuageIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return ipsec.OpenSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)


class NuageStrongSwanDriver(NuageIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return strongswan_ipsec.StrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)


class NuageStrongSwanDriverFedora(NuageIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return fedora_strongswan_ipsec.FedoraStrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
