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

import oslo_messaging

from neutron._i18n import _
from neutron.common import rpc as n_rpc
from neutron.extensions import l3
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as lib_constants
from neutron_lib.plugins import directory

from neutron_vpnaas.db.vpn import vpn_db as vpn_db
from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.services.vpn.service_drivers import base_ipsec
from neutron_vpnaas.services.vpn.service_drivers import ipsec_validator

from nuage_neutron.vpnaas.common import topics

from oslo_log import log as logging


LOG = logging.getLogger(__name__)

BASE_IPSEC_VERSION = '1.0'


class NetCreateDict(object):
    def __init__(self, tenant_id, name):
        self.name = name
        self.tenant_id = tenant_id

    @property
    def net_dict(self):
        return {
            'network': {
                'name': self.name,
                'tenant_id': self.tenant_id,
                'description': 'Dummy network for VPN Service',
                'admin_state_up': True,
                'port_security_enabled': True,
                'shared': False
            }
        }


class RouterCreateDict(object):
    def __init__(self, name, tenant_id):
        self.name = name
        self.tenant_id = tenant_id

    @property
    def rtr_dict(self):
        return {
            'router': {
                'name': self.name,
                'description': 'Dummy router for VPN Service',
                'admin_state_up': True,
                'nuage_router_template': None,
                'tenant_id': self.tenant_id
            }
        }


class SubnetCreateDict(object):
    def __init__(self, name, net_id, cidr, gw_ip, tenant_id):
        self.name = name
        self.net_id = net_id
        self.cidr = cidr
        self.gw_ip = gw_ip
        self.tenant_id = tenant_id

    @property
    def subn_dict(self):
        return {
            'subnet': {
                'name': self.name,
                'description': 'Dummy subnet for VPN Service',
                'network_id': self.net_id,
                'cidr': self.cidr,
                'gateway_ip': self.gw_ip,
                'underlay': lib_constants.ATTR_NOT_SPECIFIED,
                'nuage_uplink': None,
                'ip_version': 4,
                'allocation_pools': lib_constants.ATTR_NOT_SPECIFIED,
                'enable_dhcp': True,
                'dns_nameservers': lib_constants.ATTR_NOT_SPECIFIED,
                'host_routes': lib_constants.ATTR_NOT_SPECIFIED,
                'tenant_id': self.tenant_id
            }
        }


class PortCreateDict(object):
    def __init__(self, tenant_id, name, net_id,
                 fixed_ip=lib_constants.ATTR_NOT_SPECIFIED):
        self.tenant_id = tenant_id
        self.name = name
        self.net_id = net_id
        self.fixed_ip = fixed_ip

    @property
    def port_dict(self):
        return {
            'port': {
                'name': self.name,
                'fixed_ips': self.fixed_ip,
                'device_id': '',
                'device_owner': '',
                'network_id': self.net_id,
                'admin_state_up': True,
                'tenant_id': self.tenant_id,
                'nuage_redirect_targets': lib_constants.ATTR_NOT_SPECIFIED,
                'binding:host_id': lib_constants.ATTR_NOT_SPECIFIED,
                'allowed_address_pairs': lib_constants.ATTR_NOT_SPECIFIED,
                'security_groups': lib_constants.ATTR_NOT_SPECIFIED,
                'binding:vnic_type': 'normal',
                'extra_dhcp_opts': None,
                'mac_address': lib_constants.ATTR_NOT_SPECIFIED,
                'binding:profile': lib_constants.ATTR_NOT_SPECIFIED
            }
        }


class NuageBaseIPsecVpnAgentApi(object):
    """Base class for IPSec API to agent."""

    def __init__(self, topic, default_version, driver):
        self.topic = topic
        self.driver = driver
        target = oslo_messaging.Target(topic=topic, version=default_version)
        self.client = n_rpc.get_client(target)

    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        if not version:
            version = self.target.version

        cctxt = self.client.prepare(version=version)
        if method == 'vpnservice_updated':
            cctxt.cast(context, method, **kwargs)
        else:
            cctxt.call(context, method, **kwargs)

    def vpnservice_updated(self, context, router_id, **kwargs):
        """Send update event of vpnservices."""
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'vpnservice_updated', router_id,
                                 **kwargs)

    def tracking(self, context, router_id, **kwargs):
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'tracking', router_id,
                                 **kwargs)

    def non_tracking(self, context, router_id, **kwargs):
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'non_tracking', router_id,
                                 **kwargs)

    def plug_to_ovs(self, context, router_id, **kwargs):
        self._agent_notification(context, 'plug_to_ovs', router_id, **kwargs)

    def unplug_from_ovs(self, context, router_id, **kwargs):
        self._agent_notification(context, 'unplug_from_ovs', router_id,
                                 **kwargs)


class NuageIPsecVpnAgentApi(NuageBaseIPsecVpnAgentApi):
    """Agent RPC API for IPsecVPNAgent."""

    target = oslo_messaging.Target(version=BASE_IPSEC_VERSION)

    def __init__(self, topic, default_version, driver):
        super(NuageIPsecVpnAgentApi, self).__init__(
            topic, default_version, driver)


class NuageIPsecVpnDriverCallBack(object):
    """Callback for IPSecVpnDriver rpc."""

    target = oslo_messaging.Target(version=BASE_IPSEC_VERSION)

    def __init__(self, driver):
        super(NuageIPsecVpnDriverCallBack, self).__init__()
        self.driver = driver

    def get_vpn_services_using(self, context, router_id):
        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.IPsecSiteConnection)
        query = query.join(vpn_models.IKEPolicy)
        query = query.join(vpn_models.IPsecPolicy)
        query = query.join(vpn_models.IPsecPeerCidr)
        query = query.filter(vpn_models.VPNService.router_id == router_id)
        return query.all()

    def build_local_subnet_cidr_map(self, context):
        db = vpn_db.VPNPluginRpcDbMixin()
        return db._build_local_subnet_cidr_map(context)

    def get_vpn_services_on_host(self, context, host=None):
        """Returns info on the VPN services on the host."""
        routers = self.driver.l3_plugin.get_active_routers_for_host(context)
        host_vpn_services = []
        for router in routers:
            vpn_services = self.get_vpn_services_using(context, router['id'])
            local_cidr_map = self.build_local_subnet_cidr_map(context)
            for vpn_service in vpn_services:
                host_vpn_services.append(
                    self.driver.make_vpnservice_dict(vpn_service,
                                                     local_cidr_map))
        return host_vpn_services

    def update_status(self, context, status):
        """Update status of vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class NuageIPsecVPNDriver(base_ipsec.BaseIPsecVPNDriver):
    """Nuage VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        self.service_plugin = service_plugin
        super(NuageIPsecVPNDriver, self).__init__(
            service_plugin,
            ipsec_validator.IpsecVpnValidator(service_plugin))

    def create_rpc_conn(self):
        self.endpoints = [NuageIPsecVpnDriverCallBack(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.NUAGE_IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = NuageIPsecVpnAgentApi(
            topics.NUAGE_IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION, self)

    def _get_l3_plugin(self):
        return directory.get_plugin(lib_constants.L3)

    @staticmethod
    def get_vpn_services_using(context, router_id):
        query = context.session.query(vpn_models.VPNService)
        query = query.filter(vpn_models.VPNService.router_id == router_id)
        return query.all()

    @staticmethod
    def _get_vpn_svc_by_id(context, id):
        query = context.session.query(vpn_models.VPNService)
        return query.filter(vpn_models.VPNService.id == id).one()

    def _delete_from_db(self, context, id):
        vpns_db = self._get_vpn_svc_by_id(context, id)
        context.session.delete(vpns_db)

    def _validate_nuage_vpn_svc_create(self, context, vpnservice_dict):
        rtr_id = vpnservice_dict['router_id']
        vpn_services = self.get_vpn_services_using(context, rtr_id)
        if len(vpn_services) > 1:
            self._delete_from_db(context, vpnservice_dict['id'])
            raise l3.RouterInUse(
                router_id=rtr_id,
                reason="is currently used by VPN service."
                       " One VPN service per router")
        if not self._get_l3_plugin().rtr_in_def_ent(context, rtr_id):
            self._delete_from_db(context, vpnservice_dict['id'])
            msg = _('router %s is not associated with '
                    'default net-partition') % rtr_id
            raise n_exc.BadRequest(resource='vpn-service', msg=msg)

    def create_vpnservice(self, context, vpnservice_dict):
        self._validate_nuage_vpn_svc_create(context, vpnservice_dict)
        super(NuageIPsecVPNDriver, self).create_vpnservice(
            context, vpnservice_dict)
        l3_plugin = self._get_l3_plugin()
        # admin context requiored to get fip subnet.
        context = context if context.is_admin else context.elevated()
        try:
            vpn_serv_rtr = l3_plugin.get_router(
                context, vpnservice_dict['router_id'])
            vpn_serv_subn = l3_plugin.get_subnet(
                context, vpnservice_dict['subnet_id'])
            vpn_ext_subn = l3_plugin.get_subnet(
                context, vpn_serv_rtr['external_gateway_info']
                ['external_fixed_ips'][0]['subnet_id'])
        except IndexError:
            self._delete_from_db(context, vpnservice_dict['id'])
            msg = _('External network has no public subnet associated with it')
            raise n_exc.BadRequest(resource='vpn-service', msg=msg)

        net_dict = NetCreateDict(context.tenant_id,
                                 'n_d_' + vpn_serv_subn['id'])
        rtr_dict = RouterCreateDict('r_d_' + vpn_serv_rtr['id'],
                                    context.tenant_id)
        dummy_net = l3_plugin.create_network(context, net_dict.net_dict)
        subn_dict = SubnetCreateDict('s_d_' + vpn_serv_subn['id'],
                                     dummy_net['id'],
                                     vpn_ext_subn['cidr'],
                                     vpn_ext_subn['gateway_ip'],
                                     context.tenant_id)

        # use neutron API to create a dummy router in VSD,
        # create a dummy subnet and attached to this dummy router.
        dummy_rtr = l3_plugin.create_l3domain(context, rtr_dict.rtr_dict)
        dummy_subn = l3_plugin.create_subnet(context, subn_dict.subn_dict)
        interface_info = {'subnet_id': dummy_subn['id']}
        l3_plugin.add_router_interface(context, dummy_rtr['id'],
                                       interface_info)

        # use the vsd API to claim a FIP from the FIP n/w
        # to which router_1 (VPN g/w) is attached.
        nuage_fip = l3_plugin.claim_fip_for_domain_from_shared_resource(
            context, vpn_ext_subn['id'], dummy_rtr['id'],
            vpnservice_dict['id'])

        # use neutron API to create a dummy port on
        # dummy subnet with the nuage_fip['address']
        port_dict = PortCreateDict(context.tenant_id,
                                   'p_d_' + vpn_serv_subn['id'],
                                   dummy_net['id'],
                                   [{'subnet_id': dummy_subn['id'],
                                     'ip_address': nuage_fip['address']}])
        dummy_port = l3_plugin.create_port(context, port_dict.port_dict)
        vpnservice_dict['external_v4_ip'] = \
            dummy_port['fixed_ips'][0]['ip_address']
        self.service_plugin.set_external_tunnel_ips(
            context, vpnservice_dict['id'],
            v4_ip=dummy_port['fixed_ips'][0]['ip_address'])

        # use the vsd API to associate the fip claimed to
        # the dummy port created in above step.
        l3_plugin.associate_fip_to_dummy_port(
            context, nuage_fip, dummy_port['id'], dummy_rtr['id'])

        # This port needs to be created for every router requesting
        # vpn-service. Use neutron API to create a port on subnet
        # on which vpn-service is requested.
        port_dict = PortCreateDict(context.tenant_id,
                                   'openswan_port_' + vpn_serv_subn['id'],
                                   vpn_serv_subn['network_id'])
        l3_plugin.create_port(context, port_dict.port_dict)

        (vpn_serv_rtr['external_gateway_info']['external_fixed_ips']
         [0]['ip_address']) = nuage_fip['address']
        l3_plugin.update_router(
            context, vpnservice_dict['router_id'],
            {'router': {'external_gateway_info':
                        vpn_serv_rtr['external_gateway_info']}})

    def _get_vpn_serv_nuage_resources(self, context, vpnservice):
        ret_dict = dict()
        l3_plugin = self._get_l3_plugin()
        filters = {'name': ['p_d_' + vpnservice['subnet_id']]}
        p_dummy = l3_plugin.get_ports(context, filters=filters)
        ret_dict['p_dummy'] = p_dummy[0]
        filters = {'name': ['openswan_port_' + vpnservice['subnet_id']]}
        p_openswan = l3_plugin.get_ports(context, filters=filters)
        ret_dict['p_openswan'] = p_openswan[0]
        filters = {'name': ['s_d_' + vpnservice['subnet_id']]}
        s_dummy = l3_plugin.get_subnets(context, filters=filters)
        interface_info = {'subnet_id': s_dummy[0]['id']}
        ret_dict['s_dummy'] = s_dummy[0]
        ret_dict['interface_info'] = interface_info
        filters = {'name': ['r_d_' + vpnservice['router_id']]}
        r_dummy = l3_plugin.get_routers(context, filters=filters)
        ret_dict['r_dummy'] = r_dummy[0]
        filters = {'name': ['n_d_' + vpnservice['subnet_id']]}
        n_dummy = l3_plugin.get_networks(context, filters=filters)
        ret_dict['n_dummy'] = n_dummy[0]
        return ret_dict

    def delete_vpnservice(self, context, vpnservice):
        try:
            l3_plugin = self._get_l3_plugin()
            res = self._get_vpn_serv_nuage_resources(context, vpnservice)
        except IndexError:
            pass
        else:
            l3_plugin.delete_port(context, res['p_dummy']['id'])
            l3_plugin.delete_port(context, res['p_openswan']['id'])
            l3_plugin.remove_router_interface(context, res['r_dummy']['id'],
                                              res['interface_info'])
            l3_plugin.delete_subnet(context, res['s_dummy']['id'])
            l3_plugin.delete_l3domain(context, res['r_dummy']['id'])
            l3_plugin.delete_network(context, res['n_dummy']['id'])
        super(NuageIPsecVPNDriver, self).delete_vpnservice(
            context, vpnservice)

    def _get_cidr_list(self, context, ip_addr, subn_id):
        cidr = []
        l3_plugin = self._get_l3_plugin()
        subn = l3_plugin.get_subnet(context, subn_id)
        subn_cidr = subn['cidr'].split('/')
        cidr.append(ip_addr + '/' + subn_cidr[1])
        return cidr

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        l3_plugin = self._get_l3_plugin()
        vpnservice = self.service_plugin.get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        ns_name = 'vpn-' + vpnservice['router_id']
        try:
            res = self._get_vpn_serv_nuage_resources(context, vpnservice)
            res['p_dummy']['gw'] = res['s_dummy']['gateway_ip']
            ns_ports = (res['p_dummy'], res['p_openswan'])
        except Exception:
            # case when the user is trying to create an IPSec Site connection
            # when already there is one associated with the current VPN Svc
            self.service_plugin.delete_ipsec_site_connection(
                context, ipsec_site_connection['id'])
            raise l3.RouterInUse(
                router_id=vpnservice['router_id'],
                reason="is currently associated with IPSec Site Connection."
                       " One IPSec Site Connection per VPN service")
        else:
            self.agent_rpc.tracking(context, vpnservice['router_id'])
            for prt in ns_ports:
                device_name = 'vm-' + "".join(prt['mac_address'].split(':'))
                l3_plugin.update_port(
                    context, prt['id'], {'port': {'device_id': prt['id']}})
                cidr = self._get_cidr_list(context,
                                           prt['fixed_ips'][0]['ip_address'],
                                           prt['fixed_ips'][0]['subnet_id'])
                gw_ip = [prt.get('gw')] if prt.get('gw') else []
                self.agent_rpc.plug_to_ovs(context, vpnservice['router_id'],
                                           device_name=device_name,
                                           ns_name=ns_name,
                                           cidr=cidr, gw_ip=gw_ip,
                                           network_id=prt['network_id'],
                                           port_id=prt['id'],
                                           mac=prt['mac_address'])
                l3_plugin.update_port(
                    context, prt['id'],
                    {'port': {'device_owner': 'compute:None'}})

        l3_plugin.add_rules_vpn_ping(
            context, vpnservice['router_id'],
            ipsec_site_connection['peer_cidrs'][0],
            res['p_openswan'])

        super(NuageIPsecVPNDriver, self).create_ipsec_site_connection(
            context, ipsec_site_connection)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        l3_plugin = self._get_l3_plugin()
        vpnservice = self.service_plugin.get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        vpnservices = self.get_vpn_services_using(
            context, vpnservice['router_id'])
        if (vpnservices and len(vpnservices[0]['ipsec_site_connections'])) > 0:
            # This is temporary. For 4.0r2 only one IPSec conn. per VPN svc
            return
        res = self._get_vpn_serv_nuage_resources(context, vpnservice)
        l3_plugin.remove_rules_vpn_ping(
            context, vpnservice['router_id'],
            ipsec_site_connection['peer_cidrs'][0],
            res['p_openswan']['fixed_ips'][0]['ip_address'])
        self.agent_rpc.non_tracking(context, vpnservice['router_id'])
        super(NuageIPsecVPNDriver, self).delete_ipsec_site_connection(
            context, ipsec_site_connection)
        res['p_dummy']['gw'] = res['s_dummy']['gateway_ip']
        ns_ports = (res['p_dummy'], res['p_openswan'])
        ns_name = 'vpn-' + vpnservice['router_id']

        for prt in ns_ports:
            # Delete ports from alubr0
            device_name = 'vm-' + "".join(prt['mac_address'].split(':'))
            self.agent_rpc.unplug_from_ovs(context, vpnservice['router_id'],
                                           device_name=device_name,
                                           ns_name=ns_name)
            # update the device-id of the port
            l3_plugin.update_port(
                context, prt['id'], {'port': {'device_id': ''}})
            # update the port with device-owner = compute:None (fake vm in VSD)
            l3_plugin.update_port(
                context, prt['id'], {'port': {'device_owner': ''}})
            # delete the vm-interface
            l3_plugin.delete_dummy_vm_if(context, prt)
