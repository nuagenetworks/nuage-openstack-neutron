# Copyright 2015 Alcatel-Lucent USA Inc.
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import log
from neutron.extensions import securitygroup as ext_sg
from nuage_neutron.plugins.nuage.common import constants
from nuage_neutron.plugins.nuage.common import exceptions as nuage_exc
from nuage_neutron.plugins.nuage.common import utils
from nuage_neutron.plugins.nuage import nuagedb

LOG = logging.getLogger(__name__)


class NuagegatewayMixin(object):

    def __init__(self, *args, **kwargs):
        super(NuagegatewayMixin, self).__init__(*args, **kwargs)

    @log.log
    def _make_gw_port_dict(self, port, fields=None, context=None):
        res = {
            'id': port['gw_port_id'],
            'name': port['gw_port_name'],
            'vlan': port['gw_port_vlan'],
            'status': port['gw_port_status'],
            'usermnemonic': port['gw_port_mnemonic'],
            'physicalname': port['gw_port_phy_name']
        }

        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @log.log
    def _make_gateway_dict(self, gateway, fields=None, context=None):
        res = {
            'id': gateway['gw_id'],
            'name': gateway['gw_name'],
            'type': gateway['gw_type'],
            'status': gateway['gw_status'],
            'template': gateway['gw_template'],
            'systemid': gateway['gw_system_id']
        }

        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @log.log
    def _make_vlan_dict(self, vlan, fields=None, context=None):
        res = {
            'id': vlan['gw_vlan_id'],
            'value': vlan['gw_vlan_value'],
            'gateway': vlan['gw_vlan_gw_id'],
            'vport': vlan['gw_vlan_vport_id'],
            'gatewayport': vlan['gw_vlan_port_id'],
            'status': vlan['gw_vlan_status'],
            'usermnemonic': vlan['gw_vlan_mnemonic'],
            'assigned': vlan['gw_vlan_assigned_to']
        }

        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @utils.handle_nuage_api_error
    @log.log
    def _make_vport_dict(self, vport, fields=None, context=None):
        res = {
            'id': vport['vport_id'],
            'type': vport['vport_type'],
            'name': vport['vport_name'],
            'subnet': vport['subnet_id'],
            'interface': vport.get('interface')
        }

        if 'port_id' in vport:
            res['port'] = vport['port_id']

        if 'gateway' in vport:
            res['gateway'] = vport['gateway']

        if 'gatewayport' in vport:
            res['gatewayport'] = vport['gatewayport']

        if 'value' in vport:
            res['vlan'] = vport['value']

        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @utils.handle_nuage_api_error
    @log.log
    def create_nuage_gateway_vport(self, context, nuage_gateway_vport):
        vport = nuage_gateway_vport['nuage_gateway_vport']
        subnet_id = vport.get('subnet')
        port_id = vport.get('port')
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)
        params = {
            'gatewayinterface': vport['gatewayvlan'],
            'np_id': netpart['id'],
            'tenant': vport.get('tenant')
        }

        if subnet_id:
            params['subnet'] = self.get_subnet(context, subnet_id)

        if port_id:
            p = self.get_port(context, port_id)
            if p.get('fixed_ips'):
                subnet_id = p['fixed_ips'][0]['subnet_id']
                subnet = self.get_subnet(context, subnet_id)
                params['enable_dhcp'] = subnet.get('enable_dhcp')
            params['port'] = p

        resp = self.nuageclient.create_gateway_vport(context.tenant_id,
                                                     params)
        if port_id:
            port = params['port']
            if resp['vport_gw_type'] == constants.SOFTWARE:
                self._delete_port_security_group_bindings(context, port['id'])
                self._process_port_create_security_group(
                    context,
                    port,
                    port[ext_sg.SECURITYGROUPS]
                )
                LOG.debug("Created security group for port %s", port['id'])
            self._check_floatingip_update(context, port,
                                          vport_type=constants.HOST_VPORT,
                                          vport_id=resp['vport_id'])
        return self._make_vport_dict(resp, context=context)

    @utils.handle_nuage_api_error
    @log.log
    def create_nuage_gateway_vlan(self, context, nuage_gateway_vlan):
        vlan = nuage_gateway_vlan['nuage_gateway_vlan']
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        resp = self.nuageclient.create_gateway_port_vlan(context.tenant_id,
                                                         vlan, netpart['id'])
        return self._make_vlan_dict(resp, context=context)

    @utils.handle_nuage_api_error
    @log.log
    def delete_nuage_gateway_vlan(self, context, id):
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)
        self.nuageclient.delete_gateway_port_vlan(id, netpart['id'])

    @utils.handle_nuage_api_error
    @log.log
    def delete_nuage_gateway_vport(self, context, id):
        self.nuageclient.delete_nuage_gateway_vport(context.tenant_id, id)

    @utils.handle_nuage_api_error
    @log.log
    def update_nuage_gateway_vlan(self, context, id, nuage_gateway_vlan):
        vlan = nuage_gateway_vlan['nuage_gateway_vlan']
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        params = {
            'vlan': vlan,
            'np_id': netpart['id']
        }
        resp = self.nuageclient.update_gateway_port_vlan(context.tenant_id, id,
                                                         params)
        return self._make_vlan_dict(resp, context=context)

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vlan(self, context, id, fields=None):
        resp = self.nuageclient.get_gateway_port_vlan(context.tenant_id,
                                                      id)
        if resp:
            return self._make_vlan_dict(resp, fields=fields, context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_vlan',
                                          resource_id=id)

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vport(self, context, id, fields=None):
        fetch_tenant = self._check_for_permissions(context, None)
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        resp = self.nuageclient.get_gateway_vport(fetch_tenant,
                                                  netpart['id'],
                                                  id)
        if resp:
            return self._make_vport_dict(resp, fields=fields, context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_vport',
                                          resource_id=id)

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vports(self, context, filters=None, fields=None):
        user_tenant = filters.get('tenant')
        fetch_tenant = self._check_for_permissions(context, user_tenant)

        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        resp = self.nuageclient.get_gateway_vports(fetch_tenant,
                                                   netpart['id'],
                                                   filters)
        if resp:
            return [self._make_vport_dict(vport, fields=fields,
                                          context=context) for vport in resp]
        else:
            return []

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vlans_count(self, context, filters=None):
        return 0

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vports_count(self, context, filters=None):
        return 0

    @utils.handle_nuage_api_error
    @log.log
    def _check_for_permissions(self, context, user_tenant):
        fetch_tenant = None
        if context.is_admin:
            # Request is from an admin
            if user_tenant:
                if user_tenant[0] == context.tenant_id:
                    # User tenant is also an admin so list all the resources
                    LOG.debug("Request is from admin for an admin")
                else:
                    # User tenant is not an admin so list resources only for
                    # him
                    LOG.debug("Request is from admin for a non-admin")
                    fetch_tenant = user_tenant[0]
            else:
                # User tenant is also an admin so list all the resources
                LOG.debug("Request is from admin and no tenant specified")
        else:
            # Request is from a non-admin
            if user_tenant:
                if user_tenant[0] == context.tenant_id:
                    # User tenant is not an admin so list resources only for
                    # him
                    LOG.debug("Request is from a non-admin for a non-admin")
                    fetch_tenant = user_tenant[0]
                else:
                    # throw an error of not authorized
                    msg = _("Request is from a non-admin for a different "
                            "tenant")
                    LOG.error(msg)
                    raise nuage_exc.NuageNotAuthorized(msg=msg)
            else:
                # User tenant is not an admin so list resources only for him
                LOG.debug("Request is from a non-admin and no tenant "
                          "specified")
                fetch_tenant = context.tenant_id
        return fetch_tenant

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_vlans(self, context, filters=None, fields=None):
        if not filters:
            # No gateway or gatewayport specified by user
            if context.is_admin:
                msg = (_('--gatewayport or --gateway and --gatewayport option '
                         'is required'))
                raise nuage_exc.NuageBadRequest(msg=msg)

            fetch_tenant = context.tenant_id
        else:
            if context.is_admin:
                if 'gateway' in filters and 'gatewayport' not in filters:
                    msg = (_('--gateway and --gatewayport option '
                             'should be provided'))
                    raise nuage_exc.NuageBadRequest(msg=msg)
            else:
                if 'gateway' in filters or 'gatewayport' in filters:
                    msg = (_('--gateway or --gatewayport option not '
                             'supported'))
                    raise nuage_exc.NuageBadRequest(msg=msg)

            user_tenant = filters.get('tenant')
            fetch_tenant = self._check_for_permissions(context, user_tenant)

        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)
        resp = self.nuageclient.get_gateway_port_vlans(fetch_tenant,
                                                       netpart['id'],
                                                       filters=filters)
        if resp:
            return [self._make_vlan_dict(
                vlan, fields=fields, context=context) for vlan in resp]
        else:
            return []

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_port(self, context, id, fields=None):
        resp = self.nuageclient.get_gateway_port(context.tenant_id, id)

        if resp:
            return self._make_gw_port_dict(resp, fields=fields,
                                           context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_gateway_port',
                                          resource_id=id)

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway_ports(self, context, filters=None, fields=None):
        resp = self.nuageclient.get_gateway_ports(context.tenant_id,
                                                  filters=filters)
        return [self._make_gw_port_dict(gw, fields=fields, context=context)
                for gw in resp]

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateway(self, context, id, fields=None):
        resp = self.nuageclient.get_gateway(context.tenant_id, id)
        if resp:
            return self._make_gateway_dict(resp, fields=fields,
                                           context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_gateway',
                                          resource_id=id)

    @utils.handle_nuage_api_error
    @log.log
    def get_nuage_gateways(self, context, filters=None, fields=None):
        resp = self.nuageclient.get_gateways(context.tenant_id,
                                             filters=filters)
        return [self._make_gateway_dict(gw, fields=fields, context=context)
                for gw in resp]
