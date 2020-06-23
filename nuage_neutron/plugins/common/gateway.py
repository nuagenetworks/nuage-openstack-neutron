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
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron._i18n import _
from neutron_lib.plugins import constants as lib_constants

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import utils

from nuage_neutron.vsdclient.common.helper import get_l2_and_l3_sub_id

LOG = logging.getLogger(__name__)


class NuagegatewayMixin(utils.SubnetUtilsBase):

    def __init__(self, *args, **kwargs):
        super(NuagegatewayMixin, self).__init__(*args, **kwargs)
        self._l2_plugin = None
        self._l3plugin = None

    @property
    def core_plugin(self):
        if self._l2_plugin is None:
            self._l2_plugin = directory.get_plugin()
        return self._l2_plugin

    @property
    def l3_plugin(self):
        if self._l3plugin is None:
            self._l3plugin = directory.get_plugin(lib_constants.L3)
        return self._l3plugin

    @log_helpers.log_method_call
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

    @log_helpers.log_method_call
    def _make_gateway_dict(self, gateway, fields=None, context=None):
        res = {
            'id': gateway['gw_id'],
            'name': gateway['gw_name'],
            'type': gateway['gw_type'],
            'status': gateway['gw_status'],
            'template': gateway['gw_template'],
            'systemid': gateway['gw_system_id'],
            'redundant': gateway['gw_redundant']
        }

        if context:
            res['tenant_id'] = context.tenant_id
        return self._fields(res, fields)

    @log_helpers.log_method_call
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

    @log_helpers.log_method_call
    def _make_vport_dict(self, vport, fields=None, context=None):
        res = {
            'id': vport['vport_id'],
            'type': vport['vport_type'],
            'name': vport['vport_name'],
            'interface': vport.get('interface')
        }
        if 'subnet_id' in vport:
            res['subnet'] = vport['subnet_id']
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

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_gateway_vport(self, context, nuage_gateway_vport):
        vport = nuage_gateway_vport['nuage_gateway_vport']
        subnet_id = vport.get('subnet')
        port_id = vport.get('port')
        params = {
            'gatewayinterface': vport['gatewayvlan'],
            'tenant': vport.get('tenant')
        }

        if subnet_id:
            params['subnet'] = self.core_plugin.get_subnet(context, subnet_id)
            params['type'] = constants.BRIDGE_VPORT_TYPE

        if port_id:
            p = self.core_plugin.get_port(context, port_id)
            if p.get('fixed_ips'):
                subnet_id = p['fixed_ips'][0]['subnet_id']
                subnet = self.core_plugin.get_subnet(context, subnet_id)
                params['subnet'] = subnet
                params['enable_dhcp'] = subnet.get('enable_dhcp')
            params['port'] = p
            params['type'] = constants.HOST_VPORT

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(
            context.session, subnet_id)
        if subnet_mapping:
            params['np_id'] = subnet_mapping['net_partition_id']
            params['nuage_managed_subnet'] = (
                subnet_mapping['nuage_managed_subnet'])
        else:
            msg = 'No neutron subnet to nuage subnet mapping found'
            raise nuage_exc.NuageBadRequest(msg=msg)

        try:
            vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(
                subnet_mapping)
            params['vsd_subnet'] = vsd_subnet
            resp = self.vsdclient.create_gateway_vport(context.tenant_id,
                                                       params)
            vport = resp['vport']
        except Exception as ex:
            if hasattr(ex, 'code'):
                if ex.code == constants.RES_CONFLICT:
                    # gridinv - do not map resource in conflict to 500
                    raise nuage_exc.NuageBadRequest(msg=ex.message)
            raise
        resp_dict = {'vport_id': resp['vport']['ID'],
                     'vport_type': resp['vport']['type'],
                     'vport_name': resp['vport']['name'],
                     'interface': resp['interface']['ID'],
                     'vport_gw_type': resp['vport_gw_type'],
                     'subnet_id': subnet_id}
        if port_id:
            resp_dict['port_id'] = port_id
        return self._make_vport_dict(resp_dict, context=context)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def create_nuage_gateway_vlan(self, context, nuage_gateway_vlan):
        vlan = nuage_gateway_vlan['nuage_gateway_vlan']

        resp = self.vsdclient.create_gateway_port_vlan(vlan)
        return self._make_vlan_dict(resp, context=context)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_gateway_vlan(self, context, id):
        self.vsdclient.delete_gateway_port_vlan(id)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def delete_nuage_gateway_vport(self, context, id):
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)
        self.vsdclient.delete_nuage_gateway_vport(context,
                                                  id,
                                                  netpart['id'])

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def update_nuage_gateway_vlan(self, context, id, nuage_gateway_vlan):
        vlan = nuage_gateway_vlan['nuage_gateway_vlan']
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        params = {
            'vlan': vlan,
            'np_id': netpart['id']
        }
        resp = self.vsdclient.update_gateway_port_vlan(context.tenant_id, id,
                                                       params)
        return self._make_vlan_dict(resp, context=context)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_vlan(self, context, id, fields=None):
        resp = self.vsdclient.get_gateway_port_vlan(context.tenant_id,
                                                    id)
        if resp:
            return self._make_vlan_dict(resp, fields=fields, context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_vlan',
                                          resource_id=id)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_vport(self, context, id, fields=None):
        fetch_tenant = self._check_for_permissions(context, None)
        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        resp = self.vsdclient.get_gateway_vport(context,
                                                fetch_tenant,
                                                netpart['id'],
                                                id)
        if not resp:
            raise nuage_exc.NuageNotFound(resource='nuage_vport',
                                          resource_id=id)
        if not resp.get('subnet_id'):
            nuage_subnet_id = resp['nuage_subnet_id']
            subnet_info = nuagedb.get_subnet_info_by_nuage_id(
                context.session, nuage_subnet_id)
            if subnet_info:
                if 'subnet_id' in subnet_info:
                    resp['subnet_id'] = subnet_info['subnet_id']
                    LOG.debug('get_nuage_gateway_vport: subnet_id '
                              'could be retrieved via subnet_info')
                elif resp.get('port_id'):
                    subnet_mapping = nuagedb.\
                        get_subnet_l2dom_by_nuage_id_and_port(
                            context.session, nuage_subnet_id, resp['vport_id'])
                    if subnet_mapping:
                        resp['subnet_id'] = subnet_mapping['subnet_id']
                        LOG.debug('get_nuage_gateway_vport: subnet_id '
                                  'could be retrieved via port')
                    else:
                        LOG.debug('get_nuage_gateway_vport: subnet_id '
                                  'could not be retrieved via port')
                else:
                    LOG.debug('get_nuage_gateway_vport: subnet_id could '
                              'not be retrieved')
            else:
                LOG.debug('get_nuage_gateway_vport: subnet_id could not '
                          'be retrieved as no subnet_info is present for '
                          'nuage_subnet_id={}'.format(nuage_subnet_id))
        else:
            LOG.debug('get_nuage_gateway_vport: subnet_id already '
                      'contained')
        return self._make_vport_dict(resp, fields=fields, context=context)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_vports(self, context, filters=None, fields=None):
        user_tenant = filters.get('tenant')
        fetch_tenant = self._check_for_permissions(context, user_tenant)

        def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
        netpart = nuagedb.get_default_net_partition(context, def_netpart)

        subnet_id = filters['subnet'][0]
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if subnet_mapping:
            filters['nuage_subnet_id'] = [subnet_mapping['nuage_subnet_id']]
        else:
            msg = 'No neutron subnet to nuage subnet mapping found'
            raise nuage_exc.NuageBadRequest(msg=msg)

        resp = self.vsdclient.get_gateway_vports(context,
                                                 fetch_tenant,
                                                 netpart['id'],
                                                 filters)
        if resp:
            return [self._make_vport_dict(vport, fields=fields,
                                          context=context) for vport in resp]
        else:
            return []

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_vlans_count(self, context, filters=None):
        return 0

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_vports_count(self, context, filters=None):
        return 0

    @log_helpers.log_method_call
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

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
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
        resp = self.vsdclient.get_gateway_port_vlans(fetch_tenant,
                                                     netpart['id'],
                                                     filters=filters)
        if resp:
            return [self._make_vlan_dict(
                vlan, fields=fields, context=context) for vlan in resp]
        else:
            return []

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_port(self, context, id, fields=None):
        resp = self.vsdclient.get_gateway_port(context.tenant_id, id)

        if resp:
            return self._make_gw_port_dict(resp, fields=fields,
                                           context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_gateway_port',
                                          resource_id=id)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway_ports(self, context, filters=None, fields=None):
        resp = self.vsdclient.get_gateway_ports(context.tenant_id,
                                                filters=filters)
        return [self._make_gw_port_dict(gw, fields=fields, context=context)
                for gw in resp]

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateway(self, context, id, fields=None):
        resp = self.vsdclient.get_gateway(context.tenant_id, id)
        if resp:
            return self._make_gateway_dict(resp, fields=fields,
                                           context=context)
        else:
            raise nuage_exc.NuageNotFound(resource='nuage_gateway',
                                          resource_id=id)

    @utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_gateways(self, context, filters=None, fields=None):
        resp = self.vsdclient.get_gateways(context.tenant_id,
                                           filters=filters)
        return [self._make_gateway_dict(gw, fields=fields, context=context)
                for gw in resp]

    @log_helpers.log_method_call
    def delete_gw_host_vport(self, context, port, subnet_mapping):
        port_params = {
            'neutron_port_id': port['id']
        }

        # Check if l2domain/subnet exist. In case of router_interface_delete,
        # subnet is deleted and then call comes to delete_port. In that
        # case, we just return
        vsd_subnet = self.vsdclient.get_nuage_subnet_by_mapping(subnet_mapping)
        if not vsd_subnet:
            return

        if self._is_vsd_mgd(subnet_mapping):
            port_params['l2dom_id'] = subnet_mapping['nuage_subnet_id']
            port_params['l3dom_id'] = subnet_mapping['nuage_subnet_id']
        else:
            l2_id, l3_id = get_l2_and_l3_sub_id(subnet_mapping)
            port_params['l2dom_id'] = l2_id
            port_params['l3dom_id'] = l3_id
        nuage_vport = self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params, required=False)
        if nuage_vport and (nuage_vport['type'] == constants.HOST_VPORT):
            def_netpart = cfg.CONF.RESTPROXY.default_net_partition_name
            netpart = nuagedb.get_default_net_partition(context, def_netpart)
            self.vsdclient.delete_nuage_gateway_vport(
                context,
                nuage_vport.get('ID'),
                netpart['id'])
