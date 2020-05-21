# Copyright 2016 NOKIA
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

import logging

import netaddr
try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _

from nuage_neutron.plugins.common import exceptions as nuage_exc
from nuage_neutron.plugins.common import nuagedb

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import gw_helper
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient.resources.domain import NuageDomainSubnet
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)


class NuageGateway(object):
    def __init__(self, restproxy_serv, policygroups):
        self.restproxy = restproxy_serv
        self.domainsubnet = NuageDomainSubnet(restproxy_serv,
                                              policygroups)
        self.policygroup = policygroups

    @staticmethod
    def is_sw_gateway(gateway):
        return gateway['personality'] in constants.SW_GW_TYPES

    @staticmethod
    def is_hw_gateway(gateway):
        return gateway['personality'] not in constants.SW_GW_TYPES

    @staticmethod
    def get_personality_type(personality):
        return (constants.SOFTWARE if personality in constants.SW_GW_TYPES
                else constants.HARDWARE)

    def get_gateways(self, tenant_id, filters):
        extra_params = dict()
        extra_headers = dict()
        req_params = dict()
        gw_list = []
        if filters and 'id' in filters:
            gw_id = filters.get('id')[0]
            # Check if gw_id is a valid uuid
            if not helper.is_valid_uuid(gw_id):
                LOG.info("Gateway id %s is not a valid uuid", gw_id)
                return []
            req_params['gw_id'] = gw_id
        elif filters and 'name' in filters:
            extra_params['name'] = filters.get('name')[0]
        elif filters and 'system_id' in filters:
            extra_params['system_id'] = filters.get('system_id')[0]

        for nuage_gw in [nuagelib.NuageGatewayBase.factory(
                create_params=req_params,
                extra_params=extra_params,
                redundant=redundant) for redundant in [False, True]]:
            if req_params.get('gw_id'):
                res_url = nuage_gw.get_resource_by_id()
            elif extra_params.get('name'):
                extra_headers = nuage_gw.extra_headers_by_name()
                res_url = nuage_gw.get_resource()
            elif extra_params.get('system_id'):
                extra_headers = nuage_gw.extra_headers_by_system_id()
                res_url = nuage_gw.get_resource()
            else:
                res_url = nuage_gw.get_resource()
            gws = self.restproxy.get(res_url, extra_headers=extra_headers)
            for gw in gws:
                if (gw and self.is_sw_gateway(gw) and
                        (gw.get('redundancyGroupID') or gw.get('pending'))):
                    LOG.debug("Gateway %s is part of redundancy group"
                              " or in pending state",
                              gw['ID'])
                    continue
                gw['redundant'] = 'redundantGatewayStatus' in gw
                gw_list.append(gw)

        return gw_list

    def get_gateway_ports(self, tenant_id, filters):
        if 'gateway' in filters and 'name' in filters:
            req_params = {
                'gw_id': filters['gateway'][0]
            }
            extra_params = {
                'gw_port_name': filters['name'][0]
            }
            return self._get_gateway_ports(req_params, extra_params)

        if 'gateway' in filters and 'id' in filters:
            port = gw_helper.get_gateway_port(self.restproxy,
                                              filters['id'][0],
                                              gw_id=filters['gateway'][0])
            if not port:
                return []
            else:
                return [port]

        if 'id' in filters:
            port = gw_helper.get_gateway_port(self.restproxy, filters['id'][0])
            if not port:
                return []
            else:
                return [port]

        if 'gateway' in filters and 'gatewayport' in filters:
            # We don't need the gateway that is being passed in
            port = gw_helper.get_gateway_port(self.restproxy,
                                              filters['gatewayport'][0],
                                              gw_id=filters['gateway'][0])
            if not port:
                return []
            else:
                return [port]

        if 'gateway' not in filters:
            gws = self.get_gateways(tenant_id, filters)
            ports = []
            for gw in gws:
                req_params = {
                    'gw_id': gw['ID']
                }
                ports.extend(self._get_gateway_ports(req_params))
            return ports
        else:
            req_params = {
                'gw_id': filters['gateway'][0]
            }
            return self._get_gateway_ports(req_params)

    def _get_gateway_ports(self, req_params, extra_params=None):
        extra_headers = dict()
        if not req_params.get('personality'):
            gw = gw_helper.get_gateway(self.restproxy, req_params['gw_id'])
            req_params['personality'] = gw['personality']
            redundant = 'redundantGatewayStatus' in gw
        else:
            redundant = req_params['redundant']
        nuage_gw_port = nuagelib.NuageGatewayPortBase.factory(
            create_params=req_params,
            extra_params=extra_params,
            redundant=redundant)
        if extra_params:
            if 'gw_port_name' in extra_params:
                extra_headers = nuage_gw_port.extra_headers_by_name()

        return self.restproxy.get(
            nuage_gw_port.get_resource_by_gateway(),
            extra_headers=extra_headers,
            required=True)

    # JvB added
    def update_gateway_port(self, port_id, redundant, req_params ):
       nuage_gw_port = nuagelib.NuageGatewayPortBase.factory(
           create_params={ 'port_id' : port_id },
           extra_params=None,
           redundant=redundant)
       return self.restproxy.put( nuage_gw_port.put_url(), req_params )

    def _get_gateway_port_vlans(self, tenant_id, req_params,
                                extra_params=None):
        if not req_params.get('personality'):
            gw_port = gw_helper.get_gateway_port(self.restproxy,
                                                 req_params['port_id'])
            gw = gw_helper.get_gateway(self.restproxy, gw_port['parentID'])
            req_params['personality'] = gw['personality']
            redundant = 'redundantGatewayStatus' in gw
        else:
            redundant = req_params['redundant']
        nuage_gw_vlan = nuagelib.NuageVlanBase.factory(
            create_params=req_params,
            extra_params=extra_params,
            redundant=redundant)

        resource_url = nuage_gw_vlan.get_resource_by_port()

        extra_headers = dict()
        if extra_params and 'vlan_value' in extra_params:
            vlan_val = extra_params['vlan_value']
            if not helper.is_vlan_valid(vlan_val):
                return []
            extra_headers = nuage_gw_vlan.extra_headers_by_value()
        gw_vlans = self.restproxy.get(resource_url,
                                      extra_headers=extra_headers,
                                      required=True)
        return gw_vlans if gw_vlans else []

    def get_gateway_port_vlans(self, tenant_id, netpart_id, filters):
        if 'gateway' in filters and 'gatewayport' in filters:
            # We dont't need the gateway that is being passed in.
            # We should have verified that the gatewayport belongs
            # to this gateway in previous call.
            params = {
                'port_id': filters['gatewayport'][0]
            }
            vlan_list = self._get_gateway_port_vlans(tenant_id, params)
        elif 'gatewayport' in filters and 'name' in filters:
            params = {
                'port_id': filters['gatewayport'][0]
            }
            extra_params = {
                'vlan_value': filters['name'][0]
            }
            vlan_list = self._get_gateway_port_vlans(tenant_id, params,
                                                     extra_params)
        elif 'gatewayport' in filters and 'id' in filters:
            params = {
                'port_id': filters['gatewayport'][0]
            }
            extra_params = {
                'vlan_value': filters['id'][0]
            }
            vlan_list = self._get_gateway_port_vlans(tenant_id, params,
                                                     extra_params)
        elif 'name' in filters:
            try:
                vlan_list = [gw_helper.get_gateway_port_vlan(
                    self.restproxy,
                    filters['name'][0])]
            except Exception as e:
                # If vlan does not exist return a empty list
                if e.code == constants.RES_NOT_FOUND:
                    return []
                raise
        elif 'id' in filters:
            vlan_list = [gw_helper.get_gateway_port_vlan(self.restproxy,
                                                         filters['id'][0])]
        elif 'gatewayport' in filters:
            params = {
                'port_id': filters['gatewayport'][0]
            }
            vlan_list = self._get_gateway_port_vlans(tenant_id, params)
        else:
            # This is when no --gateway and --gatewayport option is specified
            # in neutronclient
            vlan_list = self._get_vlans_for_tenant(tenant_id, netpart_id)

        if tenant_id:
            updated_vlan_list = []
            for vlan in vlan_list:
                # Get permissions for each vlan
                ent_perm = gw_helper.get_ent_permission_on_vlan(self.restproxy,
                                                                vlan['ID'])
                if ent_perm:
                    vlan_perm = self._check_tenant_perm(
                        vlan['ID'],
                        tenant_id,
                        ent_perm['permittedEntityID'])
                    if vlan_perm:
                        vlan['assignedTo'] = tenant_id
                        updated_vlan_list.append(vlan)

            return updated_vlan_list
        else:
            # Now get the assigned tenant_id for each vlan and update vlan in
            # place
            for vlan in vlan_list:
                vlan_perm = gw_helper.get_tenant_perm(self.restproxy,
                                                      vlan['ID'])
                if vlan_perm:
                    vlan['assignedTo'] = vlan_perm['permittedEntityName']

        return vlan_list

    def _get_vlans_for_tenant(self, tenant_id, netpart_id):
        # Get all the gateways in the enterprise
        gws = self.get_gateways(tenant_id, filters=None)
        # Get all the gatewayports
        gw_port_vlans = []
        for gw in gws:
            req_params = {
                'gw_id': gw['ID'],
                'personality': gw['personality'],
                'redundant': gw['redundant']
            }

            gw_ports = self._get_gateway_ports(req_params=req_params)
            for gw_port in gw_ports:
                # Get all the vlans
                req_params = {
                    'port_id': gw_port['ID'],
                    'personality': gw['personality'],
                    'redundant': gw['redundant']
                }
                gw_port_vlans.extend(
                    self._get_gateway_port_vlans(tenant_id, req_params))

        return gw_port_vlans if gw_port_vlans else []

    def _get_ent_permissions(self, vlan_id):
        req_params = {
            'vlan_id': vlan_id
        }

        nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
        permissions = self.restproxy.get(nuage_ent_perm.get_resource_by_vlan(),
                                         required=True)
        return permissions[0] if permissions else None

    def _check_ent_permission(self, gw_id, gw_port_id, netpart_id):
        gw = gw_helper.get_gateway(self.restproxy, gw_id)
        gw_perm = gw_helper.get_ent_permission_on_gateway(self.restproxy,
                                                          gw_id,
                                                          gw['redundant'])
        if gw_perm and gw_perm['permittedEntityID'] != netpart_id:
            msg = (_("Non default enterprise %(ent)s has permission for "
                     "gateway %(gw)s, so cannot create/delete vlan") %
                   {'ent': gw_perm['permittedEntityID'],
                    'gw': gw_id})
            raise restproxy.ResourceConflictException(msg)
        else:
            gw_port_perm = gw_helper.get_ent_permission_on_port(
                self.restproxy,
                gw_port_id,
                self.is_hw_gateway(gw) and gw['redundant'])
            if gw_port_perm and (gw_port_perm['permittedEntityID'] !=
                                 netpart_id):
                msg = (_("Non default enterprise %(ent)s has permission for "
                         "gateway port %(port)s, so cannot create/delete "
                         "vlan") %
                       {'ent': gw_port_perm['permittedEntityID'],
                        'port': gw_port_id})
                raise restproxy.ResourceConflictException(msg)

    def create_gateway_port_vlan(self, vlan_dict):
        gw_id = vlan_dict.get('gateway')
        gw_port_id = vlan_dict['gatewayport']
        vlan_value = vlan_dict['value']

        # Confirm that the gatewayport belongs to the gateway
        gw_port = gw_helper.get_gateway_port(self.restproxy, gw_port_id, gw_id)
        if not gw_port:
            if gw_id:
                msg = (_("Port %(port)s not found on gateway %(gw)s")
                       % {'port': gw_port_id,
                          'gw': gw_id})
            else:
                msg = (_("Port %(port)s not found") % {'port': gw_port_id})
            raise restproxy.ResourceNotFoundException(msg)

        if not gw_id:
            gw_id = gw_port['parentID']
        gw = gw_helper.get_gateway(self.restproxy, gw_id)

        req_params = {
            'port_id': gw_port_id,
            'personality': gw['personality']
        }

        nuage_gw_vlan = nuagelib.NuageVlanBase.factory(
            create_params=req_params,
            extra_params=None,
            redundant=gw['redundant'])
        return self.restproxy.post(nuage_gw_vlan.post_vlan(),
                                   nuage_gw_vlan.post_vlan_data(vlan_value))

    def create_gateway_vlan(self, vlan_dict):
        req_params = {
            'port_id': vlan_dict['gatewayport'],
            'personality': vlan_dict['personality'],
            'description': vlan_dict['description']
                           if 'description' in vlan_dict else None
        }
        nuage_gw_vlan = nuagelib.NuageVlanBase.factory(
            create_params=req_params,
            extra_params=None,
            redundant=vlan_dict['redundant'])
        return self.restproxy.post(
            nuage_gw_vlan.post_vlan(),
            nuage_gw_vlan.post_vlan_data(vlan_dict['value']),
            on_res_exists=self.restproxy.retrieve_by_external_id,
            ignore_err_codes=[restproxy.REST_VLAN_EXISTS_ERR_CODE])[0]

    def delete_gateway_port_vlan(self, vlan_id):
        req_params = {
            'vlan_id': vlan_id
        }
        nuage_gw_vlan = nuagelib.NuageVlan(create_params=req_params)
        self.restproxy.delete(
            nuage_gw_vlan.get_resource() + '?responseChoice=1')

    def add_ent_perm(self, tenant_id, vlan_id, netpart_id):
        req_params = {
            'vlan_id': vlan_id
        }

        nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
        data = nuage_ent_perm.perm_update(netpart_id)
        data.update({'externalID': netpart_id + '@openstack'})
        try:
            self.restproxy.post(
                nuage_ent_perm.get_resource_by_vlan(),
                data,
                on_res_exists=self.restproxy.retrieve_by_external_id,
                ignore_err_codes=[restproxy.REST_ENT_PERMS_EXISTS_ERR_CODE])[0]
        except Exception as e:
            if not self._check_parent_permissions(tenant_id,
                                                  vlan_id,
                                                  netpart_id):
                raise e

    def _check_parent_permissions(self, tenant_id, vlan_id, netpart_id):
        req_params = {
            'vlan_id': vlan_id
        }

        nuage_vlan = nuagelib.NuageVlan(create_params=req_params)
        vlans = self.restproxy.get(nuage_vlan.get_resource(),
                                   required=True)
        # Get ent permissions on port
        gw_port_id = vlans[0]['parentID']
        gw_port = gw_helper.get_gateway_port(self.restproxy,
                                             gw_port_id)
        gw = gw_helper.get_gateway(self.restproxy, gw_port['parentID'])
        req_params['port_id'] = gw_port_id
        nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
        permissions = self.restproxy.get(
            nuage_ent_perm.get_resource_by_port(gw['redundant']),
            required=True)
        ent_perm = permissions[0] if permissions else None
        if ent_perm:
            ent_id = ent_perm['permittedEntityID']
            if ent_id != netpart_id:
                ent_type = ent_perm['permittedEntityType']
                LOG.debug("Port %(port)s already assigned to %(ent)s with id"
                          " %(ent_id)s", {'port': vlan_id,
                                          'ent': ent_type,
                                          'ent_id': ent_id})
                return False
            else:
                LOG.debug("Port %(port)s is assigned to enterprise %(ent)s",
                          {'port': gw_port_id,
                           'ent': ent_id})
                return True

        # Get ent permissions on gateway
        gw_port = gw_helper.get_gateway_port(self.restproxy, gw_port_id,
                                             gw_port['parentID'])
        if not gw_port:
            msg = (_("Port %s not found on gateway ", gw_port_id))  # noqa H702
            raise restproxy.ResourceNotFoundException(msg)

        gw_id = gw_port['parentID']
        req_params['gw_id'] = gw_id
        nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)
        permissions = self.restproxy.get(nuage_ent_perm.get_resource_by_gw(),
                                         required=True)
        ent_perm = permissions[0] if permissions else None
        if ent_perm:
            ent_id = ent_perm['permittedEntityID']
            if ent_id != netpart_id:
                ent_type = ent_perm['permittedEntityType']
                LOG.debug("Gateway %(gw)s already assigned to %(ent)s with "
                          "id %(ent_id)s", {'gw': gw_id,
                                            'ent': ent_type,
                                            'ent_id': ent_id})
                return False
            else:
                LOG.debug("Gateway %(gw)s is assigned to enterprise %(ent)s",
                          {'gw': gw_id,
                           'ent': ent_id})
                return True
        return False

    def remove_ent_perm(self, vlan_id):
        req_params = {
            'vlan_id': vlan_id
        }

        nuage_ent_perm = nuagelib.NuageEntPermission(create_params=req_params)

        permissions = self.restproxy.get(nuage_ent_perm.get_resource_by_vlan(),
                                         required=True)
        ent_perm = permissions[0] if permissions else None
        if ent_perm:
            req_params['perm_id'] = ent_perm['ID']
            self.restproxy.delete(
                nuage_ent_perm.get_resource_by_id() + '?responseChoice=1')

    def add_tenant_perm(self, vlan_id, user_tenant, netpart_id):
        req_params = {
            'vlan_id': vlan_id
        }
        # Check if the grp exists in VSD, if not create it
        nuage_user, nuage_group = helper.create_usergroup(
            self.restproxy, user_tenant, netpart_id)

        # Check if permission already exists
        perm = gw_helper.get_tenant_perm(self.restproxy, vlan_id)
        if perm:
            msg = _("Vlan %(vlan)s already assigned to %(ten)s") % \
                {'vlan': vlan_id, 'ten': perm['permittedEntityName']}
            if perm['permittedEntityID'] != nuage_group:
                raise restproxy.ResourceConflictException(msg)
            else:
                LOG.debug(msg)
                return

        nuage_perm = nuagelib.NuagePermission(create_params=req_params)
        data = nuage_perm.perm_update(nuage_group)
        data.update({'externalID': get_vsd_external_id(user_tenant)})
        self.restproxy.post(nuage_perm.get_resource_by_vlan(), data)

    def _check_tenant_perm(self, vlan_id, user_tenant, netpart_id):
        req_params = {
            'vlan_id': vlan_id
        }
        # Check if the grp exists in VSD, if not create it
        nuage_user, nuage_group = helper.create_usergroup(
            self.restproxy, user_tenant, netpart_id)

        nuage_perm = nuagelib.NuagePermission(create_params=req_params)
        permissions = self.restproxy.get(nuage_perm.get_resource_by_vlan(),
                                         required=True)
        if not permissions:
            return False
        else:
            return permissions[0]['permittedEntityID'] == nuage_group

    def remove_tenant_perm(self, vlan_id, user_tenant, netpart_id):
        nuage_user, nuage_group = helper.create_usergroup(
            self.restproxy, user_tenant, netpart_id)

        req_params = {
            'vlan_id': vlan_id
        }

        extra_params = {
            'entity_id': nuage_group
        }
        nuage_perm = nuagelib.NuagePermission(create_params=req_params,
                                              extra_params=extra_params)
        permissions = self.restproxy.get(nuage_perm.get_resource_by_vlan())

        for perm in permissions:
            if perm['permittedEntityID'] == nuage_group:
                LOG.debug("Removing %(grp)s permission from vlan %(vlan)s",
                          {'grp': user_tenant,
                           'vlan': vlan_id})
                req_params['perm_id'] = perm['ID']
                self.restproxy.delete(
                    nuage_perm.get_resource_by_id() + '?responseChoice=1')

                # return the num of remaining groups
                return len(permissions) - 1

        msg = _("Vlan %(vlan)s is not assigned to tenant "
                "%(grp)s") % {'grp': user_tenant,
                              'vlan': vlan_id}
        LOG.debug(msg)
        return len(permissions) - 1

    def update_gateway_port_vlan(self, tenant_id, vlan_id, params):
        action = params['vlan']['action']
        user_tenant = params['vlan']['tenant']
        netpart_id = params['np_id']

        if action == constants.ASSIGN_VLAN:
            # Give permissions for the enterprise
            self.add_ent_perm(user_tenant, vlan_id, netpart_id)

            # Give permissions for the tenant
            self.add_tenant_perm(vlan_id, user_tenant, netpart_id)
        elif action == constants.UNASSIGN_VLAN:
            # Remove permissions for the tenant
            num_grps = self.remove_tenant_perm(vlan_id, user_tenant,
                                               netpart_id)

            if num_grps == 0:
                # Remove permissions for the enterprise if it exists
                self.remove_ent_perm(vlan_id)

        # This is faking a vlan obj for neutronclient
        ret = {
            'gw_vlan_id': vlan_id,
            'gw_vlan_port_id': None,
            'gw_vlan_gw_id': None,
            'gw_vlan_value': None,
            'gw_vlan_vport_id': None,
            'gw_vlan_mnemonic': None,
            'gw_vlan_status': None,
            'gw_vlan_assigned_to': tenant_id
        }

        return ret

    def create_gateway_vport(self, tenant_id, params):
        subnet = params.get('subnet')
        enable_dhcp = params.get('enable_dhcp')
        port = params.get('port')
        type = params.get('type')
        subn_id = subnet['id']

        nuage_subnet = params.get('vsd_subnet')
        if not nuage_subnet:
            msg = (_("Nuage subnet for neutron subnet %(subn)s not found")
                   % {'subn': subn_id})
            raise restproxy.ResourceNotFoundException(msg)
        # Create a vport with bridge/host interface
        req_params = {
            'nuage_vlan_id': params['gatewayinterface'],
            'neutron_subnet': subnet,
            'nuage_managed_subnet': params.get('nuage_managed_subnet')
        }

        # Get gateway from gw interface
        gw = gw_helper.get_gateway_by_vlan(self.restproxy,
                                           params['gatewayinterface'])

        if nuage_subnet['parentType'] == 'zone':
            req_params['nuage_subnet_id'] = nuage_subnet['ID']
        else:
            req_params['l2domain_id'] = nuage_subnet['ID']

        req_params['gw_type'] = gw['personality']

        # Check if tenant has permission on gw interface
        user_tenant = params.get('tenant')
        if user_tenant:
            # Give permissions for the enterprise
            self.add_ent_perm(tenant_id, params['gatewayinterface'],
                              params['np_id'])

            # Give permissions for the tenant
            self.add_tenant_perm(params['gatewayinterface'],
                                 user_tenant, params['np_id'])

        ret = dict()
        if type == constants.BRIDGE_VPORT_TYPE:
            req_params[constants.PORTSECURITY] = True
            req_params['externalid'] = get_vsd_external_id(
                port['id'] if port else subnet['network_id'])
            resp = gw_helper.create_vport_interface(self.restproxy,
                                                    self.policygroup,
                                                    req_params, type)
        else:
            if enable_dhcp:
                req_params['ipaddress'] = port['fixed_ips'][0]['ip_address']
            else:
                req_params['ipaddress'] = None
            req_params['mac'] = port['mac_address']
            req_params['externalid'] = get_vsd_external_id(port['id'])
            req_params[constants.PORTSECURITY] = port[constants.PORTSECURITY]
            resp = gw_helper.create_vport_interface(self.restproxy,
                                                    self.policygroup,
                                                    req_params, type)

        ret = resp
        ret['vport_gw_type'] = self.get_personality_type(gw['personality'])
        return ret

    def create_gateway_vport_no_usergroup(self, tenant_id, params,
                                          create_policy_group=False):
        subnet = params.get('subnet')
        enable_dhcp = params.get('enable_dhcp')
        port = params.get('port')
        type = params.get('type')
        subn_id = subnet['id']

        nuage_subnet = params.get('vsd_subnet')
        if not nuage_subnet:
            msg = (_("Nuage subnet for neutron subnet %(subn)s not found")
                   % {'subn': subn_id})
            raise restproxy.ResourceNotFoundException(msg)
        # Create a vport with bridge/host interface
        req_params = {
            'nuage_vlan_id': params['gatewayinterface'],
            'neutron_subnet': subnet,
            'nuage_managed_subnet': params.get('nuage_managed_subnet'),
            'gw_type': params['personality'],
            'externalid': get_vsd_external_id(port['id'] if port else
                                              subnet['network_id'])
        }
        if nuage_subnet['parentType'] == 'zone':
            req_params['nuage_subnet_id'] = nuage_subnet['ID']
        else:
            req_params['l2domain_id'] = nuage_subnet['ID']

        # Check if tenant has permission on gw interface
        user_tenant = params.get('tenant')
        if user_tenant:
            # Give permissions for the enterprise
            self.add_ent_perm(tenant_id, params['gatewayinterface'],
                              params['np_id'])

        if type == constants.BRIDGE_VPORT_TYPE:
            req_params[constants.PORTSECURITY] = True
            resp = gw_helper.create_vport_interface(self.restproxy,
                                                    self.policygroup,
                                                    req_params, type,
                                                    create_policy_group)
        else:
            ips = {}
            for fixed_ip in port.get('fixed_ips', []):
                if netaddr.IPAddress(fixed_ip['ip_address']).version == 4:
                    ips[4] = fixed_ip['ip_address']
                else:
                    ips[6] = fixed_ip['ip_address']
            if enable_dhcp:
                req_params['ipaddress'] = ips.get(4)
                req_params['ipaddress_v6'] = ips.get(6)
            else:
                req_params['ipaddress'] = None
                req_params['ipaddress_v6'] = ips.get(6)
            req_params['mac'] = port['mac_address']
            req_params['externalid'] = get_vsd_external_id(port['id'])
            req_params[constants.PORTSECURITY] = port[constants.PORTSECURITY]
            resp = gw_helper.create_vport_interface(self.restproxy,
                                                    self.policygroup,
                                                    req_params, type,
                                                    create_policy_group)

        ret = resp
        ret['vport_gw_type'] = self.get_personality_type(params['personality'])
        return ret

    def _delete_policygroup(self, interface, policygroup_id):
        vport_list = gw_helper.get_vports_for_policygroup(self.restproxy,
                                                          policygroup_id)
        if vport_list:
            if len(vport_list) == 1:
                self.policygroup.delete_nuage_policy_group(policygroup_id)
                LOG.debug("Deleted policygroup associated with "
                          "interface %s", interface)

    def delete_nuage_gateway_vport(self, context, nuage_vport_id,
                                   def_netpart_id):
        # Get the gw interface and vport info
        tenant_id = context.tenant_id
        resp = self.get_gateway_vport(context, tenant_id, None, nuage_vport_id)
        if not resp:
            return

        nuage_subnet_id = resp['nuage_subnet_id']
        subnet_info = nuagedb.get_subnet_info_by_nuage_id(context.session,
                                                          nuage_subnet_id)
        if not subnet_info:
            raise nuage_exc.NuageAPIException(
                msg='No subnet info could not be retrieved')

        # Delete the interface and vport
        if resp['vport_type'] == constants.BRIDGE_VPORT_TYPE:
            if resp['interface']:
                # Delete interface
                gw_helper.delete_nuage_interface(self.restproxy,
                                                 resp['interface'],
                                                 constants.BRIDGE_VPORT_TYPE)
                LOG.debug("Deleted bridge interface %s", resp['interface'])
        elif resp['vport_type'] == constants.HOST_VPORT_TYPE:
            if resp['interface']:
                # Delete the policygroup and interface
                gw_helper.delete_nuage_interface(self.restproxy,
                                                 resp['interface'],
                                                 constants.HOST_VPORT_TYPE)
                LOG.debug("Deleted host interface %s", resp['interface'])

        # Delete the vport
        # if 'vport_type' is not None, then 'vport_id' is not None
        gw_helper.delete_nuage_vport(self.restproxy, resp['vport_id'])
        LOG.debug("Deleted vport %s", resp['vport_id'])
        # Remove Ent/Tenant permissions
        perms = self._get_ent_permissions(resp['vlanid'])
        if perms and perms['permittedEntityType'] == 'enterprise':
            netpart_id = perms['permittedEntityID']
        else:
            netpart_id = def_netpart_id
        if netpart_id != def_netpart_id:
            perm = gw_helper.get_tenant_perm(self.restproxy, resp['vlanid'])
            if perm:
                num_grps = self.remove_tenant_perm(resp['vlanid'],
                                                   perm['permittedEntityName'],
                                                   netpart_id)
                if num_grps == 0:
                    # Remove permissions for the enterprise if it exists
                    self.remove_ent_perm(resp['vlanid'])
                    LOG.debug("Deleted ent perissions on vlan %s",
                              resp['vlanid'])
        else:
            LOG.debug("Preserving ent permissions on default netpartition")

    def delete_nuage_gateway_vport_no_usergroup(self, tenant_id, vport):
        intf = gw_helper.get_interface_by_vport(
            self.restproxy,
            vport['ID'],
            vport['type'])

        if intf:
            gw_helper.delete_nuage_interface(self.restproxy,
                                             intf['ID'],
                                             vport['type'])
            LOG.debug("Deleted %(itf_type)s interface %(itf)s",
                      {'itf_type': vport['type'], 'itf': intf['ID']})
        # Delete the vport
        gw_helper.delete_nuage_vport(self.restproxy, vport['ID'])
        LOG.debug("Deleted vport %s", vport['ID'])
        # Remove Ent/Tenant permissions
        self.remove_ent_perm(vport['VLANID'])
        LOG.debug("Deleted ent permissions on vlan %s", vport['VLANID'])

    def get_gateway_vport(self, context, tenant_id, netpart_id,
                          nuage_vport_id):
        nuage_vport = gw_helper.get_nuage_vport(self.restproxy,
                                                nuage_vport_id)
        if not nuage_vport:
            # Just return empty list. Plugin will throw 404
            return []

        nuage_subnet_id = nuage_vport['parentID']
        if nuage_vport['VLANID']:
            nuage_gw_vport = self._get_gateway_vport(context, tenant_id,
                                                     netpart_id,
                                                     nuage_vport['VLANID'])
            nuage_gw_vport['vlanid'] = nuage_vport['VLANID']
            return nuage_gw_vport

        ret = dict()
        ret['nuage_subnet_id'] = nuage_subnet_id

        nuage_vport_type = nuage_vport['type']
        if nuage_vport_type == constants.BRIDGE_VPORT_TYPE:
            # Get the bridge interface on the vport
            nuage_br_intf = gw_helper.get_interface_by_vport(
                self.restproxy,
                nuage_vport_id,
                nuage_vport_type)
            if nuage_br_intf:
                ret['interface'] = nuage_br_intf['ID']

        elif nuage_vport_type == constants.HOST_VPORT_TYPE:
            # Get the host interface on the vport
            nuage_host_intf = gw_helper.get_interface_by_vport(
                self.restproxy,
                nuage_vport_id,
                nuage_vport_type)
            if nuage_host_intf:
                ret['interface'] = nuage_host_intf['ID']
                ret['port_id'] = strip_cms_id(
                    nuage_host_intf['externalID'])

        ret['vport_type'] = nuage_vport_type
        ret['vport_name'] = nuage_vport['name']
        ret['vlanid'] = None
        return ret

    def _get_gateway_vport(self, context, tenant_id, netpart_id,
                           nuage_vlan_id):
        ret = {
            'interface': None,
            'vport_id': None,
            'vport_type': None,
            'vport_name': None,
            'port_id': None
        }

        # Get the gw interface
        try:
            nuage_vlan = gw_helper.get_gateway_port_vlan(self.restproxy,
                                                         nuage_vlan_id)
        except Exception as e:
            if e.code == constants.RES_NOT_FOUND:
                return
            raise

        # Check for tenant permission
        # tenant_id is None in case of admin. We don't check permissions
        # for admin.netpart_id will be None when called from
        # delete_gateway_vport. We don't have to check permissions for
        # delete as client always calls get() before delete and we check
        # permissions during get()
        if tenant_id and netpart_id:
            ent_perm = gw_helper.get_ent_permission_on_vlan(self.restproxy,
                                                            nuage_vlan['ID'])
            has_perm = self._check_tenant_perm(nuage_vlan_id, tenant_id,
                                               ent_perm['permittedEntityID'])
            if not has_perm:
                msg = _("Tenant %(ten)s does not have permission for vlan %("
                        "vlan)s" % {'ten': tenant_id,   # noqa H702
                                    'vlan': nuage_vlan_id})
                LOG.warn(msg)
                raise restproxy.ResourceConflictException(msg)

        ret['gateway'] = nuage_vlan['gatewayID']
        ret['gatewayport'] = nuage_vlan['parentID']
        ret['value'] = nuage_vlan['value']

        # Check if it is associated with a vport
        nuage_vport_id = nuage_vlan['vportID']
        if not nuage_vport_id:
            msg = _("Nuage gateway interface %s is not associated with any "
                    "vport" % nuage_vlan_id)   # noqa H702
            raise restproxy.ResourceConflictException(msg)

        # Get the vport
        nuage_vport = gw_helper.get_nuage_vport(self.restproxy, nuage_vport_id)
        if nuage_vport:
            ret['nuage_subnet_id'] = nuage_vport['parentID']
            nuage_vport_type = nuage_vport['type']
            if nuage_vport_type == constants.BRIDGE_VPORT_TYPE:
                # Get the bridge interface on the vport
                nuage_br_intf = gw_helper.get_interface_by_vport(
                    self.restproxy,
                    nuage_vport_id,
                    nuage_vport_type)
                if nuage_br_intf:
                    ret['interface'] = nuage_br_intf['ID']

            elif nuage_vport_type == constants.HOST_VPORT_TYPE:
                # Get the host interface on the vport
                nuage_host_intf = gw_helper.get_interface_by_vport(
                    self.restproxy,
                    nuage_vport_id,
                    nuage_vport_type)
                if nuage_host_intf:
                    ret['interface'] = nuage_host_intf['ID']
                    ret['port_id'] = strip_cms_id(
                        nuage_host_intf['externalID'])
            else:
                msg = _("Nuage vport associated with gateway interface %s is"
                        " not connected to a bridge/host interface"
                        % nuage_vlan_id)   # noqa H702
                raise restproxy.ResourceConflictException(msg)

            ret['vport_id'] = nuage_vport_id
            ret['vport_type'] = nuage_vport_type
            ret['vport_name'] = nuage_vport['name']

        return ret

    def get_gateway_vports(self, context, tenant_id, netpart_id, filters):
        subnet_id = filters['subnet'][0]
        nuage_subnet_id = filters['nuage_subnet_id'][0]
        # Get the nuage l2domain/subnet corresponding to neutron subnet
        # nuage_subnet_id passed in filters by plugin

        subnet_info = nuagedb.get_subnet_info_by_nuage_id(
            context.session, nuage_subnet_id)
        if not subnet_info:
            raise nuage_exc.NuageAPIException(
                msg='No subnet info could be retrieved')

        subnet_type = subnet_info['subnet_type']

        if 'id' in filters:
            # This is to get vport by id
            vport = gw_helper.get_nuage_vport(self.restproxy, filters['id'][0])

            # Return an empty list for neutronclient get_res_by_id_or_name()
            if not vport:
                return []

            if vport['parentID'] != nuage_subnet_id:
                return []

            vport_list = [vport]
        elif 'name' in filters:
            # This is to get vport by name
            vport = gw_helper.get_nuage_vport_by_name(
                self.restproxy, nuage_subnet_id, filters['name'][0],
                subnet_type)

            # Return an empty list for neutronclient get_res_by_id_or_name()
            if not vport:
                return []

            if vport['parentID'] != nuage_subnet_id:
                return []

            vport_list = [vport]
        else:
            if subnet_type == constants.SUBNET:
                # Get all host/bridge vports
                vport_list = gw_helper.get_vports_for_subnet(
                    self.restproxy, nuage_subnet_id)
            else:
                # Get all host/bridge vports
                vport_list = gw_helper.get_vports_for_l2domain(
                    self.restproxy, nuage_subnet_id)

        resp_list = []
        for vport in vport_list:
            vport_type = vport['type']
            resp = dict()
            if vport_type in [constants.HOST_VPORT_TYPE,
                              constants.BRIDGE_VPORT_TYPE]:
                resp['vport_id'] = vport['ID']
                resp['vport_type'] = vport_type
                resp['vport_name'] = vport['name']
                # Get the host/bridge interface
                nuage_interface = gw_helper.get_interface_by_vport(
                    self.restproxy,
                    vport['ID'], vport_type)

                resp['port_id'] = None
                if nuage_interface:
                    resp['interface'] = nuage_interface['ID']
                    resp['port_id'] = strip_cms_id(
                        nuage_interface['externalID'])

                resp['subnet_id'] = subnet_id

                if not vport['VLANID']:
                    # Skip this vport as it does not have any vlan.
                    # This should never happen as if vport is created a vlan
                    # is always associated with it
                    continue

                # Get the gw interface
                nuage_vlan = gw_helper.get_gateway_port_vlan(self.restproxy,
                                                             vport['VLANID'])

                resp['nuage_vlan_id'] = nuage_vlan['ID']
                resp['gateway'] = nuage_vlan['gatewayID']
                resp['gatewayport'] = nuage_vlan['parentID']
                resp['value'] = nuage_vlan['value']

                resp_list.append(resp)

        if tenant_id:
            updated_vport_list = []
            for vport in resp_list:
                ent_perm = gw_helper.get_ent_permission_on_vlan(
                    self.restproxy,
                    vport['nuage_vlan_id'])
                if ent_perm:
                    vlan_perm = self._check_tenant_perm(
                        vport['nuage_vlan_id'],
                        tenant_id,
                        ent_perm['permittedEntityID'])
                    if vlan_perm:
                        updated_vport_list.append(vport)
            return updated_vport_list

        return resp_list
