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
from netaddr import IPNetwork

from nuage_neutron.plugins.common import utils
from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)

ACTION_NOOP = "noop"
ACTION_MACSPOOFING = "macspoofing"
ACTION_NOVIP = "novipallowed"
ACTION_VIP = "createvip"


class NuageVM(object):
    def __init__(self, restproxy_serv, vsdclient):
        self.vsdclient = vsdclient
        self.restproxy = restproxy_serv

    def vms_on_l2domain(self, l2dom_id):
        nuagel2dom = nuagelib.NuageL2Domain()
        response = self.restproxy.get(
            nuagel2dom.vm_get_resource(l2dom_id))
        return response

    def vms_on_subnet(self, nuage_subnet_id):
        nuagesubnet = nuagelib.NuageSubnet()
        response = self.restproxy.get(
            nuagesubnet.vm_get_resource(nuage_subnet_id))
        return response

    def _get_nuage_vm(self, params, isdelete=False):
        req_params = {
            'id': params['id']
        }

        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }
        nuagevm = nuagelib.NuageVM(create_params=req_params,
                                   extra_params=extra_params)
        vms = self.restproxy.get(
            nuagevm.get_resource(),
            extra_headers=nuagevm.extra_headers_get())
        if not vms:
            if isdelete:
                return None
            else:
                msg = ('VM with uuid {} not found on '
                       'VSD').format(req_params['id'])
                raise restproxy.ResourceNotFoundException(msg)
        return vms[0]['ID']

    def _attach_permissions_to_groups(self, nuage_grpid_list, nuage_id,
                                      neutron_tenant_id,
                                      target='zones'):
        for nuage_groupid in nuage_grpid_list:
            nuage_permission = nuagelib.NuagePermission()
            post_data = nuage_permission.perm_create_data(
                nuage_groupid,
                constants.NUAGE_PERMISSION_USE,
                neutron_tenant_id)
            try:
                self.restproxy.post(
                    nuage_permission.post_resource_by_parent_id(
                        target, nuage_id), post_data)
            except restproxy.RESTProxyError as e:
                if e.code != constants.CONFLICT_ERR_CODE:
                    raise

    def _make_grp_id_list(self, params):
        nuage_grp_id_list = []
        if params['subn_tenant'] != params['tenant']:
            nuage_userid, nuage_groupid = helper.create_usergroup(
                self.restproxy, params['subn_tenant'],
                params['netpart_id'])
            nuage_grp_id_list.append(nuage_groupid)
        nuage_userid, nuage_groupid = helper.create_usergroup(
            self.restproxy, params['tenant'], params['netpart_id'])
        nuage_grp_id_list.append(nuage_groupid)
        return nuage_grp_id_list

    def _attach_reqd_perm_for_vm_boot(self, params, id, on_l2=True):
        if on_l2:
            # if the vm is to be attached on a non-shared n/w and the request
            # is from an admin tenant, then add the permissions to the l2domain
            # so that the admin tenant can boot a VM on a l2domain that was
            # not created by admin himself.
            l2dom_id = id
            nuage_grp_id_list = self._make_grp_id_list(params)
            self._attach_permissions_to_groups(nuage_grp_id_list, l2dom_id,
                                               params['tenant'],
                                               target='l2domains')
        else:
            # if the vm is to be attached on a non-shared n/w and the request
            # is from an admin tenant, then add the permissions to the zone
            # so that the admin tenant can boot a VM on a domain-subnet
            # that was not created by him.
            zone_id = id
            nuage_perm = nuagelib.NuagePermission(
                create_params={'zone_id': zone_id})
            permissions = self.restproxy.get(
                nuage_perm.get_resource_by_zone_id(),
                required=True)
            for permission in permissions:
                if permission['permittedEntityName'] == params['tenant']:
                    return

            nuage_grp_id_list = self._make_grp_id_list(params)
            self._attach_permissions_to_groups(nuage_grp_id_list, id,
                                               params['tenant'])

    def _create_nuage_vm(self, params):
        vsd_subnet = params['vsd_subnet']
        req_params = {
            'id': params['id'],
            'mac': params['mac'],
            'ipv4': params['ipv4'],
            'ipv6': params['ipv6'],
            'externalID': get_vsd_external_id(params['port_id'])
        }
        # if vport_id passed in VMInterface and attachedNetworkId is not set,
        # VM create associates the passed vport to the VMInterface
        if params.get('vport_id') and not params.get('attached_network'):
            req_params['vport_id'] = params.get('vport_id')
        elif params.get('attached_network'):
            req_params['attachedNetworkID'] = vsd_subnet['ID']

        if vsd_subnet['type'] == constants.SUBNET:
            if not params['portOnSharedSubn']:
                self._attach_reqd_perm_for_vm_boot(
                    params, vsd_subnet['parentID'], on_l2=False)
        elif vsd_subnet['type'] == constants.L2DOMAIN:
            self._clear_vsd_unmanaged_l2_domain_vm_ip(vsd_subnet, req_params)
            if not params['portOnSharedSubn']:
                self._attach_reqd_perm_for_vm_boot(
                    params, vsd_subnet['ID'], on_l2=True)
        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }
        nuagevm = nuagelib.NuageVM(create_params=req_params,
                                   extra_params=extra_params)
        response = self.restproxy.post(
            nuagevm.post_resource(),
            nuagevm.post_data(),
            extra_headers=nuagevm.extra_headers_post(),
            on_res_exists=self.restproxy.retrieve_by_external_id,
            ignore_err_codes=[restproxy.REST_EXISTS_INTERNAL_ERR_CODE,
                              restproxy.REST_VM_UUID_IN_USE_ERR_CODE])

        vm_dict = {}
        new_vmif = nuagevm.get_new_vmif(response)
        if new_vmif:
            vm_dict['ip'] = nuagevm.get_vmif_ip(new_vmif)
            vm_dict['vport_id'] = nuagevm.get_vmif_vportid(new_vmif)
            vm_dict['vif_id'] = nuagevm.get_vmif_id(new_vmif)

        return vm_dict

    def _create_nuage_vm_if(self, params):
        vm_id = self._get_nuage_vm(params)
        vsd_subnet = params['vsd_subnet']

        req_params = {
            'vm_id': vm_id,
            'mac': params['mac'],
            'ipv4': params['ipv4'],
            'ipv6': params['ipv6'],
            'externalID': get_vsd_external_id(params['port_id'])
        }

        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }

        if params.get('vport_id') and not params.get('attached_network'):
            req_params['vport_id'] = params.get('vport_id')
        elif params.get('attached_network'):
            req_params['attachedNetworkID'] = vsd_subnet['ID']

        if vsd_subnet['type'] == constants.SUBNET:
            self._attach_reqd_perm_for_vm_boot(
                params, vsd_subnet['parentID'], on_l2=False)
        elif vsd_subnet['type'] == constants.L2DOMAIN:
            self._clear_vsd_unmanaged_l2_domain_vm_ip(vsd_subnet, req_params)
            self._attach_reqd_perm_for_vm_boot(
                params, vsd_subnet['ID'], on_l2=True)

        nuagevmif = nuagelib.NuageVMInterface(create_params=req_params,
                                              extra_params=extra_params)
        response = self.restproxy.post(
            nuagevmif.post_resource(),
            nuagevmif.post_data(),
            extra_headers=nuagevmif.extra_headers())

        return {'ip': nuagevmif.get_vmif_ip(response),
                'vport_id': nuagevmif.get_vport_id(response),
                'vif_id': nuagevmif.get_vif_id(response)}

    def _clear_vsd_unmanaged_l2_domain_vm_ip(self, domain, req_params):
        shared_resource_id = domain['associatedSharedNetworkResourceID']
        if (not domain['DHCPManaged']) and (not shared_resource_id):
            req_params['ipv4'] = None
            req_params['ipv6'] = None
        elif shared_resource_id:
            if not self.is_shared_l2_domain_managed(shared_resource_id):
                req_params['ipv4'] = None
                req_params['ipv6'] = None

    def is_shared_l2_domain_managed(self, shared_nuage_id):
        nuagel2dom = nuagelib.NuageL2Domain()
        response = self.restproxy.get(nuagel2dom.get_resource(shared_nuage_id),
                                      required=True)[0]
        return response['DHCPManaged']

    def create_vms(self, params):
        if params['no_of_ports'] > 1:
            nuage_vm = self._create_nuage_vm_if(params)
        else:
            nuage_vm = self._create_nuage_vm(params)
        return nuage_vm

    def _delete_vsd_permission_of_tenant(self, params, tenant):
        nuage_perm = nuagelib.NuagePermission(
            create_params=params)
        if 'l2dom_id' in params:
            permissions = self.restproxy.get(
                nuage_perm.get_resource_by_l2dom_id(),
                required=True)
        elif 'zone_id' in params:
            permissions = self.restproxy.get(
                nuage_perm.get_resource_by_zone_id(),
                required=True)
        if len(permissions) > 1:
            for permission in permissions:
                if permission['permittedEntityName'] == tenant:
                    self.restproxy.delete(
                        nuage_perm.delete_resource(permission['ID']))
                    break

    def _delete_extra_perm_attached(self, tenant, l2dom_id=None,
                                    l3dom_id=None):
        if l2dom_id:
            create_params = {'l2dom_id': l2dom_id}
            self._delete_vsd_permission_of_tenant(create_params, tenant)
        else:
            nuagesubnet = nuagelib.NuageSubnet()
            subnet = self.restproxy.get(nuagesubnet.get_resource(l3dom_id),
                                        required=True)[0]
            create_params = {'zone_id': subnet['parentID']}
            self._delete_vsd_permission_of_tenant(create_params,
                                                  tenant)

    def _delete_nuage_vm(self, params):
        nuage_vm_id = self._get_nuage_vm(params, isdelete=True)
        if not nuage_vm_id:
            # It might already be deleted from the VSD
            return
        req_params = {
            'id': nuage_vm_id,
        }

        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }

        nuagevm = nuagelib.NuageVM(create_params=req_params,
                                   extra_params=extra_params)
        self.restproxy.delete(nuagevm.delete_resource(),
                              extra_headers=nuagevm.extra_headers_delete())
        if (not params['portOnSharedSubn'] and
                (params['subn_tenant'] != params['tenant'])):
            self._delete_extra_perm_attached(params['tenant'],
                                             params.get('l2dom_id'),
                                             params.get('l3dom_id'))

    def _delete_nuage_vm_if(self, params):
        LOG.debug("vsdclient._delete_nuage_vm_if() called")
        req_params = {
            'id': params['nuage_vif_id'],
        }
        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }

        nuagevmif = nuagelib.NuageVMInterface(create_params=req_params,
                                              extra_params=extra_params)
        self.restproxy.delete(nuagevmif.delete_resource(),
                              extra_headers=nuagevmif.extra_headers())
        if (not params['portOnSharedSubn'] and
                (params['subn_tenant'] != params['tenant'])):
            self._delete_extra_perm_attached(params['tenant'],
                                             params.get('l2dom_id'),
                                             params.get('l3dom_id'))

    def delete_vms(self, params):
        LOG.debug("vsdclient.delete_vms() called")
        if params['no_of_ports'] > 1:
            self._delete_nuage_vm_if(params)
        else:
            self._delete_nuage_vm(params)

    def delete_vm_by_external_id(self, params):
        req_params = {
            'externalID': params['externalID']
        }
        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }
        nuagevm = nuagelib.NuageVM(create_params=req_params,
                                   extra_params=extra_params)
        response = self.restproxy.get(
            nuagevm.get_resource(),
            extra_headers=nuagevm.extra_headers_get_by_externalID())
        if response:
            req_params = {
                'id': response[0]['ID']
            }
            vm = nuagelib.NuageVM(create_params=req_params,
                                  extra_params=extra_params)
            self.restproxy.delete(
                vm.delete_resource(),
                extra_headers=vm.extra_headers_delete())

    def delete_vm_by_id(self, params):
        req_params = {
            'id': params['id']
        }
        extra_params = {
            'tenant': params['tenant'],
            'net_partition_name': params['netpart_name']
        }
        vm = nuagelib.NuageVM(create_params=req_params,
                              extra_params=extra_params)
        self.restproxy.delete(
            vm.delete_resource(),
            extra_headers=vm.extra_headers_delete())

    def update_nuage_vm_vport(self, params):
        req_params = {
            'vport_id': params['nuage_vport_id'],
            'fip_id': params['nuage_fip_id']
        }
        nuagevport = nuagelib.NuageVPort(create_params=req_params)
        self.restproxy.put(nuagevport.put_resource(),
                           nuagevport.fip_update_data())

    def get_nuage_vm_if_by_vport_id(self, vport_id):
        req_params = {
            'vport_id': vport_id,
        }
        nuageif = nuagelib.NuageVMInterface(create_params=req_params)
        vm_interfaces = self.restproxy.get(nuageif.get_interface_for_vport())
        if vm_interfaces:
            return vm_interfaces[0]
        else:
            return

    def update_nuage_vm_if(self, params):
        req_params = {
            'vport_id': params['nuage_vport_id'],
        }
        nuageif = nuagelib.NuageVMInterface(create_params=req_params)
        vm_interfaces = self.restproxy.get(nuageif.get_interface_for_vport())
        if vm_interfaces:
            vm_interface = vm_interfaces[0]
            params = {
                'id': vm_interface['ID'],
                'mac': params['mac'],
                'ipv4': params['ipv4'],
                'ipv6': params['ipv6']
            }
            updated_if = nuagelib.NuageVMInterface(create_params=params)
            utils.retry_on_vsdclient_error(
                self.restproxy.put,
                vsd_error_codes=[(constants.CONFLICT_ERR_CODE,
                                  constants.VSD_VPORT_ATTACHED_NET_ID_CHANGED)]
            )(updated_if.delete_resource(), updated_if.put_data())

    def create_vport(self, params):
        type_class = {constants.SUBNET: nuagelib.NuageSubnet,
                      constants.L2DOMAIN: nuagelib.NuageL2Domain}
        vsd_subnet = params['vsd_subnet']
        vsd_parent = type_class[vsd_subnet['type']]()

        vport_params = {
            'port_id': params['port_id'],
            'type': 'VM',
            'name': params.get('name', params['port_id']),
            'externalID': get_vsd_external_id(params['port_id']),
            'description': params.get('description'),
            'addressSpoofing': params['address_spoof']
        }
        vsd_vport = self.restproxy.post(
            vsd_parent.vport_post(vsd_subnet['ID']),
            vsd_parent.vm_vport_post_data(vport_params))
        return vsd_vport[0]

    def nuage_vports_on_l2domain(self, l2dom_id):
        nuagel2dom = nuagelib.NuageL2Domain()
        vports = self.restproxy.get(nuagel2dom.get_all_vports(l2dom_id))
        return len(vports) > 0

    def nuage_vports_on_subnet(self, nuage_subnet_id):
        nuagesubnet = nuagelib.NuageSubnet()
        vports = self.restproxy.get(
            nuagesubnet.get_all_vports(nuage_subnet_id))
        return len(vports > 0)

    @staticmethod
    def _get_vip_action(key):
        return {
            # full cidr # dif mac # same ip # same subnet
            (0, 0, 0, 0): ACTION_MACSPOOFING,
            (0, 0, 0, 1): ACTION_MACSPOOFING,
            (0, 0, 1, 1): ACTION_MACSPOOFING,
            (0, 1, 0, 0): ACTION_MACSPOOFING,
            (0, 1, 0, 1): ACTION_MACSPOOFING,
            (0, 1, 1, 1): ACTION_MACSPOOFING,
            (1, 0, 0, 0): ACTION_NOVIP,
            (1, 0, 0, 1): ACTION_VIP,
            (1, 0, 1, 1): ACTION_NOVIP,
            (1, 1, 0, 0): ACTION_MACSPOOFING,
            (1, 1, 0, 1): ACTION_VIP,
            (1, 1, 1, 1): ACTION_MACSPOOFING,
        }.get(key, "error")

    @staticmethod
    def _log_no_vip_allowed(params, args):
        if args['key'] == (1, 0, 1, 1):
            LOG.warn("No VIP is created for ip %(vip)s and mac %(mac)s as "
                     "private ip %(ip)s is same as vip ip",
                     {'vip': params['vip'],
                      'mac': params['mac'],
                      'ip': params['port_ips']})
        elif args['key'] == (1, 0, 0, 0):
            LOG.warn("No VIP is created for vip %(vip)s and mac %(mac)s "
                     "as vip and private ip %(ip)s belong to different "
                     "subnets", {'vip': params['vip'],
                                 'mac': params['mac'],
                                 'ip': params['port_ips']})

    def _create_vip(self, params, args):
        if args['subn_type'] == constants.SUBNET:
            # Create VIP only for l3 subnet
            try:
                vip = self.create_vip_on_vport(params)
                if params['os_fip']:
                    self._add_os_fip_to_vip(params, vip)
            except restproxy.RESTProxyError as e:
                if e.vsd_code == constants.VSD_IP_IN_USE_ERR_CODE:
                    # Vip address already in use by other vminterface.
                    # Workaround by allowing source address spoofing.
                    LOG.warn("Could not create VIP as it's in use"
                             " by other VM interface, hence we will"
                             " enable MAC spoofing.")
                    return True
                elif e.code == constants.REST_SERV_INTERNAL_ERROR:
                    raise
            return False
        else:
            return True

    def _add_os_fip_to_vip(self, params, vip):
        os_fip = params['os_fip']
        vsd_fip = self.vsdclient.get_nuage_fip_by_id(os_fip['id'])
        if not vsd_fip:
            params = {
                'nuage_rtr_id': params['vsd_l3domain_id'],
                'nuage_fippool_id': os_fip['vsd_fip_subnet_id'],
                'neutron_fip_ip': os_fip.floating_ip_address,
                'neutron_fip_id': os_fip.id
            }
            vsd_fip_id = self.vsdclient.create_nuage_floatingip(
                params)
        else:
            vsd_fip_id = vsd_fip['ID']
        if vsd_fip_id:
            self._update_fip_to_vip(vip, vsd_fip_id)

    @staticmethod
    def get_net_size(netmask):
        binary_str = ''
        for octet in netmask:
            binary_str += bin(int(octet))[2:].zfill(8)
        return str(len(binary_str.rstrip('0')))

    @staticmethod
    def _check_cidr(params):
        ip = IPNetwork(params['vip'])
        if ip.size != 1:
            LOG.info("No VIP will be created for %s", str(ip.cidr))
            return False

        return True

    @staticmethod
    def _compare_ip(params):
        vip_addr = params['vip']
        if '/' in vip_addr:
            vip_ip = vip_addr.split('/')
            vip_addr = vip_ip[0]
        if IPNetwork(vip_addr) in [IPNetwork(ip) for ip in
                                   params['port_ips']]:
            LOG.info("No VIP will be created for %s as it is same as the"
                     "ip of the port", params['vip'])
            return True

        return False

    @staticmethod
    def _compare_mac(params):
        if params['mac'] == params['port_mac']:
            LOG.info("VIP mac %s is same as physical mac", params['port_mac'])
            return False

        return True

    def _get_subnet_type(self, params):
        nuage_subnet = params['vsd_subnet']

        if nuage_subnet['parentType'] == constants.ENTERPRISE:
            LOG.info("No VIP will be created for %(ip)s and %(mac)s",
                     {'ip': params['vip'],
                      'mac': params['mac']})
            return constants.L2DOMAIN
        else:
            return constants.SUBNET

    @staticmethod
    def _check_if_same_subnet(params):
        nuage_subnet = params['vsd_subnet']

        if not nuage_subnet.get('DHCPManaged', True):
            return True

        vip = IPNetwork(params['vip'])
        if vip.version == 6:
            if not nuage_subnet['IPv6Address']:
                return False
            subnet = IPNetwork(nuage_subnet['IPv6Address'])
        else:
            if not nuage_subnet['address']:
                return False
            subnet = IPNetwork('{}/{}'.format(nuage_subnet['address'],
                                              nuage_subnet['netmask']))
        return vip in subnet

    def process_vip(self, params):
        key, action = self._find_vip_action(params)

        # check if subnet is l2 or l3
        subn_type = self._get_subnet_type(params)
        args = {
            'key': key,
            'subn_type': subn_type
        }

        if action == ACTION_NOOP:
            LOG.warn("No action on VSD for vip with ip %(vip)s and mac %("
                     "mac)s", {'vip': params['vip'],
                               'mac': params['mac']})
        elif action == ACTION_MACSPOOFING:
            return True
        elif action == ACTION_VIP:
            return self._create_vip(params, args)
        elif action == ACTION_NOVIP:
            self._log_no_vip_allowed(params, args)
        else:
            msg = ("VIP creation not supported in VSD for ip %(vip)s and "
                   "mac %(mac)s", {'vip': params['vip'],
                                   'mac': params['mac']})
            LOG.error(msg)
            raise Exception(msg)
        return False

    def _find_vip_action(self, params):
        # check if it is a /32 ip
        full_cidr = self._check_cidr(params)

        # check if mac is diff from port mac
        diff_mac = self._compare_mac(params)

        # check if vip is same as private ip
        same_ip = self._compare_ip(params)

        # check if ip and vip are in same subnet
        same_subn = self._check_if_same_subnet(params)

        key = (full_cidr, diff_mac, same_ip, same_subn)
        action = self._get_vip_action(key)
        if action == ACTION_VIP and IPNetwork(params['vip']).version == 6:
            params['IPType'] = constants.IPV6
        LOG.debug("Key is %s and action is %s", key, action)
        return key, action

    def process_deleted_addr_pair(self, params):
        params['vsd_subnet'] = helper.get_nuage_subnet(
            self.restproxy, params['subnet_mapping'])
        _, action = self._find_vip_action(params)
        if action == ACTION_MACSPOOFING or action == ACTION_VIP:
            self.update_mac_spoofing_on_vport(params, constants.DISABLED)

    def update_mac_spoofing_on_vport(self, params, status):
        req_params = {'vport_id': params['vport_id']}
        extra_params = {'mac_spoofing': status}
        nuage_vport = nuagelib.NuageVPort(create_params=req_params,
                                          extra_params=extra_params)
        self.restproxy.put(nuage_vport.put_resource(),
                           nuage_vport.mac_spoofing_update_data())
        LOG.debug("MAC spoofing changed to %s on vport %s",
                  status, params['vport_id'])

    def create_vip_on_vport(self, params):
        req_params = {
            'vport_id': params['vport_id'],
            'externalID': get_vsd_external_id(params['externalID'])
        }

        extra_params = {
            'vip': params['vip'],
            'subnet': params['subnet_id'],
            'mac': params['mac']
        }

        if params.get('IPType') == constants.IPV6:
            extra_params['IPType'] = constants.IPV6
        else:
            extra_params['IPType'] = constants.IPV4

        nuage_vip = nuagelib.NuageVIP(create_params=req_params,
                                      extra_params=extra_params)
        vip = self.restproxy.post(nuage_vip.get_resource_for_vport(),
                                  nuage_vip.post_vip_data())[0]
        LOG.debug("VIP with ip %(vip)s and mac %(mac)s created for %(vport)s",
                  {'vip': params['vip'],
                   'mac': params['mac'],
                   'vport': params['vport_id']})
        return vip

    def get_vips_on_vport(self, vport_id):
        req_params = {
            'vport_id': vport_id
        }

        nuage_vip = nuagelib.NuageVIP(create_params=req_params)
        vips = self.restproxy.get(nuage_vip.get_resource_for_vport(),
                                  required=True)
        resp = []
        if vips:
            for vip in vips:
                ret = {
                    'vip': nuagelib.NuageVIP.get_ip_addr(vip),
                    'mac': nuagelib.NuageVIP.get_mac_addr(vip),
                    'vip_id': nuagelib.NuageVIP.get_vip_id(vip)
                }

                resp.append(ret)
        return resp

    def delete_vips(self, vport_id, vip_dict, vips):
        nuage_vips = self.get_vips_on_vport(vport_id)

        nuage_vip_dict = dict()
        for vip in vips:
            nuage_vip_dict[vip] = vip_dict[vip]

        for nuage_vip in nuage_vips:
            if nuage_vip['vip'] in nuage_vip_dict:
                req_params = {
                    'vip_id': nuage_vip['vip_id']
                }
                nuage_vip = nuagelib.NuageVIP(create_params=req_params)
                try:
                    self.restproxy.delete(nuage_vip.delete_resource())
                except restproxy.ResourceNotFoundException:
                    LOG.error("Error in deleting vip with ip %(vip)s and mac "
                              "%(mac)s", {'vip': nuage_vip['vip'],
                                          'mac': nuage_vip['mac']})
                    raise

    def get_vips(self, parent, parent_id, **filters):
        nuage_vip = nuagelib.NuageVIP()
        headers = nuage_vip.extra_header_filter(**filters)
        return self.restproxy.get(
            nuage_vip.get_child_resource(parent, parent_id),
            extra_headers=headers)

    def _get_vips_for_subnet(self, neutron_subnet, **filters):
        subnet = helper.get_domain_subnet_by_ext_id_and_cidr(self.restproxy,
                                                             neutron_subnet)
        return self.get_vips(nuagelib.NuageSubnet.resource,
                             subnet['ID'],
                             **filters)

    def _update_fip_to_vip(self, vip, vsd_fip_id):
        create_params = {'vip_id': vip['ID']}
        nuage_vip = nuagelib.NuageVIP(create_params=create_params)
        self.restproxy.put(nuage_vip.put_resource(),
                           {'associatedFloatingIPID': vsd_fip_id})

    def update_fip_to_vips(self, neutron_subnet, vip, vsd_fip_id):
        vip_list = self._get_vips_for_subnet(neutron_subnet,
                                             virtualIP=vip)
        for vip in vip_list:
            self._update_fip_to_vip(vip, vsd_fip_id)
