# Copyright 2017 NOKIA
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

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

LOG = logging.getLogger(__name__)

OS_TRUNK_STATE_TO_VSD = {
    True: 'UP',
    False: 'DOWN'
}


def copy(value):
    return value


class NuageTrunkBase(object):

    def __init__(self, restproxy):
        super(NuageTrunkBase, self).__init__()
        self.restproxy = restproxy

    def _get_by_openstack_id(self, resource, id, parent=None, parent_id=None,
                             required=False):
        external_id = get_vsd_external_id(id)
        objects = self.get(resource, parent=parent, parent_id=parent_id,
                           externalID=external_id)
        if not objects and required:
            raise restproxy.ResourceNotFoundException(
                "Can not find %s with externalID %s on vsd"
                % (resource.resource, external_id))
        return objects[0] if objects else None

    def get(self, resource, parent=None, parent_id=None, **filters):
        headers = resource.extra_header_filter(**filters)
        return self.restproxy.get(
            resource.get_url(parent=parent, parent_id=parent_id),
            extra_headers=headers)

    def post(self, resource, data, extra_headers=None, on_res_exists=None,
             parent=None, parent_id=None):
        if on_res_exists is None:
            on_res_exists = self.restproxy.retrieve_by_external_id
        return self.restproxy.post(
            resource.post_url(parent=parent, parent_id=parent_id),
            data, extra_headers=extra_headers, on_res_exists=on_res_exists)[0]

    def put(self, resource, id, data, extra_headers=None):
        return self.restproxy.put(resource.put_url() % id, data,
                                  extra_headers=extra_headers)

    def delete(self, resource, id, extra_headers=None):
        return self.restproxy.delete(resource.delete_url() % id,
                                     extra_headers=extra_headers)


class NuageTrunk(NuageTrunkBase):

    trunk_obj = nuagelib.Trunk()
    trunkport_obj = nuagelib.TrunkPort()
    trunkinterface_obj = nuagelib.TrunkInterface()

    os_trunk_to_vsd_trunk = {
        'name': [('description', copy)],
        # TODO(gridinv): VSP team decided not to support it in initial release
        # not sure if we plan to support it ever
        # 'admin_state_up': [('trunkStatus',
        #                     lambda x: OS_TRUNK_STATE_TO_VSD[x])],
        'id': [('externalID', lambda x: get_vsd_external_id(x))]
    }

    os_subport_to_vsd_vport = {
        'segmentation_id': [('segmentationID', copy)],
        'segmentation_type': [('segmentationType', lambda x: x.upper())]
    }

    params_to_vm_interface = {
        'ipv4': [('IPAddress', copy)],
        'ipv6': [('IPv6Address', copy)],
        'mac': [('MAC', copy)],
        'id': [('externalID', lambda x: get_vsd_external_id(x))],
    }

    def do_mapping(self, mapping, object):
        result = {}
        for key in object:
            if key in mapping and key in object:
                for attr_mapping in mapping[key]:
                    result_key, method = attr_mapping
                    result[result_key] = method(object[key])
        return result

    def map_trunk_os_to_vsd(self, os_trunk):
        return self.do_mapping(self.os_trunk_to_vsd_trunk, os_trunk)

    def map_subport_to_vsd_vport(self, subport):
        return self.do_mapping(self.os_subport_to_vsd_vport, subport)

    def map_port_to_interface(self, params):
        return self.do_mapping(self.params_to_vm_interface, params)

    # Trunk

    def create_trunk(self, os_trunk, subnet_mapping):
        ent_id = subnet_mapping.get('net_partition_id')
        data = self.map_trunk_os_to_vsd(os_trunk)
        data['associatedVPortID'] = subnet_mapping.get('nuage_vport_id')
        data['name'] = os_trunk['id']
        self.post(self.trunk_obj, data, parent='enterprises', parent_id=ent_id)

    def delete_trunk(self, os_trunk, subnet_mapping):
        ent_id = subnet_mapping.get('net_partition_id')
        vsd_trunk = self._get_by_openstack_id(self.trunk_obj, os_trunk.id,
                                              parent='enterprises',
                                              parent_id=ent_id)
        if vsd_trunk:
            self.delete(self.trunk_obj, vsd_trunk['ID'])

    # TrunkPort
    def add_subport(self, os_trunk_id, subport, vport_id, params):
        vsd_trunk = self._get_by_openstack_id(
            self.trunk_obj, os_trunk_id,
            parent='enterprises',
            parent_id=params['net_partition_id'])

        data = self.map_subport_to_vsd_vport(subport)
        data['associatedTrunkID'] = vsd_trunk.get('ID')
        self.put(self.trunkport_obj, vport_id, data)
        self.add_subport_interface(vport_id, params)

    def remove_subport(self, os_port, vport):
        self.remove_subport_interface(os_port, vport)
        data = {'associatedTrunkID': None}
        self.put(self.trunkport_obj, vport['ID'], data)

    def update_subport(self, os_port, vport, params):
        vm_interface = self._get_by_openstack_id(self.trunkinterface_obj,
                                                 os_port['id'],
                                                 parent='vports',
                                                 parent_id=vport.get('ID'))
        if vm_interface:
            data = self.map_port_to_interface(params)
            self.put(self.trunkinterface_obj, vm_interface.get('ID'), data)

    # TrunkInterface
    def add_subport_interface(self, nuage_vport_id, params):

        data = self.map_port_to_interface(params)
        data['VPortID'] = nuage_vport_id
        self.post(self.trunkinterface_obj, data,
                  parent='vports',
                  parent_id=nuage_vport_id)

    def remove_subport_interface(self, os_port, vport):
        vm_interface = self._get_by_openstack_id(self.trunkinterface_obj,
                                                 os_port['id'],
                                                 parent='vports',
                                                 parent_id=vport.get('ID'))
        if vm_interface:
            self.delete(self.trunkinterface_obj, vm_interface['ID'])
