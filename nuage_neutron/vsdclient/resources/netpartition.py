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
import logging.handlers

from nuage_neutron.plugins.common import constants

from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.common import helper
from nuage_neutron.vsdclient.common import nuagelib
from nuage_neutron.vsdclient import restproxy

DEF_L3DOM_TEMPLATE_PFIX = constants.DEF_L3DOM_TEMPLATE_PFIX
DEF_L2DOM_TEMPLATE_PFIX = constants.DEF_L2DOM_TEMPLATE_PFIX
SHARED_INFRASTRUCTURE = constants.SHARED_INFRASTRUCTURE
SHARED_DOMAIN_TEMPLATE = constants.SHARED_DOMAIN_TEMPLATE


class NuageNetPartition(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy

    def link_default_netpartition(self, params):
        nuagenet_partition = nuagelib.NuageNetPartition(create_params=params)
        nuage_ent_extra_headers = nuagenet_partition.extra_headers_get()
        enterprise = self.restproxy.get(nuagenet_partition.get_resource(),
                                        extra_headers=nuage_ent_extra_headers,
                                        required=True)
        np_id = enterprise['ID']
        l3dom_id = helper.get_l3domid_for_netpartition(self.restproxy, np_id,
                                                       params['l3template'])
        l2dom_id = helper.get_l2domid_for_netpartition(self.restproxy, np_id,
                                                       params['l2template'])
        return np_id, l3dom_id, l2dom_id

    def create_net_partition(self, params):
        nuagenet_partition = nuagelib.NuageNetPartition(create_params=params)
        enterprise = self.restproxy.post(nuagenet_partition.post_resource(),
                                         nuagenet_partition.post_data())[0]
        net_partition_dict = {'np_id': enterprise['ID']}

        l3_tmplt_name = params['name'] + DEF_L3DOM_TEMPLATE_PFIX
        l3dom_tid = self._create_default_l3template_for_netpart(
            net_partition_dict['np_id'], l3_tmplt_name)
        net_partition_dict['l3dom_tid'] = l3dom_tid

        l2_tmplt_name = params['name'] + DEF_L2DOM_TEMPLATE_PFIX
        l2dom_tid = self._create_default_l2template_for_netpart(
            net_partition_dict['np_id'], l2_tmplt_name)
        net_partition_dict['l2dom_tid'] = l2dom_tid

        return net_partition_dict

    def delete_net_partition(self, id):
        nuagenet_partition = nuagelib.NuageNetPartition(
            create_params={"netpart_id": id})
        try:
            enterprise = self.restproxy.get(
                nuagenet_partition.get_resource_by_id(),
                required=True)[0]
        except restproxy.RESTProxyError as e:
            if e.code != constants.RES_NOT_FOUND:
                raise restproxy.RESTProxyError(nuagenet_partition.error_msg)
            return

        external_id = enterprise.get('externalID')
        if external_id and external_id.endswith('@openstack'):
            nuagenet_partition = nuagelib.NuageNetPartition()
            self.restproxy.delete(nuagenet_partition.delete_resource(id))
        else:
            logging.warning("Enterprise {} is not deleted!".format(
                enterprise['name']))

    def _create_default_l3template_for_netpart(self, np_id, name):
        req_params = {
            'net_partition_id': np_id,
            'name': name
        }
        extra_params = {
            'externalID': np_id + '@openstack'
        }
        nuagel3domtemplate = nuagelib.NuageL3DomTemplate(
            create_params=req_params,
            extra_params=extra_params)
        l3_dom_temp = self.restproxy.post(nuagel3domtemplate.post_resource(),
                                          nuagel3domtemplate.post_data())[0]
        l3dom_tid = l3_dom_temp['ID']
        isolated_zone_name = constants.DEF_NUAGE_ZONE_PREFIX + '-' + l3dom_tid
        params = {
            'name': isolated_zone_name,
            'l3domain_id': l3dom_tid
        }
        nuagezonetemplate = nuagelib.NuageZoneTemplate(
            create_params=params,
            extra_params=extra_params)
        self.restproxy.post(nuagezonetemplate.post_resource(),
                            nuagezonetemplate.post_data())
        shared_zone_name = (constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' +
                            l3dom_tid)
        nuagezonetemplate.create_params['name'] = shared_zone_name
        self.restproxy.post(nuagezonetemplate.post_resource(),
                            nuagezonetemplate.post_data())
        return l3dom_tid

    def _create_default_l2template_for_netpart(self, np_id, name):
        req_params = {
            'net_partition_id': np_id,
            'name': name
        }
        extra_params = {
            'externalID': np_id + '@openstack'
        }
        nuagel2domtemplate = nuagelib.NuageL2DomTemplate(
            create_params=req_params,
            extra_params=extra_params)
        l2_dom_temp = self.restproxy.post(nuagel2domtemplate.post_resource(),
                                          nuagel2domtemplate.post_data())[0]
        return l2_dom_temp['ID']

    def get_net_partitions(self):
        netpartition = nuagelib.NuageNetPartition()
        enterprises = self.restproxy.get(netpartition.get_resource(),
                                         required=True)
        res = []
        for enterprise in enterprises:
            np_dict = dict()
            np_dict['net_partition_name'] = enterprise['name']
            np_dict['net_partition_id'] = enterprise['ID']
            res.append(np_dict)
        return res

    def get_netpartition_by_name(self, name):
        req_params = {
            'name': name
        }
        netpartition = nuagelib.NuageNetPartition(create_params=req_params)
        nuage_ent_extra_headers = netpartition.extra_headers_get()
        enterprises = self.restproxy.get(netpartition.get_resource(),
                                         extra_headers=nuage_ent_extra_headers)
        if enterprises:
            netpartition = enterprises[0]
            return {
                'id': netpartition['ID'],
                'name': netpartition['name'],
                'description': netpartition['description'],
                'neutron_id': netpartition['externalID'],
            }

    def get_netpartition_data(self, ent_name):
        req_params = {
            'name': ent_name
        }
        nuagenet_partition = nuagelib.NuageNetPartition(
            create_params=req_params)
        nuage_ent_extra_headers = nuagenet_partition.extra_headers_get()
        enterprises = self.restproxy.get(nuagenet_partition.get_resource(),
                                         extra_headers=nuage_ent_extra_headers)
        if enterprises:
            np_id = enterprises[0]['ID']
            if ent_name == SHARED_INFRASTRUCTURE:
                l3dom_tname = SHARED_DOMAIN_TEMPLATE
                l3dom_id = helper.get_l3domid_for_netpartition(self.restproxy,
                                                               np_id,
                                                               l3dom_tname)
                nuage_netpart_data = {
                    'l2dom_tid': None
                }
            else:
                l3dom_tname = ent_name + DEF_L3DOM_TEMPLATE_PFIX
                l3dom_id = helper.get_l3domid_for_netpartition(self.restproxy,
                                                               np_id,
                                                               l3dom_tname)
                if not l3dom_id:
                    l3dom_id = self._create_default_l3template_for_netpart(
                        np_id, l3dom_tname)
                l2dom_tname = ent_name + DEF_L2DOM_TEMPLATE_PFIX
                l2dom_id = helper.get_l2domid_for_netpartition(self.restproxy,
                                                               np_id,
                                                               l2dom_tname)
                if not l2dom_id:
                    l2dom_id = self._create_default_l2template_for_netpart(
                        np_id, l2dom_tname)
                nuage_netpart_data = {
                    'l2dom_tid': l2dom_id
                }
            nuage_netpart_data['np_id'] = np_id
            nuage_netpart_data['l3dom_tid'] = l3dom_id
            return nuage_netpart_data
        else:
            return None

    def get_net_partition_name_by_id(self, ent_id):
        create_params = {'netpart_id': ent_id}
        nuage_net_partition = nuagelib.NuageNetPartition(create_params)
        enterprises = self.restproxy.get(
            nuage_net_partition.get_resource_by_id())
        return enterprises[0]['name'] if enterprises else None

    def get_nuage_fip_by_id(self, neutron_fip_id):
        req_params = {
            'externalID': get_vsd_external_id(neutron_fip_id)
        }
        nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
        nuage_extra_headers = nuage_fip.extra_headers()

        fips = self.restproxy.get(nuage_fip.get_resource(),
                                  extra_headers=nuage_extra_headers,
                                  required=True)
        return fips[0] if fips else None

    def get_nuage_fip_pool_by_id(self, nuage_subnet_id):
        nuage_fip_pool = nuagelib.NuageSubnet()
        response = self.restproxy.get(nuage_fip_pool.get_resource(
            nuage_subnet_id))
        if response:
            ret = {'nuage_fip_pool_id': response[0]['ID']}
            return ret
        else:
            return None
