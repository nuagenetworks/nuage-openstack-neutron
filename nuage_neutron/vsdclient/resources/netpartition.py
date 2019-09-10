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
        response = self.restproxy.rest_call(
            'GET', nuagenet_partition.get_resource(),
            '', extra_headers=nuage_ent_extra_headers)
        if not nuagenet_partition.validate(response):
            raise nuagenet_partition.get_rest_proxy_error()
        np_id = nuagenet_partition.get_net_partition_id(response)

        l3dom_id = \
            helper.get_l3domid_for_netpartition(self.restproxy, np_id,
                                                params['l3template'])
        l2dom_id = \
            helper.get_l2domid_for_netpartition(self.restproxy, np_id,
                                                params['l2template'])
        return (np_id, l3dom_id, l2dom_id)

    def set_external_id_for_netpart_rel_elems(self, net_partition_dict):
        # set external-ID for Enterprise on VSD.
        params = {"netpart_id": net_partition_dict['np_id']}
        nuagenet_partition = nuagelib.NuageNetPartition(create_params=params)
        response = helper.set_external_id_with_openstack(
            self.restproxy, nuagenet_partition.get_resource_by_id(),
            net_partition_dict['np_id'])
        if not nuagenet_partition.validate(response):
            raise nuagenet_partition.get_rest_proxy_error()

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
        resp = self.restproxy.rest_call(
            'GET', nuagenet_partition.get_resource_by_id(), '')
        if not nuagenet_partition.validate(resp):
            if resp[0] != constants.RES_NOT_FOUND:
                raise nuagenet_partition.get_rest_proxy_error()
            else:
                return
        details_on_nuage = nuagenet_partition.get_response_obj(resp)
        if details_on_nuage.get('externalID') == id + '@openstack':
            nuagenet_partition = nuagelib.NuageNetPartition()
            response = self.restproxy.rest_call(
                'DELETE', nuagenet_partition.delete_resource(id), '')
            if not nuagenet_partition.validate(response):
                raise nuagenet_partition.get_rest_proxy_error()

    def _create_default_l3template_for_netpart(self, np_id, name):
        req_params = {
            'net_partition_id': np_id,
            'name': name
        }
        extra_params = {
            'externalID': np_id + '@openstack'
        }
        nuagel3domtemplate = \
            nuagelib.NuageL3DomTemplate(create_params=req_params,
                                        extra_params=extra_params)
        response = self.restproxy.rest_call('POST',
                                            nuagel3domtemplate.post_resource(),
                                            nuagel3domtemplate.post_data())
        if not nuagel3domtemplate.validate(response):
            raise nuagel3domtemplate.get_rest_proxy_error()
        l3dom_tid = nuagel3domtemplate.get_templateid(response)
        isolated_zone_name = constants.DEF_NUAGE_ZONE_PREFIX + '-' + l3dom_tid
        params = {
            'name': isolated_zone_name,
            'l3domain_id': l3dom_tid
        }
        nuagezonetemplate = nuagelib.NuageZoneTemplate(
            create_params=params,
            extra_params=extra_params)
        self.restproxy.rest_call('POST',
                                 nuagezonetemplate.post_resource(),
                                 nuagezonetemplate.post_data())
        if not nuagezonetemplate.validate(response):
            raise nuagezonetemplate.get_rest_proxy_error()

        shared_zone_name = (constants.DEF_NUAGE_ZONE_PREFIX + '-pub-' +
                            l3dom_tid)
        nuagezonetemplate.create_params['name'] = shared_zone_name
        self.restproxy.rest_call('POST',
                                 nuagezonetemplate.post_resource(),
                                 nuagezonetemplate.post_data())
        if not nuagezonetemplate.validate(response):
            raise nuagezonetemplate.get_rest_proxy_error()
        return l3dom_tid

    def _create_default_l2template_for_netpart(self, np_id, name):
        req_params = {
            'net_partition_id': np_id,
            'name': name
        }
        extra_params = {
            'externalID': np_id + '@openstack'
        }
        nuagel2domtemplate = \
            nuagelib.NuageL2DomTemplate(create_params=req_params,
                                        extra_params=extra_params)
        response = self.restproxy.rest_call('POST',
                                            nuagel2domtemplate.post_resource(),
                                            nuagel2domtemplate.post_data())
        if not nuagel2domtemplate.validate(response):
            raise nuagel2domtemplate.get_rest_proxy_error()
        return nuagel2domtemplate.get_templateid(response)

    def get_net_partitions(self):
        netpartition = nuagelib.NuageNetPartition()
        response = self.restproxy.rest_call(
            'GET', netpartition.get_resource(), '')
        if not netpartition.validate(response):
            raise netpartition.get_rest_proxy_error()
        res = []
        for netpart in netpartition.get_response_objlist(response):
            np_dict = dict()
            np_dict['net_partition_name'] = netpart['name']
            np_dict['net_partition_id'] = netpart['ID']
            res.append(np_dict)
        return res

    def get_netpartition_by_name(self, name):
        req_params = {
            'name': name
        }
        netpartition = nuagelib.NuageNetPartition(create_params=req_params)
        nuage_ent_extra_headers = netpartition.extra_headers_get()
        response = self.restproxy.rest_call(
            'GET', netpartition.get_resource(),
            '', extra_headers=nuage_ent_extra_headers)
        if netpartition.get_validate(response):
            netpartition = netpartition.get_response_obj(response)
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
        response = self.restproxy.rest_call(
            'GET', nuagenet_partition.get_resource(),
            '', extra_headers=nuage_ent_extra_headers)
        if nuagenet_partition.get_validate(response):
            np_id = nuagenet_partition.get_net_partition_id(response)
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
        response = self.restproxy.rest_call(
            'GET', nuage_net_partition.get_resource_by_id(), '')
        if nuage_net_partition.get_validate(response):
            name = nuage_net_partition.get_response_obj(response)['name']
            return name

    def _is_first_netpartition(self):
        nuagenet_partition = nuagelib.NuageNetPartition()
        response = self.restproxy.rest_call('GET',
                                            nuagenet_partition.get_resource(),
                                            '')
        if nuagenet_partition.validate(response) and response[3] == '':
            return True
        return False

    def get_nuage_fip_by_id(self, params):
        req_params = {
            'externalID': get_vsd_external_id(params['fip_id'])
        }
        nuage_fip = nuagelib.NuageFloatingIP(create_params=req_params)
        nuage_extra_headers = nuage_fip.extra_headers()

        response = self.restproxy.rest_call(
            'GET', nuage_fip.get_resource(),
            '',
            extra_headers=nuage_extra_headers)

        if not nuage_fip.validate(response):
            raise nuage_fip.get_rest_proxy_error()

        ret = None
        if len(response[3]) > 0:
            ret = {
                'nuage_fip_id': response[3][0]['ID'],
                'nuage_assigned': response[3][0]['assigned']
            }
        return ret

    def get_nuage_fip_pool_by_id(self, net_id):
        req_params = {
            'externalID': get_vsd_external_id(net_id)
        }
        nuage_fip_pool = nuagelib.NuageSubnet(create_params=req_params)
        response = self.restproxy.get(
            nuage_fip_pool.get_resource_with_ext_id(),
            extra_headers=nuage_fip_pool.extra_headers_get())
        if response:
            ret = {'nuage_fip_pool_id': response[0]['ID']}
            return ret
        else:
            return None

    def set_fip_quota_at_ent_profile(self, fip_quota):
        if self._is_first_netpartition():
            nuage_ent_profile = nuagelib.NuageEntProfile()
            response = self.restproxy.rest_call(
                'GET',
                nuage_ent_profile.get_resource(),
                '')
            if nuage_ent_profile.validate(response):
                if response[3][0]['name'] == "Default Enterprise Profile":
                    self.restproxy.rest_call(
                        'PUT',
                        nuage_ent_profile.get_resource_by_id(
                            response[3][0]['ID']),
                        nuage_ent_profile.post_fip_quota(fip_quota))
        else:
            logging.warning("FIP Quota already set at the Enterprise Profile "
                            "Level")
