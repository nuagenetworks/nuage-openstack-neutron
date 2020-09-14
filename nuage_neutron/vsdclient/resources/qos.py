# Copyright 2020 NOKIA
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
from nuage_neutron.vsdclient.common import constants
from nuage_neutron.vsdclient.common import nuagelib

LOG = logging.getLogger(__name__)


class NuageQos(object):

    def __init__(self, restproxy_serv):
        self.restproxy = restproxy_serv
        self.ratelimiter_obj = nuagelib.NuageRateLimiter()
        self.qos_obj = nuagelib.NuageQos()

    def _get_ratelimiter(self, ratelimiter_id):
        rl = self.restproxy.get(
            self.ratelimiter_obj.show_url() % ratelimiter_id)
        return rl[0] if rl else None

    def _create_ratelimiter(self, name, description, external_id,
                            peak_information_rate):
        post_data = {
            'peakInformationRate': peak_information_rate,
            'name': name,
            'description': description,
            'externalID': external_id,
            # Defaults
            'peakBurstSize': 100,
            'committedInformationRate': 0
        }
        return self.restproxy.post(
            self.ratelimiter_obj.post_url(),
            post_data)[0]

    def _update_ratelimiter(self, ratelimiter_id, peak_information_rate):
        self.restproxy.put(self.ratelimiter_obj.put_url() % ratelimiter_id,
                           {'peakInformationRate': peak_information_rate})

    def _delete_ratelimiter(self, ratelimiter_id):
        self.restproxy.delete(
            self.ratelimiter_obj.delete_url() % ratelimiter_id)

    def get_fip_qos(self, nuage_fip):
        qos_values = {}
        for os_direction, vsd_direction in constants.DIRECTIONS_OS_VSD.items():
            ratelimiter_id = nuage_fip['{}RateLimiterID'.format(
                vsd_direction)]
            if ratelimiter_id:
                ratelimiter = self._get_ratelimiter(ratelimiter_id)
                peakinformationrate = ratelimiter['peakInformationRate']
                # VSD is defined as mbps, OS as kbps
                qos_values[os_direction] = float(peakinformationrate) * 1000
            else:
                qos_values[os_direction] = -1

        return qos_values

    def create_update_fip_qos(self, neutron_fip, nuage_fip):
        fip_updates = {}
        ratelimiters_to_be_deleted = []
        for os_direction, vsd_direction in constants.DIRECTIONS_OS_VSD.items():
            existing_ratelimit = nuage_fip['{}RateLimiterID'.format(
                vsd_direction)]
            new_rate = neutron_fip['nuage_{}_fip_rate_kbps'.format(
                os_direction)]
            if new_rate is None:
                continue
            if float(new_rate) == -1:
                # remove fip rate limit if exists
                if existing_ratelimit:
                    ratelimiters_to_be_deleted.append(existing_ratelimit)
                    fip_updates['{}RateLimiterID'.format(vsd_direction)] = None
            else:
                # VSD is defined as mbps, OS as kbps
                new_rate = float(new_rate) / 1000
                if existing_ratelimit:
                    self._update_ratelimiter(existing_ratelimit, new_rate)
                else:
                    name = '{}_{}'.format(vsd_direction, neutron_fip['id'])
                    rl = self._create_ratelimiter(
                        name=name,
                        description='Openstack FIP Rate Limiter for FIP {}, '
                                    'vsd direction: {}.'.format(
                                        neutron_fip['id'], vsd_direction),
                        external_id=get_vsd_external_id(name),
                        peak_information_rate=new_rate)
                    fip_updates['{}RateLimiterID'.format(
                        vsd_direction)] = rl['ID']

        if fip_updates:
            floatingip = nuagelib.NuageFloatingIP(
                create_params={'domain_id'})
            self.restproxy.put(
                floatingip.put_resource() % nuage_fip['ID'], fip_updates)

        if ratelimiters_to_be_deleted:
            # We can only delete a rate limiter once it is no longer in use
            for ratelimiter in ratelimiters_to_be_deleted:
                self._delete_ratelimiter(ratelimiter)

    def delete_fip_qos(self, nuage_fip):
        fip_updates = {}
        ratelimiters_to_be_deleted = []
        for os_direction, vsd_direction in constants.DIRECTIONS_OS_VSD.items():
            existing_ratelimit = nuage_fip['{}RateLimiterID'.format(
                vsd_direction)]
            if existing_ratelimit:
                fip_updates['{}RateLimiterID'.format(vsd_direction)] = None
                ratelimiters_to_be_deleted.append(existing_ratelimit)

        if fip_updates:
            floatingip = nuagelib.NuageFloatingIP(
                create_params={'domain_id'})
            self.restproxy.put(
                floatingip.put_resource() % nuage_fip['ID'], fip_updates)

        if ratelimiters_to_be_deleted:
            # We can only delete a rate limiter once it is no longer in use
            for ratelimiter in ratelimiters_to_be_deleted:
                self._delete_ratelimiter(ratelimiter)

    def create_update_qos(self, parent_type, parent_id, qos_policy_id,
                          qos_policy_options, original_qos_policy_id=None):
        if parent_type == constants.L2DOMAIN:
            parent_type = nuagelib.NuageL2Domain.resource
        elif parent_type == constants.SUBNET:
            parent_type = nuagelib.NuageSubnet.resource
        elif parent_type == constants.VPORT:
            parent_type = nuagelib.NuageVPort.resource

        if original_qos_policy_id:
            # If there is already a QOS policy active on the resource
            # Delete it.
            self.delete_qos(parent_type, parent_id, original_qos_policy_id)
        if not qos_policy_options:
            return
        qos_data = {
            'name': 'OS_QOS_policy_' + qos_policy_id,
            'active': True,
            'commitedInformationRate': 0,
            'externalID': get_vsd_external_id(qos_policy_id)
        }
        qos_data.update(qos_policy_options)
        self.restproxy.post(
            self.qos_obj.post_url(parent=parent_type, parent_id=parent_id),
            qos_data)

    def bulk_update_existing_qos(self, qos_policy_id, qos_policy_options):
        # find all existing QOS objects
        filters = {'externalID': get_vsd_external_id(qos_policy_id)}
        qoss = self.restproxy.get(
            self.qos_obj.get_url(),
            extra_headers=self.qos_obj.extra_header_filter(**filters))
        if not qoss:
            return
        updates = [{'ID': qos['ID']} for qos in qoss]
        for update in updates:
            update.update(qos_policy_options)

        self.restproxy.bulk_put(self.qos_obj.get_url() + '?responseChoice=1',
                                updates)

    def delete_qos(self, parent_type, parent_id, qos_policy_id):

        qos_resource = nuagelib.NuageQos()
        filters = {'externalID': get_vsd_external_id(qos_policy_id)}
        qos = self.restproxy.get(
            qos_resource.get_url(parent=parent_type, parent_id=parent_id),
            extra_headers=qos_resource.extra_header_filter(**filters))
        if qos:
            self.restproxy.delete(
                qos_resource.delete_url() % qos[0]['ID'])
