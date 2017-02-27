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

CMS_ID = None


def get_vsd_external_id(neutron_id):
    if neutron_id and '@' not in neutron_id and CMS_ID:
        return neutron_id + '@' + CMS_ID
    return neutron_id


def strip_cms_id(external_id):
    return external_id.split('@')[0] if external_id else external_id


def extra_headers_get():
    return {
        'X-NUAGE-FilterType': "predicate",
        'X-Nuage-Filter': "externalID ENDSWITH '@%s'" % CMS_ID
    }
