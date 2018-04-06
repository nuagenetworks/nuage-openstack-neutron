# (C) Nokia 2018
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


class ExperimentalFeatures(object):
    def __init__(self):
        pass

    # set of experimental features which can be dynamically enabled

    # -- None for now =-


class Capabilities(object):
    def __init__(self):
        pass

    # list of capabilities
    BRIDGED_NETWORKS = 1

    by_port_vnic_type = {
        'normal': {
            BRIDGED_NETWORKS: True
        },
        'direct': {
            BRIDGED_NETWORKS: True
        },
        'baremetal': {
            BRIDGED_NETWORKS: False
        }
    }
