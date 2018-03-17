# Copyright 2018 NOKIA
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

from neutron.db import agents_db
from neutron.db.common_db_mixin import CommonDbMixin
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import securitygroups_db as sg_db

from neutron_lib.plugins.ml2 import api
from neutron_lib.services import base as service_base

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import externalsg
from nuage_neutron.plugins.common import gateway


class NuageML2Wrapper(base_plugin.RootNuagePlugin,
                      api.MechanismDriver,
                      db_base_plugin_v2.NeutronDbPluginV2,
                      agents_db.AgentDbMixin):

    def __init__(self):
        super(NuageML2Wrapper, self).__init__()


class NuageApiWrapper(base_plugin.BaseNuagePlugin,
                      service_base.ServicePluginBase,
                      externalsg.NuageexternalsgMixin,
                      gateway.NuagegatewayMixin,
                      sg_db.SecurityGroupDbMixin):

    def __init__(self):
        super(NuageApiWrapper, self).__init__()


class NuageL3Wrapper(base_plugin.BaseNuagePlugin,
                     service_base.ServicePluginBase,
                     CommonDbMixin,
                     extraroute_db.ExtraRoute_db_mixin,
                     l3_gwmode_db.L3_NAT_db_mixin):
    def __init__(self):
        super(NuageL3Wrapper, self).__init__()
