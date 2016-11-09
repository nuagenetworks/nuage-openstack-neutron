# Copyright 2016 Nuage Netowrks USA Inc.
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

from neutron.agent import l3_agent as entry
from neutron.i18n import _

from nuage_neutron.vpnaas.nuage_vpn_svc import NuageVPNService

from oslo_config import cfg

vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['nuage_neutron.vpnaas.device_drivers.driver.'
                 'NuageOpenSwanDriver'],
        help=_("The vpn device drivers Neutron will use")),
]
cfg.CONF.register_opts(vpn_agent_opts, 'vpnagent')


class NuageVPNAgent(object):
    """VPNAgent class which can handle vpn service drivers."""
    def __init__(self, host=None, conf=None):
        self.host = host
        self.conf = cfg.CONF
        self.service = NuageVPNService(self)
        self.device_drivers = self.service.load_device_drivers(host)

    def init_host(self):
        return self.host

    def periodic_tasks(self, ctx, raise_on_error=False):
        pass

    def after_start(self):
        pass

    def router_deleted(self, context, router_id):
        pass

    def routers_updated(self, context, routers):
        pass


def main():
    entry.main(manager='nuage_neutron.vpnaas.nuage_agent.NuageVPNAgent')
