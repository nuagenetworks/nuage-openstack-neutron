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

from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import portbindings_db
from neutron.db import portsecurity_db_common as ps_db_common
from neutron.db import securitygroups_db as sg_db

from neutron_lib import constants as lib_constants

from nuage_neutron.plugins.common import addresspair
from nuage_neutron.plugins.common import gateway
from nuage_neutron.plugins.common import port_dhcp_options
from nuage_neutron.plugins.common.time_tracker import TimeTracker
from nuage_neutron.plugins.nuage import externalsg


class NuageCoreWrapper(port_dhcp_options.PortDHCPOptionsNuage,
                       addresspair.NuageAddressPair,
                       db_base_plugin_v2.NeutronDbPluginV2,
                       addr_pair_db.AllowedAddressPairsMixin,
                       external_net_db.External_net_db_mixin,
                       extraroute_db.ExtraRoute_db_mixin,
                       l3_gwmode_db.L3_NAT_db_mixin,
                       gateway.NuagegatewayMixin,
                       externalsg.NuageexternalsgMixin,
                       sg_db.SecurityGroupDbMixin,
                       portbindings_db.PortBindingMixin,
                       ps_db_common.PortSecurityDbCommon,
                       extradhcpopt_db.ExtraDhcpOptMixin,
                       agentschedulers_db.AgentSchedulerDbMixin):

    def __init__(self):
        super(NuageCoreWrapper, self).__init__()

    @TimeTracker.untracked
    def get_port(self, context, id, fields=None):
        return super(NuageCoreWrapper, self).get_port(
            context, id, fields)

    @TimeTracker.untracked
    def delete_port(self, context, id):
        super(NuageCoreWrapper, self).delete_port(context, id)

    @TimeTracker.untracked
    def _delete_port_security_group_bindings(self, context, port_id):
        super(NuageCoreWrapper,
              self)._delete_port_security_group_bindings(context, port_id)

    @TimeTracker.untracked
    def get_ports_count(self, context, filters=None):
        return super(NuageCoreWrapper, self).get_ports_count(context, filters)

    @TimeTracker.untracked
    def update_network(self, context, id, network):
        return super(NuageCoreWrapper, self).update_network(context, id,
                                                            network)

    @TimeTracker.untracked
    def delete_network(self, context, id):
        super(NuageCoreWrapper, self).delete_network(context, id)

    @TimeTracker.untracked
    def create_subnet(self, context, subnet):
        return super(NuageCoreWrapper, self).create_subnet(
            context, subnet)

    @TimeTracker.untracked
    def create_port(self, context, port):
        return super(NuageCoreWrapper, self).create_port(context, port)

    @TimeTracker.untracked
    def delete_subnet(self, context, id):
        super(NuageCoreWrapper, self).delete_subnet(context, id)

    @TimeTracker.untracked
    def get_subnet(self, context, id, fields=None):
        return super(NuageCoreWrapper, self).get_subnet(context, id, fields)

    @TimeTracker.untracked
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        return super(NuageCoreWrapper, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @TimeTracker.untracked
    def update_subnet(self, context, id, subnet):
        return super(NuageCoreWrapper, self).update_subnet(
            context, id, subnet)

    @TimeTracker.untracked
    def add_router_interface(self, context, router_id, interface_info):
        return super(NuageCoreWrapper, self).add_router_interface(
            context, router_id, interface_info)

    @TimeTracker.untracked
    def remove_router_interface(self, context, router_id, interface_info):
        return super(NuageCoreWrapper,
                     self).remove_router_interface(
            context, router_id, interface_info)

    @TimeTracker.untracked
    def _get_port(self, context, id):
        return super(NuageCoreWrapper, self)._get_port(context, id)

    @TimeTracker.untracked
    def get_router(self, context, id, fields=None):
        return super(NuageCoreWrapper, self).get_router(context, id, fields)

    @TimeTracker.untracked
    def create_router(self, context, router):
        return super(NuageCoreWrapper, self).create_router(context, router)

    @TimeTracker.untracked
    def delete_router(self, context, id):
        super(NuageCoreWrapper, self).delete_router(context, id)

    @TimeTracker.untracked
    def update_router(self, context, id, router):
        return super(NuageCoreWrapper, self).update_router(
            context, id, router)

    @TimeTracker.untracked
    def get_floatingip(self, context, id, fields=None):
        return super(NuageCoreWrapper, self).get_floatingip(context, id)

    @TimeTracker.untracked
    def create_floatingip(self, context, floatingip,
                          initial_status=lib_constants.
                          FLOATINGIP_STATUS_ACTIVE):
        return super(NuageCoreWrapper, self).create_floatingip(
            context, floatingip, initial_status)

    @TimeTracker.untracked
    def delete_floatingip(self, context, id):
        super(NuageCoreWrapper, self).delete_floatingip(context, id)

    @TimeTracker.untracked
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        return super(NuageCoreWrapper, self).disassociate_floatingips(
            context, port_id, do_notify)

    @TimeTracker.untracked
    def update_floatingip(self, context, id, floatingip):
        return super(NuageCoreWrapper, self).update_floatingip(
            context, id, floatingip)

    @TimeTracker.untracked
    def delete_security_group(self, context, id):
        super(NuageCoreWrapper, self).delete_security_group(context, id)

    @TimeTracker.untracked
    def create_security_group_rule(self, context, security_group_rule):
        return super(NuageCoreWrapper, self).create_security_group_rule(
            context, security_group_rule)

    @TimeTracker.untracked
    def delete_security_group_rule(self, context, id):
        super(NuageCoreWrapper, self).delete_security_group_rule(context, id)
