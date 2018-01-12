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

from neutron.plugins.ml2 import driver_api as api

from neutron_lib import constants as lib_constants
from neutron_lib.services import base as service_base

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import externalsg
from nuage_neutron.plugins.common import gateway
from nuage_neutron.plugins.common.time_tracker import TimeTracker


class NuageML2Wrapper(base_plugin.RootNuagePlugin,
                      api.MechanismDriver,
                      db_base_plugin_v2.NeutronDbPluginV2,
                      agents_db.AgentDbMixin):

    def __init__(self):
        super(NuageML2Wrapper, self).__init__()

    @TimeTracker.untracked
    def get_port(self, context, id, fields=None):
        super(NuageML2Wrapper, self).get_port(context, id, fields)

    @TimeTracker.untracked
    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        return super(NuageML2Wrapper, self).get_ports(context, filters, fields,
                                                      sorts, limit, marker,
                                                      page_reverse)

    @TimeTracker.untracked
    def delete_port(self, context, id):
        super(NuageML2Wrapper, self).delete_port(context, id)

    @TimeTracker.untracked
    def get_ports_count(self, context, filters=None):
        return super(NuageML2Wrapper, self).get_ports_count(context, filters)

    @TimeTracker.untracked
    def update_network(self, context, id, network):
        return super(NuageML2Wrapper, self).update_network(context, id,
                                                           network)

    @TimeTracker.untracked
    def delete_network(self, context, id):
        super(NuageML2Wrapper, self).delete_network(context, id)

    @TimeTracker.untracked
    def create_subnet(self, context, subnet):
        return super(NuageML2Wrapper, self).create_subnet(
            context, subnet)

    @TimeTracker.untracked
    def create_port(self, context, port):
        return super(NuageML2Wrapper, self).create_port(context, port)

    @TimeTracker.untracked
    def delete_subnet(self, context, id):
        super(NuageML2Wrapper, self).delete_subnet(context, id)

    @TimeTracker.untracked
    def get_subnet(self, context, id, fields=None):
        return super(NuageML2Wrapper, self).get_subnet(context, id, fields)

    @TimeTracker.untracked
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        return super(NuageML2Wrapper, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @TimeTracker.untracked
    def update_subnet(self, context, id, subnet):
        return super(NuageML2Wrapper, self).update_subnet(
            context, id, subnet)

    @TimeTracker.untracked
    def _get_port(self, context, id):
        return super(NuageML2Wrapper, self)._get_port(context, id)


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

    @TimeTracker.untracked
    def add_router_interface(self, context, router_id, interface_info):
        return super(NuageL3Wrapper, self).add_router_interface(
            context, router_id, interface_info)

    @TimeTracker.untracked
    def remove_router_interface(self, context, router_id, interface_info):
        return super(NuageL3Wrapper, self).remove_router_interface(
            context, router_id, interface_info)

    @TimeTracker.untracked
    def get_router(self, context, id, fields=None):
        return super(NuageL3Wrapper, self).get_router(
            context, id, fields)

    @TimeTracker.untracked
    def create_router(self, context, router):
        return super(NuageL3Wrapper, self).create_router(
            context, router)

    @TimeTracker.untracked
    def delete_router(self, context, id):
        super(NuageL3Wrapper, self).delete_router(context, id)

    @TimeTracker.untracked
    def update_router(self, context, id, router):
        return super(NuageL3Wrapper, self).update_router(
            context, id, router)

    @TimeTracker.untracked
    def get_floatingip(self, context, id, fields=None):
        return super(NuageL3Wrapper, self).get_floatingip(
            context, id, fields)

    @TimeTracker.untracked
    def create_floatingip(self, context, floatingip,
                          initial_status=lib_constants.
                          FLOATINGIP_STATUS_ACTIVE):
        return super(NuageL3Wrapper, self).create_floatingip(
            context, floatingip, initial_status)

    @TimeTracker.untracked
    def delete_floatingip(self, context, id):
        super(NuageL3Wrapper, self).delete_floatingip(context, id)

    @TimeTracker.untracked
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        return super(NuageL3Wrapper, self).disassociate_floatingips(
            context, port_id, do_notify)

    @TimeTracker.untracked
    def notify_routers_updated(self, context, router_ids):
        # attention : L3_NAT_db_mixin signature seems buggy i.e. incomplete
        super(NuageL3Wrapper, self).notify_routers_updated(
            context, router_ids)

    @TimeTracker.untracked
    def update_floatingip(self, context, id, floatingip):
        return super(NuageL3Wrapper, self).update_floatingip(
            context, id, floatingip)
