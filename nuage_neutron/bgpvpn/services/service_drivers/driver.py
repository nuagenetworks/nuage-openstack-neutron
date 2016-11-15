# Copyright 2015 Alcatel-Lucent USA Inc.
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

from oslo_utils import excutils

from neutron._i18n import _
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron import manager
from neutron.plugins.common import constants as plugin_constants

from networking_bgpvpn.neutron.db import bgpvpn_db
from networking_bgpvpn.neutron.extensions import bgpvpn as bgpvpn_ext
from networking_bgpvpn.neutron.services.common \
    import constants as bgpvpn_constants
from networking_bgpvpn.neutron.services.service_drivers import driver_api

from nuage_neutron.plugins.common.base_plugin import BaseNuagePlugin
from nuage_neutron.plugins.common import constants

NUAGE_BGPVPN_DRIVER_NAME = 'Nuage'


class BGPVPNNetworkAssociationNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support network "
                "associations")


def get_bgpvpns_by_router(context, router_id):
    return (
        context.session.query(bgpvpn_db.BGPVPN).
        join(bgpvpn_db.BGPVPN.router_associations).
        filter(
            bgpvpn_db.BGPVPNRouterAssociation.router_id == router_id
        ).all()
    )


class NuageBGPVPNDriver(driver_api.BGPVPNDriver,
                        BaseNuagePlugin):

    @property
    def l3_plugin(self):
        if not hasattr(self, '_l3plugin'):
            self._l3plugin = manager.NeutronManager.get_service_plugins()[
                plugin_constants.L3_ROUTER_NAT]
        return self._l3plugin

    @property
    def bgpvpn_plugin(self):
        if not hasattr(self, '_bgpvpn_plugin'):
            self._bgpvpn_plugin = manager.NeutronManager.get_service_plugins()[
                bgpvpn_constants.BGPVPN]
        return self._bgpvpn_plugin

    def __init__(self, service_plugin):
        super(NuageBGPVPNDriver, self).__init__(service_plugin)
        BaseNuagePlugin.__init__(self)
        self.nuage_callbacks.subscribe(self.post_router_update,
                                       resources.ROUTER,
                                       constants.AFTER_UPDATE)

    def create_bgpvpn(self, context, bgpvpn):
        if bgpvpn['type'] != bgpvpn_constants.BGPVPN_L3:
            raise bgpvpn_ext.BGPVPNTypeNotSupported(
                driver=NUAGE_BGPVPN_DRIVER_NAME, type=bgpvpn['type'])
        return super(NuageBGPVPNDriver, self).create_bgpvpn(context, bgpvpn)

    def update_bgpvpn(self, context, id, bgpvpn):
        router_assocs = self.get_router_assocs(context, id)
        if router_assocs:
            self._validate_bgpvpn_for_router_assoc(bgpvpn)
            self._update_nuage_router(context, id,
                                      router_assocs[0]['router_id'])
        return super(NuageBGPVPNDriver, self).update_bgpvpn(context,
                                                            id,
                                                            bgpvpn)

    def update_bgpvpn_postcommit(self, context, old_bgpvpn, bgpvpn):
        router_assocs = self.get_router_assocs(context, bgpvpn['id'])
        if router_assocs:
            self._update_nuage_router(context,
                                      bgpvpn['id'],
                                      router_assocs[0]['router_id'])

    def create_net_assoc(self, context, bgpvpn_id, network_association):
        raise BGPVPNNetworkAssociationNotSupported(
            driver=NUAGE_BGPVPN_DRIVER_NAME)

    def get_net_assoc(self, context, assoc_id, bgpvpn_id, fields=None):
        raise BGPVPNNetworkAssociationNotSupported(
            driver=NUAGE_BGPVPN_DRIVER_NAME)

    def get_net_assocs(self, context, bgpvpn_id, filters=None, fields=None):
        raise BGPVPNNetworkAssociationNotSupported(
            driver=NUAGE_BGPVPN_DRIVER_NAME)

    def delete_net_assoc(self, context, assoc_id, bgpvpn_id):
        raise BGPVPNNetworkAssociationNotSupported(
            driver=NUAGE_BGPVPN_DRIVER_NAME)

    def create_router_assoc(self, context, bgpvpn_id, router_association):
        bgpvpn = self.get_bgpvpn(context, bgpvpn_id)
        bgpvpn = self._validate_no_associations_exist(
            bgpvpn, bgpvpn_id, context, router_association)
        self._validate_bgpvpn_for_router_assoc(bgpvpn)
        return super(NuageBGPVPNDriver, self).create_router_assoc(
            context, bgpvpn_id, router_association)

    def create_router_assoc_postcommit(self, context, router_assoc):
        router_id = router_assoc['router_id']
        bgpvpn_id = router_assoc['bgpvpn_id']

        try:
            self._update_nuage_router(context, bgpvpn_id, router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.bgpvpn_plugin.delete_bgpvpn_router_association(
                    context, router_assoc['id'], bgpvpn_id)

    def _validate_no_associations_exist(self, bgpvpn, bgpvpn_id,
                                        context, router_association):
        if self.get_router_assocs(context, bgpvpn_id):
            msg = _("Can not have more than 1 router association per bgpvpn")
            raise n_exc.BadRequest(resource='router_association', msg=msg)
        filter = {'tenant_id': [bgpvpn['tenant_id']]}
        bgpvpns = self.get_bgpvpns(context, filters=filter)
        bgpvpns = [_bgpvpn for _bgpvpn in bgpvpns
                   if router_association['router_id'] in _bgpvpn['routers']]
        if bgpvpns:
            msg = _("Can not have more than 1 router association per router")
            raise n_exc.BadRequest(resource='router_association', msg=msg)
        return bgpvpn

    def _validate_bgpvpn_for_router_assoc(self, bgpvpn):
        route_targets = bgpvpn.get('route_targets')
        import_targets = bgpvpn.get('import_targets')
        export_targets = bgpvpn.get('export_targets')
        route_distinguishers = bgpvpn.get('route_distinguishers')

        if not self._list_has_length(route_targets, 1):
            msg = _("Exactly 1 route_target is required for this bgpvpn")
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

        if not self._list_has_length(import_targets, 0):
            msg = _("This bgpvpn can't have any import_targets")
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

        if not self._list_has_length(export_targets, 0):
            msg = _("This bgpvpn can't have any export_targets")
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

        if not self._list_has_length(route_distinguishers, 1):
            msg = _("Exactly 1 route_distinguisher is required for this "
                    "bgpvpn")
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

    def _list_has_length(self, list, length):
        return list is None or len(list) == length

    def _update_nuage_router(self, context, bgpvpn_id, router_id):
        bgpvpn = self.get_bgpvpn(context, bgpvpn_id)
        update_dict = {
            'router': {
                'rd': bgpvpn['route_distinguishers'][0],
                'rt': bgpvpn['route_targets'][0]
            }
        }
        self.l3_plugin.update_router(context, router_id, update_dict)

    def post_router_update(self, resource, event, trigger, **kwargs):
        request_router = kwargs.get('request_router')
        updated_router = kwargs.get('updated_router')
        rollbacks = kwargs.get('rollbacks')
        context = kwargs.get('context')
        rd = request_router.get('rd')
        rt = request_router.get('rt')
        if not rd and not rt:
            return

        self._post_router_update(context, updated_router, rollbacks)

    def _post_router_update(self, context, updated_router, rollbacks):
        bgpvpns = get_bgpvpns_by_router(context, updated_router['id'])
        for bgpvpn in bgpvpns:
            rollbacks.append(
                (self.bgpvpn_db.update_bgpvpn,
                 [context, bgpvpn['id'],
                  {'route_distinguishers': bgpvpn['route_distinguishers'],
                   'route_targets': bgpvpn['route_targets']}], {})
            )
            self.bgpvpn_db.update_bgpvpn(
                context, bgpvpn['id'],
                {'route_distinguishers': [updated_router['rd']],
                 'route_targets': [updated_router['rt']]})
