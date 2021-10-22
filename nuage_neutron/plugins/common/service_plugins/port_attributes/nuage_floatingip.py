# Copyright 2016 Alcatel-Lucent USA Inc.
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

from oslo_log import helpers as log_helpers

from neutron._i18n import _
from neutron import policy
from neutron_lib.callbacks import resources

from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common.extensions.nuagefloatingip \
    import NUAGE_FLOATINGIP
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common.service_plugins \
    import vsd_passthrough_resource
from nuage_neutron.plugins.common import utils as nuage_utils
from nuage_neutron.plugins.common.validation import require
from nuage_neutron.vsdclient.common.cms_id_helper import get_vsd_external_id
from nuage_neutron.vsdclient.restproxy import ResourceNotFoundException


class NuageFloatingip(vsd_passthrough_resource.VsdPassthroughResource):
    vsd_to_os = {
        'ID': 'id',
        'address': 'floating_ip_address',
        'assigned': 'assigned'
    }
    os_to_vsd = {
        'id': 'ID',
        'floating_ip_address': 'address',
        'assigned': 'assigned'
    }
    vsd_filterables = ['id', 'floating_ip_address', 'assigned']
    extra_filters = ['for_port', 'for_subnet', 'ports']

    def __init__(self):
        super(NuageFloatingip, self).__init__()
        self.nuage_callbacks.subscribe(self.post_port_update_nuage_fip,
                                       resources.PORT, constants.AFTER_UPDATE)
        self.nuage_callbacks.subscribe(self.post_port_create_nuage_fip,
                                       resources.PORT, constants.AFTER_CREATE)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_floatingip(self, context, id, fields=None):
        try:
            floatingip = self.vsdclient.get_nuage_floatingip(id,
                                                             externalID=None)
            if not floatingip:
                raise exceptions.NuageNotFound(resource="nuage-floatingip",
                                               resource_id=id)
            return self.map_vsd_to_os(floatingip, fields=fields)
        except ResourceNotFoundException:
            raise exceptions.NuageNotFound(resource="nuage_floatingip",
                                           resource_id=id)

    @nuage_utils.handle_nuage_api_errorcode
    @log_helpers.log_method_call
    def get_nuage_floatingips(self, context, filters=None, fields=None):
        if sum(key in filters for key in ['for_port', 'for_subnet',
                                          'ports']) > 1:
            msg = _("Can't combine both 'for_port', 'for_subnet' and "
                    "'ports' filter")
            raise exceptions.NuageBadRequest(msg=msg)

        if 'for_port' in filters:
            getter = self.get_port_available_nuage_floatingips
        elif 'for_subnet' in filters:
            getter = self.get_subnet_available_nuage_floatingips
        elif 'ports' in filters:
            # Get the floating IP assigned to a specific OS port
            getter = self.get_nuage_floatingip_assigned_to_port
        else:
            policy.enforce(context, 'get_nuage_floatingip_all', None)
            getter = self.get_all_nuage_floatingips
        floatingips = getter(context, filters=filters)

        return [self.map_vsd_to_os(fip, fields=fields) for fip in floatingips]

    def get_nuage_floatingip_assigned_to_port(self, context, filters=None):
        port_id = filters['ports'][0]
        vsd_mapping = nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                          port_id)
        if vsd_mapping['nuage_l2dom_tmplt_id']:
            return []
        vports = self.vsdclient.get_vports(
            constants.SUBNET,
            vsd_mapping['nuage_subnet_id'],
            externalID=get_vsd_external_id(port_id))
        fip_id = vports[0]['associatedFloatingIPID'] if vports else None

        return (self.vsdclient.get_nuage_floatingips(required=True, ID=fip_id)
                if fip_id else [])

    def get_port_available_nuage_floatingips(self, context, filters=None):
        port_id = filters.pop('for_port')[0]
        vsd_mapping = nuagedb.get_subnet_l2dom_by_port_id(context.session,
                                                          port_id)
        return self._get_available_nuage_floatingips(vsd_mapping, filters)

    def get_subnet_available_nuage_floatingips(self, context, filters=None):
        subnet_id = filters.pop('for_subnet')[0]
        vsd_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                     subnet_id)
        require(vsd_mapping, 'vsd subnet mapping for subnet', subnet_id)
        return self._get_available_nuage_floatingips(vsd_mapping, filters)

    def get_all_nuage_floatingips(self, context, filters=None):
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        return self.vsdclient.get_nuage_floatingips(externalID=None,
                                                    **vsd_filters)

    def _get_available_nuage_floatingips(self, vsd_mapping, filters):
        vsd_filters = self.osfilters_to_vsdfilters(filters)
        vsd_id = vsd_mapping['nuage_subnet_id']
        vsd_subnet = self.vsdclient.get_nuage_subnet_by_id(vsd_id)
        if not vsd_subnet:
            raise exceptions.VsdSubnetNotFound(id=vsd_id)
        if vsd_subnet['type'] == constants.L2DOMAIN:
            return []

        domain_id = self.vsdclient.get_l3domain_id_by_domain_subnet_id(
            vsd_subnet['ID'])
        return self.vsdclient.get_nuage_domain_floatingips(
            domain_id, assigned=False, externalID=None, **vsd_filters)

    def post_port_update_nuage_fip(self, resource, event, trigger, payload):
        port = payload.latest_state
        metadata = payload.metadata
        self.process_port_nuage_floatingip(event, port, metadata.get('vport'),
                                           rollbacks=metadata.get('rollbacks'))

    def post_port_create_nuage_fip(self, resource, event, trigger, payload):
        port = payload.latest_state
        vport = payload.metadata.get('vport')
        if vport and port.get(NUAGE_FLOATINGIP):
            self.process_port_nuage_floatingip(event, port, vport)
        if NUAGE_FLOATINGIP not in port:
            port[NUAGE_FLOATINGIP] = None

    def process_port_nuage_floatingip(self, event, port, vport,
                                      rollbacks=None):
        if not vport or NUAGE_FLOATINGIP not in port:
            return
        self._process_port_nuage_floatingip(event, port, rollbacks, vport)

    @nuage_utils.handle_nuage_api_errorcode
    def _process_port_nuage_floatingip(self, event, request_port, rollbacks,
                                       vport):
        request_fip = request_port[NUAGE_FLOATINGIP] or {}
        if request_fip:
            floatingip = self.vsdclient.get_nuage_floatingip(
                request_fip.get('id'), required=True)
            if floatingip['externalID']:
                msg = _("Floatingip %s has externalID, it can't be used with "
                        "this API.") % floatingip['ID']
                raise exceptions.NuageBadRequest(msg=msg)
            request_port['nuage_floatingip'] = self.map_vsd_to_os(
                floatingip, fields=['id', 'floating_ip_address'])
        if event == constants.AFTER_UPDATE:
            rollbacks.append(
                (self.vsdclient.update_vport,
                 [vport['ID'],
                  {'associatedFloatingIPID': vport['associatedFloatingIPID']}],
                 {})
            )
        self.vsdclient.update_vport(
            vport['ID'],
            {'associatedFloatingIPID': request_fip.get('id')})
