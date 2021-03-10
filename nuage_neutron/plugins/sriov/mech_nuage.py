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

import inspect

from neutron._i18n import _
from neutron.services.trunk import constants as t_consts
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as os_constants
from neutron_lib import context as neutron_context
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log as logging

from nuage_neutron.plugins.common import base_plugin
from nuage_neutron.plugins.common import constants as nuage_const
from nuage_neutron.plugins.common import exceptions
from nuage_neutron.plugins.common import net_topology_db as ext_db
from nuage_neutron.plugins.common import nuagedb
from nuage_neutron.plugins.common import port_security
from nuage_neutron.plugins.common import trunk_db
from nuage_neutron.plugins.common import utils
from nuage_neutron.plugins.common.utils import handle_nuage_api_errorcode
from nuage_neutron.plugins.common.utils import ignore_no_update
from nuage_neutron.plugins.common.utils import ignore_not_found
from nuage_neutron.plugins.sriov import trunk_driver
from nuage_neutron.vsdclient.common import constants as vsd_constants
from nuage_neutron.vsdclient.restproxy import ResourceExistsException


LOG = logging.getLogger(__name__)

driver_opts = [
    cfg.BoolOpt('allow_existing_flat_vlan', default=False,
                help=_("Set to true to enable driver to complete port "
                       "binding on flat networks, when corresponding"
                       "GW port has vlan 0 provisioned by external entity"))]

cfg.CONF.register_opts(driver_opts, "nuage_sriov")


class NuageSriovMechanismDriver(base_plugin.RootNuagePlugin,
                                api.MechanismDriver):
    """Ml2 Mechanism driver interface

    for provisioning sriov instances.
    """

    def initialize(self):
        LOG.debug('Initializing driver')
        self.init_vsd_client()
        self._wrap_vsdclient()
        self.trunk_driver = trunk_driver.NuageTrunkDriver.create(self)
        self.psec_handler = port_security.NuagePortSecurityHandler(
            self.vsdclient, self)
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}
        self.conf = cfg.CONF
        self.supported_network_types = [os_constants.TYPE_VXLAN,
                                        nuage_const.NUAGE_HYBRID_MPLS_NET_TYPE]
        LOG.debug('Initializing complete')

    def _wrap_vsdclient(self):
        """Wraps nuagecient methods with try-except to ignore certain errors.

        When updating an entity on the VSD and there is nothing to actually
        update because the values don't change, VSD will throw an error. This
        is not needed for neutron so all these exceptions are ignored.

        When VSD responds with a 404, this is sometimes good (for example when
        trying to update an entity). Yet sometimes this is not required to be
        an actual exception. When deleting an entity that does no longer exist
        it is fine for neutron. Also when trying to retrieve something from VSD
        having None returned is easier to work with than RESTProxy exceptions.
        """

        methods = inspect.getmembers(self.vsdclient,
                                     lambda x: inspect.ismethod(x))
        for m in methods:
            wrapped = ignore_no_update(m[1])
            if m[0].startswith('get_') or m[0].startswith('delete_'):
                wrapped = ignore_not_found(wrapped)
            setattr(self.vsdclient, m[0], wrapped)

    @utils.context_log
    def create_network_precommit(self, context):
        db_context = context._plugin_context
        segments = context.current.get('segments')
        if segments:
            bad_segment = next(
                (segment for segment in segments if
                 segment.get('provider:network_type') == t_consts.VLAN and
                 trunk_db.vlan_in_use_by_subport(db_context.session,
                                                 segment)), None)
            if bad_segment:
                raise exceptions.VlanIdInUseBySubport(
                    vlan=bad_segment['provider:segmentation_id'],
                    physnet=bad_segment['provider:physical_network']
                )

    @utils.context_log
    def create_port_precommit(self, context):
        port = context.current
        db_context = context._plugin_context
        if not self.is_port_vnic_type_supported(port):
            return
        self._validate_nuage_l2bridges(db_context, port)
        self._validate_port_request_attributes(context.current)
        subnets = self.core_plugin._get_subnets_by_network(
            db_context,
            port.get('network_id'))
        if len(subnets) != 1:
            if ((len(subnets) != 2 or
                 subnets[0]['ip_version'] ==
                 subnets[1]['ip_version'])):
                raise exceptions.DirectPortSubnetConflict()

    @utils.context_log
    def update_port_precommit(self, context):
        """update_port_precommit."""
        port = context.current
        original = context.original
        if not self.is_port_vnic_type_supported(port):
            return
        self._validate_port_request_attributes(port, original=original)

    @handle_nuage_api_errorcode
    @utils.context_log
    def update_port_postcommit(self, context):
        """update_port_postcommit."""
        port = context.current
        original = context.original
        if not self.is_port_vnic_type_supported(port):
            return
        host_removed = host_changed = False
        if original['binding:host_id'] and not port['binding:host_id']:
            host_removed = True
        elif original['binding:host_id'] != port['binding:host_id']:
            host_changed = True
        if host_removed or host_changed:
            self._delete_port(context)

    @utils.context_log
    def delete_port_precommit(self, context):
        """delete_port_precommit."""
        if not self.is_port_vnic_type_supported(context.current):
            return
        self._delete_port(context)

    @utils.context_log
    def bind_port(self, context):
        """bind_port."""
        if context.binding_levels:
            return  # we've already got a top binding

        subnet_mapping = self._get_subnet_mapping(context._plugin_context,
                                                  context.current)
        if not subnet_mapping:
            return

        port_id = context.current['id']
        for segment in context.segments_to_bind:
            if self._check_segment(segment, context):
                if not self._can_bind(context):
                    return
                if (context.current.get('device_owner') in
                        [t_consts.TRUNK_SUBPORT_OWNER]):
                    next_segment = segment
                    profile = context.current.get(portbindings.PROFILE)
                    # get vlan id from binding profile
                    segmentation_id = profile.get('vlan')
                else:
                    # get a vlan segment or allocate dynamic
                    next_segment = self._allocate_segment(context)

                    # get vlan id from segment or 0 for flat nets
                    segmentation_id = (next_segment.get(api.SEGMENTATION_ID) or
                                       0)

                port_status = os_constants.PORT_STATUS_ACTIVE
                # create a VPort at TOR level
                host_id = context.current['binding:host_id']
                if host_id:
                    port = self._make_port_dict(context, segmentation_id)
                    vif_type = self._create_port(port)
                    if vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
                        context.set_binding(
                            segment[api.ID],
                            portbindings.VIF_TYPE_BINDING_FAILED,
                            {})
                        LOG.error("Failed to bind port")
                        return
                    if (context.current.get('device_owner') in
                            [t_consts.TRUNK_SUBPORT_OWNER]):
                        vif_binding = self.vif_details
                        vif_binding['vlan'] = str(segmentation_id)
                        context.set_binding(segment[api.ID],
                                            vif_type,
                                            vif_binding,
                                            status=port_status)
                        LOG.debug("port bind using segment for port %(port)s :"
                                  " %(vif_type)s",
                                  {'port': port_id, 'vif_type': vif_type})
                    else:
                        # Have other drivers bind at the hv level.
                        LOG.debug("partial port bind for port %(port)s :"
                                  " %(vif_type)s",
                                  {'port': port_id, 'vif_type': vif_type})
                        context.continue_binding(segment[api.ID],
                                                 [next_segment])
            else:
                LOG.debug("Ignoring segment %(seg)s  for port %(port)s",
                          {'seg': segment,
                           'port': port_id})

    def _check_segment(self, segment, context):
        """Verify a segment is valid for the current driver.

        Verify the requested segment is supported and return True or
        False to indicate this to callers.
        """
        network_type = segment[api.NETWORK_TYPE]
        return network_type in self.supported_network_types

    def _allocate_segment(self, context):
        """Find or allocate new segment suitable for Hw VTEP

        """
        segment = next((item for item in context.segments_to_bind if
                       item[api.NETWORK_TYPE] in [os_constants.TYPE_FLAT,
                                                  os_constants.TYPE_VLAN]),
                       None)
        if not segment:
            binding_profile = self._get_binding_profile(context.current)
            segment = context.allocate_dynamic_segment(
                {api.NETWORK_TYPE: 'vlan',
                 api.PHYSICAL_NETWORK: binding_profile.get('physical_network')
                 })
        return segment

    def _make_port_dict(self, context, segmentation_id=None, port=None):
        """Get required info from neutron port.

        Combine everything to a single dict.
        """
        if not port:
            port = context.current
        port_id = port['id']
        network_id = port['network_id']
        subnet_mapping = self._get_subnet_mapping(context._plugin_context,
                                                  port)
        if not subnet_mapping:
            LOG.warning("_make_port_dict can not get subnet_mapping"
                        " for port %(port)s",
                        {'port': port})
            return None
        profile = self._get_binding_profile(port)
        host_id = port['binding:host_id']
        gw_port_mapping = ext_db.get_switchport_by_host_slot(
            context._plugin_context,
            {'host_id': host_id, 'pci_slot': profile.get('pci_slot')})
        if not gw_port_mapping:
            LOG.warning("_make_port_dict can not get switchport_mapping "
                        "for %(vif)s",
                        {'vif': {'host_id': host_id,
                                 'pci_slot': profile.get('pci_slot')}})
            local_link_information = None
        else:
            if gw_port_mapping.get('redundant_port_uuid'):
                # Redundant port: determine redundancy_type
                gw_port = self.vsdclient.get_gateway_port(
                    gw_port_mapping['id'])
                redundancy_type = gw_port['gw_redundancy_type']
            else:
                redundancy_type = vsd_constants.SINGLE_GW
            local_link_information = [{
                'id': gw_port_mapping['id'],
                'switch_info': gw_port_mapping['switch_info'],
                'switch_id': gw_port_mapping['switch_id'],
                'redundancy_type': redundancy_type,
                'port_id': gw_port_mapping['port_uuid']
            }]

        port_dict = {'port':
                     {'id': port_id,
                      'name': port.get('name'),
                      'network_id': network_id,
                      'link_info': local_link_information,
                      'host_id': host_id,
                      'tenant_id': port['tenant_id'],
                      'fixed_ips': port['fixed_ips'],
                      'mac_address': port['mac_address']
                      },
                     'subnet_mapping': subnet_mapping
                     }
        subnet = context._plugin.get_subnet(context._plugin_context,
                                            subnet_mapping['subnet_id'])
        port_dict['subnet'] = subnet
        port_dict['enable_dhcp'] = subnet['enable_dhcp']
        if segmentation_id is not None:
            port_dict['segmentation_id'] = segmentation_id
        LOG.debug("port dict  %(port_dict)s",
                  {'port_dict': port_dict})
        return port_dict

    def _get_binding_profile(self, port):
        profile = port.get(portbindings.PROFILE, {})
        if not profile:
            LOG.warning("Missing profile in port binding")
        return profile

    def _can_bind(self, context):
        """Check that all required binding info is present"""
        vnic_type = context.current.get(portbindings.VNIC_TYPE, "")
        if vnic_type not in self._supported_vnic_types():
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return False
        if not self.is_port_vnic_type_supported(context.current):
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s "
                      "with switchdev capability", portbindings.VNIC_DIRECT)
            return False
        return True

    def _supported_vnic_types(self):
        """Vnic type current driver does handle"""
        return [portbindings.VNIC_DIRECT,
                portbindings.VNIC_DIRECT_PHYSICAL]

    @staticmethod
    def _direct_vnic_supported(port):
        profile = port.get(portbindings.PROFILE)
        capabilities = []
        if profile:
            capabilities = profile.get('capabilities', [])
        return (port.get(portbindings.VNIC_TYPE) ==
                portbindings.VNIC_DIRECT and
                'switchdev' not in capabilities)

    def _get_subnet_mapping(self, db_context, port):
        for fixed_ip in port.get('fixed_ips', []):
            return nuagedb.get_subnet_l2dom_by_id(db_context.session,
                                                  fixed_ip['subnet_id'])
        return None

    def _get_nuage_vport(self, port, required=True):
        subnet_id = port['port'].get('fixed_ips')[0]['subnet_id']
        port_params = {
            'neutron_port_id': subnet_id,
            'l2dom_id': port['subnet_mapping']['nuage_subnet_id'],
            'l3dom_id': port['subnet_mapping']['nuage_subnet_id']
        }
        return self.vsdclient.get_nuage_vport_by_neutron_id(
            port_params,
            required=required)

    def _create_nuage_bridge_vport(self, port_dict):
        """Create a BRIDGE VPort on VSD"""
        port = port_dict['port']
        gw_ports = port.get('link_info')
        if not gw_ports:
            raise exceptions.DirectPortSwithportMappingNotFound(
                port=port['id'])
        segmentation_id = port_dict['segmentation_id']
        ctx = neutron_context.get_admin_context()
        bridgeports = ext_db.get_switchport_binding_by_neutron_port(
            ctx,
            port['id'],
            segmentation_id)
        if bridgeports:
            LOG.info("bridge port(s) %(bp)s for port %(port)s already exist",
                     {'bp': bridgeports,
                      'port': port['id']})
            return
        for gwport in gw_ports:
            vports = ext_db.get_switchport_bindings_by_switchport_vlan(
                ctx,
                gwport['port_id'],
                segmentation_id)
            if len(vports) == 0:
                filters = {'system_id': [gwport['switch_id']]}
                # Explicitely do not support RG en ESGW for faster retrieval
                gws = self.vsdclient.get_gateways(
                    ctx.tenant_id, filters,
                    redundancy_type=vsd_constants.SINGLE_GW)
                if len(gws) == 0:
                    msg = (_("No gateway found %s")
                           % filters['system_id'][0])
                    raise exceptions.NuageBadRequest(msg=msg)
                gw = gws[0]

                # gridinv: following code should be removed when
                # we have proper support of native vlan on cisco/netconf
                if ('NETCONF_THIRDPARTY' in gw['gw_type'] and
                        segmentation_id == 0):
                    return

                port_id = gwport['port_id']
                params = {
                    'gatewayport': port_id,
                    'value': segmentation_id,
                    'redundancy_type': gwport['redundancy_type'],
                    'personality': gw['gw_type']
                }
                try:
                    vlan = self.vsdclient.create_gateway_vlan(params)
                    LOG.debug("created vlan: %(vlan_dict)s",
                              {'vlan_dict': vlan})
                except ResourceExistsException:
                    allow_flat = self.conf.nuage_sriov.allow_existing_flat_vlan
                    if segmentation_id == 0 and allow_flat:
                        LOG.info('Reusing existing vlan due to '
                                 'allow_existing_flat_vlan=%s', allow_flat)
                        return
                    else:
                        raise
                # create dummy subnet - we need only id
                params = {
                    'gatewayinterface': vlan['ID'],
                    'np_id': port_dict['subnet_mapping']['net_partition_id'],
                    'tenant': port['tenant_id'],
                    'subnet': port_dict['subnet'],
                    'enable_dhcp': port_dict['enable_dhcp'],
                    'nuage_managed_subnet':
                        port_dict['subnet_mapping']['nuage_managed_subnet'],
                    'port_security_enabled': False,
                    'personality': gw['gw_type'],
                    'type': nuage_const.BRIDGE_VPORT_TYPE
                }
                vsd_subnet = self.vsdclient \
                    .get_nuage_subnet_by_id(
                        port_dict['subnet_mapping']['nuage_subnet_id'])
                params['vsd_subnet'] = vsd_subnet

                vport = self.vsdclient.create_gateway_vport_no_usergroup(
                    ctx.tenant_id,
                    params)
                # policy groups are not supported on netconf
                # managed gateways and unmanaged gateways
                create_policy = (gw['gw_type'] not in
                                 ['NETCONF_THIRDPARTY_HW_VTEP',
                                  'UNMANAGED_GATEWAY'])
                if create_policy:
                    (domain_type,
                     domain_id) = self._get_domain_type_id_from_vsd_subnet(
                        self.vsdclient, vsd_subnet)
                    self.psec_handler.process_pg_allow_all(
                        ctx, nuage_const.HARDWARE,
                        port_dict['subnet_mapping'], vport['vport'],
                        domain_type, domain_id)
                LOG.debug("created vport: %(vport_dict)s",
                          {'vport_dict': vport})
                bridge_port_id = vport.get('vport').get('ID')
            else:
                LOG.debug("bridge port %(bp)s for vlan %(vlan)s already exist",
                          {'bp': vports[0]['nuage_vport_id'],
                           'vlan': segmentation_id})
                bridge_port_id = vports[0]['nuage_vport_id']
            binding = {
                'neutron_port_id': port.get('id'),
                'nuage_vport_id': bridge_port_id,
                'switchport_uuid': gwport['port_id'],
                'segmentation_id': segmentation_id,
                'switchport_mapping_id': gwport['id']
            }
            ext_db.add_switchport_binding(ctx, binding)

    def _create_port(self, port):
        """_create_port. This call makes the REST request to VSD

        for provisioning VLAN/Vport for the gateway
        port where sriov instance is connected.
        """

        try:
            self._create_nuage_bridge_vport(port)
        except Exception as ex:
            LOG.error("exception creating bridge vport: %(msg)s", {'msg': ex})
            return portbindings.VIF_TYPE_BINDING_FAILED
        return portbindings.VIF_TYPE_HW_VEB

    def _delete_port(self, context):
        """delete_port. This call makes the REST request to VSD

        for un provision VLAN/VPort for the gateway port where
        sriov instance is connected.
        """
        port = context.current
        db_context = context._plugin_context
        LOG.debug("delete_port with port_id %(port_id)s",
                  {'port_id': port['id']})
        port_bindings = ext_db.get_switchport_binding_by_neutron_port(
            db_context, port['id'])
        if not port_bindings:
            return
        for binding in port_bindings:
            bindings = ext_db.get_switchport_bindings_by_switchport_vlan(
                db_context, binding['switchport_uuid'],
                binding['segmentation_id'])
            if len(bindings) == 1:
                vport = self.vsdclient.get_nuage_vport_by_id(
                    binding['nuage_vport_id'],
                    required=False)
                if not vport:
                    LOG.debug("couldn't find a vport")
                else:
                    LOG.debug("Deleting vport %(vport)s", {'vport': vport})
                    self.vsdclient.delete_nuage_gateway_vport_no_usergroup(
                        port['tenant_id'],
                        vport)
                    if vport.get('VLANID'):
                        LOG.debug("Deleting vlan %(vlan)s",
                                  {'vlan': vport['VLANID']})
                        self.vsdclient.delete_gateway_port_vlan(
                            vport['VLANID'])
            ext_db.delete_switchport_binding(db_context, port['id'],
                                             binding['segmentation_id'])

    def check_vlan_transparency(self, context):
        """Nuage driver vlan transparency support."""
        return True

    def _validate_port_request_attributes(self, current, original=None):
        unsupported_attributes = ['extra_dhcp_opts']
        no_update_attributes = ['admin_state_up']
        for attribute in unsupported_attributes:
            if current.get(attribute):
                msg = _("Unsupported attribute %(attr)s can't be set for "
                        "ports which have one of the following vnic "
                        "types %(vnic)s")
                raise exceptions.NuageBadRequest(
                    msg=msg % {'attr': attribute,
                               'vnic': self._supported_vnic_types()})
        if original is None:
            return
        for attribute in no_update_attributes:
            if current[attribute] != original[attribute]:
                msg = _("No update support for attribute %(attr)s for "
                        "ports which have one of the following vnic "
                        "types %(vnic)s")
                raise exceptions.NuageBadRequest(
                    msg=msg % {'attr': attribute,
                               'vnic': self._supported_vnic_types()})

    @staticmethod
    def is_port_vnic_type_supported(port):
        return (NuageSriovMechanismDriver._direct_vnic_supported(port) or
                port.get(portbindings.VNIC_TYPE, '') ==
                portbindings.VNIC_DIRECT_PHYSICAL)
