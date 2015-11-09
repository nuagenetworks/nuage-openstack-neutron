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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.extensions import allowedaddresspairs as addr_pair
from nuage_neutron.plugins.common import nuagedb

LOG = logging.getLogger(__name__)


class NuageAddressPair(addr_pair_db.AllowedAddressPairsMixin):

    def _create_vips(self, nuage_subnet_id, port, nuage_vport):
        nuage_vip_dict = dict()
        for allowed_addr_pair in port[addr_pair.ADDRESS_PAIRS]:
            vip = allowed_addr_pair['ip_address']
            mac = allowed_addr_pair['mac_address']

            params = {
                'vip': vip,
                'mac': mac,
                'subnet_id': nuage_subnet_id,
                'vport_id': nuage_vport['nuage_vport_id'],
                'port_ip': port['fixed_ips'][0]['ip_address'],
                'port_mac': port['mac_address']
            }

            try:
                self.nuageclient.create_vip(params)
                nuage_vip_dict[params['vip']] = params['mac']

            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error("Error in creating  vip for ip %(vip)s and mac "
                              "%(mac)s: %(err)s", {'vip': vip,
                                                   'mac': mac,
                                                   'err': e.message})
                    self.nuageclient.delete_vips(nuage_vport['nuage_vport_id'],
                                                 nuage_vip_dict,
                                                 nuage_vip_dict.keys())

    def _update_vips(self, nuage_subnet_id, port, nuage_vport,
                     deleted_addr_pairs):
        if deleted_addr_pairs:
            # If some addr pairs were deleted we might have to undo some
            # action on VSD
            for addrpair in deleted_addr_pairs:
                params = {
                    'vip': addrpair['ip_address'],
                    'mac': addrpair['mac_address'],
                    'subnet_id': nuage_subnet_id,
                    'vport_id': nuage_vport['nuage_vport_id'],
                    'port_ip': port['fixed_ips'][0]['ip_address'],
                    'port_mac': port['mac_address']
                }
                self.nuageclient.process_deleted_addr_pair(params)

        # Get all the vips on vport
        nuage_vips = self.nuageclient.get_vips(nuage_vport['nuage_vport_id'])

        nuage_vip_dict = dict()
        for nuage_vip in nuage_vips:
            nuage_vip_dict[nuage_vip['vip']] = nuage_vip['mac']

        os_vip_dict = dict()
        if addr_pair.ADDRESS_PAIRS in port:
            for allowed_addr_pair in port[addr_pair.ADDRESS_PAIRS]:
                # OS allows addr pairs with same ip and different mac,
                # which does not make sense in VSD. We will create only one
                # of the pair in VSD
                if allowed_addr_pair['ip_address'] in os_vip_dict:
                    LOG.warning("Duplicate ip found in allowed address "
                                "pairs, so %s will be ignored",
                                allowed_addr_pair)
                    continue
                os_vip_dict[allowed_addr_pair['ip_address']] = (
                    allowed_addr_pair['mac_address'])

        vips_add_list = []
        vips_delete_set = set()
        for vip, mac in os_vip_dict.iteritems():
            if vip in nuage_vip_dict:
                # Check if mac is same
                if mac != nuage_vip_dict.get(vip):
                    vips_add_dict = {
                        'ip_address': vip,
                        'mac_address': mac
                    }
                    vips_add_list.append(vips_add_dict)
            else:
                vips_add_dict = {
                    'ip_address': vip,
                    'mac_address': mac
                }
                vips_add_list.append(vips_add_dict)

        for vip, mac in nuage_vip_dict.iteritems():
            if vip in os_vip_dict:
                # Check if mac is same
                if mac != os_vip_dict.get(vip):
                    vips_delete_set.add(vip)
            else:
                vips_delete_set.add(vip)

        if vips_delete_set:
            try:
                self.nuageclient.delete_vips(nuage_vport['nuage_vport_id'],
                                             nuage_vip_dict,
                                             vips_delete_set)
            except Exception as e:
                with excutils.save_and_reraise_exception:
                    LOG.error("Error in deleting vips on vport %(port)s: %("
                              "err)s", {'port': nuage_vport['nuage_vport_id'],
                                        'err': e})

        if vips_add_list:
            port_dict = {
                addr_pair.ADDRESS_PAIRS: vips_add_list,
                'fixed_ips': port['fixed_ips'],
                'mac_address': port['mac_address']
            }
            self._create_vips(nuage_subnet_id, port_dict, nuage_vport)

    def _process_allowed_address_pairs(self, context, port, create=False,
                                       delete_addr_pairs=None):
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if subnet_mapping:
            l2dom_id = None
            l3dom_id = None
            if subnet_mapping['nuage_l2dom_tmplt_id']:
                l2dom_id = subnet_mapping['nuage_subnet_id']
            else:
                l3dom_id = subnet_mapping['nuage_subnet_id']

            params = {
                'neutron_port_id': port['id'],
                'l2dom_id': l2dom_id,
                'l3dom_id': l3dom_id
            }

            nuage_vport = self.nuageclient.get_nuage_vport_by_id(params)
            if nuage_vport:
                if create:
                    # Create a VIP
                    self._create_vips(l2dom_id or l3dom_id, port, nuage_vport)
                else:
                    self._update_vips(l2dom_id or l3dom_id, port,
                                      nuage_vport, delete_addr_pairs)

    def _verify_allowed_address_pairs(self, context, port, port_data):
        empty_allowed_address_pairs = (
            addr_pair.ADDRESS_PAIRS in port_data and (
                not (port_data[addr_pair.ADDRESS_PAIRS] or
                     port[addr_pair.ADDRESS_PAIRS])))
        if ((addr_pair.ADDRESS_PAIRS not in port_data) or (
                not attr.is_attr_set(port_data[addr_pair.ADDRESS_PAIRS])) or
                empty_allowed_address_pairs):
            # No change is required if port_data doesn't have addr pairs
            LOG.info('No allowed address pairs update required for port %s',
                     port['id'])
            return False

        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        subnet_id)
        if subnet_mapping['nuage_managed_subnet']:
            msg = _('Allowed address pair is not supported for VSD managed '
                    'subnet %s') % subnet_id
            raise n_exc.BadRequest(resource='subnet',
                                   msg=msg)

        return True

    def create_allowed_address_pairs(self, context, port, port_data):
        verify = self._verify_allowed_address_pairs(context, port, port_data)
        if not verify:
            return

        port[addr_pair.ADDRESS_PAIRS] = (
            self._process_create_allowed_address_pairs(
                context, port, port_data.get(addr_pair.ADDRESS_PAIRS)))

        self._process_allowed_address_pairs(context, port, True)

    def update_allowed_address_pairs(self, context, id, port, port_data,
                                     updated_port, updated_port_dict):
        verify = self._verify_allowed_address_pairs(context, port, port_data)
        if not verify:
            return

        if addr_pair.ADDRESS_PAIRS in port:
            if not cmp(port_data[addr_pair.ADDRESS_PAIRS],
                       port[addr_pair.ADDRESS_PAIRS]):
                # No change is required if addr pairs in port and port_data are
                # same
                LOG.info('Allowed address pairs to update %(upd)s and one '
                         'in db %(db)s are same, so no change is required',
                         {'upd': port_data[addr_pair.ADDRESS_PAIRS],
                          'db': port[addr_pair.ADDRESS_PAIRS]})
                return

        old_addr_pairs = updated_port[addr_pair.ADDRESS_PAIRS]
        self.update_address_pairs_on_port(context, id,
                                          updated_port_dict,
                                          port,
                                          updated_port)
        port = self.get_port(context, id)
        new_addr_pairs = port[addr_pair.ADDRESS_PAIRS]
        delete_addr_pairs = self._get_deleted_addr_pairs(old_addr_pairs,
                                                         new_addr_pairs)
        self._process_allowed_address_pairs(context, port, False,
                                            delete_addr_pairs)

    def _get_deleted_addr_pairs(self, old_addr_pairs, new_addr_pairs):
        addr_pair_dict = dict()
        deleted_addr_pairs = []
        for addrpair in new_addr_pairs:
            addr_pair_dict[addrpair['ip_address']] = addrpair['mac_address']

        for addrpair in old_addr_pairs:
            if addrpair['ip_address'] in addr_pair_dict:
                # check if mac is also same, if not add it to deleted list
                if (addr_pair_dict[addrpair['ip_address']] !=
                        addrpair['mac_address']):
                    deleted_addr_pairs.append(addrpair)
            else:
                deleted_addr_pairs.append(addrpair)

        return deleted_addr_pairs

    def _process_fip_to_vip(self, context, port_id, nuage_fip_id=None):
        port = self._get_port(context, port_id)
        params = {
            'nuage_fip_id': nuage_fip_id,
            'neutron_subnet_id': port['fixed_ips'][0]['subnet_id'],
            'vip': port['fixed_ips'][0]['ip_address']
        }
        self.nuageclient.associate_fip_to_vips(params)
