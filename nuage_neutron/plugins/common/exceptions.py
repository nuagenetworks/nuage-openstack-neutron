# Copyright 2014 Alcatel-Lucent USA Inc.
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

# Nuage specific exceptions

from neutron._i18n import _
from neutron_lib import exceptions as n_exc


class OperationNotSupported(n_exc.InvalidConfigurationOption):
    message = _("Nuage Plugin does not support this operation: %(msg)s")


class NuageBadRequest(n_exc.BadRequest):
    message = _("Bad request: %(msg)s")


class NuageAPIException(n_exc.NeutronException):
    message = _("Nuage API: %(msg)s")


class NuageNotFound(n_exc.NotFound):
    message = _("%(resource)s %(resource_id)s could not be found")


class NuageDualstackSubnetNotFound(n_exc.ObjectNotFound):
    message = _("%(resource)s could not be found so retrying")


class NuageNotAuthorized(n_exc.NotAuthorized):
    message = _("Not authorized for this operation: %(msg)s")


class NuagePortBound(n_exc.InUse):
    message = _("Unable to complete operation on port %(port_id)s, "
                "port is already bound, port type: %(vif_type)s, "
                "old_ips %(old_ips)s, new_ips %(new_ips)s.")


class VsdSubnetNotFound(n_exc.BadRequest):
    message = _("Vsd subnet with id '%(id)s' not found")


class SubnetMappingNotFound(n_exc.BadRequest):
    message = _("Vsd subnet mapping not found for %(resource)s '%(id)s'")


class NuageDriverNotFound(n_exc.NotFound):
    message = _("Could not find the following driver(s): %(driver_name)s.")


class UniqueSubnetConflict(n_exc.Conflict):
    message = _("Subports with segmentattion id %(vlan)s cannot belong to "
                "multiple subnets %(subnets)s in a single physical network")


class VlanIdInUseByNetwork(n_exc.Conflict):
    message = _("Vlan %(vlan)s is used by a network %(network)s in a "
                "physical network %(physnet)s")


class VlanIdInUseBySubport(n_exc.Conflict):
    message = _("Vlan %(vlan)s is used by a subport in a "
                "physical network %(physnet)s")


class TrunkVlanConflict(n_exc.Conflict):
    message = _("Subnet %(subnet)s cannot use multiple vlans %(vlans)s in a "
                "single trunk")


class UniqueVlanConflict(n_exc.Conflict):
    message = _("Subports on subnet %(subnet)s cannot use multiple vlans "
                "%(vlans)s in a single physical network")


class SubPortNetConflict(n_exc.Conflict):
    message = _("Subport %(subport)s in the network with vlan segment "
                "must use segmentation id of that segment.")


class SubPortParentPortConflict(n_exc.Conflict):
    message = _("Subport %(subport)s cannot be in the same network as the "
                "trunk's parent port.")


class SubPortNetpartitionConflict(n_exc.Conflict):
    message = _("Subport %(subport)s cannot be in the different netpartition "
                "than the trunk's parent port.")


class TrunkVnicTypeConflict(n_exc.Conflict):
    message = _("Subport %(subport)s has vnic_type '%(vnic_type_sub)s' and "
                "parent port %(parent)s has vnic_type '%(vnic_type_parent)s'")


class DirectPortSubnetConflict(n_exc.Conflict):
    message = _("Creation of direct ports is supported in a dualstack "
                "networks, or networks with single subnet only.")


class DirectPortSwithportMappingNotFound(n_exc.NotFound):
    message = _("Could not find switchport mapping for port %(port)s.")
