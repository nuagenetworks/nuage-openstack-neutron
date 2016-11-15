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

from neutron.common import exceptions as n_exc
from neutron.i18n import _


class OperationNotSupported(n_exc.InvalidConfigurationOption):
    message = _("Nuage Plugin does not support this operation: %(msg)s")


class NuageBadRequest(n_exc.BadRequest):
    message = _("Bad request: %(msg)s")


class NuageAPIException(n_exc.NeutronException):
    message = _("Nuage API: %(msg)s")


class NuageNotFound(n_exc.NotFound):
    message = _("%(resource)s %(resource_id)s could not be found")


class NuageNotAuthorized(n_exc.NotAuthorized):
    message = _("Not authorized for this operation: %(msg)s")


class VsdSubnetNotFound(n_exc.BadRequest):
    message = _("Vsd subnet with id '%(id)s' not found")


class SubnetMappingNotFound(n_exc.BadRequest):
    message = _("Vsd subnet mapping not found for %(resource)s '%(id)s'")
