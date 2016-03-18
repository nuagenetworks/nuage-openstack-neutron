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

from neutron.services import service_base
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_floatingip
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_policy_group
from nuage_neutron.plugins.common.service_plugins.port_attributes \
    import nuage_redirect_target


class NuagePortAttributesServicePlugin(service_base.ServicePluginBase):
    """Combines the seperate "plugin" classes into a single service plugin

    This class' only purpose is to contain the port attribute classes and it
    links the required method into itself. That way this single class can be
    set as service plugin to enable all port attribute extensions instead of
    needing multiple service plugins.
    Multiple inheritance to automatically have all the methods as part of this
    class makes things more complex in the classes.
    """

    supported_extension_aliases = ['nuage-redirect-target',
                                   'allowed-address-pairs',
                                   'nuage-policy-group',
                                   'nuage-vsd-floatingip']

    def __init__(self):
        super(NuagePortAttributesServicePlugin, self).__init__()
        self.nuage_redirect_target = nuage_redirect_target \
            .NuageRedirectTarget()
        self.nuage_policy_group = nuage_policy_group.NuagePolicyGroup()
        self.nuage_floatingip = nuage_floatingip.NuageFloatingip()
        self.init_methods()

    def get_plugin_name(self):
        return constants.NUAGE_PORT_MANAGEMENT_SERVICE_PLUGIN

    def get_plugin_type(self):
        return constants.NUAGE_PORT_MANAGEMENT_SERVICE_PLUGIN

    def get_plugin_description(self):
        return ("Plugin providing support for nuage-specific apis which "
                "passthrough to VSD")

    def init_methods(self):
        self.init_redirect_targets()
        self.init_nuage_policy_group()
        self.init_nuage_floatingip()

    def init_redirect_targets(self):
        source = self.nuage_redirect_target
        self.get_nuage_redirect_target = source.get_nuage_redirect_target
        self.get_nuage_redirect_targets = source.get_nuage_redirect_targets
        self.delete_nuage_redirect_target = source.delete_nuage_redirect_target
        self.get_nuage_redirect_targets_count = source \
            .get_nuage_redirect_targets_count
        self.create_nuage_redirect_target = source.create_nuage_redirect_target
        self.create_nuage_redirect_target_vip = source \
            .create_nuage_redirect_target_vip
        self.get_nuage_redirect_target_vips_count = source \
            .get_nuage_redirect_target_vips_count
        self.create_nuage_redirect_target_rule = source \
            .create_nuage_redirect_target_rule
        self.get_nuage_redirect_target_rule = source \
            .get_nuage_redirect_target_rule
        self.delete_nuage_redirect_target_rule = source \
            .delete_nuage_redirect_target_rule
        self.get_nuage_redirect_target_rules = source \
            .get_nuage_redirect_target_rules
        self.get_nuage_redirect_target_rules_count = source \
            .get_nuage_redirect_target_rules_count

    def init_nuage_policy_group(self):
        source = self.nuage_policy_group
        self.get_nuage_policy_group = source.get_nuage_policy_group
        self.get_nuage_policy_groups = source.get_nuage_policy_groups

    def init_nuage_floatingip(self):
        source = self.nuage_floatingip
        self.get_nuage_floatingip = source.get_nuage_floatingip
        self.get_nuage_floatingips = source.get_nuage_floatingips
