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

from oslo_config import cfg

from neutron._i18n import _
from nuage_neutron.plugins.common import constants

nuage_pat_choices = [constants.NUAGE_PAT_NOT_AVAILABLE,
                     constants.NUAGE_PAT_DEF_ENABLED,
                     constants.NUAGE_PAT_DEF_DISABLED]

restproxy_opts = [
    cfg.StrOpt('server', default='vsd.example.com:8443',
               help=_("IP address and port of Nuage's VSD server or cluster")),
    cfg.StrOpt('serverauth', default='csproot:csproot',
               secret=True,
               help=_("Username and password for authentication")),
    cfg.BoolOpt('serverssl', default=True,
                help=_("Boolean for SSL connection with VSD server")),
    cfg.IntOpt('server_timeout', default=30,
               help=_("VSD server invocation timeout")),
    cfg.IntOpt('server_max_retries', default=5,
               help=_("Number of retries invoking VSD server")),
    cfg.StrOpt('base_uri', default='/nuage/api/v5_0',
               help=_("Nuage provided base uri to reach out to VSD")),
    cfg.StrOpt('organization', default='csp',
               help=_("Organization name in which VSD will orchestrate "
                      "network resources using openstack")),
    cfg.StrOpt('auth_resource', default='/me',
               help=_("Nuage provided uri for initial authorization to "
                      "access VSD")),
    cfg.StrOpt('default_net_partition_name',
               default='OpenStackDefaultNetPartition',
               help=_("Default Network partition in which VSD will "
                      "orchestrate network resources using openstack")),
    cfg.IntOpt('default_floatingip_quota',
               default=254,
               help=_("Per netpartition quota of floating ips")),
    cfg.StrOpt('default_l3domain_template', default=''),
    cfg.StrOpt('default_l2domain_template', default=''),
    cfg.StrOpt('default_isolated_zone', default=''),
    cfg.StrOpt('default_shared_zone', default=''),
    cfg.StrOpt('nuage_pat',
               choices=nuage_pat_choices,
               default=constants.NUAGE_PAT_DEF_DISABLED),
    cfg.BoolOpt('nuage_fip_underlay', default=False),
    cfg.StrOpt('cms_id', default=None,
               help=_("ID of a Cloud Management System on the VSD which "
                      "identifies this openstack instance")),
    cfg.StrOpt('nuage_uplink', default=None)
]

fiprate_opts = [
    cfg.StrOpt('fip_rate_change_log', default=''),
    cfg.IntOpt('default_fip_rate', default=-1,
               help=_("FIP rate limit in egress direction in mbs. "
                      "This option is deprecated in favor of "
                      "default_egress_fip_rate_kbps and "
                      "will be removed in a future release."),
               deprecated_for_removal=True),
    cfg.IntOpt('default_ingress_fip_rate_kbps',
               help=_("FIP rate limit in ingress direction in kbs."),
               default=-1),
    cfg.IntOpt('default_egress_fip_rate_kbps',
               help=_("FIP rate limit in egress direction in kbs."),
               default=None),
]

plugin_opts = [
    cfg.ListOpt('device_owner_prefix', default=[],
                help=_("List of device_owners prefix for which vports are "
                       "not created in VSD.")),
    cfg.BoolOpt('flow_logging_enabled', default=False,
                help=_("Set to true to enable flow logging on all policy "
                       "entries. Changing this does not affect existing "
                       "policy entries.")),
    cfg.BoolOpt('stats_collection_enabled', default=False,
                help=_("Set to true to enable statistics collecting on all "
                       "policy entries. Changing this does not affect "
                       "existing policy entries.")),
    cfg.ListOpt('experimental_features', default=[],
                help=_("List of experimental features to be enabled.")),
    cfg.ListOpt('enable_debug', default=[],
                help=_("List of debug features to be enabled."))
]


def nuage_register_cfg_opts():
    cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
    cfg.CONF.register_opts(fiprate_opts, "FIPRATE")
    cfg.CONF.register_opts(plugin_opts, "PLUGIN")


def is_enabled(name):
    if name in cfg.CONF.PLUGIN.experimental_features:
        return True
    if name in cfg.CONF.PLUGIN.enable_debug:
        return True
    return False
