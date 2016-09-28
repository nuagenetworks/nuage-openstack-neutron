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

from nuage_neutron.plugins.common import constants

nuage_pat_choices = [constants.NUAGE_PAT_NOT_AVAILABLE,
                     constants.NUAGE_PAT_DEF_ENABLED,
                     constants.NUAGE_PAT_DEF_DISABLED]

restproxy_opts = [
    cfg.StrOpt('server', default='localhost:8800',
               help=_("IP Address and Port of Nuage's VSD server")),
    cfg.StrOpt('serverauth', default='username:password',
               secret=True,
               help=_("Username and password for authentication")),
    cfg.BoolOpt('serverssl', default=False,
                help=_("Boolean for SSL connection with VSD server")),
    cfg.StrOpt('base_uri', default='/',
               help=_("Nuage provided base uri to reach out to VSD")),
    cfg.StrOpt('organization', default='system',
               help=_("Organization name in which VSD will orchestrate "
                      "network resources using openstack")),
    cfg.StrOpt('auth_resource', default='',
               help=_("Nuage provided uri for initial authorization to "
                      "access VSD")),
    cfg.StrOpt('default_net_partition_name',
               default='OpenStackDefaultNetPartition',
               help=_("Default Network partition in which VSD will "
                      "orchestrate network resources using openstack")),
    cfg.IntOpt('default_floatingip_quota',
               default=254,
               help=_("Per Net Partition quota of floating ips")),
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
                      "identifies this OpenStack instance")),
    cfg.StrOpt('nuage_uplink', default=None)
]

syncmanager_opts = [
    cfg.BoolOpt('enable_sync', default=False,
                help=_("Nuage plugin will sync resources between openstack "
                       "and VSD")),
    cfg.BoolOpt('enable_audit', default=False,
                help=_("Nuage plugin will audit resources between openstack "
                       "and VSD. If 'enable_sync' flag is set to TRUE, "
                       "plugin will audit and sync resources.")),
    cfg.IntOpt('sync_interval', default=0,
               help=_("Sync interval in seconds between openstack and VSD. "
                      "It defines how often the synchronization is done. "
                      "If not set, value of 0 is assumed and sync will be "
                      "performed only once, at the Neutron startup time.")),
]

fiprate_opts = [
    cfg.StrOpt('fip_rate_change_log', default=''),
    cfg.IntOpt('default_fip_rate', default=-1),
]

plugin_opts = [
    cfg.ListOpt('device_owner_prefix', default=[],
                help=_("List of device_owners prefix for which vports are "
                       "not created in VSD.")),
    cfg.ListOpt('experimental_features', default=[],
                help=_("List of experimental features to be enabled."))
]


def nuage_register_cfg_opts():
    cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
    cfg.CONF.register_opts(syncmanager_opts, "SYNCMANAGER")
    cfg.CONF.register_opts(fiprate_opts, "FIPRATE")
    cfg.CONF.register_opts(plugin_opts, "PLUGIN")
