#!/bin/bash

# Copyright 2015 Alcatel-Lucent USA Inc.
#
# All Rights Reserved
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


DIR_NUAGE=$DEST/nuage-openstack-neutron
source $DIR_NUAGE/devstack/functions
if [[ "$1" == "stack" ]]; then
    source $DIR_NUAGE/devstack/lib/$Q_PLUGIN
    if [[ "$2" == "pre-install" ]]; then
        source $DIR_NUAGE/devstack/lib/nuagenetlib
        echo_summary "Installing nuagenetlib"
        install_nuagenetlib
    elif [[ "$2" == "install" ]]; then
        echo_summary "Installing Nuage plugin"
        setup_develop $DIR_NUAGE
        mkdir -v -p $NEUTRON_CONF_DIR/policy.d && cp -v $DIR_NUAGE/etc/neutron/policy.d/nuage_policy.json $NEUTRON_CONF_DIR/policy.d
    elif [[ "$2" == "post-config" ]]; then
        configure_neutron_nuage
    fi
elif [[ "$1" == "unstack" ]]; then
        # no-op
        :
fi
