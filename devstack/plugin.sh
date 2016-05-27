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


dir=${GITDIR['nuage']}/devstack

if [[ $Q_PLUGIN == 'nuage' ]]; then
    source $dir/lib/nuage

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        source $dir/lib/nuagenetlib
        echo_summary "Installing nuagenetlib"
        install_nuagenetlib

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Nuage plugin"
        setup_develop ${GITDIR['nuage']}

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        mkdir -v -p $NEUTRON_CONF_DIR/policy.d && cp -v ${GITDIR['nuage']}/etc/neutron/policy.d/nuage_policy.json $NEUTRON_CONF_DIR/policy.d
        _neutron_deploy_rootwrap_filters ${GITDIR['nuage']}/nuage_neutron/lbaas
    fi

    if [[ "$1" == "unstack" ]]; then
        # no-op
        :
    fi
fi

