#!/bin/bash

# Copyright 2017 NOKIA
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
    if [[ "$2" == "install" ]]; then
        if [ "$NUAGE_CREATE_FAKE_UPLINK" == "True" ]; then
            echo_summary "Creating fake uplink itf"
            if ! ip addr show fake_interface; then
                sudo ip link add fake_interface type dummy
                sudo ip link set fake_interface up
            fi
            sudo ip addr add $PUBLIC_NETWORK_GATEWAY/$UPLINK_PREFIX_LEN dev fake_interface
        fi
        echo_summary "Configuring Nuage VRS"
        configure_vrs_nuage
        echo_summary "Installing Nuage plugin"
        setup_develop $DIR_NUAGE

    elif [[ "$2" == "post-config" ]]; then
        mkdir -v -p $NEUTRON_CONF_DIR/policy.d && cp -v $DIR_NUAGE/etc/neutron/policy.d/nuage_policy.json $NEUTRON_CONF_DIR/policy.d
        configure_neutron_nuage
        configure_networking_sfc_policy
        configure_nova_nuage
        if [[ "${NUAGE_USE_METADATA}" == "True" ]]; then
            # Tweak the chain for nuage metadata proxy.
            sudo iptables -I openstack-INPUT 1 -i ${OVS_BRIDGE} -j ACCEPT || :
        fi
    elif [[ "$2" == "test-config" ]]; then
        # must run after Octavia is running.
        configure_octavia_nuage
    fi

elif [[ "$1" == "unstack" ]]; then
        stop_octavia_nuage
        if [ "$NUAGE_CREATE_FAKE_UPLINK" == "True" ]; then
            sudo ip link delete fake_interface
        fi
fi
