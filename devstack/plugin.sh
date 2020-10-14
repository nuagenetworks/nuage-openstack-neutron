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


source $NUAGE_OPENSTACK_NEUTRON_DIR/devstack/functions
if [[ "$1" == "stack" ]]; then
    source $NUAGE_OPENSTACK_NEUTRON_DIR/devstack/lib/$Q_PLUGIN
    if [[ "$2" == "install" ]]; then

        if is_service_enabled q-agt; then
            echo "Not installing Nuage VRS as Openvswitch is used"
        else
            echo_summary "Installing Nuage VRS"
            install_vrs
            echo_summary "Configuring Nuage VRS"
            configure_vrs_nuage
        fi

        echo_summary "Installing Nuage plugin"
        setup_develop $NUAGE_OPENSTACK_NEUTRON_DIR

    elif [[ "$2" == "post-config" ]]; then
        if is_service_enabled q-svc; then
            mkdir -v -p $NEUTRON_CONF_DIR/policy.d && cp -v $NUAGE_OPENSTACK_NEUTRON_DIR/etc/neutron/policy.d/nuage_policy.json $NEUTRON_CONF_DIR/policy.d
            configure_neutron_nuage
            configure_networking_sfc_policy
            clean_vsd_public_network
            if [[ "${NUAGE_USE_SWITCHDEV}" == "True" ]]; then
                cp -v $NUAGE_OPENSTACK_NEUTRON_DIR/devstack/lib/nuage_switchdev_policy.json $NEUTRON_CONF_DIR/policy.d
            fi
            # Create fake bridges for hw vtep if applicable
            if is_service_enabled q-agt; then
                create_fake_bridges_for_hwvtep
            fi
        fi
        configure_nova_nuage
        if [[ "${NUAGE_USE_METADATA}" == "True" ]]; then
            # Tweak the chain for nuage metadata proxy.
            sudo iptables -I openstack-INPUT 1 -i ${OVS_BRIDGE} -j ACCEPT || :
        fi
    elif [[ "$2" == "test-config" ]]; then
        if is_service_enabled q-svc; then
            # Must run after Octavia is running
            configure_octavia_nuage
            # Configure Hardware VTEP if applicable
            if is_service_enabled q-agt; then
                create_fake_gateway_for_hw_vtep
            fi
        fi
    fi

elif [[ "$1" == "unstack" ]]; then
        stop_octavia_nuage
        GUEST_INTERFACE_DEFAULT=$(ip link \
            | grep 'state UP' \
            | awk '{print $2}' \
            | sed 's/://' \
            | grep ^[ep] \
            | head -1)
        sudo ip a del "$PUBLIC_NETWORK_GATEWAY/$UPLINK_PREFIX_LEN" dev $GUEST_INTERFACE_DEFAULT
fi
